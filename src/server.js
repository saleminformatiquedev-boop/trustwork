// src/server.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const path = require('path');
const crypto = require('crypto');

const { pool, initDatabase } = require('./db');
const { setupAuth, ensureAuthenticated, normalizeUser } = require('./auth');
const escrow = require('./escrow');

const app = express();
const PORT = process.env.PORT || 3000;

// Configurations Express & Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Session
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'escrow-secret-key-1234',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Injection globale de l'utilisateur dans les vues EJS
app.use((req, res, next) => {
  res.locals.user = req.user ? normalizeUser(req.user) : null;
  next();
});

// Setup auth
setupAuth(app, pool);

// Helper pour formater les prix / nombres dans les vues
function formatRows(rows) {
  return rows.map(r => ({
    ...r,
    price: r.price !== undefined ? parseFloat(r.price) : undefined,
    amount: r.amount !== undefined ? parseFloat(r.amount) : undefined,
    walletBalance: r.walletBalance !== undefined ? parseFloat(r.walletBalance) : undefined,
    escrowBalance: r.escrowBalance !== undefined ? parseFloat(r.escrowBalance) : undefined
  }));
}

// ==========================================
// ROUTES PUBLIQUES
// ==========================================

// Page d'accueil : Liste des services
app.get('/', async (req, res) => {
  try {
    const srvRes = await pool.query(`
      SELECT s.*, u.name as "sellerName", u.avatar as "sellerAvatar"
      FROM services s
      JOIN users u ON s."sellerId" = u.id
      ORDER BY s."createdAt" DESC
    `);
    res.render('index', { services: formatRows(srvRes.rows) });
  } catch (err) {
    res.status(500).send("Erreur serveur: " + err.message);
  }
});

// Page de connexion
app.get('/login', (req, res) => {
  res.render('login', { msg: req.query.msg || null });
});

// Formulaire nouveau service (placé avant /services/:id)
app.get('/services/new', ensureAuthenticated, (req, res) => {
  res.render('new-service');
});

// Détail d'un service
app.get('/services/:id', async (req, res) => {
  try {
    const srvRes = await pool.query(`
      SELECT s.*, u.name as "sellerName", u.avatar as "sellerAvatar"
      FROM services s
      JOIN users u ON s."sellerId" = u.id
      WHERE s.id = $1
    `, [req.params.id]);

    if (srvRes.rows.length === 0) return res.status(404).send("Service introuvable");
    const service = formatRows(srvRes.rows)[0];

    res.render('service-detail', { service });
  } catch (err) {
    res.status(500).send("Erreur: " + err.message);
  }
});

// ==========================================
// ROUTES MEMBRE (SERVICES & COMMANDES)
// ==========================================

// Création d'un service
app.post('/services/new', ensureAuthenticated, async (req, res) => {
  try {
    const { title, description, category, price, deliveryDays } = req.body;
    const newId = 'srv_' + crypto.randomBytes(6).toString('hex');

    await pool.query(`
      INSERT INTO services (id, "sellerId", title, description, category, price, "deliveryDays")
      VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, [
      newId,
      req.user.id,
      title,
      description,
      category || 'Développement Web & Mobile',
      parseFloat(price),
      parseInt(deliveryDays, 10) || 3
    ]);

    res.redirect('/services/' + newId);
  } catch (err) {
    res.status(500).send("Erreur création service: " + err.message);
  }
});

// Créer une commande avec séquestre (Escrow)
app.post('/orders/create', ensureAuthenticated, async (req, res) => {
  try {
    const { serviceId, requirements } = req.body;
    const order = await escrow.createOrderWithEscrow(pool, {
      buyerId: req.user.id,
      serviceId,
      requirements
    });

    res.redirect('/orders/' + order.id);
  } catch (err) {
    res.status(400).send(`
      <script>
        alert("Erreur: ${err.message}");
        window.history.back();
      </script>
    `);
  }
});

// Suivi d'une commande
app.get('/orders/:id', ensureAuthenticated, async (req, res) => {
  try {
    const ordRes = await pool.query(`
      SELECT o.*, 
             s.title as "serviceTitle",
             b.name as "buyerName", b.email as "buyerEmail",
             sl.name as "sellerName", sl.email as "sellerEmail"
      FROM orders o
      JOIN services s ON o."serviceId" = s.id
      JOIN users b ON o."buyerId" = b.id
      JOIN users sl ON o."sellerId" = sl.id
      WHERE o.id = $1
    `, [req.params.id]);

    if (ordRes.rows.length === 0) return res.status(404).send("Commande introuvable");
    const order = formatRows(ordRes.rows)[0];

    // Vérification des droits d'accès
    if (req.user.role !== 'ADMIN' && req.user.id !== order.buyerId && req.user.id !== order.sellerId) {
      return res.status(403).send("Accès refusé à cette commande");
    }

    const dispRes = await pool.query('SELECT * FROM disputes WHERE "orderId" = $1', [order.id]);
    const dispute = dispRes.rows[0] ? formatRows(dispRes.rows)[0] : null;

    const msgRes = await pool.query(`
      SELECT m.*, u.name as "senderName"
      FROM messages m
      JOIN users u ON m."senderId" = u.id
      WHERE m."orderId" = $1
      ORDER BY m."createdAt" ASC
    `, [order.id]);

    res.render('order-detail', { order, dispute, messages: msgRes.rows });
  } catch (err) {
    res.status(500).send("Erreur: " + err.message);
  }
});

// Livraison par le vendeur
app.post('/orders/:id/deliver', ensureAuthenticated, async (req, res) => {
  try {
    await escrow.deliverOrder(pool, {
      orderId: req.params.id,
      sellerId: req.user.id,
      deliveryNote: req.body.deliveryNote
    });
    res.redirect('/orders/' + req.params.id);
  } catch (err) {
    res.status(400).send("Erreur: " + err.message);
  }
});

// Validation et déblocage des fonds par l'acheteur
app.post('/orders/:id/complete', ensureAuthenticated, async (req, res) => {
  try {
    await escrow.completeOrderAndReleaseFunds(pool, {
      orderId: req.params.id,
      buyerId: req.user.id
    });
    res.redirect('/orders/' + req.params.id);
  } catch (err) {
    res.status(400).send("Erreur: " + err.message);
  }
});

// Ouverture d'une enquête / litige
app.post('/orders/:id/dispute', ensureAuthenticated, async (req, res) => {
  try {
    const { reason, details } = req.body;
    await escrow.openDispute(pool, {
      orderId: req.params.id,
      userId: req.user.id,
      reason,
      details
    });
    res.redirect('/orders/' + req.params.id);
  } catch (err) {
    res.status(400).send("Erreur: " + err.message);
  }
});

// Message dans le fil de commande
app.post('/orders/:id/messages', ensureAuthenticated, async (req, res) => {
  try {
    const content = req.body.content;
    if (!content || !content.trim()) return res.redirect('/orders/' + req.params.id);

    const newId = 'msg_' + crypto.randomBytes(6).toString('hex');
    await pool.query(`
      INSERT INTO messages (id, "orderId", "senderId", content)
      VALUES ($1, $2, $3, $4)
    `, [newId, req.params.id, req.user.id, content.trim()]);

    res.redirect('/orders/' + req.params.id);
  } catch (err) {
    res.status(500).send("Erreur message: " + err.message);
  }
});

// ==========================================
// TABLEAU DE BORD & PORTEFEUILLE BINANCE
// ==========================================

app.get('/dashboard', ensureAuthenticated, async (req, res) => {
  try {
    const uRes = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    const user = normalizeUser(uRes.rows[0]);

    const buyerRes = await pool.query(`
      SELECT o.*, s.title as "serviceTitle", u.name as "sellerName"
      FROM orders o
      JOIN services s ON o."serviceId" = s.id
      JOIN users u ON o."sellerId" = u.id
      WHERE o."buyerId" = $1
      ORDER BY o."createdAt" DESC
    `, [user.id]);

    const sellerRes = await pool.query(`
      SELECT o.*, s.title as "serviceTitle", u.name as "buyerName"
      FROM orders o
      JOIN services s ON o."serviceId" = s.id
      JOIN users u ON o."buyerId" = u.id
      WHERE o."sellerId" = $1
      ORDER BY o."createdAt" DESC
    `, [user.id]);

    res.render('dashboard', {
      user,
      buyerOrders: formatRows(buyerRes.rows),
      sellerOrders: formatRows(sellerRes.rows)
    });
  } catch (err) {
    res.status(500).send("Erreur dashboard: " + err.message);
  }
});

// Dépôt de test USDT
app.post('/wallet/deposit-test', ensureAuthenticated, async (req, res) => {
  try {
    await pool.query('UPDATE users SET "walletBalance" = "walletBalance" + 50.00 WHERE id = $1', [req.user.id]);
    res.redirect('/dashboard');
  } catch (err) {
    res.status(500).send("Erreur: " + err.message);
  }
});

// Enregistrer Binance Pay ID
app.post('/wallet/update-binance', ensureAuthenticated, async (req, res) => {
  try {
    const { binanceId } = req.body;
    await pool.query('UPDATE users SET "binanceId" = $1 WHERE id = $2', [binanceId, req.user.id]);
    res.redirect('/dashboard');
  } catch (err) {
    res.status(500).send("Erreur: " + err.message);
  }
});

// ==========================================
// ARBITRAGE ADMIN (LITIGES)
// ==========================================

app.get('/admin/disputes', ensureAuthenticated, async (req, res) => {
  try {
    if (req.user.role !== 'ADMIN') {
      return res.status(403).send("Accès réservé aux modérateurs.");
    }

    const dispRes = await pool.query(`
      SELECT d.*, o.amount, o."serviceId", s.title as "serviceTitle"
      FROM disputes d
      JOIN orders o ON d."orderId" = o.id
      JOIN services s ON o."serviceId" = s.id
      ORDER BY d."createdAt" DESC
    `);

    res.render('disputes', { disputes: formatRows(dispRes.rows) });
  } catch (err) {
    res.status(500).send("Erreur arbitrage: " + err.message);
  }
});

app.post('/disputes/:id/resolve', ensureAuthenticated, async (req, res) => {
  try {
    if (req.user.role !== 'ADMIN') {
      return res.status(403).send("Non autorisé");
    }

    const { resolution, resolutionNote } = req.body;
    await escrow.resolveDispute(pool, {
      disputeId: req.params.id,
      resolution,
      resolutionNote
    });

    res.redirect('/admin/disputes');
  } catch (err) {
    res.status(500).send("Erreur résolution: " + err.message);
  }
});

// Initialiser les tables PostgreSQL puis démarrer le serveur
initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`\n🚀 Serveur TrustWork démarré avec succès sur http://localhost:${PORT}`);
    console.log(`🐘 Base de Données : PostgreSQL 18 (ACID Enabled)`);
    console.log(`🔒 Système de Séquestre Escrow : Actif`);
    console.log(`💰 Mode Binance Pay & USDT : Actif\n`);
  });
}).catch(err => {
  console.error("❌ Erreur au démarrage de PostgreSQL :", err);
});
