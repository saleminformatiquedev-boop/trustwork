// src/server.js
require('dotenv').config();
const http = require('http');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { Server } = require('socket.io');
const multer = require('multer');

const { pool, initDatabase } = require('./db');
const { setupAuth, ensureAuthenticated, normalizeUser } = require('./auth');
const escrow = require('./escrow');
const emailService = require('./services/email');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

// Configuration Upload fichiers (Livrables, Pièces jointes, Preuves de litige)
const uploadDir = path.join(__dirname, '../public/uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const uniqueName = Date.now() + '-' + crypto.randomBytes(4).toString('hex') + ext;
    cb(null, uniqueName);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024 } // 25 MB max
});

// Middleware Express
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

// Helper de formatage
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
// SOCKET.IO (MESSAGERIE & SÉQUESTRE TEMPS RÉEL)
// ==========================================
io.on('connection', (socket) => {
  socket.on('join_order', ({ orderId }) => {
    socket.join(`order_${orderId}`);
  });

  socket.on('send_message', async ({ orderId, senderId, senderName, content, fileUrl, fileName }) => {
    try {
      if ((!content || !content.trim()) && !fileUrl) return;

      const newId = 'msg_' + crypto.randomBytes(6).toString('hex');
      const insertRes = await pool.query(`
        INSERT INTO messages (id, "orderId", "senderId", content, "fileUrl", "fileName")
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
      `, [newId, orderId, senderId, content ? content.trim() : '', fileUrl || null, fileName || null]);

      const savedMsg = insertRes.rows[0];

      io.to(`order_${orderId}`).emit('new_message', {
        id: savedMsg.id,
        orderId,
        senderId,
        senderName: senderName || 'Utilisateur',
        content: savedMsg.content,
        fileUrl: savedMsg.fileUrl,
        fileName: savedMsg.fileName,
        createdAt: savedMsg.createdAt
      });
    } catch (err) {
      console.error("Erreur socket send_message :", err);
    }
  });
});

// ==========================================
// ROUTES PUBLIQUES
// ==========================================

// Page d'accueil : Catalogue des services
app.get('/', async (req, res) => {
  try {
    const srvRes = await pool.query(`
      SELECT s.*, u.name as "sellerName", u.avatar as "sellerAvatar",
             COALESCE(AVG(r.rating), 5.0) as "avgRating",
             COUNT(r.id) as "reviewsCount"
      FROM services s
      JOIN users u ON s."sellerId" = u.id
      LEFT JOIN reviews r ON s.id = r."serviceId"
      GROUP BY s.id, u.name, u.avatar
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

// Détail d'un service avec avis clients
app.get('/services/:id', async (req, res) => {
  try {
    const srvRes = await pool.query(`
      SELECT s.*, u.name as "sellerName", u.avatar as "sellerAvatar", u.bio as "sellerBio", u.skills as "sellerSkills"
      FROM services s
      JOIN users u ON s."sellerId" = u.id
      WHERE s.id = $1
    `, [req.params.id]);

    if (srvRes.rows.length === 0) return res.status(404).send("Service introuvable");
    const service = formatRows(srvRes.rows)[0];

    // Avis associés à ce service
    const reviewsRes = await pool.query(`
      SELECT r.*, u.name as "buyerName", u.avatar as "buyerAvatar"
      FROM reviews r
      JOIN users u ON r."buyerId" = u.id
      WHERE r."serviceId" = $1
      ORDER BY r."createdAt" DESC
    `, [service.id]);

    res.render('service-detail', { service, reviews: reviewsRes.rows });
  } catch (err) {
    res.status(500).send("Erreur: " + err.message);
  }
});

// Profil public d'un travailleur
app.get('/profile/:id', async (req, res) => {
  try {
    const uRes = await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
    if (uRes.rows.length === 0) return res.status(404).send("Profil utilisateur introuvable");
    const profile = normalizeUser(uRes.rows[0]);

    const srvRes = await pool.query(`
      SELECT s.*, u.name as "sellerName", u.avatar as "sellerAvatar"
      FROM services s
      JOIN users u ON s."sellerId" = u.id
      WHERE s."sellerId" = $1
      ORDER BY s."createdAt" DESC
    `, [profile.id]);

    const revRes = await pool.query(`
      SELECT r.*, u.name as "buyerName", u.avatar as "buyerAvatar", s.title as "serviceTitle"
      FROM reviews r
      JOIN users u ON r."buyerId" = u.id
      JOIN services s ON r."serviceId" = s.id
      WHERE r."sellerId" = $1
      ORDER BY r."createdAt" DESC
    `, [profile.id]);

    res.render('profile', { profile, services: formatRows(srvRes.rows), reviews: revRes.rows });
  } catch (err) {
    res.status(500).send("Erreur profil: " + err.message);
  }
});

// ==========================================
// ROUTES MEMBRE (SERVICES, COMMANDES & FICHIERS)
// ==========================================

// Upload de fichier dans le chat / commande
app.post('/api/upload', ensureAuthenticated, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, error: 'Aucun fichier fourni' });
  }
  const fileUrl = `/uploads/${req.file.filename}`;
  res.json({
    success: true,
    fileUrl,
    fileName: req.file.originalname,
    fileSize: req.file.size
  });
});

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

    if (req.user.role !== 'ADMIN' && req.user.id !== order.buyerId && req.user.id !== order.sellerId) {
      return res.status(403).send("Accès refusé à cette commande");
    }

    const dispRes = await pool.query('SELECT * FROM disputes WHERE "orderId" = $1', [order.id]);
    const dispute = dispRes.rows[0] ? formatRows(dispRes.rows)[0] : null;

    const reviewRes = await pool.query('SELECT * FROM reviews WHERE "orderId" = $1', [order.id]);
    const review = reviewRes.rows[0] || null;

    const msgRes = await pool.query(`
      SELECT m.*, u.name as "senderName"
      FROM messages m
      JOIN users u ON m."senderId" = u.id
      WHERE m."orderId" = $1
      ORDER BY m."createdAt" ASC
    `, [order.id]);

    res.render('order-detail', { order, dispute, review, messages: msgRes.rows });
  } catch (err) {
    res.status(500).send("Erreur: " + err.message);
  }
});

// Livraison par le vendeur (notifie en direct via Socket.io)
app.post('/orders/:id/deliver', ensureAuthenticated, async (req, res) => {
  try {
    const updated = await escrow.deliverOrder(pool, {
      orderId: req.params.id,
      sellerId: req.user.id,
      deliveryNote: req.body.deliveryNote
    });

    io.to(`order_${req.params.id}`).emit('order_updated', { status: 'DELIVERED', order: updated });
    res.redirect('/orders/' + req.params.id);
  } catch (err) {
    res.status(400).send("Erreur: " + err.message);
  }
});

// Validation et déblocage des fonds par l'acheteur
app.post('/orders/:id/complete', ensureAuthenticated, async (req, res) => {
  try {
    const updated = await escrow.completeOrderAndReleaseFunds(pool, {
      orderId: req.params.id,
      buyerId: req.user.id
    });

    io.to(`order_${req.params.id}`).emit('order_updated', { status: 'COMPLETED', order: updated });
    res.redirect('/orders/' + req.params.id);
  } catch (err) {
    res.status(400).send("Erreur: " + err.message);
  }
});

// Laisser un avis / note sur la commande complétée
app.post('/orders/:id/review', ensureAuthenticated, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    const ordRes = await pool.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);
    const order = ordRes.rows[0];

    if (!order || order.buyerId !== req.user.id) {
      return res.status(403).send("Seul l'acheteur peut déposer un avis.");
    }
    if (order.status !== 'COMPLETED') {
      return res.status(400).send("L'avis ne peut être déposé que sur une commande terminée.");
    }

    const reviewId = 'rev_' + crypto.randomBytes(6).toString('hex');
    await pool.query(`
      INSERT INTO reviews (id, "orderId", "serviceId", "buyerId", "sellerId", rating, comment)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      ON CONFLICT ("orderId") DO UPDATE SET rating = $6, comment = $7
    `, [reviewId, order.id, order.serviceId, order.buyerId, order.sellerId, parseInt(rating, 10), comment || '']);

    // Notification email vendeur
    (async () => {
      try {
        const uSeller = await pool.query('SELECT * FROM users WHERE id = $1', [order.sellerId]);
        const uBuyer = await pool.query('SELECT * FROM users WHERE id = $1', [order.buyerId]);
        if (uSeller.rows[0] && uBuyer.rows[0]) {
          emailService.notifyReviewSubmitted({
            review: { rating: parseInt(rating, 10), comment: comment || '' },
            order,
            seller: uSeller.rows[0],
            buyer: uBuyer.rows[0]
          });
        }
      } catch (e) {
        console.warn("Erreur notification review email:", e.message);
      }
    })();

    res.redirect('/orders/' + req.params.id);
  } catch (err) {
    res.status(500).send("Erreur avis: " + err.message);
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

    io.to(`order_${req.params.id}`).emit('order_updated', { status: 'DISPUTED' });
    res.redirect('/orders/' + req.params.id);
  } catch (err) {
    res.status(400).send("Erreur: " + err.message);
  }
});

// ==========================================
// TABLEAU DE BORD, PORTEFEUILLE & RETRAITS
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

    // Retraits demandés
    const withRes = await pool.query(`
      SELECT * FROM withdrawals WHERE "userId" = $1 ORDER BY "createdAt" DESC LIMIT 10
    `, [user.id]);

    res.render('dashboard', {
      user,
      buyerOrders: formatRows(buyerRes.rows),
      sellerOrders: formatRows(sellerRes.rows),
      withdrawals: formatRows(withRes.rows)
    });
  } catch (err) {
    res.status(500).send("Erreur dashboard: " + err.message);
  }
});

// Demande de retrait vers Binance Pay
app.post('/api/wallet/withdraw', ensureAuthenticated, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const amount = parseFloat(req.body.amount);

    if (isNaN(amount) || amount <= 0) {
      return res.status(400).json({ success: false, error: 'Montant de retrait invalide' });
    }

    const uRes = await client.query('SELECT * FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
    const user = uRes.rows[0];

    if (!user.binanceId) {
      return res.status(400).json({ success: false, error: 'Veuillez enregistrer votre Binance Pay ID avant de demander un retrait' });
    }

    if (parseFloat(user.walletBalance) < amount) {
      return res.status(400).json({ success: false, error: 'Solde disponible insuffisant' });
    }

    // Déduire du solde
    await client.query('UPDATE users SET "walletBalance" = "walletBalance" - $1 WHERE id = $2', [amount, user.id]);

    // Créer la demande de retrait
    const withId = 'wth_' + crypto.randomBytes(6).toString('hex');
    await client.query(`
      INSERT INTO withdrawals (id, "userId", amount, "binanceId", status)
      VALUES ($1, $2, $3, $4, 'PENDING')
    `, [withId, user.id, amount, user.binanceId]);

    await client.query('COMMIT');

    // Notification email retrait
    (async () => {
      try {
        emailService.notifyWithdrawalRequested({
          user,
          amount,
          binanceId: user.binanceId
        });
      } catch (e) {
        console.warn("Erreur notification retrait email:", e.message);
      }
    })();

    res.json({ success: true, message: `Demande de retrait de ${amount.toFixed(2)} USDT transmise avec succès.` });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// Page Historique
app.get('/history', ensureAuthenticated, async (req, res) => {
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
    const buyerHistory = formatRows(buyerRes.rows);

    const sellerRes = await pool.query(`
      SELECT o.*, s.title as "serviceTitle", u.name as "buyerName"
      FROM orders o
      JOIN services s ON o."serviceId" = s.id
      JOIN users u ON o."buyerId" = u.id
      WHERE o."sellerId" = $1
      ORDER BY o."createdAt" DESC
    `, [user.id]);
    const sellerHistory = formatRows(sellerRes.rows);

    let adminDisputes = [];
    if (user.role === 'ADMIN') {
      const dispRes = await pool.query(`
        SELECT d.*, o.amount, o."serviceId", s.title as "serviceTitle"
        FROM disputes d
        JOIN orders o ON d."orderId" = o.id
        JOIN services s ON o."serviceId" = s.id
        ORDER BY d."createdAt" DESC
      `);
      adminDisputes = formatRows(dispRes.rows);
    }

    const totalSpent = buyerHistory
      .filter(o => o.status !== 'REFUNDED')
      .reduce((acc, curr) => acc + (curr.amount || 0), 0);

    const totalEarned = sellerHistory
      .filter(o => o.status === 'COMPLETED')
      .reduce((acc, curr) => acc + (curr.amount || 0), 0);

    const completedCount = buyerHistory.filter(o => o.status === 'COMPLETED').length + 
                           sellerHistory.filter(o => o.status === 'COMPLETED').length;

    res.render('history', {
      user,
      buyerHistory,
      sellerHistory,
      adminDisputes,
      totalSpent,
      totalEarned,
      completedCount
    });
  } catch (err) {
    res.status(500).send("Erreur historique: " + err.message);
  }
});

// API AJAX : Recharger le solde USDT
app.post('/api/wallet/deposit-test', ensureAuthenticated, async (req, res) => {
  try {
    const upd = await pool.query(`
      UPDATE users 
      SET "walletBalance" = "walletBalance" + 50.00 
      WHERE id = $1 
      RETURNING "walletBalance"
    `, [req.user.id]);

    res.json({ success: true, newWalletBalance: parseFloat(upd.rows[0].walletBalance) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// API AJAX : Enregistrer Binance Pay ID & Bio
app.post('/api/wallet/update-binance', ensureAuthenticated, async (req, res) => {
  try {
    const { binanceId, bio, skills } = req.body;
    await pool.query(`
      UPDATE users 
      SET "binanceId" = COALESCE($1, "binanceId"),
          bio = COALESCE($2, bio),
          skills = COALESCE($3, skills)
      WHERE id = $4
    `, [binanceId || null, bio || null, skills || null, req.user.id]);
    res.json({ success: true, binanceId });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
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

// Initialiser PostgreSQL et démarrer le serveur Socket.io
initDatabase().then(() => {
  server.listen(PORT, () => {
    console.log(`\n🚀 Serveur TrustWork démarré avec succès sur http://localhost:${PORT}`);
    console.log(`⚡ WebSocket / Socket.io : Actif (Temps réel)`);
    console.log(`📎 Upload de Fichiers & Pièces Jointes : Actif`);
    console.log(`🐘 Base de Données : PostgreSQL 18 (ACID Enabled)`);
    console.log(`🔒 Système de Séquestre Escrow : Actif`);
    console.log(`💰 Mode Binance Pay & USDT : Actif\n`);
  });
}).catch(err => {
  console.error("❌ Erreur au démarrage de PostgreSQL :", err);
});
