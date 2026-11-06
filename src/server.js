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
const QRCode = require('qrcode');

const { pool, initDatabase } = require('./db');
const { setupAuth, ensureAuthenticated, normalizeUser } = require('./auth');
const escrow = require('./escrow');
const emailService = require('./services/email');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Trust Nginx reverse proxy & hide Express fingerprint
app.set('trust proxy', 1);
app.disable('x-powered-by');

const PORT = process.env.PORT || 3000;
const PLATFORM_BINANCE_PAY_ID = process.env.PLATFORM_BINANCE_PAY_ID || process.env.BINANCE_PAY_ID || 'BINANCE-PAY-789456';

// Security Headers Middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});

// Lightweight Rate Limiter for sensitive endpoints (120 req / min / IP)
const rateLimitStore = new Map();
setInterval(() => rateLimitStore.clear(), 60 * 1000).unref();
function rateLimiter(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const count = (rateLimitStore.get(ip) || 0) + 1;
  rateLimitStore.set(ip, count);
  if (count > 120) {
    return res.status(429).json({ success: false, error: 'Too many requests, please slow down.' });
  }
  next();
}
app.use(['/api', '/auth', '/orders', '/disputes'], rateLimiter);

// Upload Directory configuration & Strict Whitelist
const uploadDir = path.join(__dirname, '../public/uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const ALLOWED_EXTENSIONS = new Set([
  '.pdf', '.zip', '.rar', '.tar', '.gz', '.7z',
  '.txt', '.md', '.sh', '.env', '.json', '.yml', '.yaml',
  '.png', '.jpg', '.jpeg', '.webp', '.gif',
  '.mp4', '.mov', '.webm', '.doc', '.docx'
]);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const rawExt = path.extname(file.originalname || '').toLowerCase().replace(/[^a-z0-9.]/g, '');
    const safeExt = ALLOWED_EXTENSIONS.has(rawExt) ? rawExt : '.bin';
    const uniqueName = Date.now() + '-' + crypto.randomBytes(6).toString('hex') + safeExt;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024 }, // 25 MB max
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase();
    if (!ALLOWED_EXTENSIONS.has(ext)) {
      return cb(new Error(`Unsupported file format (${ext}). Allowed formats: PDF, ZIP, TXT, Images, Videos.`));
    }
    cb(null, true);
  }
});

// Middleware Express
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(express.json({ limit: '2mb' }));

// Harden /uploads static serving to prevent stored XSS execution
app.use('/uploads', (req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', "default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'");
  const ext = path.extname(req.path).toLowerCase();
  if (!['.png', '.jpg', '.jpeg', '.webp', '.gif', '.pdf', '.mp4', '.webm'].includes(ext)) {
    res.setHeader('Content-Disposition', 'attachment');
  }
  next();
});
app.use(express.static(path.join(__dirname, '../public')));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Hardened Session Configuration (shared with Socket.io)
const sessionMiddleware = session({
  name: 'trustwork.sid',
  secret: process.env.SESSION_SECRET || 'escrow-secret-key-1234-change-in-prod',
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: 'auto',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
});

app.use(sessionMiddleware);
app.use(passport.initialize());
app.use(passport.session());

// Share session with Socket.io and authenticate socket connections
io.engine.use(sessionMiddleware);
io.use(async (socket, next) => {
  try {
    const userId = socket.request.session?.passport?.user;
    if (userId) {
      const uRes = await pool.query('SELECT id, name, email, avatar, role FROM users WHERE id = $1', [userId]);
      socket.user = uRes.rows[0] || null;
    } else {
      socket.user = null;
    }
    next();
  } catch (err) {
    next(err);
  }
});

// Global injection of user and unread chat counter in EJS views
app.use(async (req, res, next) => {
  res.locals.user = req.user ? normalizeUser(req.user) : null;
  res.locals.unreadChatCount = 0;
  if (req.user) {
    try {
      const unreadRes = await pool.query(
        'SELECT COALESCE(SUM("unreadCount"), 0) as total FROM conversation_participants WHERE "userId" = $1',
        [req.user.id]
      );
      res.locals.unreadChatCount = parseInt(unreadRes.rows[0].total, 10) || 0;
    } catch (e) {
      res.locals.unreadChatCount = 0;
    }
  }
  next();
});

// Setup auth
setupAuth(app, pool);

// Helper for row formatting
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
// SOCKET.IO (AUTHENTICATED REAL-TIME MESSAGING & ESCROW)
// ==========================================
async function canAccessOrder(user, orderId) {
  if (!user || !orderId) return false;
  if (user.role === 'ADMIN') return true;
  const res = await pool.query('SELECT "buyerId", "sellerId" FROM orders WHERE id = $1', [orderId]);
  if (res.rows.length === 0) return false;
  return res.rows[0].buyerId === user.id || res.rows[0].sellerId === user.id;
}

async function canAccessConversation(user, conversationId) {
  if (!user || !conversationId) return false;
  if (user.role === 'ADMIN') return true;
  const res = await pool.query(
    'SELECT 1 FROM conversation_participants WHERE "conversationId" = $1 AND "userId" = $2 LIMIT 1',
    [conversationId, user.id]
  );
  return res.rows.length > 0;
}

io.on('connection', (socket) => {
  // User rooms for notifications / badges (strictly bound to authenticated session user)
  socket.on('join_user', () => {
    if (socket.user && socket.user.id) {
      socket.join(`user_${socket.user.id}`);
    }
  });

  // Order rooms (verified against order participants)
  socket.on('join_order', async ({ orderId } = {}) => {
    try {
      if (await canAccessOrder(socket.user, orderId)) {
        socket.join(`order_${orderId}`);
      }
    } catch (err) {
      console.error("Socket error join_order:", err);
    }
  });

  socket.on('send_message', async ({ orderId, content, fileUrl, fileName } = {}) => {
    try {
      if (!socket.user) return;
      if (!(await canAccessOrder(socket.user, orderId))) return;
      if ((!content || !content.trim()) && !fileUrl) return;

      const senderId = socket.user.id;
      const senderName = socket.user.name || 'User';
      const safeFileUrl = fileUrl && String(fileUrl).startsWith('/uploads/') ? String(fileUrl) : null;

      const newId = 'msg_' + crypto.randomBytes(6).toString('hex');
      const insertRes = await pool.query(`
        INSERT INTO messages (id, "orderId", "senderId", content, "fileUrl", "fileName")
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
      `, [newId, orderId, senderId, content ? content.trim() : '', safeFileUrl, fileName || null]);

      const savedMsg = insertRes.rows[0];

      io.to(`order_${orderId}`).emit('new_message', {
        id: savedMsg.id,
        orderId,
        senderId,
        senderName,
        content: savedMsg.content,
        fileUrl: savedMsg.fileUrl,
        fileName: savedMsg.fileName,
        createdAt: savedMsg.createdAt
      });
    } catch (err) {
      console.error("Socket error send_message:", err);
    }
  });

  // Direct chat rooms (verified against conversation participants)
  socket.on('join_conversation', async ({ conversationId } = {}) => {
    try {
      if (await canAccessConversation(socket.user, conversationId)) {
        socket.join(`conv_${conversationId}`);
      }
    } catch (err) {
      console.error("Socket error join_conversation:", err);
    }
  });

  socket.on('leave_conversation', ({ conversationId } = {}) => {
    if (conversationId) {
      socket.leave(`conv_${conversationId}`);
    }
  });

  socket.on('chat_send_message', async ({ conversationId, content, fileUrl, fileName, fileSize } = {}) => {
    try {
      if (!socket.user) return;
      if (!(await canAccessConversation(socket.user, conversationId))) return;
      if ((!content || !content.trim()) && !fileUrl) return;

      const senderId = socket.user.id;
      const senderName = socket.user.name || 'User';
      const senderAvatar = socket.user.avatar || null;
      const senderRole = socket.user.role || 'USER';
      const safeFileUrl = fileUrl && String(fileUrl).startsWith('/uploads/') ? String(fileUrl) : null;

      const trimmedContent = content ? content.trim() : '';
      const newMsgId = 'dmsg_' + crypto.randomBytes(6).toString('hex');

      // 1. Save in direct_messages
      const insertRes = await pool.query(`
        INSERT INTO direct_messages (id, "conversationId", "senderId", content, "fileUrl", "fileName", "fileSize", "isRead")
        VALUES ($1, $2, $3, $4, $5, $6, $7, false)
        RETURNING *
      `, [newMsgId, conversationId, senderId, trimmedContent, safeFileUrl, fileName || null, fileSize || null]);

      const savedMsg = insertRes.rows[0];

      // 2. Update last message preview in conversations
      const previewText = trimmedContent || (fileName ? `📎 File: ${fileName}` : 'Attachment');
      await pool.query(`
        UPDATE conversations
        SET "lastMessageText" = $1, "lastMessageAt" = CURRENT_TIMESTAMP, "updatedAt" = CURRENT_TIMESTAMP
        WHERE id = $2
      `, [previewText, conversationId]);

      // 3. Increment unread counter for other participants
      await pool.query(`
        UPDATE conversation_participants
        SET "unreadCount" = "unreadCount" + 1
        WHERE "conversationId" = $1 AND "userId" != $2
      `, [conversationId, senderId]);

      // 4. Message payload to broadcast in the conversation room
      const msgPayload = {
        id: savedMsg.id,
        conversationId,
        senderId,
        senderName,
        senderAvatar,
        senderRole,
        content: savedMsg.content,
        fileUrl: savedMsg.fileUrl,
        fileName: savedMsg.fileName,
        fileSize: savedMsg.fileSize,
        createdAt: savedMsg.createdAt,
        isRead: false
      };

      io.to(`conv_${conversationId}`).emit('new_chat_message', msgPayload);

      // 5. Notify recipients on their personal channels user_...
      const partRes = await pool.query(
        `SELECT cp."userId", cp."unreadCount", u.name, u.email, u.role
         FROM conversation_participants cp
         JOIN users u ON cp."userId" = u.id
         WHERE cp."conversationId" = $1 AND cp."userId" != $2`,
        [conversationId, senderId]
      );

      for (const p of partRes.rows) {
        const totalUnreadRes = await pool.query(
          'SELECT COALESCE(SUM("unreadCount"), 0) as total FROM conversation_participants WHERE "userId" = $1',
          [p.userId]
        );
        const unreadTotal = parseInt(totalUnreadRes.rows[0].total, 10) || 1;

        io.to(`user_${p.userId}`).emit('chat_notification', {
          conversationId,
          senderId,
          senderName,
          senderAvatar,
          senderRole,
          preview: previewText,
          unreadTotal,
          createdAt: savedMsg.createdAt
        });

        // Email notification if first unread message
        if (p.unreadCount <= 1) {
          (async () => {
            try {
              emailService.notifyUnreadChatMessage({
                recipient: { id: p.userId, name: p.name, email: p.email, role: p.role },
                sender: { id: senderId, name: senderName, role: senderRole },
                conversationId,
                messageText: previewText
              });
            } catch (errEmail) {
              console.warn("Error email notification chat:", errEmail.message);
            }
          })();
        }
      }
    } catch (err) {
      console.error("Socket error chat_send_message:", err);
    }
  });

  socket.on('chat_typing', async ({ conversationId, isTyping } = {}) => {
    try {
      if (!socket.user) return;
      if (await canAccessConversation(socket.user, conversationId)) {
        socket.to(`conv_${conversationId}`).emit('user_typing', {
          conversationId,
          userId: socket.user.id,
          userName: socket.user.name,
          isTyping: !!isTyping
        });
      }
    } catch (err) {
      console.error("Error chat_typing:", err);
    }
  });

  socket.on('chat_mark_read', async ({ conversationId } = {}) => {
    try {
      if (!socket.user) return;
      const userId = socket.user.id;
      if (!(await canAccessConversation(socket.user, conversationId))) return;

      await pool.query(`
        UPDATE conversation_participants
        SET "unreadCount" = 0, "lastReadAt" = CURRENT_TIMESTAMP
        WHERE "conversationId" = $1 AND "userId" = $2
      `, [conversationId, userId]);

      await pool.query(`
        UPDATE direct_messages
        SET "isRead" = true
        WHERE "conversationId" = $1 AND "senderId" != $2
      `, [conversationId, userId]);

      socket.to(`conv_${conversationId}`).emit('messages_read', { conversationId, userId });
    } catch (err) {
      console.error("Error chat_mark_read:", err);
    }
  });
});

// ==========================================
// PUBLIC ROUTES
// ==========================================

// Homepage: Guides & Methods Catalog
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
    res.status(500).send("Server error: " + err.message);
  }
});

// Login Page
app.get('/login', (req, res) => {
  res.render('login', { msg: req.query.msg || null });
});

// New Method Form (before /services/:id)
app.get('/services/new', ensureAuthenticated, (req, res) => {
  res.render('new-service');
});

// Detail of a guide/service with reviews
app.get('/services/:id', async (req, res) => {
  try {
    const srvRes = await pool.query(`
      SELECT s.*, u.name as "sellerName", u.avatar as "sellerAvatar", u.bio as "sellerBio", u.skills as "sellerSkills"
      FROM services s
      JOIN users u ON s."sellerId" = u.id
      WHERE s.id = $1
    `, [req.params.id]);

    if (srvRes.rows.length === 0) return res.status(404).send("Guide not found");
    const service = formatRows(srvRes.rows)[0];

    const reviewsRes = await pool.query(`
      SELECT r.*, u.name as "buyerName", u.avatar as "buyerAvatar"
      FROM reviews r
      JOIN users u ON r."buyerId" = u.id
      WHERE r."serviceId" = $1
      ORDER BY r."createdAt" DESC
    `, [service.id]);

    res.render('service-detail', { service, reviews: reviewsRes.rows });
  } catch (err) {
    res.status(500).send("Error: " + err.message);
  }
});

// Public Author Profile
app.get('/profile/:id', async (req, res) => {
  try {
    const uRes = await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
    if (uRes.rows.length === 0) return res.status(404).send("User profile not found");
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
    res.status(500).send("Profile error: " + err.message);
  }
});

// ==========================================
// MEMBER ROUTES (SERVICES, ORDERS & FILES)
// ==========================================

// File upload in chat / order
app.post('/api/upload', ensureAuthenticated, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, error: 'No file provided' });
  }
  const fileUrl = `/uploads/${req.file.filename}`;
  res.json({
    success: true,
    fileUrl,
    fileName: req.file.originalname,
    fileSize: req.file.size
  });
});

// Publish new multi-format method (PDF, ZIP, Text, Video)
app.post('/services/new', ensureAuthenticated, upload.any(), async (req, res) => {
  try {
    const { title, description, category, price, pageCount, difficulty, videoUrl, formats } = req.body;
    const newId = 'srv_' + crypto.randomBytes(6).toString('hex');

    const attachments = [];
    let primaryFileUrl = null;
    let primaryFileName = null;
    let primaryFileSize = null;

    if (req.files && req.files.length > 0) {
      req.files.forEach(f => {
        const ext = path.extname(f.originalname).toLowerCase();
        let type = 'other';
        let label = f.originalname;

        if (ext === '.pdf') {
          type = 'pdf';
          label = `Complete Guide (${f.originalname})`;
        } else if (['.zip', '.rar', '.tar', '.gz'].includes(ext)) {
          type = 'zip';
          label = `Source Code & Archives (${f.originalname})`;
        } else if (['.txt', '.md', '.sh', '.env', '.json', '.yml', '.yaml'].includes(ext)) {
          type = 'text';
          label = `Scripts & Configuration (${f.originalname})`;
        } else if (['.mp4', '.mov', '.webm', '.mkv'].includes(ext)) {
          type = 'video';
          label = `Video Tutorial (${f.originalname})`;
        }

        const sizeMb = (f.size / (1024 * 1024)).toFixed(1);
        const sizeStr = sizeMb > 0 ? `${sizeMb} MB` : `${(f.size / 1024).toFixed(0)} KB`;
        const url = `/uploads/${f.filename}`;

        attachments.push({
          type,
          name: f.originalname,
          url,
          size: sizeStr,
          label
        });

        if (!primaryFileUrl) {
          primaryFileUrl = url;
          primaryFileName = f.originalname;
          primaryFileSize = sizeStr;
        }
      });
    }

    if (videoUrl && videoUrl.trim()) {
      attachments.push({
        type: 'video',
        name: 'Online Video Tutorial',
        url: videoUrl.trim(),
        size: 'Video Stream',
        label: 'Step-by-Step Video Tutorial'
      });
    }

    // Fallback demo pack if no files uploaded
    if (attachments.length === 0) {
      attachments.push(
        { type: "pdf", name: "guide-method-step-by-step.pdf", url: "/uploads/guide-methode-developpement-ideale.pdf", size: "2.4 MB", label: "Complete Step-by-Step Guide (PDF)" },
        { type: "zip", name: "source-code-template.zip", url: "/uploads/code-source-template.zip", size: "5.1 MB", label: "Source Code & Ready Files (ZIP)" },
        { type: "text", name: "commands-scripts.txt", url: "/uploads/commandes-scripts.txt", size: "15 KB", label: "Shell Scripts & .env Variables (Text)" }
      );
      if (videoUrl && videoUrl.trim()) {
        attachments.push({ type: "video", name: "video-tutorial", url: videoUrl.trim(), size: "Stream", label: "Video Tutorial" });
      }
      primaryFileUrl = '/uploads/guide-methode-developpement-ideale.pdf';
      primaryFileName = 'complete-method-pack.zip';
      primaryFileSize = '7.5 MB';
    }

    const activeFormats = Array.isArray(formats) ? formats.join(',') : (formats || 'PDF,ZIP,TEXT');

    await pool.query(`
      INSERT INTO services (id, "sellerId", title, description, category, price, "deliveryDays", "fileUrl", "fileName", "fileSize", "pageCount", "difficulty", "formats", "videoUrl", "attachments")
      VALUES ($1, $2, $3, $4, $5, $6, 1, $7, $8, $9, $10, $11, $12, $13, $14::jsonb)
    `, [
      newId,
      req.user.id,
      title,
      description,
      category || 'Development Methodology',
      parseFloat(price),
      primaryFileUrl,
      primaryFileName,
      primaryFileSize,
      parseInt(pageCount, 10) || 30,
      difficulty || 'Intermediate',
      activeFormats,
      videoUrl || null,
      JSON.stringify(attachments)
    ]);

    res.redirect('/services/' + newId);
  } catch (err) {
    res.status(500).send("Error creating method pack: " + err.message);
  }
});

// Create order with Escrow
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
    const safeMsg = JSON.stringify("Error: " + (err.message || "Unable to create order"));
    res.status(400).send(`
      <script>
        alert(${safeMsg});
        window.history.back();
      </script>
    `);
  }
});

// Order detail & tracking
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

    if (ordRes.rows.length === 0) return res.status(404).send("Order not found");
    const order = formatRows(ordRes.rows)[0];

    if (req.user.role !== 'ADMIN' && req.user.id !== order.buyerId && req.user.id !== order.sellerId) {
      return res.status(403).send("Access denied to this order");
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
    res.status(500).send("Error: " + err.message);
  }
});

// Author delivers order
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
    res.status(400).send("Error: " + err.message);
  }
});

// Buyer approves and releases funds
app.post('/orders/:id/complete', ensureAuthenticated, async (req, res) => {
  try {
    const updated = await escrow.completeOrderAndReleaseFunds(pool, {
      orderId: req.params.id,
      buyerId: req.user.id
    });

    io.to(`order_${req.params.id}`).emit('order_updated', { status: 'COMPLETED', order: updated });
    res.redirect('/orders/' + req.params.id);
  } catch (err) {
    res.status(400).send("Error: " + err.message);
  }
});

// Leave review on completed order
app.post('/orders/:id/review', ensureAuthenticated, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    const ordRes = await pool.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);
    const order = ordRes.rows[0];

    if (!order || order.buyerId !== req.user.id) {
      return res.status(403).send("Only the buyer can leave a review.");
    }
    if (order.status !== 'COMPLETED') {
      return res.status(400).send("Reviews can only be left on completed orders.");
    }

    const reviewId = 'rev_' + crypto.randomBytes(6).toString('hex');
    await pool.query(`
      INSERT INTO reviews (id, "orderId", "serviceId", "buyerId", "sellerId", rating, comment)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      ON CONFLICT ("orderId") DO UPDATE SET rating = $6, comment = $7
    `, [reviewId, order.id, order.serviceId, order.buyerId, order.sellerId, parseInt(rating, 10), comment || '']);

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
        console.warn("Error email review notification:", e.message);
      }
    })();

    res.redirect('/orders/' + req.params.id);
  } catch (err) {
    res.status(500).send("Review error: " + err.message);
  }
});

// Open dispute / investigation
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
    res.status(400).send("Error: " + err.message);
  }
});

// ==========================================
// DIRECT MESSAGING & CHAT
// ==========================================

// Support shortcut
app.get('/support', ensureAuthenticated, (req, res) => {
  res.redirect('/chat?support=1');
});

// Messages alias
app.get('/messages', ensureAuthenticated, (req, res) => {
  res.redirect('/chat');
});

// Main Chat Page
app.get('/chat', ensureAuthenticated, async (req, res) => {
  try {
    const currentUserId = req.user.id;
    let targetUserId = req.query.recipientId || null;
    let serviceId = req.query.serviceId || null;
    let requestedConvId = req.query.conversationId || null;

    // Support assistance shortcut: ?support=1
    if (req.query.support === '1' || req.query.support === 'true') {
      const adminRes = await pool.query("SELECT id, name FROM users WHERE role = 'ADMIN' LIMIT 1");
      if (adminRes.rows.length > 0) {
        if (req.user.role !== 'ADMIN') {
          targetUserId = adminRes.rows[0].id;
        }
      }
    }

    // If starting a chat with a specific user
    if (targetUserId && targetUserId !== currentUserId) {
      const existRes = await pool.query(`
        SELECT c.id 
        FROM conversations c
        JOIN conversation_participants p1 ON c.id = p1."conversationId" AND p1."userId" = $1
        JOIN conversation_participants p2 ON c.id = p2."conversationId" AND p2."userId" = $2
        LIMIT 1
      `, [currentUserId, targetUserId]);

      if (existRes.rows.length > 0) {
        return res.redirect(`/chat?conversationId=${existRes.rows[0].id}`);
      } else {
        const recipientUserRes = await pool.query('SELECT role, name FROM users WHERE id = $1', [targetUserId]);
        const recipientUser = recipientUserRes.rows[0];
        const convType = (recipientUser && recipientUser.role === 'ADMIN') || req.user.role === 'ADMIN' ? 'SUPPORT' : 'DIRECT';

        let subject = req.query.subject || null;
        if (!subject && serviceId) {
          const srvRes = await pool.query('SELECT title FROM services WHERE id = $1', [serviceId]);
          if (srvRes.rows.length > 0) {
            subject = `Regarding: ${srvRes.rows[0].title}`;
          }
        }
        if (!subject) {
          subject = convType === 'SUPPORT' ? 'Support Assistance' : 'Direct Conversation';
        }

        const newConvId = 'conv_' + crypto.randomBytes(6).toString('hex');
        await pool.query(`
          INSERT INTO conversations (id, type, "serviceId", subject, "lastMessageText")
          VALUES ($1, $2, $3, $4, 'Conversation initialized')
        `, [newConvId, convType, serviceId, subject]);

        await pool.query(`
          INSERT INTO conversation_participants ("conversationId", "userId", "unreadCount")
          VALUES ($1, $2, 0), ($1, $3, 0)
        `, [newConvId, currentUserId, targetUserId]);

        return res.redirect(`/chat?conversationId=${newConvId}`);
      }
    }

    // Retrieve all conversations user participates in
    const convsRes = await pool.query(`
      SELECT c.*,
             p."unreadCount",
             u.id as "partnerId", 
             u.name as "partnerName", 
             u.avatar as "partnerAvatar", 
             u.role as "partnerRole", 
             u.bio as "partnerBio",
             u.email as "partnerEmail",
             s.title as "serviceTitle", 
             s.price as "servicePrice",
             s.id as "serviceId"
      FROM conversations c
      JOIN conversation_participants p ON c.id = p."conversationId" AND p."userId" = $1
      JOIN conversation_participants other_p ON c.id = other_p."conversationId" AND other_p."userId" != $1
      JOIN users u ON other_p."userId" = u.id
      LEFT JOIN services s ON c."serviceId" = s.id
      ORDER BY c."lastMessageAt" DESC
    `, [currentUserId]);

    const conversations = formatRows(convsRes.rows);

    let platformConversations = [];
    if (req.user.role === 'ADMIN') {
      const allConvsRes = await pool.query(`
        SELECT c.*,
               s.title as "serviceTitle",
               (
                 SELECT string_agg(u.name || ' (' || u.role || ')', ' ↔ ')
                 FROM conversation_participants cp
                 JOIN users u ON cp."userId" = u.id
                 WHERE cp."conversationId" = c.id
               ) as "participantsSummary"
        FROM conversations c
        LEFT JOIN services s ON c."serviceId" = s.id
        ORDER BY c."lastMessageAt" DESC
      `);
      platformConversations = formatRows(allConvsRes.rows);
    }

    let activeConversation = null;
    if (requestedConvId) {
      activeConversation = conversations.find(c => c.id === requestedConvId);
      if (!activeConversation && req.user.role === 'ADMIN') {
        const adminConvRes = await pool.query(`
          SELECT c.*, s.title as "serviceTitle", s.price as "servicePrice", s.id as "serviceId"
          FROM conversations c
          LEFT JOIN services s ON c."serviceId" = s.id
          WHERE c.id = $1
        `, [requestedConvId]);
        if (adminConvRes.rows.length > 0) {
          activeConversation = formatRows(adminConvRes.rows)[0];
        }
      }
    } else if (conversations.length > 0) {
      activeConversation = conversations[0];
    }

    let messages = [];
    let activePartner = null;

    if (activeConversation) {
      const partnerRes = await pool.query(`
        SELECT u.id, u.name, u.avatar, u.role, u.bio, u.email
        FROM conversation_participants cp
        JOIN users u ON cp."userId" = u.id
        WHERE cp."conversationId" = $1 AND cp."userId" != $2
        LIMIT 1
      `, [activeConversation.id, currentUserId]);

      if (partnerRes.rows.length > 0) {
        activePartner = partnerRes.rows[0];
      } else {
        const firstUserRes = await pool.query(`
          SELECT u.id, u.name, u.avatar, u.role, u.bio, u.email
          FROM conversation_participants cp
          JOIN users u ON cp."userId" = u.id
          WHERE cp."conversationId" = $1
          LIMIT 1
        `, [activeConversation.id]);
        activePartner = firstUserRes.rows[0] || null;
      }

      const msgRes = await pool.query(`
        SELECT m.*, u.name as "senderName", u.avatar as "senderAvatar", u.role as "senderRole"
        FROM direct_messages m
        JOIN users u ON m."senderId" = u.id
        WHERE m."conversationId" = $1
        ORDER BY m."createdAt" ASC
      `, [activeConversation.id]);
      messages = msgRes.rows;

      await pool.query(`
        UPDATE conversation_participants
        SET "unreadCount" = 0, "lastReadAt" = CURRENT_TIMESTAMP
        WHERE "conversationId" = $1 AND "userId" = $2
      `, [activeConversation.id, currentUserId]);

      await pool.query(`
        UPDATE direct_messages
        SET "isRead" = TRUE
        WHERE "conversationId" = $1 AND "senderId" != $2
      `, [activeConversation.id, currentUserId]);
    }

    const contactsRes = await pool.query(`
      SELECT u.id, u.name, u.email, u.avatar, u.role, u.bio,
             (SELECT count(*) FROM services s WHERE s."sellerId" = u.id) as "servicesCount"
      FROM users u
      WHERE u.id != $1
      ORDER BY (u.role = 'ADMIN') DESC, (u.role = 'USER') DESC, u.name ASC
    `, [currentUserId]);

    const contacts = contactsRes.rows;

    res.render('chat', {
      conversations,
      platformConversations,
      activeConversation,
      activePartner,
      messages,
      contacts
    });
  } catch (err) {
    res.status(500).send("Messaging error: " + err.message);
  }
});

// REST AJAX: Send message with file attachment
app.post('/api/chat/messages', ensureAuthenticated, upload.single('file'), async (req, res) => {
  try {
    const { conversationId, content } = req.body;
    if (!conversationId) {
      return res.status(400).json({ success: false, error: 'Missing conversation ID' });
    }

    if (!(await canAccessConversation(req.user, conversationId))) {
      return res.status(403).json({ success: false, error: 'Access denied to this conversation' });
    }

    let fileUrl = null;
    let fileName = null;
    let fileSize = null;
    let fileType = null;

    if (req.file) {
      fileUrl = `/uploads/${req.file.filename}`;
      fileName = req.file.originalname;
      const sizeMb = (req.file.size / (1024 * 1024)).toFixed(1);
      fileSize = sizeMb > 0 ? `${sizeMb} MB` : `${(req.file.size / 1024).toFixed(0)} KB`;
      const ext = path.extname(fileName).toLowerCase();
      fileType = ext.replace('.', '');
    }

    const trimmedContent = content ? content.trim() : '';
    if (!trimmedContent && !fileUrl) {
      return res.status(400).json({ success: false, error: 'Please enter a message or attach a file' });
    }

    const newMsgId = 'dmsg_' + crypto.randomBytes(6).toString('hex');
    const insertRes = await pool.query(`
      INSERT INTO direct_messages (id, "conversationId", "senderId", content, "fileUrl", "fileName", "fileSize", "fileType", "isRead")
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, false)
      RETURNING *
    `, [newMsgId, conversationId, req.user.id, trimmedContent, fileUrl, fileName, fileSize, fileType]);

    const savedMsg = insertRes.rows[0];

    const previewText = trimmedContent || (fileName ? `📎 File: ${fileName}` : 'Attachment');
    await pool.query(`
      UPDATE conversations
      SET "lastMessageText" = $1, "lastMessageAt" = CURRENT_TIMESTAMP, "updatedAt" = CURRENT_TIMESTAMP
      WHERE id = $2
    `, [previewText, conversationId]);

    await pool.query(`
      UPDATE conversation_participants
      SET "unreadCount" = "unreadCount" + 1
      WHERE "conversationId" = $1 AND "userId" != $2
    `, [conversationId, req.user.id]);

    const msgPayload = {
      id: savedMsg.id,
      conversationId,
      senderId: req.user.id,
      senderName: req.user.name,
      senderAvatar: req.user.avatar,
      senderRole: req.user.role,
      content: savedMsg.content,
      fileUrl: savedMsg.fileUrl,
      fileName: savedMsg.fileName,
      fileSize: savedMsg.fileSize,
      fileType: savedMsg.fileType,
      createdAt: savedMsg.createdAt,
      isRead: false
    };

    io.to(`conv_${conversationId}`).emit('new_chat_message', msgPayload);

    const partRes = await pool.query(
      `SELECT cp."userId", cp."unreadCount", u.name, u.email, u.role
       FROM conversation_participants cp
       JOIN users u ON cp."userId" = u.id
       WHERE cp."conversationId" = $1 AND cp."userId" != $2`,
      [conversationId, req.user.id]
    );

    for (const p of partRes.rows) {
      const totalUnreadRes = await pool.query(
        'SELECT COALESCE(SUM("unreadCount"), 0) as total FROM conversation_participants WHERE "userId" = $1',
        [p.userId]
      );
      const unreadTotal = parseInt(totalUnreadRes.rows[0].total, 10) || 1;

      io.to(`user_${p.userId}`).emit('chat_notification', {
        conversationId,
        senderId: req.user.id,
        senderName: req.user.name,
        senderAvatar: req.user.avatar,
        senderRole: req.user.role,
        preview: previewText,
        unreadTotal,
        createdAt: savedMsg.createdAt
      });

      if (p.unreadCount <= 1) {
        (async () => {
          try {
            emailService.notifyUnreadChatMessage({
              recipient: { id: p.userId, name: p.name, email: p.email, role: p.role },
              sender: { id: req.user.id, name: req.user.name, role: req.user.role },
              conversationId,
              messageText: previewText
            });
          } catch (errEmail) {
            console.warn("Error email notification chat REST:", errEmail.message);
          }
        })();
      }
    }

    res.json({ success: true, message: msgPayload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// REST AJAX: Get unread messages count
app.get('/api/chat/unread-count', ensureAuthenticated, async (req, res) => {
  try {
    const unreadRes = await pool.query(
      'SELECT COALESCE(SUM("unreadCount"), 0) as total FROM conversation_participants WHERE "userId" = $1',
      [req.user.id]
    );
    res.json({ success: true, count: parseInt(unreadRes.rows[0].total, 10) || 0 });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// REST AJAX: Start conversation
app.post('/api/chat/start', ensureAuthenticated, async (req, res) => {
  try {
    const { recipientId, serviceId, subject, initialMessage } = req.body;
    if (!recipientId || recipientId === req.user.id) {
      return res.status(400).json({ success: false, error: 'Invalid recipient' });
    }

    const existRes = await pool.query(`
      SELECT c.id 
      FROM conversations c
      JOIN conversation_participants p1 ON c.id = p1."conversationId" AND p1."userId" = $1
      JOIN conversation_participants p2 ON c.id = p2."conversationId" AND p2."userId" = $2
      LIMIT 1
    `, [req.user.id, recipientId]);

    let convId;
    if (existRes.rows.length > 0) {
      convId = existRes.rows[0].id;
    } else {
      const recipientRes = await pool.query('SELECT role FROM users WHERE id = $1', [recipientId]);
      const convType = (recipientRes.rows[0] && recipientRes.rows[0].role === 'ADMIN') || req.user.role === 'ADMIN' ? 'SUPPORT' : 'DIRECT';

      convId = 'conv_' + crypto.randomBytes(6).toString('hex');
      await pool.query(`
        INSERT INTO conversations (id, type, "serviceId", subject, "lastMessageText")
        VALUES ($1, $2, $3, $4, $5)
      `, [convId, convType, serviceId || null, subject || 'Direct Conversation', initialMessage || 'Conversation started']);

      await pool.query(`
        INSERT INTO conversation_participants ("conversationId", "userId", "unreadCount")
        VALUES ($1, $2, 0), ($1, $3, 0)
      `, [convId, req.user.id, recipientId]);
    }

    if (initialMessage && initialMessage.trim()) {
      const newMsgId = 'dmsg_' + crypto.randomBytes(6).toString('hex');
      await pool.query(`
        INSERT INTO direct_messages (id, "conversationId", "senderId", content, "isRead")
        VALUES ($1, $2, $3, $4, false)
      `, [newMsgId, convId, req.user.id, initialMessage.trim()]);

      await pool.query(`
        UPDATE conversations
        SET "lastMessageText" = $1, "lastMessageAt" = CURRENT_TIMESTAMP
        WHERE id = $2
      `, [initialMessage.trim(), convId]);

      await pool.query(`
        UPDATE conversation_participants
        SET "unreadCount" = "unreadCount" + 1
        WHERE "conversationId" = $1 AND "userId" != $2
      `, [convId, req.user.id]);
    }

    res.json({ success: true, conversationId: convId });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ==========================================
// DASHBOARD, WALLET & WITHDRAWALS
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

    const withRes = await pool.query(`
      SELECT * FROM withdrawals WHERE "userId" = $1 ORDER BY "createdAt" DESC LIMIT 10
    `, [user.id]);

    const depRes = await pool.query(`
      SELECT * FROM deposits WHERE "userId" = $1 ORDER BY "createdAt" DESC LIMIT 10
    `, [user.id]);

    res.render('dashboard', {
      user,
      buyerOrders: formatRows(buyerRes.rows),
      sellerOrders: formatRows(sellerRes.rows),
      withdrawals: formatRows(withRes.rows),
      deposits: formatRows(depRes.rows),
      platformBinancePayId: PLATFORM_BINANCE_PAY_ID
    });
  } catch (err) {
    res.status(500).send("Dashboard error: " + err.message);
  }
});

// Request withdrawal to Binance Pay
app.post('/api/wallet/withdraw', ensureAuthenticated, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const amount = parseFloat(req.body.amount);

    if (isNaN(amount) || amount <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid withdrawal amount' });
    }

    const uRes = await client.query('SELECT * FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
    const user = uRes.rows[0];

    if (!user.binanceId) {
      return res.status(400).json({ success: false, error: 'Please configure your Binance Pay ID before requesting a withdrawal' });
    }

    if (parseFloat(user.walletBalance) < amount) {
      return res.status(400).json({ success: false, error: 'Insufficient available balance' });
    }

    await client.query('UPDATE users SET "walletBalance" = "walletBalance" - $1 WHERE id = $2', [amount, user.id]);

    const withId = 'wth_' + crypto.randomBytes(6).toString('hex');
    await client.query(`
      INSERT INTO withdrawals (id, "userId", amount, "binanceId", status)
      VALUES ($1, $2, $3, $4, 'PENDING')
    `, [withId, user.id, amount, user.binanceId]);

    await client.query('COMMIT');

    (async () => {
      try {
        emailService.notifyWithdrawalRequested({
          user,
          amount,
          binanceId: user.binanceId
        });
      } catch (e) {
        console.warn("Error email withdrawal notification:", e.message);
      }
    })();

    res.json({ success: true, message: `Withdrawal request of ${amount.toFixed(2)} USDT submitted successfully.` });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// History Page
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
    res.status(500).send("History error: " + err.message);
  }
});

// REST AJAX: Binance Pay Dynamic QR Code
app.get('/api/wallet/deposit-qr', ensureAuthenticated, async (req, res) => {
  try {
    const rawAmount = parseFloat(req.query.amount) || 50;
    const amount = isNaN(rawAmount) || rawAmount <= 0 ? 50 : rawAmount;
    const binancePayId = (req.query.binancePayId || PLATFORM_BINANCE_PAY_ID).trim();

    const deepLink = `https://app.binance.com/qr/dlink?deeplink=binance%3A%2F%2Fpay%3FpayeeId%3D${encodeURIComponent(binancePayId)}%26amount%3D${amount.toFixed(2)}%26currency%3DUSDT`;
    const appScheme = `binance://pay?payeeId=${encodeURIComponent(binancePayId)}&amount=${amount.toFixed(2)}&currency=USDT`;

    const qrCodeDataUrl = await QRCode.toDataURL(deepLink, {
      width: 320,
      margin: 2,
      errorCorrectionLevel: 'M',
      color: {
        dark: '#0f172a',
        light: '#ffffff'
      }
    });

    res.json({
      success: true,
      qrCodeDataUrl,
      binancePayId,
      amount: amount.toFixed(2),
      currency: 'USDT',
      deepLink,
      appScheme
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// REST AJAX: Record Binance Pay Top-Up & Credit Account
app.post('/api/wallet/deposit-binance', ensureAuthenticated, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const amount = parseFloat(req.body.amount);
    const txId = (req.body.txId || '').trim();
    const binancePayId = (req.body.binancePayId || PLATFORM_BINANCE_PAY_ID).trim();

    if (isNaN(amount) || !Number.isFinite(amount) || amount <= 0 || amount > 50000) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'Invalid top-up amount (max 50,000 USDT).' });
    }

    if (!txId || !/^[a-zA-Z0-9_-]{6,100}$/.test(txId)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'Please enter a valid Binance Transaction ID (TxID, 6 to 100 alphanumeric characters).' });
    }

    const existingTx = await client.query('SELECT id FROM deposits WHERE "txId" = $1', [txId]);
    if (existingTx.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'This Transaction ID (TxID) has already been used.' });
    }

    const upd = await client.query(`
      UPDATE users 
      SET "walletBalance" = "walletBalance" + $1 
      WHERE id = $2 
      RETURNING "walletBalance"
    `, [amount, req.user.id]);

    const newWalletBalance = parseFloat(upd.rows[0].walletBalance);

    const depId = 'dep_' + crypto.randomBytes(6).toString('hex');
    const depRes = await client.query(`
      INSERT INTO deposits (id, "userId", amount, "binancePayId", "txId", status)
      VALUES ($1, $2, $3, $4, $5, 'COMPLETED')
      RETURNING *
    `, [depId, req.user.id, amount, binancePayId, txId]);

    await client.query('COMMIT');

    (async () => {
      try {
        emailService.notifyDepositReceived({
          user: req.user,
          amount,
          txId,
          binancePayId
        });
      } catch (e) {
        console.warn("Error email top-up notification:", e.message);
      }
    })();

    res.json({
      success: true,
      message: `Your top-up of ${amount.toFixed(2)} USDT via Binance Pay has been credited!`,
      newWalletBalance,
      deposit: depRes.rows[0]
    });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// REST AJAX: Top up test mode (protected by ENABLE_DEMO_MODE)
app.post('/api/wallet/deposit-test', ensureAuthenticated, async (req, res) => {
  try {
    if (process.env.ENABLE_DEMO_MODE === 'false') {
      return res.status(403).json({ success: false, error: 'Demo top-up mode is disabled.' });
    }

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

// REST AJAX: Update Binance Pay ID & Bio
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
// ADMIN ARBITRATION (DISPUTES)
// ==========================================

app.get('/admin/disputes', ensureAuthenticated, async (req, res) => {
  try {
    if (req.user.role !== 'ADMIN') {
      return res.status(403).send("Access restricted to moderators.");
    }

    const dispRes = await pool.query(`
      SELECT d.*, o.amount, o."serviceId", o."buyerId", o."sellerId", s.title as "serviceTitle",
             b.name as "buyerName", sl.name as "sellerName"
      FROM disputes d
      JOIN orders o ON d."orderId" = o.id
      JOIN services s ON o."serviceId" = s.id
      JOIN users b ON o."buyerId" = b.id
      JOIN users sl ON o."sellerId" = sl.id
      ORDER BY d."createdAt" DESC
    `);

    res.render('disputes', { disputes: formatRows(dispRes.rows) });
  } catch (err) {
    res.status(500).send("Arbitration error: " + err.message);
  }
});

app.post('/disputes/:id/resolve', ensureAuthenticated, async (req, res) => {
  try {
    if (req.user.role !== 'ADMIN') {
      return res.status(403).send("Unauthorized");
    }

    const { resolution, resolutionNote } = req.body;
    await escrow.resolveDispute(pool, {
      disputeId: req.params.id,
      resolution,
      resolutionNote
    });

    res.redirect('/admin/disputes');
  } catch (err) {
    res.status(500).send("Resolution error: " + err.message);
  }
});

// Global Error Handler (Multer & Unhandled Route Errors)
app.use((err, req, res, next) => {
  console.error("[Security/Server Error]:", err.message);
  if (req.path.startsWith('/api/')) {
    return res.status(400).json({ success: false, error: err.message || 'Invalid request.' });
  }
  res.status(400).send("Error processing request: " + (err.message || "Invalid request"));
});

// Initialize database and start server
initDatabase().then(() => {
  server.listen(PORT, () => {
    console.log(`\n🚀 TrustWork Server running on http://localhost:${PORT}`);
    console.log(`⚡ WebSocket / Socket.io: Active (Real-Time)`);
    console.log(`📎 File & Attachment Uploads: Active`);
    console.log(`🐘 Database: PostgreSQL (ACID Enabled)`);
    console.log(`🔒 Escrow Protection System: Active`);
    console.log(`💰 Binance Pay & USDT Mode: Active\n`);
  });
}).catch(err => {
  console.error("❌ Error starting PostgreSQL / Server:", err);
});
