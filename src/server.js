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
const {
  setupAuth, ensureAuthenticated, normalizeUser, isDemoModeEnabled, isDemoUser,
  enforceAdminSessionLimit, requireFreshAdmin, requireFreshIfAdmin,
  safeReturnPath, rememberReturnTo
} = require('./auth');
const escrow = require('./escrow');
const emailService = require('./services/email');
const telegramStars = require('./services/telegramStars');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Trust local Nginx reverse proxy & hide Express fingerprint
app.set('trust proxy', 1);
app.disable('x-powered-by');

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '127.0.0.1';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(48).toString('hex');

// Strict Security Headers Middleware
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=()');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  next();
});

// Bounded Two-Tier Rate Limiter (prevents brute-force, flood, and memory exhaustion)
const generalRateMap = new Map();
const strictRateMap = new Map();
setInterval(() => {
  generalRateMap.clear();
  strictRateMap.clear();
}, 60 * 1000).unref();

function createRateLimiter(store, maxRequests, errorMessage) {
  return (req, res, next) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    if (store.size > 10000 && !store.has(ip)) {
      store.clear();
    }
    const count = (store.get(ip) || 0) + 1;
    store.set(ip, count);
    if (count > maxRequests) {
      if (req.path.startsWith('/api/') || req.xhr) {
        return res.status(429).json({ success: false, error: errorMessage });
      }
      return res.status(429).send(errorMessage);
    }
    next();
  };
}

app.use(createRateLimiter(generalRateMap, 120, 'Too many requests, please wait a moment.'));
app.use(
  ['/auth', '/api/wallet', '/api/store/order', '/orders/create', '/disputes', '/admin'],
  createRateLimiter(strictRateMap, 25, 'Rate limit exceeded on sensitive endpoint. Please wait 1 minute.')
);

// Upload Directory configuration & Strict Whitelist
const uploadDir = path.join(__dirname, '../public/uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const ALLOWED_EXTENSIONS = new Set([
  '.pdf', '.zip', '.rar', '.tar', '.gz', '.7z',
  '.txt', '.md', '.sh', '.json', '.yml', '.yaml',
  '.png', '.jpg', '.jpeg', '.webp', '.gif',
  '.mp4', '.mov', '.webm', '.doc', '.docx'
]);

function getUploadOwnerTag(userId) {
  if (!userId) return 'anon';
  return crypto.createHmac('sha256', SESSION_SECRET).update('upload:' + String(userId)).digest('hex').slice(0, 12);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const rawExt = path.extname(file.originalname || '').toLowerCase().replace(/[^a-z0-9.]/g, '');
    const safeExt = ALLOWED_EXTENSIONS.has(rawExt) ? rawExt : '.bin';
    const ownerTag = req.user && req.user.id ? `u${getUploadOwnerTag(req.user.id)}-` : '';
    const uniqueName = Date.now() + '-' + ownerTag + crypto.randomBytes(8).toString('hex') + safeExt;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024, files: 6 }, // 25 MB max, up to 6 files
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase();
    if (!ALLOWED_EXTENSIONS.has(ext)) {
      return cb(new Error(`Unsupported file format (${ext}). Allowed formats: PDF, ZIP, TXT, Images, Videos.`));
    }
    cb(null, true);
  }
});

/**
 * Inspect uploaded file magic bytes & block polyglot HTML/script payloads
 */
function verifyUploadedFileSafety(filePath, ext) {
  try {
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(4096);
    const bytesRead = fs.readSync(fd, buf, 0, 4096, 0);
    fs.closeSync(fd);
    const slice = buf.subarray(0, bytesRead);
    const headAscii = slice.toString('utf8').toLowerCase();

    // Block disguised HTML/SVG/JS/PHP files regardless of extension
    if (
      headAscii.includes('<script') ||
      headAscii.includes('<!doctype html') ||
      headAscii.includes('<html') ||
      headAscii.includes('<?php') ||
      headAscii.includes('javascript:')
    ) {
      fs.unlinkSync(filePath);
      throw new Error('Security check failed: executable HTML/Script content detected inside file.');
    }

    // Verify PDF magic header (%PDF-)
    if (ext === '.pdf' && bytesRead >= 4 && slice.subarray(0, 4).toString('ascii') !== '%PDF') {
      fs.unlinkSync(filePath);
      throw new Error('Invalid PDF file signature.');
    }

    // Verify ZIP magic header (PK\x03\x04 or PK\x05\x06)
    if (ext === '.zip' && bytesRead >= 2 && slice.subarray(0, 2).toString('ascii') !== 'PK') {
      fs.unlinkSync(filePath);
      throw new Error('Invalid ZIP archive signature.');
    }
  } catch (err) {
    if (fs.existsSync(filePath)) {
      try { fs.unlinkSync(filePath); } catch (_) {}
    }
    throw err;
  }
}

// Body Parsers
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.json({ limit: '1mb' }));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Hardened Session Configuration (shared with Socket.io)
const sessionMiddleware = session({
  name: 'methods.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: 'auto',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
});

app.use(sessionMiddleware);
app.use(passport.initialize());
app.use(passport.session());
app.use(enforceAdminSessionLimit);

// Structured audit trail of every sensitive admin action (visible with `pm2 logs trustwork`)
function adminAudit(req, action, detail = {}) {
  console.log('[ADMIN-AUDIT]', JSON.stringify({
    ts: new Date().toISOString(),
    adminId: req.user && req.user.id,
    ip: req.ip,
    action,
    ...detail
  }));
}

// Parse cookies helper for stateless HttpOnly CSRF seed when unauthenticated
function parseCookie(req, name) {
  const raw = req.headers.cookie || '';
  const match = raw.split(';').map(c => c.trim()).find(c => c.startsWith(name + '='));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : null;
}

// Synchronizer + HMAC-Bound Cookie CSRF Protection (Prevents MemoryStore DoS on unauthenticated requests)
app.use((req, res, next) => {
  // Telegram calls the webhook server-to-server; it is authenticated by the
  // secret path + X-Telegram-Bot-Api-Secret-Token header, not by a browser CSRF token.
  if (req.path.startsWith('/telegram/webhook/')) return next();

  let csrfSeed = parseCookie(req, 'methods.csrf');
  if (!csrfSeed || !/^[a-f0-9]{32,64}$/.test(csrfSeed)) {
    csrfSeed = crypto.randomBytes(24).toString('hex');
    const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
    res.setHeader(
      'Set-Cookie',
      `methods.csrf=${csrfSeed}; Path=/; HttpOnly; SameSite=Lax${isSecure ? '; Secure' : ''}`
    );
  }

  const expectedToken = crypto.createHmac('sha256', SESSION_SECRET).update('csrf:' + csrfSeed).digest('hex');
  res.locals.csrfToken = expectedToken;

  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    // 1. Verify Origin / Referer host matches target Host when present
    const host = req.get('host');
    const origin = req.get('origin');
    const referer = req.get('referer');
    if (origin && host) {
      try {
        if (new URL(origin).host !== host) {
          return res.status(403).json({ success: false, error: 'Cross-origin request blocked (Origin mismatch).' });
        }
      } catch (_) {
        return res.status(403).json({ success: false, error: 'Malformed Origin header.' });
      }
    } else if (referer && host) {
      try {
        if (new URL(referer).host !== host) {
          return res.status(403).json({ success: false, error: 'Cross-origin request blocked (Referer mismatch).' });
        }
      } catch (_) {
        return res.status(403).json({ success: false, error: 'Malformed Referer header.' });
      }
    }

    // 2. Verify cryptographic CSRF token
    const providedToken =
      req.headers['x-csrf-token'] ||
      (req.body && req.body._csrf) ||
      (req.query && req.query._csrf);

    if (
      !expectedToken ||
      !providedToken ||
      typeof providedToken !== 'string' ||
      providedToken.length !== expectedToken.length ||
      !crypto.timingSafeEqual(Buffer.from(providedToken), Buffer.from(expectedToken))
    ) {
      if (req.path.startsWith('/api/') || req.xhr) {
        return res.status(403).json({ success: false, error: 'Invalid or expired security token (CSRF). Please refresh the page.' });
      }
      return res.status(403).send('Invalid or expired security token (CSRF). Please go back and refresh the page.');
    }
  }

  next();
});

// Share session with Socket.io and authenticate socket connections
io.engine.use(sessionMiddleware);
io.use(async (socket, next) => {
  try {
    const userId = socket.request.session?.passport?.user;
    if (userId) {
      const uRes = await pool.query('SELECT id, name, email, avatar, role FROM users WHERE id = $1', [userId]);
      socket.user = uRes.rows[0] || null;
      const sock = socket.user;
      if (sock && sock.role === 'ADMIN' && !String(sock.email || '').toLowerCase().endsWith('.local')) {
        const at = socket.request.session && socket.request.session.loginAt;
        if (!at || Date.now() - at > 4 * 60 * 60 * 1000) socket.user = null;
      }
    } else {
      socket.user = null;
    }
    next();
  } catch (err) {
    next(err);
  }
});

// Global injection of user, total users counter, unread chat counter & Telegram Stars config in EJS views
app.use(async (req, res, next) => {
  res.locals.user = req.user ? normalizeUser(req.user) : null;
  res.locals.unreadChatCount = 0;
  res.locals.totalUsersCount = 0;
  res.locals.starsPerUsd = telegramStars.STARS_PER_USD;
  res.locals.telegramStarsConfigured = telegramStars.isConfigured();
  res.locals.telegramBotUsername = telegramStars.BOT_USERNAME;
  try {
    const countRes = await pool.query('SELECT COUNT(*)::int AS total FROM users');
    res.locals.totalUsersCount = countRes.rows[0]?.total ?? 0;
  } catch (e) {
    res.locals.totalUsersCount = 0;
  }
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
setupAuth(app, pool, io);

// ==========================================
// PROTECTED PAID FILE GATEKEEPER (/uploads/:filename)
// ==========================================
const DEFAULT_SAMPLE_FILES = new Set([
  'guide-methode-developpement-ideale.pdf',
  'code-source-template.zip',
  'commandes-scripts.txt'
]);

async function canAccessUploadedFile(user, filename) {
  if (!user || !filename || !/^[a-zA-Z0-9._-]+$/.test(filename)) return false;
  if (user.role === 'ADMIN' && !isDemoUser(user)) return true;
  if (user.role === 'ADMIN' && isDemoUser(user) && DEFAULT_SAMPLE_FILES.has(filename)) return true;

  // Owner HMAC tag check (the user who uploaded this file via /api/upload)
  const ownerMarker = `-u${getUploadOwnerTag(user.id)}-`;
  if (filename.includes(ownerMarker)) return true;

  const filePathUrl = `/uploads/${filename}`;

  // 1. Is user the author of a service containing this file?
  const sellerCheck = await pool.query(
    `SELECT 1 FROM services 
     WHERE "sellerId" = $1 
       AND ("fileUrl" = $2 OR "attachments"::text LIKE $3)
     LIMIT 1`,
    [user.id, filePathUrl, `%/uploads/${filename}%`]
  );
  if (sellerCheck.rows.length > 0) return true;

  // 2. Has user purchased an order that includes this file (or default sample files if they have any valid order)?
  if (DEFAULT_SAMPLE_FILES.has(filename)) {
    const anyOrderCheck = await pool.query(
      `SELECT 1 FROM orders 
       WHERE ("buyerId" = $1 OR "sellerId" = $1)
         AND status IN ('ESCROWED', 'DELIVERED', 'COMPLETED', 'DISPUTED')
       LIMIT 1`,
      [user.id]
    );
    if (anyOrderCheck.rows.length > 0) return true;
  }

  const buyerOrderCheck = await pool.query(
    `SELECT 1 FROM orders o
     JOIN services s ON o."serviceId" = s.id
     WHERE (o."buyerId" = $1 OR o."sellerId" = $1)
       AND o.status IN ('ESCROWED', 'DELIVERED', 'COMPLETED', 'DISPUTED')
       AND (o."fileUrl" = $2 OR s."fileUrl" = $2 OR o."attachments"::text LIKE $3 OR s."attachments"::text LIKE $3)
     LIMIT 1`,
    [user.id, filePathUrl, `%/uploads/${filename}%`]
  );
  if (buyerOrderCheck.rows.length > 0) return true;

  // 3. Was the file sent in an order chat message where the user is buyer or seller?
  const orderMsgCheck = await pool.query(
    `SELECT 1 FROM messages m
     JOIN orders o ON m."orderId" = o.id
     WHERE m."fileUrl" = $1
       AND (o."buyerId" = $2 OR o."sellerId" = $2)
     LIMIT 1`,
    [filePathUrl, user.id]
  );
  if (orderMsgCheck.rows.length > 0) return true;

  // 4. Was the file sent in a direct message conversation where the user is a participant?
  const directMsgCheck = await pool.query(
    `SELECT 1 FROM direct_messages dm
     JOIN conversation_participants cp ON dm."conversationId" = cp."conversationId"
     WHERE dm."fileUrl" = $1
       AND cp."userId" = $2
     LIMIT 1`,
    [filePathUrl, user.id]
  );
  if (directMsgCheck.rows.length > 0) return true;

  return false;
}

app.get('/uploads/:filename', ensureAuthenticated, async (req, res) => {
  try {
    const safeFilename = path.basename(req.params.filename || '');
    if (!safeFilename || safeFilename.includes('..')) {
      return res.status(400).send('Invalid file name.');
    }

    const fullPath = path.join(uploadDir, safeFilename);
    if (!fs.existsSync(fullPath)) {
      return res.status(404).send('File not found.');
    }

    const allowed = await canAccessUploadedFile(req.user, safeFilename);
    if (!allowed) {
      return res.status(403).send('Access denied: You must purchase this method before downloading its package files.');
    }

    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'");
    const ext = path.extname(safeFilename).toLowerCase();
    if (!['.png', '.jpg', '.jpeg', '.webp', '.gif', '.pdf'].includes(ext)) {
      res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);
    }
    return res.sendFile(fullPath);
  } catch (err) {
    console.error('Error serving protected upload:', err.message);
    return res.status(500).send('Error retrieving file.');
  }
});

// Helper for row formatting
function formatRows(rows) {
  return rows.map(r => {
    const amt = r.amount !== undefined ? parseFloat(r.amount) : undefined;
    const fee = r.platformFee !== undefined && parseFloat(r.platformFee) > 0
      ? parseFloat(r.platformFee)
      : (amt !== undefined ? Math.round(amt * 0.15 * 100) / 100 : undefined);
    const net = r.sellerNetAmount !== undefined && parseFloat(r.sellerNetAmount) > 0
      ? parseFloat(r.sellerNetAmount)
      : (amt !== undefined && fee !== undefined ? Math.round((amt - fee) * 100) / 100 : undefined);

    return {
      ...r,
      price: r.price !== undefined ? parseFloat(r.price) : undefined,
      amount: amt,
      platformFee: fee,
      sellerNetAmount: net,
      walletBalance: r.walletBalance !== undefined ? parseFloat(r.walletBalance) : undefined,
      escrowBalance: r.escrowBalance !== undefined ? parseFloat(r.escrowBalance) : undefined
    };
  });
}

/**
 * Strip secret file URLs and private video links from public catalog & service pages
 */
function sanitizePublicService(srv) {
  if (!srv) return srv;
  const copy = { ...srv };
  delete copy.fileUrl;
  delete copy.videoUrl;
  if (Array.isArray(copy.attachments)) {
    copy.attachments = copy.attachments.map(att => ({
      type: att.type,
      label: att.label,
      size: att.size
    }));
  }
  return copy;
}

// ==========================================
// SOCKET.IO (AUTHENTICATED REAL-TIME MESSAGING & ESCROW)
// ==========================================
async function canAccessOrder(user, orderId) {
  if (!user || !orderId) return false;
  if (user.role === 'ADMIN' && !isDemoUser(user)) return true;
  const res = await pool.query(`
    SELECT o."buyerId", o."sellerId", b.email as "buyerEmail", s.email as "sellerEmail"
    FROM orders o
    JOIN users b ON o."buyerId" = b.id
    JOIN users s ON o."sellerId" = s.id
    WHERE o.id = $1
  `, [orderId]);
  if (res.rows.length === 0) return false;
  const row = res.rows[0];
  if (user.role === 'ADMIN' && isDemoUser(user)) {
    return isDemoUser(row.buyerEmail) && isDemoUser(row.sellerEmail);
  }
  return row.buyerId === user.id || row.sellerId === user.id;
}

async function canAccessConversation(user, conversationId) {
  if (!user || !conversationId) return false;
  if (user.role === 'ADMIN' && !isDemoUser(user)) return true;
  if (user.role === 'ADMIN' && isDemoUser(user)) {
    const nonDemoCheck = await pool.query(`
      SELECT 1 FROM conversation_participants cp
      JOIN users u ON cp."userId" = u.id
      WHERE cp."conversationId" = $1 AND u.email NOT LIKE '%.local'
      LIMIT 1
    `, [conversationId]);
    return nonDemoCheck.rows.length === 0;
  }
  const res = await pool.query(
    'SELECT 1 FROM conversation_participants WHERE "conversationId" = $1 AND "userId" = $2 LIMIT 1',
    [conversationId, user.id]
  );
  return res.rows.length > 0;
}

io.on('connection', (socket) => {
  socket.on('join_user', () => {
    if (socket.user && socket.user.id) {
      socket.join(`user_${socket.user.id}`);
    }
  });

  socket.on('join_order', async ({ orderId } = {}) => {
    try {
      if (await canAccessOrder(socket.user, orderId)) {
        socket.join(`order_${orderId}`);
      }
    } catch (err) {
      console.error("Socket error join_order:", err.message);
    }
  });

  socket.on('send_message', async ({ orderId, content, fileUrl, fileName } = {}) => {
    try {
      if (!socket.user) return;
      if (!(await canAccessOrder(socket.user, orderId))) return;
      if ((!content || !content.trim()) && !fileUrl) return;

      const senderId = socket.user.id;
      const senderName = socket.user.name || 'User';
      let safeFileUrl = fileUrl && /^\/uploads\/[a-zA-Z0-9._-]+$/.test(String(fileUrl)) ? String(fileUrl) : null;
      if (safeFileUrl && !(await canAccessUploadedFile(socket.user, path.basename(safeFileUrl)))) {
        safeFileUrl = null;
      }
      const trimmedContent = content ? String(content).trim().slice(0, 4000) : '';
      if (!trimmedContent && !safeFileUrl) return;

      const newId = 'msg_' + crypto.randomBytes(8).toString('hex');
      const insertRes = await pool.query(`
        INSERT INTO messages (id, "orderId", "senderId", content, "fileUrl", "fileName")
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
      `, [newId, orderId, senderId, trimmedContent, safeFileUrl, fileName ? String(fileName).slice(0, 255) : null]);

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

      // Also notify the other participant on their global user channel for browser notification
      const ordRes = await pool.query('SELECT "buyerId", "sellerId" FROM orders WHERE id = $1', [orderId]);
      if (ordRes.rows[0]) {
        const targetId = ordRes.rows[0].buyerId === senderId ? ordRes.rows[0].sellerId : ordRes.rows[0].buyerId;
        io.to(`user_${targetId}`).emit('user_notification', {
          title: `Order Message from ${senderName}`,
          body: trimmedContent || (fileName ? `Attachment: ${fileName}` : 'New message on your order'),
          url: `/orders/${orderId}`,
          type: 'order_message'
        });
      }
    } catch (err) {
      console.error("Socket error send_message:", err.message);
    }
  });

  socket.on('join_conversation', async ({ conversationId } = {}) => {
    try {
      if (await canAccessConversation(socket.user, conversationId)) {
        socket.join(`conv_${conversationId}`);
      }
    } catch (err) {
      console.error("Socket error join_conversation:", err.message);
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
      let safeFileUrl = fileUrl && /^\/uploads\/[a-zA-Z0-9._-]+$/.test(String(fileUrl)) ? String(fileUrl) : null;
      if (safeFileUrl && !(await canAccessUploadedFile(socket.user, path.basename(safeFileUrl)))) {
        safeFileUrl = null;
      }

      const trimmedContent = content ? String(content).trim().slice(0, 4000) : '';
      if (!trimmedContent && !safeFileUrl) return;
      const newMsgId = 'dmsg_' + crypto.randomBytes(8).toString('hex');

      const insertRes = await pool.query(`
        INSERT INTO direct_messages (id, "conversationId", "senderId", content, "fileUrl", "fileName", "fileSize", "isRead")
        VALUES ($1, $2, $3, $4, $5, $6, $7, false)
        RETURNING *
      `, [newMsgId, conversationId, senderId, trimmedContent, safeFileUrl, fileName ? String(fileName).slice(0, 255) : null, fileSize || null]);

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
      `, [conversationId, senderId]);

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
      console.error("Socket error chat_send_message:", err.message);
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
      console.error("Error chat_typing:", err.message);
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
      console.error("Error chat_mark_read:", err.message);
    }
  });
});

// ==========================================
// PUBLIC ROUTES (SANITIZED)
// ==========================================

const STORE_OWNER_EMAIL = 'saleminformatiquedev@gmail.com';
function isStoreOwner(user) {
  if (!user) return false;
  return user.role === 'ADMIN' || String(user.email || '').toLowerCase() === STORE_OWNER_EMAIL;
}

// Homepage: Simple Direct Storefront
// All methods are public; no sign-in required
app.get('/', async (req, res) => {
  try {
    const srvRes = await pool.query(`
      SELECT s.id, s."sellerId", s.title, s.description, s.category, s.price,
             s."deliveryDays", s."pageCount", s.difficulty, s.formats, s."createdAt",
             s."unitCost", s."durationLabel", s."offerType",
             s."screenShareDemo", s."openToExchange", s."bulkAvailable",
             s."supplierHandle", s."whatsappNumber", s."telegramBot",
             u.name as "sellerName", u.avatar as "sellerAvatar"
      FROM services s
      JOIN users u ON s."sellerId" = u.id
      WHERE LOWER(u.email) = $1
        AND s.category <> 'Simple Methods ($1.5)'
      ORDER BY
        CASE s.id
          WHEN 'srv_notion_edu_plus_1y' THEN 1
          WHEN 'srv_adobe_express_6m_script' THEN 2
          WHEN 'srv_capcut_ready' THEN 3
          ELSE 4
        END ASC,
        s.title ASC
    `, [STORE_OWNER_EMAIL]);
    res.render('index', {
      services: formatRows(srvRes.rows).map(sanitizePublicService),
      starsPerUsd: telegramStars.STARS_PER_USD,
      telegramBotUsername: telegramStars.BOT_USERNAME,
      telegramStarsConfigured: telegramStars.isConfigured()
    });
  } catch (err) {
    console.error("Homepage error:", err.message);
    res.status(500).send("Unable to load methods at the moment.");
  }
});

// Dedicated Method Exchange Page (no Telegram Stars checkout section)
app.get('/exchange', async (req, res) => {
  try {
    const srvRes = await pool.query(`
      SELECT s.id, s.title, s.price, s."unitCost", s."durationLabel"
      FROM services s
      JOIN users u ON s."sellerId" = u.id
      WHERE LOWER(u.email) = $1
        AND s.category <> 'Simple Methods ($1.5)'
      ORDER BY
        CASE s.id
          WHEN 'srv_notion_edu_plus_1y' THEN 1
          WHEN 'srv_adobe_express_6m_script' THEN 2
          WHEN 'srv_capcut_ready' THEN 3
          ELSE 4
        END ASC
    `, [STORE_OWNER_EMAIL]);
    res.render('exchange', {
      services: formatRows(srvRes.rows)
    });
  } catch (err) {
    console.error("Exchange page error:", err.message);
    res.status(500).send("Unable to load exchange page.");
  }
});

// ==========================================
// TELEGRAM STARS PAYMENT HELPERS & WEBHOOK HANDLER
// ==========================================

function makeStarsPayload(prefix) {
  return `${prefix}_${crypto.randomBytes(12).toString('hex')}`;
}

function safeSecretEquals(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

async function handleStarsPreCheckout(query) {
  const payload = String(query.invoice_payload || '');
  const total = Number(query.total_amount);
  const currency = String(query.currency || '');
  let ok = false;
  let errorMessage = 'Invoice not found or expired.';

  try {
    const invRes = await pool.query(
      `SELECT i.*, o.status AS order_status
       FROM stars_invoices i
       LEFT JOIN store_orders o ON o.id = i."storeOrderId"
       WHERE i.payload = $1`,
      [payload]
    );
    const invoice = invRes.rows[0];

    if (!invoice) {
      errorMessage = 'Invoice not found or expired.';
    } else if (invoice.status !== 'PENDING') {
      errorMessage = 'This invoice is no longer active.';
    } else if (currency !== 'XTR') {
      errorMessage = 'Unsupported payment currency.';
    } else if (!Number.isInteger(total) || total !== invoice.stars) {
      errorMessage = 'Invoice amount mismatch. Please restart the checkout.';
    } else if (invoice.purpose === 'STORE_ORDER' && ['REJECTED', 'REFUNDED'].includes(invoice.order_status)) {
      errorMessage = 'This order was cancelled. Please create a new order.';
    } else {
      ok = true;
      errorMessage = '';
    }
  } catch (err) {
    console.error('[Telegram Stars] pre_checkout verification error:', err.message);
    errorMessage = 'Unable to verify the invoice. Please try again.';
  }

  try {
    await telegramStars.answerPreCheckoutQuery(query.id, ok, errorMessage);
  } catch (err) {
    console.error('[Telegram Stars] answerPreCheckoutQuery failed:', err.message);
  }
}

async function handleStarsSuccessfulPayment(message) {
  const payment = message.successful_payment || {};
  const payload = String(payment.invoice_payload || '');
  const chargeId = String(payment.telegram_payment_charge_id || '');
  const providerChargeId = String(payment.provider_payment_charge_id || '');
  const starsAmount = Number(payment.total_amount);
  const currency = String(payment.currency || '');
  const telegramUserId = message.from && message.from.id ? message.from.id : null;
  const chatId = message.chat && message.chat.id ? message.chat.id : null;

  if (!payload || !chargeId) {
    console.error('[Telegram Stars] successful_payment missing payload or charge id.');
    return;
  }

  const client = await pool.connect();
  let paidInvoice = null;
  let paidOrder = null;
  let creditedUser = null;

  try {
    await client.query('BEGIN');

    const invRes = await client.query(
      'SELECT * FROM stars_invoices WHERE payload = $1 FOR UPDATE',
      [payload]
    );
    const invoice = invRes.rows[0];
    if (!invoice) {
      await client.query('ROLLBACK');
      console.error('[Telegram Stars] Payment received for unknown payload:', payload);
      return;
    }

    // Telegram retries webhooks: a second delivery for the same payload is a no-op.
    if (invoice.status === 'PAID' || invoice.status === 'REFUNDED') {
      await client.query('ROLLBACK');
      return;
    }

    if (currency !== 'XTR' || !Number.isInteger(starsAmount) || starsAmount !== invoice.stars) {
      await client.query(
        `UPDATE stars_invoices
         SET status = 'FAILED', "rawUpdate" = $1::jsonb
         WHERE id = $2`,
        [JSON.stringify(payment), invoice.id]
      );
      await client.query('COMMIT');
      console.error('[Telegram Stars] Paid amount/currency mismatch for invoice', invoice.id);
      return;
    }

    const duplicate = await client.query(
      'SELECT id FROM stars_invoices WHERE "telegramPaymentChargeId" = $1 AND id <> $2',
      [chargeId, invoice.id]
    );
    if (duplicate.rows.length > 0) {
      await client.query('ROLLBACK');
      console.error('[Telegram Stars] Duplicate telegram_payment_charge_id:', chargeId);
      return;
    }

    const updatedInv = await client.query(
      `UPDATE stars_invoices
       SET status = 'PAID',
           "telegramPaymentChargeId" = $1,
           "providerPaymentChargeId" = $2,
           "telegramUserId" = $3,
           "rawUpdate" = $4::jsonb,
           "paidAt" = CURRENT_TIMESTAMP
       WHERE id = $5
       RETURNING *`,
      [chargeId, providerChargeId || null, telegramUserId, JSON.stringify(payment), invoice.id]
    );
    paidInvoice = updatedInv.rows[0];

    if (invoice.purpose === 'STORE_ORDER') {
      const ordRes = await client.query(
        `UPDATE store_orders
         SET status = 'PAID',
             "txId" = $1,
             "starsAmount" = $2,
             "telegramPaymentChargeId" = $1,
             "telegramUserId" = $3
         WHERE id = $4
         RETURNING *`,
        [chargeId, starsAmount, telegramUserId, invoice.storeOrderId]
      );
      paidOrder = ordRes.rows[0] || null;
    } else if (invoice.purpose === 'WALLET_TOPUP') {
      if (!invoice.userId) {
        console.error('[Telegram Stars] Top-up invoice has no user:', invoice.id);
      } else {
        // The invoice row is locked above, so this check is safe even on legacy
        // databases that were created without a UNIQUE constraint on deposits.txId.
        const existingDep = await client.query(
          'SELECT id FROM deposits WHERE "txId" = $1 LIMIT 1',
          [chargeId]
        );

        if (existingDep.rows.length === 0) {
          await client.query(
            `INSERT INTO deposits (id, "userId", amount, "txId", status, "starsAmount", provider)
             VALUES ($1, $2, $3, $4, 'COMPLETED', $5, 'TELEGRAM_STARS')`,
            ['dep_' + crypto.randomBytes(8).toString('hex'), invoice.userId, invoice.amount, chargeId, starsAmount]
          );
          await client.query(
            'UPDATE users SET "walletBalance" = "walletBalance" + $1 WHERE id = $2',
            [invoice.amount, invoice.userId]
          );
          const userRes = await client.query(
            'SELECT id, name, email, role FROM users WHERE id = $1',
            [invoice.userId]
          );
          creditedUser = userRes.rows[0] || null;
        }
      }
    }

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[Telegram Stars] successful_payment processing error:', err.message);
    // Rethrow so the webhook replies 500 and Telegram retries the update.
    // The handler is idempotent, so retries cannot double-credit a wallet.
    throw err;
  } finally {
    client.release();
  }

  if (!paidInvoice) return;

  const starsLabel = `${starsAmount} Star${starsAmount === 1 ? '' : 's'}`;
  const usdLabel = `$${parseFloat(paidInvoice.amount).toFixed(2)}`;

  if (paidOrder) {
    const titles = Array.isArray(paidOrder.items)
      ? paidOrder.items.map(i => i.title).join(', ')
      : 'Digital methods';
    try {
      const ownerRes = await pool.query('SELECT id FROM users WHERE LOWER(email) = $1 LIMIT 1', [STORE_OWNER_EMAIL]);
      if (ownerRes.rows[0]) {
        io.to(`user_${ownerRes.rows[0].id}`).emit('user_notification', {
          title: `⭐ Telegram Stars order paid (${usdLabel})`,
          body: `${paidOrder.customerContact} paid ${starsLabel} for: ${titles}`,
          url: '/admin/store',
          type: 'store_order'
        });
      }
    } catch (err) {
      console.warn('[Telegram Stars] Owner socket notification failed:', err.message);
    }

    try {
      emailService.notifyStoreOrderPaid({
        order: paidOrder,
        items: Array.isArray(paidOrder.items) ? paidOrder.items : [],
        customerContact: paidOrder.customerContact,
        amount: parseFloat(paidOrder.totalAmount),
        starsAmount,
        telegramUsername: message.from && message.from.username ? '@' + message.from.username : ''
      });
    } catch (err) {
      console.warn('[Telegram Stars] Store order email failed:', err.message);
    }

    if (chatId) {
      try {
        await telegramStars.sendMessage(
          chatId,
          `✅ Payment received: ${starsLabel} (${usdLabel}).\nOrder #${paidOrder.id} is confirmed.\n@Melasbit will contact you at ${paidOrder.customerContact} for the screen-share.`
        );
      } catch (err) {
        console.warn('[Telegram Stars] Buyer confirmation message failed:', err.message);
      }
    }
  }

  if (creditedUser) {
    const amount = parseFloat(paidInvoice.amount);
    io.to(`user_${creditedUser.id}`).emit('user_notification', {
      title: '⭐ Wallet topped up with Telegram Stars!',
      body: `+$${amount.toFixed(2)} has been credited to your wallet (${starsLabel}).`,
      url: '/dashboard',
      type: 'deposit_decision'
    });

    try {
      emailService.notifyDepositReceived({
        user: creditedUser,
        amount,
        txId: chargeId,
        starsAmount
      });
    } catch (err) {
      console.warn('[Telegram Stars] Deposit email failed:', err.message);
    }

    if (chatId) {
      try {
        await telegramStars.sendMessage(
          chatId,
          `✅ Top-up received: ${starsLabel}.\n+$${amount.toFixed(2)} has been credited to your wallet balance.`
        );
      } catch (err) {
        console.warn('[Telegram Stars] Top-up confirmation message failed:', err.message);
      }
    }
  }
}

async function handleTelegramUpdate(update) {
  if (!update || typeof update !== 'object') return;

  if (update.pre_checkout_query) {
    await handleStarsPreCheckout(update.pre_checkout_query);
    return;
  }

  const message = update.message;
  if (message && message.successful_payment) {
    await handleStarsSuccessfulPayment(message);
    return;
  }

  if (message && typeof message.text === 'string' && message.text.startsWith('/start')) {
    const baseUrl = (process.env.BASE_URL || telegramStars.WEBHOOK_URL || '').replace(/\/$/, '');
    const text = baseUrl
      ? `Welcome to @Melasbit Methods!\nBrowse the catalog and pay securely with Telegram Stars:\n${baseUrl}`
      : 'Welcome to @Melasbit Methods! Open the website, choose a method and pay securely with Telegram Stars.';
    try {
      await telegramStars.sendMessage(message.chat.id, text);
    } catch (err) {
      console.warn('[Telegram Stars] /start reply failed:', err.message);
    }
  }
}

// ==========================================
// SIMPLE DIRECT STORE API (BUY 1 OR MORE METHODS + EXCHANGE REQUEST)
// ==========================================

// Submit a direct Telegram Stars order for 1 or multiple methods
app.post('/api/store/order', async (req, res) => {
  try {
    const { serviceIds, customerContact, note } = req.body || {};

    if (!Array.isArray(serviceIds) || serviceIds.length === 0) {
      return res.status(400).json({ success: false, error: 'Please select at least one method.' });
    }

    const cleanIds = [...new Set(serviceIds.map(id => String(id || '').trim()).filter(Boolean))];
    if (cleanIds.length === 0 || cleanIds.length > 20) {
      return res.status(400).json({ success: false, error: 'Invalid method selection.' });
    }

    const cleanContact = String(customerContact || '').trim().slice(0, 200);
    const cleanNote = String(note || '').trim().slice(0, 1000);

    if (!cleanContact) {
      return res.status(400).json({ success: false, error: 'Please enter your WhatsApp, Telegram, or Email contact.' });
    }

    if (!telegramStars.isConfigured()) {
      return res.status(503).json({
        success: false,
        error: 'Telegram Stars checkout is not configured yet. Please contact @Melasbit directly.'
      });
    }

    // Fetch exact server-side prices from DB
    const srvRes = await pool.query(
      `SELECT id, title, price FROM services WHERE id = ANY($1::text[])`,
      [cleanIds]
    );
    if (srvRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Selected method(s) not found.' });
    }

    const items = srvRes.rows.map(r => ({
      id: r.id,
      title: r.title,
      price: parseFloat(r.price)
    }));
    const totalAmount = Math.round(items.reduce((sum, i) => sum + i.price, 0) * 100) / 100;
    const stars = telegramStars.usdToStars(totalAmount);

    const orderId = 'ord_' + crypto.randomBytes(6).toString('hex');
    const invoiceId = 'inv_' + crypto.randomBytes(8).toString('hex');
    const payload = makeStarsPayload('ord');
    const userId = req.user ? req.user.id : null;

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`
        INSERT INTO store_orders
          (id, "userId", "customerContact", items, "totalAmount", "paymentMethod", "txId", note, status, "invoicePayload")
        VALUES
          ($1, $2, $3, $4::jsonb, $5, 'TELEGRAM_STARS', $6, $7, 'PENDING', $6)
      `, [orderId, userId, cleanContact, JSON.stringify(items), totalAmount, payload, cleanNote || null]);

      await client.query(`
        INSERT INTO stars_invoices (id, payload, purpose, "userId", "storeOrderId", amount, stars, status)
        VALUES ($1, $2, 'STORE_ORDER', $3, $4, $5, $6, 'PENDING')
      `, [invoiceId, payload, userId, orderId, totalAmount, stars]);

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

    let invoiceLink;
    try {
      invoiceLink = await telegramStars.createInvoiceLink({
        title: `Order #${orderId.slice(-6)}`,
        description: items.map(i => i.title).join(' + ').slice(0, 250),
        payload,
        stars
      });
      await pool.query('UPDATE stars_invoices SET "invoiceLink" = $1 WHERE id = $2', [invoiceLink, invoiceId]);
    } catch (linkErr) {
      console.error('[Telegram Stars] Invoice creation error:', linkErr.message);
      await pool.query(`UPDATE stars_invoices SET status = 'FAILED' WHERE id = $1`, [invoiceId]);
      await pool.query(`UPDATE store_orders SET status = 'REJECTED' WHERE id = $1`, [orderId]);
      return res.status(502).json({
        success: false,
        error: 'Unable to create the Telegram Stars invoice. Please try again in a moment.'
      });
    }

    return res.json({
      success: true,
      invoiceLink,
      stars,
      order: {
        id: orderId,
        items,
        totalAmount,
        paymentMethod: 'TELEGRAM_STARS',
        customerContact: cleanContact,
        status: 'PENDING',
        stars
      }
    });
  } catch (err) {
    console.error('Store order error:', err.message);
    return res.status(500).json({ success: false, error: 'Unable to submit order right now.' });
  }
});

// Public payment status for a direct store order (no personal data returned)
app.get('/api/store/orders/:id/status', async (req, res) => {
  try {
    const orderId = String(req.params.id || '').trim();
    if (!/^ord_[a-f0-9]{12}$/.test(orderId)) {
      return res.status(400).json({ success: false, error: 'Invalid order id.' });
    }
    const ordRes = await pool.query(
      `SELECT id, status, "totalAmount", "starsAmount", "createdAt"
       FROM store_orders WHERE id = $1`,
      [orderId]
    );
    if (!ordRes.rows[0]) {
      return res.status(404).json({ success: false, error: 'Order not found.' });
    }
    return res.json({ success: true, order: ordRes.rows[0] });
  } catch (err) {
    console.error('Store order status error:', err.message);
    return res.status(500).json({ success: false, error: 'Unable to check order status.' });
  }
});

// Telegram webhook (secret path + secret header). CSRF is intentionally skipped above.
app.post('/telegram/webhook/:secret', async (req, res) => {
  const configuredSecret = telegramStars.WEBHOOK_SECRET;
  if (!configuredSecret) {
    return res.status(503).send('Telegram webhook is not configured.');
  }

  const pathSecret = req.params.secret || '';
  const headerSecret = req.get('x-telegram-bot-api-secret-token') || '';
  if (!safeSecretEquals(pathSecret, configuredSecret) || !safeSecretEquals(headerSecret, configuredSecret)) {
    return res.status(403).send('Forbidden');
  }

  try {
    await handleTelegramUpdate(req.body);
    return res.json({ ok: true });
  } catch (err) {
    console.error('[Telegram Stars] Webhook handler error:', err.message);
    // Non-200 makes Telegram retry. The handler is idempotent, so this is safe.
    return res.status(500).json({ ok: false });
  }
});

// Submit a Method Exchange Request
app.post('/api/store/exchange', async (req, res) => {
  try {
    const { senderName, contact, offeredMethod, wantedMethods, details } = req.body || {};
    const cleanName = String(senderName || '').trim().slice(0, 150);
    const cleanContact = String(contact || '').trim().slice(0, 200);
    const cleanOffered = String(offeredMethod || '').trim().slice(0, 1000);
    const cleanWanted = Array.isArray(wantedMethods)
      ? wantedMethods.map(w => String(w).trim()).filter(Boolean).join(', ').slice(0, 500)
      : String(wantedMethods || '').trim().slice(0, 500);
    const cleanDetails = String(details || '').trim().slice(0, 2000);

    if (!cleanName || !cleanContact || !cleanOffered) {
      return res.status(400).json({ success: false, error: 'Please fill in your name/handle, contact, and the method you offer.' });
    }

    const reqId = 'exch_' + crypto.randomBytes(6).toString('hex');
    await pool.query(`
      INSERT INTO exchange_requests (id, "userId", "senderName", contact, "offeredMethod", "wantedMethods", details, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7, 'NEW')
    `, [
      reqId,
      req.user ? req.user.id : null,
      cleanName,
      cleanContact,
      cleanOffered,
      cleanWanted || 'Any available method',
      cleanDetails || null
    ]);

    const ownerRes = await pool.query(`SELECT id FROM users WHERE LOWER(email) = $1 LIMIT 1`, [STORE_OWNER_EMAIL]);
    if (ownerRes.rows[0]) {
      io.to(`user_${ownerRes.rows[0].id}`).emit('user_notification', {
        title: `🔄 New Method Exchange Request`,
        body: `${cleanName} (${cleanContact}) offers: ${cleanOffered}`,
        url: '/admin/store',
        type: 'exchange_request'
      });
    }

    return res.json({
      success: true,
      exchange: { id: reqId, senderName: cleanName, contact: cleanContact, offeredMethod: cleanOffered, wantedMethods: cleanWanted }
    });
  } catch (err) {
    console.error('Exchange request error:', err.message);
    return res.status(500).json({ success: false, error: 'Unable to submit exchange request.' });
  }
});

// Admin Store Panel (ONLY saleminformatiquedev@gmail.com)
app.get('/admin/store', ensureAuthenticated, async (req, res) => {
  if (!isStoreOwner(req.user)) {
    return res.status(403).send('Access restricted to store owner (saleminformatiquedev@gmail.com).');
  }
  try {
    const ordersRes = await pool.query(`SELECT * FROM store_orders ORDER BY "createdAt" DESC LIMIT 100`);
    const exchangesRes = await pool.query(`SELECT * FROM exchange_requests ORDER BY "createdAt" DESC LIMIT 100`);
    const invoicesRes = await pool.query(`SELECT * FROM stars_invoices ORDER BY "createdAt" DESC LIMIT 25`);

    let starBalance = null;
    let starTransactions = [];
    let starsError = null;
    if (telegramStars.isConfigured()) {
      const [balanceResult, txResult] = await Promise.allSettled([
        telegramStars.getMyStarBalance(),
        telegramStars.getStarTransactions({ offset: 0, limit: 15 })
      ]);

      if (balanceResult.status === 'fulfilled') {
        const balanceRes = balanceResult.value;
        const rawBalance = balanceRes && (balanceRes.amount !== undefined ? balanceRes.amount : balanceRes.balance);
        starBalance = rawBalance !== undefined && rawBalance !== null && Number.isFinite(Number(rawBalance))
          ? Number(rawBalance)
          : null;
      } else {
        starsError = balanceResult.reason && balanceResult.reason.message
          ? balanceResult.reason.message
          : 'Unable to read the Stars balance.';
      }

      if (txResult.status === 'fulfilled') {
        const txRes = txResult.value;
        starTransactions = Array.isArray(txRes && txRes.transactions) ? txRes.transactions : [];
      } else if (!starsError) {
        starsError = txResult.reason && txResult.reason.message
          ? txResult.reason.message
          : 'Unable to read Stars transactions.';
      }
    }

    res.render('admin-store', {
      storeOrders: ordersRes.rows,
      exchangeRequests: exchangesRes.rows,
      starsInvoices: invoicesRes.rows,
      starBalance,
      starTransactions,
      starsError,
      starsConfigured: telegramStars.isConfigured(),
      starsPerUsd: telegramStars.STARS_PER_USD,
      telegramBotUsername: telegramStars.BOT_USERNAME
    });
  } catch (err) {
    console.error('Admin store error:', err.message);
    res.status(500).send('Unable to load admin store panel.');
  }
});

app.post('/admin/store/orders/:id/status', ensureAuthenticated, async (req, res) => {
  if (!isStoreOwner(req.user)) return res.status(403).json({ success: false, error: 'Forbidden' });
  const allowed = new Set(['PENDING', 'PAID', 'DELIVERED', 'REJECTED']);
  const nextStatus = String(req.body.status || '').toUpperCase();
  if (!allowed.has(nextStatus)) return res.status(400).json({ success: false, error: 'Invalid status' });
  try {
    await pool.query(`UPDATE store_orders SET status = $1 WHERE id = $2`, [nextStatus, req.params.id]);
    res.redirect('/admin/store');
  } catch (err) {
    res.status(500).send('Unable to update order status.');
  }
});

// Refund a paid Stars invoice back to the buyer's Telegram Stars balance.
app.post('/admin/store/orders/:id/refund', ensureAuthenticated, requireFreshAdmin, async (req, res) => {
  if (!isStoreOwner(req.user)) return res.status(403).send('Forbidden');
  if (!telegramStars.isConfigured()) {
    return res.status(503).send('Telegram Stars is not configured on this server.');
  }

  try {
    const ordRes = await pool.query('SELECT * FROM store_orders WHERE id = $1', [req.params.id]);
    const order = ordRes.rows[0];
    if (!order) return res.status(404).send('Order not found.');
    if (order.status === 'REFUNDED') return res.redirect('/admin/store');
    if (!order.telegramPaymentChargeId || !order.telegramUserId) {
      return res.status(400).send('This order has no Telegram Stars charge to refund.');
    }

    await telegramStars.refundStarPayment(Number(order.telegramUserId), order.telegramPaymentChargeId);
    await pool.query(`UPDATE store_orders SET status = 'REFUNDED' WHERE id = $1`, [order.id]);
    await pool.query(
      `UPDATE stars_invoices SET status = 'REFUNDED' WHERE "storeOrderId" = $1 AND status = 'PAID'`,
      [order.id]
    );
    adminAudit(req, 'STORE_ORDER_REFUNDED', {
      orderId: order.id,
      chargeId: order.telegramPaymentChargeId,
      starsAmount: order.starsAmount
    });
    res.redirect('/admin/store');
  } catch (err) {
    console.error('Stars refund error:', err.message);
    res.status(400).send('Telegram Stars refund failed: ' + err.message);
  }
});

app.post('/admin/store/exchanges/:id/status', ensureAuthenticated, async (req, res) => {
  if (!isStoreOwner(req.user)) return res.status(403).json({ success: false, error: 'Forbidden' });
  const allowed = new Set(['NEW', 'IN_PROGRESS', 'ACCEPTED', 'DECLINED']);
  const nextStatus = String(req.body.status || '').toUpperCase();
  if (!allowed.has(nextStatus)) return res.status(400).json({ success: false, error: 'Invalid status' });
  try {
    await pool.query(`UPDATE exchange_requests SET status = $1 WHERE id = $2`, [nextStatus, req.params.id]);
    res.redirect('/admin/store');
  } catch (err) {
    res.status(500).send('Unable to update exchange status.');
  }
});

// Login Page
app.get('/login', (req, res) => {
  const nextPath = safeReturnPath(req.query.next);
  if (nextPath) {
    if (req.isAuthenticated()) return res.redirect(nextPath);
    rememberReturnTo(req, res, nextPath);
  }
  res.render('login', { msg: req.query.msg || null });
});

// New Method Form (restricted strictly to store owner saleminformatiquedev@gmail.com)
app.get('/services/new', ensureAuthenticated, (req, res) => {
  if (!isStoreOwner(req.user)) {
    return res.status(403).send('Only the store owner (saleminformatiquedev@gmail.com) can add methods.');
  }
  res.render('new-service');
});

// Detail of a method/account offer with reviews
app.get('/services/:id', async (req, res) => {
  try {
    const srvRes = await pool.query(`
      SELECT s.*, u.name as "sellerName", u.avatar as "sellerAvatar", u.bio as "sellerBio", u.skills as "sellerSkills"
      FROM services s
      JOIN users u ON s."sellerId" = u.id
      WHERE s.id = $1
    `, [req.params.id]);

    if (srvRes.rows.length === 0) return res.status(404).send("Method not found");
    const service = sanitizePublicService(formatRows(srvRes.rows)[0]);

    const reviewsRes = await pool.query(`
      SELECT r.*, u.name as "buyerName", u.avatar as "buyerAvatar"
      FROM reviews r
      JOIN users u ON r."buyerId" = u.id
      WHERE r."serviceId" = $1
      ORDER BY r."createdAt" DESC
    `, [service.id]);

    res.render('service-detail', {
      service,
      reviews: reviewsRes.rows,
      starsPerUsd: telegramStars.STARS_PER_USD,
      telegramBotUsername: telegramStars.BOT_USERNAME,
      telegramStarsConfigured: telegramStars.isConfigured()
    });
  } catch (err) {
    console.error("Service detail error:", err.message);
    res.status(500).send("Unable to load guide details.");
  }
});

// Public Author Profile (never exposes private email or balance)
app.get('/profile/:id', async (req, res) => {
  try {
    const uRes = await pool.query(
      'SELECT id, name, avatar, bio, skills, role, "createdAt" FROM users WHERE id = $1',
      [req.params.id]
    );
    if (uRes.rows.length === 0) return res.status(404).send("User profile not found");
    const profile = uRes.rows[0];

    const srvRes = await pool.query(`
      SELECT s.id, s."sellerId", s.title, s.description, s.category, s.price,
             s."deliveryDays", s."pageCount", s.difficulty, s.formats, s."createdAt",
             u.name as "sellerName", u.avatar as "sellerAvatar"
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

    res.render('profile', { profile, services: formatRows(srvRes.rows).map(sanitizePublicService), reviews: revRes.rows });
  } catch (err) {
    console.error("Profile error:", err.message);
    res.status(500).send("Unable to load profile.");
  }
});

// ==========================================
// MEMBER ROUTES (SERVICES, ORDERS & FILES)
// ==========================================

// File upload in chat / order
app.post('/api/upload', ensureAuthenticated, upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No file provided' });
    }
    if (isDemoUser(req.user)) {
      if (fs.existsSync(req.file.path)) {
        try { fs.unlinkSync(req.file.path); } catch (_) {}
      }
      return res.status(403).json({ success: false, error: 'Demo accounts cannot upload files to the server. Please sign in with a real Google account.' });
    }
    const ext = path.extname(req.file.filename).toLowerCase();
    verifyUploadedFileSafety(req.file.path, ext);

    const fileUrl = `/uploads/${req.file.filename}`;
    res.json({
      success: true,
      fileUrl,
      fileName: req.file.originalname,
      fileSize: req.file.size
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message || 'File validation failed' });
  }
});

// Publish new method (strictly restricted to store owner saleminformatiquedev@gmail.com)
app.post('/services/new', ensureAuthenticated, upload.any(), async (req, res) => {
  try {
    if (!isStoreOwner(req.user)) {
      if (req.files && req.files.length > 0) {
        for (const f of req.files) {
          if (fs.existsSync(f.path)) {
            try { fs.unlinkSync(f.path); } catch (_) {}
          }
        }
      }
      return res.status(403).send("Only the store owner (saleminformatiquedev@gmail.com) can publish methods.");
    }
    if (isDemoUser(req.user)) {
      if (req.files && req.files.length > 0) {
        for (const f of req.files) {
          if (fs.existsSync(f.path)) {
            try { fs.unlinkSync(f.path); } catch (_) {}
          }
        }
      }
      return res.status(403).send("Demo test accounts cannot publish new methods to the public catalog. Please sign in with your Google account.");
    }
    const {
      title, description, category, price, pageCount, difficulty, videoUrl, formats,
      unitCost, durationLabel, offerType, screenShareDemo, openToExchange, bulkAvailable,
      supplierHandle, whatsappNumber, telegramBot
    } = req.body;

    const cleanTitle = String(title || '').trim();
    const cleanDesc = String(description || '').trim();
    const numericPrice = Math.round(parseFloat(price) * 100) / 100;

    if (!cleanTitle || cleanTitle.length < 1 || cleanTitle.length > 200) {
      return res.status(400).send("<script>alert('Please enter a title (1 to 200 characters).'); window.history.back();</script>");
    }
    if (!cleanDesc || cleanDesc.length < 1 || cleanDesc.length > 10000) {
      return res.status(400).send("<script>alert('Please enter a description (1 to 10,000 characters).'); window.history.back();</script>");
    }
    if (!Number.isFinite(numericPrice) || numericPrice < 0.50 || numericPrice > 50000.00) {
      return res.status(400).send("<script>alert('Invalid price: must be between $0.50 and $50,000.00.'); window.history.back();</script>");
    }

    let safeVideoUrl = null;
    if (videoUrl && String(videoUrl).trim()) {
      try {
        const parsedUrl = new URL(String(videoUrl).trim());
        if (parsedUrl.protocol === 'https:' || parsedUrl.protocol === 'http:') {
          safeVideoUrl = parsedUrl.toString();
        }
      } catch (_) {
        return res.status(400).send("Invalid external video URL.");
      }
    }

    const newId = 'srv_' + crypto.randomBytes(8).toString('hex');

    const attachments = [];
    let primaryFileUrl = null;
    let primaryFileName = null;
    let primaryFileSize = null;

    if (req.files && req.files.length > 0) {
      for (const f of req.files) {
        const ext = path.extname(f.filename).toLowerCase();
        verifyUploadedFileSafety(f.path, ext);

        let type = 'other';
        let label = f.originalname;

        if (ext === '.pdf') {
          type = 'pdf';
          label = `Complete Guide (${f.originalname})`;
        } else if (['.zip', '.rar', '.tar', '.gz', '.7z'].includes(ext)) {
          type = 'zip';
          label = `Source Code & Archives (${f.originalname})`;
        } else if (['.txt', '.md', '.sh', '.json', '.yml', '.yaml'].includes(ext)) {
          type = 'text';
          label = `Scripts & Configuration (${f.originalname})`;
        } else if (['.mp4', '.mov', '.webm'].includes(ext)) {
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
      }
    }

    if (safeVideoUrl) {
      attachments.push({
        type: 'video',
        name: 'Online Video Tutorial',
        url: safeVideoUrl,
        size: 'Video Stream',
        label: 'Step-by-Step Video Tutorial'
      });
    }

    if (attachments.length === 0) {
      attachments.push(
        { type: "pdf", name: "guide-method-step-by-step.pdf", url: "/uploads/guide-methode-developpement-ideale.pdf", size: "2.4 MB", label: "Complete Step-by-Step Guide (PDF)" },
        { type: "zip", name: "source-code-template.zip", url: "/uploads/code-source-template.zip", size: "5.1 MB", label: "Source Code & Ready Files (ZIP)" },
        { type: "text", name: "commands-scripts.txt", url: "/uploads/commandes-scripts.txt", size: "15 KB", label: "Shell Scripts & Variables (Text)" }
      );
      primaryFileUrl = '/uploads/guide-methode-developpement-ideale.pdf';
      primaryFileName = 'complete-method-pack.zip';
      primaryFileSize = '7.5 MB';
    }

    const activeFormats = Array.isArray(formats) ? formats.join(',') : (formats || 'METHOD,SCRIPT,SCREEN-SHARE');
    const safePages = Math.min(Math.max(parseInt(pageCount, 10) || 10, 1), 5000);
    const cleanUnitCost = unitCost ? String(unitCost).trim().slice(0, 200) : null;
    const cleanDuration = durationLabel ? String(durationLabel).trim().slice(0, 100) : null;
    const cleanOfferType = ['METHOD', 'READY_ACCOUNT', 'BULK_DEAL'].includes(offerType) ? offerType : 'METHOD';
    const hasScreenShare = screenShareDemo === 'on' || screenShareDemo === 'true' || screenShareDemo === true;
    const isOpenExchange = openToExchange === 'on' || openToExchange === 'true' || openToExchange === true;
    const hasBulk = bulkAvailable === 'on' || bulkAvailable === 'true' || bulkAvailable === true;
    const cleanHandle = supplierHandle ? String(supplierHandle).trim().slice(0, 100) : '@Melasbit';
    const cleanWhatsapp = whatsappNumber ? String(whatsappNumber).trim().slice(0, 40) : '+21627076373';
    const cleanBot = telegramBot ? String(telegramBot).trim().slice(0, 100) : '@LicenzioChannel';

    await pool.query(`
      INSERT INTO services (
        id, "sellerId", title, description, category, price, "deliveryDays",
        "fileUrl", "fileName", "fileSize", "pageCount", "difficulty", "formats", "videoUrl", "attachments",
        "unitCost", "durationLabel", "offerType", "screenShareDemo", "openToExchange", "bulkAvailable",
        "supplierHandle", "whatsappNumber", "telegramBot"
      )
      VALUES (
        $1, $2, $3, $4, $5, $6, 1,
        $7, $8, $9, $10, $11, $12, $13, $14::jsonb,
        $15, $16, $17, $18, $19, $20,
        $21, $22, $23
      )
    `, [
      newId,
      req.user.id,
      cleanTitle,
      cleanDesc,
      category || 'Digital Accounts & Methods',
      numericPrice,
      primaryFileUrl,
      primaryFileName,
      primaryFileSize,
      safePages,
      difficulty || 'Beginner',
      activeFormats,
      safeVideoUrl,
      JSON.stringify(attachments),
      cleanUnitCost,
      cleanDuration,
      cleanOfferType,
      hasScreenShare,
      isOpenExchange,
      hasBulk,
      cleanHandle,
      cleanWhatsapp,
      cleanBot
    ]);

    res.redirect('/services/' + newId);
  } catch (err) {
    console.error("Error creating service:", err.message);
    res.status(400).send("Unable to publish method: " + (err.message || "Invalid input"));
  }
});

// Create order with Escrow
app.post('/orders/create', ensureAuthenticated, async (req, res) => {
  try {
    const { serviceId, requirements } = req.body;

    const order = await escrow.createOrderWithEscrow(pool, {
      buyerId: req.user.id,
      serviceId,
      requirements: requirements ? String(requirements).slice(0, 2000) : ''
    });

    io.to(`user_${order.sellerId}`).emit('user_notification', {
      title: '🎉 New Order Received!',
      body: `${req.user.name} purchased your method (${parseFloat(order.amount).toFixed(2)} USD locked in escrow).`,
      url: `/orders/${order.id}`,
      type: 'new_order'
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

// Order detail & tracking (strictly restricted to Buyer, Seller, or matching-sandbox Admin)
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

    const isParticipant = req.user.id === order.buyerId || req.user.id === order.sellerId;
    const isAuthorizedAdmin = req.user.role === 'ADMIN' && (
      !isDemoUser(req.user) || (isDemoUser(order.buyerEmail) && isDemoUser(order.sellerEmail))
    );

    if (!isParticipant && !isAuthorizedAdmin) {
      return res.status(403).send("Access denied to this order (Sandbox isolation)");
    }
    delete order.buyerEmail;
    delete order.sellerEmail;

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
    console.error("Order detail error:", err.message);
    res.status(500).send("Unable to load order.");
  }
});

// Author delivers order
app.post('/orders/:id/deliver', ensureAuthenticated, async (req, res) => {
  try {
    const updated = await escrow.deliverOrder(pool, {
      orderId: req.params.id,
      sellerId: req.user.id,
      deliveryNote: String(req.body.deliveryNote || '').slice(0, 2000)
    });

    io.to(`order_${req.params.id}`).emit('order_updated', { status: 'DELIVERED', order: updated });
    io.to(`user_${updated.buyerId}`).emit('user_notification', {
      title: '📦 Order Delivered!',
      body: 'The author has delivered your order files. Review and approve when ready.',
      url: `/orders/${req.params.id}`,
      type: 'order_delivered'
    });
    res.redirect('/orders/' + req.params.id);
  } catch (err) {
    res.status(400).send("Error: " + err.message);
  }
});

// Buyer (within 2 days) or Admin approves and releases funds
app.post('/orders/:id/complete', ensureAuthenticated, requireFreshIfAdmin, async (req, res) => {
  try {
    const updated = await escrow.completeOrderAndReleaseFunds(pool, {
      orderId: req.params.id,
      buyerId: req.user.id,
      isAdmin: req.user.role === 'ADMIN',
      adminUser: req.user
    });

    const netAmt = parseFloat(updated.sellerNetAmount || (updated.amount * 0.85)).toFixed(2);
    io.to(`order_${req.params.id}`).emit('order_updated', { status: 'COMPLETED', order: updated });
    io.to(`user_${updated.sellerId}`).emit('user_notification', {
      title: '💰 Payment Released!',
      body: `Order approved! +${netAmt} USD (85% net) has been credited to your wallet.`,
      url: `/orders/${req.params.id}`,
      type: 'order_completed'
    });
    res.redirect('/orders/' + req.params.id);
  } catch (err) {
    res.status(400).send("Error: " + err.message);
  }
});

// Leave review on order (Buyer within 2 days, or Admin after 2 days)
app.post('/orders/:id/review', ensureAuthenticated, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    const ordRes = await pool.query(`
      SELECT o.*, b.email as "buyerEmail", s.email as "sellerEmail"
      FROM orders o
      JOIN users b ON o."buyerId" = b.id
      JOIN users s ON o."sellerId" = s.id
      WHERE o.id = $1
    `, [req.params.id]);
    const order = ordRes.rows[0];

    if (!order) {
      return res.status(404).send("Order not found.");
    }

    const baseMs = new Date(order.deliveredAt || order.createdAt).getTime();
    const isExpired = Date.now() > baseMs + (2 * 24 * 60 * 60 * 1000);
    const isAdmin = req.user.role === 'ADMIN';
    const isBuyer = order.buyerId === req.user.id;

    if (isAdmin && isDemoUser(req.user) && (!isDemoUser(order.buyerEmail) || !isDemoUser(order.sellerEmail))) {
      return res.status(403).send("Sandbox isolation: Demo Admin cannot review real users' orders.");
    }

    if (!isAdmin) {
      if (!isBuyer) {
        return res.status(403).send("Only the buyer (within 2 days) or the Admin can leave a review.");
      }
      if (isExpired) {
        return res.status(403).send("Only 2 days are allowed to validate the method. After 2 days, the review is for the Admin.");
      }
      if (order.status !== 'COMPLETED') {
        return res.status(400).send("Please approve the order before submitting your review.");
      }
    }

    const safeRating = Math.min(Math.max(parseInt(rating, 10) || 5, 1), 5);
    const safeComment = String(comment || '').trim().slice(0, 1500);

    const reviewId = 'rev_' + crypto.randomBytes(8).toString('hex');
    await pool.query(`
      INSERT INTO reviews (id, "orderId", "serviceId", "buyerId", "sellerId", rating, comment)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      ON CONFLICT ("orderId") DO UPDATE SET rating = $6, comment = $7
    `, [reviewId, order.id, order.serviceId, order.buyerId, order.sellerId, safeRating, safeComment]);

    (async () => {
      try {
        const uSeller = await pool.query('SELECT * FROM users WHERE id = $1', [order.sellerId]);
        const uBuyer = await pool.query('SELECT * FROM users WHERE id = $1', [order.buyerId]);
        if (uSeller.rows[0] && uBuyer.rows[0]) {
          emailService.notifyReviewSubmitted({
            review: { rating: safeRating, comment: safeComment },
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
    console.error("Review error:", err.message);
    res.status(500).send("Unable to save review.");
  }
});

// Open dispute / investigation
app.post('/orders/:id/dispute', ensureAuthenticated, async (req, res) => {
  try {
    const { reason, details } = req.body;
    await escrow.openDispute(pool, {
      orderId: req.params.id,
      userId: req.user.id,
      reason: String(reason || '').slice(0, 250),
      details: String(details || '').slice(0, 3000)
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

app.get('/support', ensureAuthenticated, (req, res) => {
  res.redirect('/chat?support=1');
});

app.get('/messages', ensureAuthenticated, (req, res) => {
  res.redirect('/chat');
});

// Main Chat Page (strictly isolates Demo test accounts from Real accounts)
app.get('/chat', ensureAuthenticated, async (req, res) => {
  try {
    const currentUserId = req.user.id;
    const currentIsDemo = isDemoUser(req.user);
    let targetUserId = req.query.recipientId || null;
    let serviceId = req.query.serviceId || null;
    let requestedConvId = req.query.conversationId || null;

    if (req.query.support === '1' || req.query.support === 'true') {
      let adminRes = await pool.query(
        "SELECT id, name FROM users WHERE role = 'ADMIN' AND LOWER(email) = 'saleminformatiquedev@gmail.com' LIMIT 1"
      );
      if (adminRes.rows.length === 0) {
        adminRes = await pool.query(`
          INSERT INTO users (id, email, name, role, "walletBalance", "escrowBalance", bio)
          VALUES ('usr_real_admin', 'saleminformatiquedev@gmail.com', 'Platform Admin', 'ADMIN', 0.00, 0.00, 'Official TrustWork Platform Administrator')
          ON CONFLICT (email) DO UPDATE SET role = 'ADMIN'
          RETURNING id, name
        `);
      }
      if (adminRes.rows.length > 0 && req.user.role !== 'ADMIN') {
        targetUserId = adminRes.rows[0].id;
      }
    }

    if (targetUserId && targetUserId !== currentUserId) {
      const recipientUserRes = await pool.query('SELECT id, role, name, email FROM users WHERE id = $1', [targetUserId]);
      if (recipientUserRes.rows.length > 0) {
        const recipientUser = recipientUserRes.rows[0];
        if (isDemoUser(recipientUser) !== currentIsDemo) {
          return res.status(403).send("Sandbox isolation: Demo test accounts can only message other demo test accounts.");
        }

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
          const convType = recipientUser.role === 'ADMIN' || req.user.role === 'ADMIN' ? 'SUPPORT' : 'DIRECT';

          let subject = req.query.subject ? String(req.query.subject).slice(0, 200) : null;
          if (!subject && serviceId) {
            const srvRes = await pool.query('SELECT title FROM services WHERE id = $1', [serviceId]);
            if (srvRes.rows.length > 0) {
              subject = `Regarding: ${srvRes.rows[0].title}`;
            }
          }
          if (!subject) {
            subject = convType === 'SUPPORT' ? 'Support Assistance' : 'Direct Conversation';
          }

          const newConvId = 'conv_' + crypto.randomBytes(8).toString('hex');
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
    }

    const convsRes = await pool.query(`
      SELECT c.*,
             p."unreadCount",
             u.id as "partnerId", 
             u.name as "partnerName", 
             u.avatar as "partnerAvatar", 
             u.role as "partnerRole", 
             u.bio as "partnerBio",
             s.title as "serviceTitle", 
             s.price as "servicePrice",
             s.id as "serviceId"
      FROM conversations c
      JOIN conversation_participants p ON c.id = p."conversationId" AND p."userId" = $1
      JOIN conversation_participants other_p ON c.id = other_p."conversationId" AND other_p."userId" != $1
      JOIN users u ON other_p."userId" = u.id
      LEFT JOIN services s ON c."serviceId" = s.id
      WHERE (u.email LIKE '%.local') = $2
      ORDER BY c."lastMessageAt" DESC
    `, [currentUserId, currentIsDemo]);

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
        WHERE NOT EXISTS (
          SELECT 1 FROM conversation_participants cp2
          JOIN users u2 ON cp2."userId" = u2.id
          WHERE cp2."conversationId" = c.id
            AND (u2.email LIKE '%.local') != $1
        )
        ORDER BY c."lastMessageAt" DESC
      `, [currentIsDemo]);
      platformConversations = formatRows(allConvsRes.rows);
    }

    let activeConversation = null;
    if (requestedConvId) {
      activeConversation = conversations.find(c => c.id === requestedConvId);
      if (!activeConversation && req.user.role === 'ADMIN' && (await canAccessConversation(req.user, requestedConvId))) {
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
        SELECT u.id, u.name, u.avatar, u.role, u.bio
        FROM conversation_participants cp
        JOIN users u ON cp."userId" = u.id
        WHERE cp."conversationId" = $1 AND cp."userId" != $2
        LIMIT 1
      `, [activeConversation.id, currentUserId]);

      if (partnerRes.rows.length > 0) {
        activePartner = partnerRes.rows[0];
      } else {
        const firstUserRes = await pool.query(`
          SELECT u.id, u.name, u.avatar, u.role, u.bio
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
      SELECT u.id, u.name, u.avatar, u.role, u.bio,
             (SELECT count(*) FROM services s WHERE s."sellerId" = u.id) as "servicesCount"
      FROM users u
      WHERE u.id != $1
        AND (u.email LIKE '%.local') = $2
      ORDER BY (u.role = 'ADMIN') DESC, (u.role = 'USER') DESC, u.name ASC
    `, [currentUserId, currentIsDemo]);

    res.render('chat', {
      conversations,
      platformConversations,
      activeConversation,
      activePartner,
      messages,
      contacts: contactsRes.rows,
      showMobileList: !requestedConvId
    });
  } catch (err) {
    console.error("Chat error:", err.message);
    res.status(500).send("Unable to load messaging.");
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
      if (isDemoUser(req.user)) {
        try { fs.unlinkSync(req.file.path); } catch (_) {}
        return res.status(403).json({ success: false, error: 'Shared demo accounts cannot upload files to the server.' });
      }
      const ext = path.extname(req.file.filename).toLowerCase();
      verifyUploadedFileSafety(req.file.path, ext);

      fileUrl = `/uploads/${req.file.filename}`;
      fileName = req.file.originalname;
      const sizeMb = (req.file.size / (1024 * 1024)).toFixed(1);
      fileSize = sizeMb > 0 ? `${sizeMb} MB` : `${(req.file.size / 1024).toFixed(0)} KB`;
      fileType = ext.replace('.', '');
    }

    const trimmedContent = content ? String(content).trim().slice(0, 4000) : '';
    if (!trimmedContent && !fileUrl) {
      return res.status(400).json({ success: false, error: 'Please enter a message or attach a file' });
    }

    const newMsgId = 'dmsg_' + crypto.randomBytes(8).toString('hex');
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
    res.status(400).json({ success: false, error: err.message || 'Unable to send message' });
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
    res.status(500).json({ success: false, error: 'Error retrieving unread count' });
  }
});

// REST AJAX: Start conversation
app.post('/api/chat/start', ensureAuthenticated, async (req, res) => {
  try {
    const { recipientId, serviceId, subject, initialMessage } = req.body;
    if (!recipientId || recipientId === req.user.id) {
      return res.status(400).json({ success: false, error: 'Invalid recipient' });
    }

    const recipientRes = await pool.query('SELECT role, email FROM users WHERE id = $1', [recipientId]);
    if (recipientRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Recipient not found' });
    }
    if (isDemoUser(recipientRes.rows[0]) !== isDemoUser(req.user)) {
      return res.status(403).json({ success: false, error: 'Sandbox isolation: Demo accounts can only chat with other demo accounts.' });
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
      const convType = recipientRes.rows[0].role === 'ADMIN' || req.user.role === 'ADMIN' ? 'SUPPORT' : 'DIRECT';

      convId = 'conv_' + crypto.randomBytes(8).toString('hex');
      await pool.query(`
        INSERT INTO conversations (id, type, "serviceId", subject, "lastMessageText")
        VALUES ($1, $2, $3, $4, $5)
      `, [convId, convType, serviceId || null, subject ? String(subject).slice(0, 200) : 'Direct Conversation', initialMessage ? String(initialMessage).slice(0, 500) : 'Conversation started']);

      await pool.query(`
        INSERT INTO conversation_participants ("conversationId", "userId", "unreadCount")
        VALUES ($1, $2, 0), ($1, $3, 0)
      `, [convId, req.user.id, recipientId]);
    }

    if (initialMessage && String(initialMessage).trim()) {
      const cleanMsg = String(initialMessage).trim().slice(0, 4000);
      const newMsgId = 'dmsg_' + crypto.randomBytes(8).toString('hex');
      await pool.query(`
        INSERT INTO direct_messages (id, "conversationId", "senderId", content, "isRead")
        VALUES ($1, $2, $3, $4, false)
      `, [newMsgId, convId, req.user.id, cleanMsg]);

      await pool.query(`
        UPDATE conversations
        SET "lastMessageText" = $1, "lastMessageAt" = CURRENT_TIMESTAMP
        WHERE id = $2
      `, [cleanMsg, convId]);

      await pool.query(`
        UPDATE conversation_participants
        SET "unreadCount" = "unreadCount" + 1
        WHERE "conversationId" = $1 AND "userId" != $2
      `, [convId, req.user.id]);
    }

    res.json({ success: true, conversationId: convId });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Unable to start conversation' });
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
      SELECT * FROM withdrawals WHERE "userId" = $1 ORDER BY "createdAt" DESC LIMIT 20
    `, [user.id]);

    const depRes = await pool.query(`
      SELECT * FROM deposits WHERE "userId" = $1 ORDER BY "createdAt" DESC LIMIT 20
    `, [user.id]);

    let adminCommissionOrders = [];
    let totalAdminCommission = 0;
    if (user.role === 'ADMIN') {
      const adminIsDemo = isDemoUser(user);
      const commRes = await pool.query(`
        SELECT o.*, s.title as "serviceTitle", b.name as "buyerName", sl.name as "sellerName"
        FROM orders o
        JOIN services s ON o."serviceId" = s.id
        JOIN users b ON o."buyerId" = b.id
        JOIN users sl ON o."sellerId" = sl.id
        WHERE o.status = 'COMPLETED'
          AND ((NOT $1 AND b.email NOT LIKE '%.local') OR ($1 AND b.email LIKE '%.local'))
        ORDER BY o."completedAt" DESC NULLS LAST, o."createdAt" DESC
      `, [adminIsDemo]);
      adminCommissionOrders = formatRows(commRes.rows);
      totalAdminCommission = adminCommissionOrders.reduce((acc, o) => acc + (o.platformFee || 0), 0);
    }

    res.render('dashboard', {
      user,
      buyerOrders: formatRows(buyerRes.rows),
      sellerOrders: formatRows(sellerRes.rows),
      withdrawals: formatRows(withRes.rows),
      deposits: formatRows(depRes.rows),
      adminCommissionOrders,
      totalAdminCommission,
      starsPerUsd: telegramStars.STARS_PER_USD,
      telegramStarsConfigured: telegramStars.isConfigured(),
      telegramBotUsername: telegramStars.BOT_USERNAME
    });
  } catch (err) {
    console.error("Dashboard error:", err.message);
    res.status(500).send("Unable to load dashboard.");
  }
});

// Real-Money Ledger Solvency Guard: Recomputes a real user's maximum legitimate balance from COMPLETED real-money transactions
async function verifyRealUserSolvency(client, user) {
  if (!user || isDemoUser(user)) return { solvent: false, maxAllowedBalance: 0 };

  const depRes = await client.query(
    `SELECT COALESCE(SUM(amount), 0) AS total FROM deposits WHERE "userId" = $1 AND status = 'COMPLETED'`,
    [user.id]
  );
  const salesRes = await client.query(
    `SELECT COALESCE(SUM(COALESCE(o."sellerNetAmount", ROUND(o.amount * 0.85, 2))), 0) AS total
     FROM orders o
     JOIN users b ON o."buyerId" = b.id
     WHERE o."sellerId" = $1 AND o.status = 'COMPLETED' AND b.email NOT LIKE '%.local'`,
    [user.id]
  );
  let adminComm = 0;
  if (user.role === 'ADMIN') {
    const commRes = await client.query(
      `SELECT COALESCE(SUM(COALESCE(o."platformFee", ROUND(o.amount * 0.15, 2))), 0) AS total
       FROM orders o
       JOIN users b ON o."buyerId" = b.id
       WHERE o.status = 'COMPLETED' AND b.email NOT LIKE '%.local'`
    );
    adminComm = parseFloat(commRes.rows[0].total) || 0;
  }
  const spentRes = await client.query(
    `SELECT COALESCE(SUM(amount), 0) AS total FROM orders WHERE "buyerId" = $1 AND status != 'REFUNDED'`,
    [user.id]
  );
  const withRes = await client.query(
    `SELECT COALESCE(SUM(amount), 0) AS total FROM withdrawals WHERE "userId" = $1 AND status IN ('PENDING', 'COMPLETED')`,
    [user.id]
  );

  const completedDeposits = parseFloat(depRes.rows[0].total) || 0;
  const completedSalesNet = parseFloat(salesRes.rows[0].total) || 0;
  const buyerSpent = parseFloat(spentRes.rows[0].total) || 0;
  const priorWithdrawals = parseFloat(withRes.rows[0].total) || 0;

  const maxAllowedBalance = Math.round((completedDeposits + completedSalesNet + adminComm - buyerSpent - priorWithdrawals) * 100) / 100;
  const currentWallet = Math.round((parseFloat(user.walletBalance) || 0) * 100) / 100;

  return {
    solvent: currentWallet <= maxAllowedBalance + 0.05,
    maxAllowedBalance,
    currentWallet
  };
}

// Request a manual USD payout (bank transfer, PayPal, Fragment, etc. — processed by the admin)
app.post('/api/wallet/withdraw', ensureAuthenticated, requireFreshIfAdmin, async (req, res) => {
  if (isDemoUser(req.user)) {
    return res.status(403).json({ success: false, error: 'Demo accounts cannot withdraw real funds.' });
  }

  const rawAmount = parseFloat(req.body.amount);
  const amount = Math.round(rawAmount * 100) / 100;

  if (!Number.isFinite(amount) || amount < 1.00 || amount > 50000.00) {
    return res.status(400).json({ success: false, error: 'Invalid withdrawal amount (min $1.00).' });
  }

  const client = await pool.connect();
  let withId = null;
  let destination = null;
  let userObj = null;

  try {
    await client.query('BEGIN');

    const uRes = await client.query('SELECT * FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
    const user = uRes.rows[0];
    userObj = user;

    if (!user || !user.binanceId) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        success: false,
        error: 'Please save your payout details (IBAN, PayPal email, Fragment username, etc.) before requesting a withdrawal.'
      });
    }

    if (parseFloat(user.walletBalance) < amount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'Insufficient available balance.' });
    }

    const solvency = await verifyRealUserSolvency(client, user);
    if (!solvency.solvent || solvency.maxAllowedBalance + 0.05 < amount) {
      await client.query('ROLLBACK');
      return res.status(403).json({
        success: false,
        error: 'Security check: Withdrawal exceeds verified real-money deposit/escrow ledger balance.'
      });
    }

    await client.query('UPDATE users SET "walletBalance" = "walletBalance" - $1 WHERE id = $2', [amount, user.id]);

    withId = 'wth_' + crypto.randomBytes(8).toString('hex');
    destination = user.binanceId;
    await client.query(`
      INSERT INTO withdrawals (id, "userId", amount, "binanceId", status)
      VALUES ($1, $2, $3, $4, 'PENDING')
    `, [withId, user.id, amount, destination]);

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Withdrawal error:", err.message);
    return res.status(500).json({ success: false, error: 'Unable to process withdrawal request.' });
  } finally {
    client.release();
  }

  (async () => {
    try {
      emailService.notifyWithdrawalRequested({
        user: userObj,
        amount,
        payoutDetails: destination
      });
    } catch (e) {
      console.warn("Error email withdrawal notification:", e.message);
    }

    try {
      const ownerRes = await pool.query('SELECT id FROM users WHERE LOWER(email) = $1 LIMIT 1', [STORE_OWNER_EMAIL]);
      if (ownerRes.rows[0]) {
        io.to(`user_${ownerRes.rows[0].id}`).emit('user_notification', {
          title: `💸 Payout request ($${amount.toFixed(2)})`,
          body: `${userObj.name || userObj.email} requested a manual payout to: ${destination}`,
          url: '/admin/disputes',
          type: 'withdrawal_request'
        });
      }
    } catch (e) {
      console.warn("Payout admin notification error:", e.message);
    }
  })();

  return res.json({
    success: true,
    message: `Payout request of $${amount.toFixed(2)} submitted. The admin will process it manually to: ${destination}.`
  });
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
      const adminIsDemo = isDemoUser(user);
      const dispRes = await pool.query(`
        SELECT d.*, o.amount, o."serviceId", s.title as "serviceTitle"
        FROM disputes d
        JOIN orders o ON d."orderId" = o.id
        JOIN services s ON o."serviceId" = s.id
        JOIN users b ON o."buyerId" = b.id
        WHERE (NOT $1) OR (b.email LIKE '%.local')
        ORDER BY d."createdAt" DESC
      `, [adminIsDemo]);
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
    console.error("History error:", err.message);
    res.status(500).send("Unable to load history.");
  }
});

// REST AJAX: Create a Telegram Stars wallet top-up invoice
app.post('/api/wallet/topup', ensureAuthenticated, async (req, res) => {
  if (isDemoUser(req.user)) {
    return res.status(403).json({ success: false, error: 'Demo test accounts cannot create real Stars invoices.' });
  }

  const rawAmount = parseFloat(req.body.amount);
  const amount = Math.round(rawAmount * 100) / 100;

  if (!Number.isFinite(amount) || amount < 0.50 || amount > 50000.00) {
    return res.status(400).json({ success: false, error: 'Invalid top-up amount (between $0.50 and $50,000).' });
  }

  if (!telegramStars.isConfigured()) {
    return res.status(503).json({
      success: false,
      error: 'Telegram Stars is not configured on this server yet.'
    });
  }

  const invoiceId = 'inv_' + crypto.randomBytes(8).toString('hex');
  const payload = makeStarsPayload('top');
  const stars = telegramStars.usdToStars(amount);

  try {
    await pool.query(`
      INSERT INTO stars_invoices (id, payload, purpose, "userId", amount, stars, status)
      VALUES ($1, $2, 'WALLET_TOPUP', $3, $4, $5, 'PENDING')
    `, [invoiceId, payload, req.user.id, amount, stars]);
  } catch (err) {
    console.error('Top-up invoice insert error:', err.message);
    return res.status(500).json({ success: false, error: 'Unable to create the top-up invoice.' });
  }

  let invoiceLink;
  try {
    invoiceLink = await telegramStars.createInvoiceLink({
      title: `Wallet top-up $${amount.toFixed(2)}`,
      description: `Add $${amount.toFixed(2)} to your @Melasbit wallet balance.`,
      payload,
      stars
    });
    await pool.query('UPDATE stars_invoices SET "invoiceLink" = $1 WHERE id = $2', [invoiceLink, invoiceId]);
  } catch (err) {
    console.error('Top-up invoice link error:', err.message);
    await pool.query(`UPDATE stars_invoices SET status = 'FAILED' WHERE id = $1`, [invoiceId]);
    return res.status(502).json({ success: false, error: 'Unable to create the Telegram Stars invoice.' });
  }

  return res.json({
    success: true,
    invoiceId,
    invoiceLink,
    amount,
    stars,
    message: `Invoice created: ${stars} Stars for $${amount.toFixed(2)}.`
  });
});

// Poll a Telegram Stars top-up invoice after the user pays
app.get('/api/wallet/topup/:id/status', ensureAuthenticated, async (req, res) => {
  try {
    const invRes = await pool.query(
      `SELECT id, status, amount, stars, "paidAt"
       FROM stars_invoices
       WHERE id = $1 AND "userId" = $2 AND purpose = 'WALLET_TOPUP'`,
      [req.params.id, req.user.id]
    );
    if (!invRes.rows[0]) {
      return res.status(404).json({ success: false, error: 'Top-up invoice not found.' });
    }
    return res.json({ success: true, invoice: invRes.rows[0] });
  } catch (err) {
    console.error('Top-up status error:', err.message);
    return res.status(500).json({ success: false, error: 'Unable to check top-up status.' });
  }
});

// REST AJAX: Save payout details (IBAN, PayPal email, Fragment username, etc.) & Bio
app.post(['/api/wallet/update-payout', '/api/wallet/update-binance'], ensureAuthenticated, requireFreshIfAdmin, async (req, res) => {
  try {
    if (isDemoUser(req.user)) {
      return res.status(403).json({ success: false, error: 'Shared demo accounts cannot modify profile or payout settings.' });
    }
    const rawPayout = req.body.payoutDetails !== undefined ? req.body.payoutDetails : req.body.binanceId;
    const payoutDetails = rawPayout ? String(rawPayout).trim().slice(0, 120) : null;
    const bio = req.body.bio ? String(req.body.bio).trim().slice(0, 1000) : null;
    const skills = req.body.skills ? String(req.body.skills).trim().slice(0, 500) : null;

    if (payoutDetails && !/^[a-zA-Z0-9_@.+\- ]{4,120}$/.test(payoutDetails)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid payout details. Use 4–120 letters, digits, spaces or @ . + - _ characters.'
      });
    }

    // The administrator payout destination is locked in the web app (a stolen session can never redirect funds)
    if (payoutDetails && req.user.role === 'ADMIN' && payoutDetails !== req.user.binanceId) {
      adminAudit(req, 'ADMIN_PAYOUT_CHANGE_BLOCKED', { attempted: payoutDetails });
      return res.status(403).json({
        success: false,
        error: 'The administrator payout details are locked for security. Change them directly on the server.'
      });
    }

    await pool.query(`
      UPDATE users
      SET "binanceId" = COALESCE($1, "binanceId"),
          bio = COALESCE($2, bio),
          skills = COALESCE($3, skills)
      WHERE id = $4
    `, [payoutDetails, bio, skills, req.user.id]);
    res.json({ success: true, payoutDetails });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Unable to update profile settings.' });
  }
});

// ==========================================
// ADMIN ARBITRATION & FINANCIAL APPROVALS
// ==========================================

app.get('/admin/disputes', ensureAuthenticated, async (req, res) => {
  try {
    if (req.user.role !== 'ADMIN') {
      return res.status(403).send("Access restricted to administrators.");
    }

    const adminIsDemo = isDemoUser(req.user);

    const dispRes = await pool.query(`
      SELECT d.*, o.amount, o."serviceId", o."buyerId", o."sellerId", s.title as "serviceTitle",
             b.name as "buyerName", sl.name as "sellerName"
      FROM disputes d
      JOIN orders o ON d."orderId" = o.id
      JOIN services s ON o."serviceId" = s.id
      JOIN users b ON o."buyerId" = b.id
      JOIN users sl ON o."sellerId" = sl.id
      WHERE (NOT $1) OR (b.email LIKE '%.local' AND sl.email LIKE '%.local')
      ORDER BY d."createdAt" DESC
    `, [adminIsDemo]);

    const depRes = await pool.query(`
      SELECT d.*, u.name as "userName", u.email as "userEmail"
      FROM deposits d
      JOIN users u ON d."userId" = u.id
      WHERE (NOT $1) OR (u.email LIKE '%.local')
      ORDER BY (d.status = 'PENDING') DESC, d."createdAt" DESC
      LIMIT 50
    `, [adminIsDemo]);

    const withRes = await pool.query(`
      SELECT w.*, u.name as "userName", u.email as "userEmail"
      FROM withdrawals w
      JOIN users u ON w."userId" = u.id
      WHERE (NOT $1) OR (u.email LIKE '%.local')
      ORDER BY (w.status = 'PENDING') DESC, w."createdAt" DESC
      LIMIT 50
    `, [adminIsDemo]);

    const commRes = await pool.query(`
      SELECT o.*, s.title as "serviceTitle", b.name as "buyerName", sl.name as "sellerName"
      FROM orders o
      JOIN services s ON o."serviceId" = s.id
      JOIN users b ON o."buyerId" = b.id
      JOIN users sl ON o."sellerId" = sl.id
      WHERE o.status = 'COMPLETED'
        AND ((NOT $1 AND b.email NOT LIKE '%.local') OR ($1 AND b.email LIKE '%.local'))
      ORDER BY o."completedAt" DESC NULLS LAST, o."createdAt" DESC
      LIMIT 50
    `, [adminIsDemo]);

    const commissionOrders = formatRows(commRes.rows);
    const totalCommissionEarned = commissionOrders.reduce((acc, o) => acc + (o.platformFee || 0), 0);
    const totalCompletedVolume = commissionOrders.reduce((acc, o) => acc + (o.amount || 0), 0);

    res.render('disputes', {
      disputes: formatRows(dispRes.rows),
      deposits: formatRows(depRes.rows),
      withdrawals: formatRows(withRes.rows),
      commissionOrders,
      totalCommissionEarned,
      totalCompletedVolume
    });
  } catch (err) {
    console.error("Admin center error:", err.message);
    res.status(500).send("Unable to load admin center.");
  }
});

app.post('/disputes/:id/resolve', ensureAuthenticated, requireFreshAdmin, async (req, res) => {
  try {
    if (req.user.role !== 'ADMIN') {
      return res.status(403).send("Unauthorized");
    }

    const { resolution, resolutionNote } = req.body;
    await escrow.resolveDispute(pool, {
      disputeId: req.params.id,
      resolution,
      resolutionNote: String(resolutionNote || '').slice(0, 1000),
      adminUser: req.user
    });

    adminAudit(req, 'DISPUTE_RESOLVED', { disputeId: req.params.id, resolution });
    res.redirect('/admin/disputes');
  } catch (err) {
    res.status(400).send("Resolution error: " + err.message);
  }
});

// Admin: Approve or Reject a Pending Deposit (Stars top-ups are normally auto-credited by the webhook)
app.post('/admin/deposits/:id/decision', ensureAuthenticated, requireFreshAdmin, async (req, res) => {
  if (req.user.role !== 'ADMIN' || isDemoUser(req.user)) {
    return res.status(403).send("Unauthorized: Real Administrator account required.");
  }
  const { action } = req.body;
  if (!['APPROVE', 'REJECT'].includes(action)) {
    return res.status(400).send("Invalid decision action.");
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const depRes = await client.query('SELECT * FROM deposits WHERE id = $1 FOR UPDATE', [req.params.id]);
    const deposit = depRes.rows[0];
    if (!deposit || deposit.status !== 'PENDING') {
      await client.query('ROLLBACK');
      return res.redirect('/admin/disputes');
    }

    await client.query('SELECT pg_advisory_xact_lock(hashtext(LOWER($1)))', [deposit.txId]);

    const uRes = await client.query('SELECT id, email FROM users WHERE id = $1 FOR UPDATE', [deposit.userId]);
    const targetUser = uRes.rows[0];
    if (!targetUser || isDemoUser(targetUser)) {
      await client.query('ROLLBACK');
      return res.status(403).send("Sandbox isolation: Demo accounts cannot receive real deposit credits.");
    }

    let finalDecision = action;

    if (finalDecision === 'APPROVE') {
      // Ensure no other COMPLETED deposit already used this txId
      const dupCheck = await client.query(
        `SELECT id FROM deposits WHERE id != $1 AND LOWER("txId") = LOWER($2) AND status = 'COMPLETED'`,
        [deposit.id, deposit.txId]
      );
      if (dupCheck.rows.length > 0) {
        await client.query('ROLLBACK');
        return res.status(400).send("Duplicate TxID: Another deposit with this transaction ID was already completed.");
      }

      const amount = Math.round(parseFloat(deposit.amount) * 100) / 100;
      await client.query('UPDATE users SET "walletBalance" = "walletBalance" + $1 WHERE id = $2', [amount, deposit.userId]);
      await client.query("UPDATE deposits SET status = 'COMPLETED' WHERE id = $1", [deposit.id]);
    } else if (finalDecision === 'REJECT') {
      await client.query("UPDATE deposits SET status = 'REJECTED' WHERE id = $1", [deposit.id]);
    }

    await client.query('COMMIT');

    io.to(`user_${deposit.userId}`).emit('user_notification', {
      title: finalDecision === 'APPROVE' ? '💰 Deposit Confirmed!' : '⚠️ Deposit Rejected',
      body: finalDecision === 'APPROVE'
        ? `+$${parseFloat(deposit.amount).toFixed(2)} has been credited to your available balance.`
        : `Your deposit request ($${parseFloat(deposit.amount).toFixed(2)}) was rejected.`,
      url: '/dashboard',
      type: 'deposit_decision'
    });

    adminAudit(req, 'DEPOSIT_' + finalDecision, { depositId: deposit.id, userId: deposit.userId, amount: deposit.amount, txId: deposit.txId });
    res.redirect('/admin/disputes');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Admin deposit decision error:", err.message);
    res.status(500).send("Error processing deposit decision.");
  } finally {
    client.release();
  }
});

// Admin: Mark a manual payout as sent, or reject and refund it
app.post('/admin/withdrawals/:id/decision', ensureAuthenticated, requireFreshAdmin, async (req, res) => {
  if (req.user.role !== 'ADMIN' || isDemoUser(req.user)) {
    return res.status(403).send("Unauthorized: Real Administrator account required.");
  }
  const { action } = req.body;
  if (!['APPROVE', 'REJECT'].includes(action)) {
    return res.status(400).send("Invalid decision action.");
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const withRes = await client.query('SELECT * FROM withdrawals WHERE id = $1 FOR UPDATE', [req.params.id]);
    const withdrawal = withRes.rows[0];
    if (!withdrawal || withdrawal.status !== 'PENDING') {
      await client.query('ROLLBACK');
      return res.redirect('/admin/disputes');
    }

    const uRes = await client.query('SELECT * FROM users WHERE id = $1 FOR UPDATE', [withdrawal.userId]);
    const targetUser = uRes.rows[0];
    if (!targetUser || isDemoUser(targetUser)) {
      await client.query('ROLLBACK');
      return res.status(403).send("Sandbox isolation: Demo accounts cannot process real withdrawals.");
    }

    let finalDecision = action;

    if (finalDecision === 'APPROVE') {
      await client.query("UPDATE withdrawals SET status = 'COMPLETED', \"processedAt\" = CURRENT_TIMESTAMP WHERE id = $1", [withdrawal.id]);
    } else if (finalDecision === 'REJECT') {
      const amount = Math.round(parseFloat(withdrawal.amount) * 100) / 100;
      await client.query('UPDATE users SET "walletBalance" = "walletBalance" + $1 WHERE id = $2', [amount, withdrawal.userId]);
      await client.query("UPDATE withdrawals SET status = 'REJECTED', \"processedAt\" = CURRENT_TIMESTAMP WHERE id = $1", [withdrawal.id]);
    }

    await client.query('COMMIT');

    io.to(`user_${withdrawal.userId}`).emit('user_notification', {
      title: finalDecision === 'APPROVE' ? '💸 Payout Sent!' : '↩️ Payout Refunded',
      body: finalDecision === 'APPROVE'
        ? `Your payout of $${parseFloat(withdrawal.amount).toFixed(2)} has been processed.`
        : `Your payout of $${parseFloat(withdrawal.amount).toFixed(2)} was cancelled and refunded to your wallet.`,
      url: '/dashboard',
      type: 'withdrawal_decision'
    });

    adminAudit(req, 'WITHDRAWAL_' + finalDecision, { withdrawalId: withdrawal.id, userId: withdrawal.userId, amount: withdrawal.amount, to: withdrawal.binanceId });
    res.redirect('/admin/disputes');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Admin withdrawal decision error:", err.message);
    res.status(500).send("Error processing withdrawal decision.");
  } finally {
    client.release();
  }
});

// Static assets (ONLY CSS/JS/images if any — /uploads is intercepted above!)
app.use(express.static(path.join(__dirname, '../public'), {
  index: false,
  dotfiles: 'deny'
}));

// Global Error Handler (Multer & Unhandled Route Errors)
app.use((err, req, res, next) => {
  console.error("[Security/Server Error]:", err.message);
  if (req.path.startsWith('/api/')) {
    return res.status(400).json({ success: false, error: err.message || 'Invalid request.' });
  }
  res.status(400).send("Request rejected: " + (err.message || "Invalid request"));
});

// Initialize database and start server bound to HOST (127.0.0.1 by default)
initDatabase().then(() => {
  server.listen(PORT, HOST, async () => {
    console.log(`\n🚀 TrustWork Server running on http://${HOST}:${PORT}`);
    console.log(`🛡️ Security: CSRF, HSTS, Magic-Byte Upload Filter, Protected /uploads Active`);
    console.log(`🐘 Database: PostgreSQL (ACID + Non-Negative Check Constraints Enabled)`);
    console.log(`🔒 Escrow & Telegram Stars payments: Active\n`);

    if (!telegramStars.isConfigured()) {
      console.warn('⭐ Telegram Stars: TELEGRAM_BOT_TOKEN is not set — Stars checkout is disabled.');
      return;
    }

    try {
      const baseUrl = telegramStars.WEBHOOK_URL.replace(/\/$/, '');
      if (baseUrl && telegramStars.WEBHOOK_SECRET) {
        const webhookUrl = `${baseUrl}/telegram/webhook/${telegramStars.WEBHOOK_SECRET}`;
        await telegramStars.setWebhook(webhookUrl, telegramStars.WEBHOOK_SECRET);
        console.log(`⭐ Telegram Stars: webhook registered at ${baseUrl}/telegram/webhook/***`);
      } else {
        console.log('⭐ Telegram Stars: no webhook configured — starting long polling (development mode).');
        await telegramStars.startPolling(handleTelegramUpdate);
      }
    } catch (err) {
      console.error('❌ Telegram Stars setup failed:', err.message);
    }
  });
}).catch(err => {
  console.error("❌ Error starting PostgreSQL / Server:", err);
});
