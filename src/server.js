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
const {
  setupAuth, ensureAuthenticated, normalizeUser, isDemoModeEnabled, isDemoUser,
  enforceAdminSessionLimit, requireFreshAdmin, requireFreshIfAdmin,
  safeReturnPath, rememberReturnTo
} = require('./auth');
const escrow = require('./escrow');
const emailService = require('./services/email');
const binanceService = require('./services/binance');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Trust local Nginx reverse proxy & hide Express fingerprint
app.set('trust proxy', 1);
app.disable('x-powered-by');

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '127.0.0.1';
const PLATFORM_BINANCE_PAY_ID = binanceService.PLATFORM_BINANCE_PAY_ID;
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
  ['/auth', '/api/wallet', '/orders/create', '/disputes', '/admin'],
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
  name: 'trustwork.sid',
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
  let csrfSeed = parseCookie(req, 'trustwork.csrf');
  if (!csrfSeed || !/^[a-f0-9]{32,64}$/.test(csrfSeed)) {
    csrfSeed = crypto.randomBytes(24).toString('hex');
    const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
    res.setHeader(
      'Set-Cookie',
      `trustwork.csrf=${csrfSeed}; Path=/; HttpOnly; SameSite=Lax${isSecure ? '; Secure' : ''}`
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

// Global injection of user, total users counter, and unread chat counter in EJS views
app.use(async (req, res, next) => {
  res.locals.user = req.user ? normalizeUser(req.user) : null;
  res.locals.unreadChatCount = 0;
  res.locals.totalUsersCount = 0;
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
setupAuth(app, pool);

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

// Homepage: Guides & Methods Catalog
app.get('/', async (req, res) => {
  try {
    const srvRes = await pool.query(`
      SELECT s.id, s."sellerId", s.title, s.description, s.category, s.price,
             s."deliveryDays", s."pageCount", s.difficulty, s.formats, s."createdAt",
             u.name as "sellerName", u.avatar as "sellerAvatar",
             COALESCE(AVG(r.rating), 5.0) as "avgRating",
             COUNT(r.id) as "reviewsCount"
      FROM services s
      JOIN users u ON s."sellerId" = u.id
      LEFT JOIN reviews r ON s.id = r."serviceId"
      GROUP BY s.id, u.name, u.avatar
      ORDER BY s."createdAt" DESC
    `);
    res.render('index', { services: formatRows(srvRes.rows).map(sanitizePublicService) });
  } catch (err) {
    console.error("Homepage error:", err.message);
    res.status(500).send("Unable to load catalog at the moment.");
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

// New Method Form (before /services/:id)
app.get('/services/new', ensureAuthenticated, (req, res) => {
  res.render('new-service');
});

// Detail of a guide/service with reviews (strips private download links before purchase)
app.get('/services/:id', async (req, res) => {
  // Visitors must sign up / sign in first, then land straight back on this exact offer
  if (!req.isAuthenticated()) {
    rememberReturnTo(req, res, req.originalUrl);
    return res.redirect('/login?msg=' + encodeURIComponent(
      'Create your free account or sign in to view this method — you will be taken straight back to it.'
    ) + '&next=' + encodeURIComponent(req.originalUrl));
  }
  try {
    const srvRes = await pool.query(`
      SELECT s.*, u.name as "sellerName", u.avatar as "sellerAvatar", u.bio as "sellerBio", u.skills as "sellerSkills"
      FROM services s
      JOIN users u ON s."sellerId" = u.id
      WHERE s.id = $1
    `, [req.params.id]);

    if (srvRes.rows.length === 0) return res.status(404).send("Guide not found");
    const service = sanitizePublicService(formatRows(srvRes.rows)[0]);

    const reviewsRes = await pool.query(`
      SELECT r.*, u.name as "buyerName", u.avatar as "buyerAvatar"
      FROM reviews r
      JOIN users u ON r."buyerId" = u.id
      WHERE r."serviceId" = $1
      ORDER BY r."createdAt" DESC
    `, [service.id]);

    res.render('service-detail', { service, reviews: reviewsRes.rows });
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

// Publish new multi-format method (PDF, ZIP, Text, Video)
app.post('/services/new', ensureAuthenticated, upload.any(), async (req, res) => {
  try {
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
    const { title, description, category, price, pageCount, difficulty, videoUrl, formats } = req.body;

    const cleanTitle = String(title || '').trim();
    const cleanDesc = String(description || '').trim();
    const numericPrice = Math.round(parseFloat(price) * 100) / 100;

    if (!cleanTitle || cleanTitle.length < 5 || cleanTitle.length > 200) {
      return res.status(400).send("Invalid title (must be between 5 and 200 characters).");
    }
    if (!cleanDesc || cleanDesc.length < 10 || cleanDesc.length > 10000) {
      return res.status(400).send("Invalid description (must be between 10 and 10,000 characters).");
    }
    if (!Number.isFinite(numericPrice) || numericPrice < 1.00 || numericPrice > 50000.00) {
      return res.status(400).send("Invalid price: must be between 1.00 USDT and 50,000.00 USDT.");
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

    const activeFormats = Array.isArray(formats) ? formats.join(',') : (formats || 'PDF,ZIP,TEXT');
    const safePages = Math.min(Math.max(parseInt(pageCount, 10) || 40, 1), 5000);

    await pool.query(`
      INSERT INTO services (id, "sellerId", title, description, category, price, "deliveryDays", "fileUrl", "fileName", "fileSize", "pageCount", "difficulty", "formats", "videoUrl", "attachments")
      VALUES ($1, $2, $3, $4, $5, $6, 1, $7, $8, $9, $10, $11, $12, $13, $14::jsonb)
    `, [
      newId,
      req.user.id,
      cleanTitle,
      cleanDesc,
      category || 'Development Methodology',
      numericPrice,
      primaryFileUrl,
      primaryFileName,
      primaryFileSize,
      safePages,
      difficulty || 'Intermediate',
      activeFormats,
      safeVideoUrl,
      JSON.stringify(attachments)
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
      body: `${req.user.name} purchased your method (${parseFloat(order.amount).toFixed(2)} USDT locked in escrow).`,
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
      body: `Order approved! +${netAmt} USDT (85% net) has been credited to your wallet.`,
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

    const trc20QrDataUrl = await QRCode.toDataURL(binanceService.DEFAULT_USDT_TRC20, {
      width: 320,
      margin: 2,
      errorCorrectionLevel: 'M',
      color: { dark: '#0f172a', light: '#ffffff' }
    });
    const bep20QrDataUrl = await QRCode.toDataURL(binanceService.DEFAULT_USDT_BEP20, {
      width: 320,
      margin: 2,
      errorCorrectionLevel: 'M',
      color: { dark: '#0f172a', light: '#ffffff' }
    });

    res.render('dashboard', {
      user,
      buyerOrders: formatRows(buyerRes.rows),
      sellerOrders: formatRows(sellerRes.rows),
      withdrawals: formatRows(withRes.rows),
      deposits: formatRows(depRes.rows),
      adminCommissionOrders,
      totalAdminCommission,
      platformBinancePayId: PLATFORM_BINANCE_PAY_ID,
      trc20Address: binanceService.DEFAULT_USDT_TRC20,
      bep20Address: binanceService.DEFAULT_USDT_BEP20,
      trc20QrDataUrl,
      bep20QrDataUrl
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

// Request withdrawal via Binance API (On-Chain TRC20/BEP20 or Binance Pay ID)
app.post('/api/wallet/withdraw', ensureAuthenticated, requireFreshIfAdmin, async (req, res) => {
  if (isDemoUser(req.user)) {
    return res.status(403).json({ success: false, error: 'Demo accounts cannot withdraw real USDT.' });
  }

  const rawAmount = parseFloat(req.body.amount);
  const amount = Math.round(rawAmount * 100) / 100;

  if (!Number.isFinite(amount) || amount < 0.10 || amount > 50000.00) {
    return res.status(400).json({ success: false, error: 'Invalid withdrawal amount (min 0.10 USDT).' });
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
      return res.status(400).json({ success: false, error: 'Please save your USDT Address (TRC20 / BEP20) or Binance Pay ID before requesting a withdrawal.' });
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

  // Attempt automatic on-chain payout via Binance API if destination is a TRC20 or BEP20 address
  let autoSent = false;
  try {
    const apiResult = await binanceService.executeUsdtWithdrawal({
      destination,
      amount,
      withdrawalId: withId
    });
    if (apiResult && apiResult.success) {
      autoSent = true;
      await pool.query(
        "UPDATE withdrawals SET status = 'COMPLETED', \"processedAt\" = CURRENT_TIMESTAMP WHERE id = $1",
        [withId]
      );
      io.to(`user_${req.user.id}`).emit('user_notification', {
        title: '💸 USDT Withdrawal Sent!',
        body: `Your withdrawal of ${amount.toFixed(2)} USDT (${apiResult.network}) has been sent automatically via Binance.`,
        url: '/dashboard',
        type: 'withdrawal_decision'
      });
    }
  } catch (apiErr) {
    console.warn("Automatic Binance API withdrawal deferred to Admin:", apiErr.message);
  }

  (async () => {
    try {
      emailService.notifyWithdrawalRequested({
        user: userObj,
        amount,
        binanceId: destination
      });
    } catch (e) {
      console.warn("Error email withdrawal notification:", e.message);
    }
  })();

  return res.json({
    success: true,
    message: autoSent
      ? `✅ Withdrawal of ${amount.toFixed(2)} USDT has been sent automatically to ${destination} via Binance API!`
      : `Withdrawal request of ${amount.toFixed(2)} USDT to ${destination} submitted and queued for processing.`
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

// REST AJAX: Binance Pay ID & On-Chain USDT Wallet QR Code
app.get('/api/wallet/deposit-qr', ensureAuthenticated, async (req, res) => {
  try {
    const rawAmount = parseFloat(req.query.amount) || 50;
    const amount = !Number.isFinite(rawAmount) || rawAmount < 0.5 || rawAmount > 50000 ? 50 : Math.round(rawAmount * 100) / 100;
    const network = String(req.query.network || 'TRC20').toUpperCase() === 'BEP20' ? 'BEP20' : 'TRC20';
    const binancePayId = PLATFORM_BINANCE_PAY_ID;
    const trc20Address = binanceService.DEFAULT_USDT_TRC20;
    const bep20Address = binanceService.DEFAULT_USDT_BEP20;
    const targetAddress = network === 'BEP20' ? bep20Address : trc20Address;

    // Encode the clean USDT wallet address in the QR code so any wallet or Binance scanner reads it without deep-link errors
    const qrCodeDataUrl = await QRCode.toDataURL(targetAddress, {
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
      network,
      address: targetAddress,
      trc20Address,
      bep20Address,
      amount: amount.toFixed(2),
      currency: 'USDT',
      binanceWebPayUrl: 'https://www.binance.com/en/my/wallet/account/payment',
      androidLauncherIntent: 'intent://#Intent;action=android.intent.action.MAIN;category=android.intent.category.LAUNCHER;package=com.binance.dev;S.browser_fallback_url=https%3A%2F%2Fwww.binance.com%2Fen%2Fmy%2Fwallet%2Faccount%2Fpayment;end'
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Unable to generate QR code' });
  }
});

// REST AJAX: Record & Automatically Verify Binance Pay / On-Chain Deposit via Binance API
app.post('/api/wallet/deposit-binance', ensureAuthenticated, async (req, res) => {
  if (isDemoUser(req.user)) {
    return res.status(403).json({ success: false, error: 'Demo test accounts cannot submit real Binance deposits.' });
  }

  const rawAmount = parseFloat(req.body.amount);
  const amount = Math.round(rawAmount * 100) / 100;
  const txId = String(req.body.txId || '').trim();
  const binancePayId = PLATFORM_BINANCE_PAY_ID;

  if (!Number.isFinite(amount) || amount < 0.50 || amount > 50000.00) {
    return res.status(400).json({ success: false, error: 'Invalid top-up amount (between 0.50 and 50,000 USDT).' });
  }

  if (!txId || !/^[a-zA-Z0-9_-]{8,120}$/.test(txId)) {
    return res.status(400).json({ success: false, error: 'Please enter a valid Binance Pay Order ID or Blockchain TxID (8 to 120 characters).' });
  }

  // 1. Check live Binance API (Binance Pay History + On-Chain USDT Deposit History)
  const verification = await binanceService.verifyIncomingDeposit({
    txId,
    expectedAmount: amount
  });

  // If Binance API found a matching TxID that is invalid (e.g. outgoing payment, wrong currency, mismatching amount, or expired), block immediately
  if (
    !verification.verified &&
    verification.reason &&
    (verification.reason.includes('outgoing payment') ||
     verification.reason.includes('instead of USDT') ||
     verification.reason.includes('does not match') ||
     verification.reason.includes('expired or predates'))
  ) {
    return res.status(400).json({ success: false, error: verification.reason });
  }

  const canonicalTxId = verification.canonicalTxId || txId;
  const shouldAutoCredit = Boolean(verification.verified && verification.autoCreditAllowed);
  const creditAmount = verification.verified ? verification.actualAmount : amount;
  const targetStatus = shouldAutoCredit ? 'COMPLETED' : 'PENDING';

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Serialize concurrent submissions of the same txId across ALL users using PostgreSQL transaction-level advisory locks
    const lockKeys = Array.from(new Set([txId.toLowerCase(), canonicalTxId.toLowerCase()])).sort();
    for (const k of lockKeys) {
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [k]);
    }

    // Lock user and check for duplicate txId (case-insensitive)
    await client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
    const existingTx = await client.query(
      'SELECT id FROM deposits WHERE LOWER("txId") = LOWER($1) OR LOWER("txId") = LOWER($2)',
      [txId, canonicalTxId]
    );
    if (existingTx.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'This Transaction ID (TxID) has already been used.' });
    }

    const depId = 'dep_' + crypto.randomBytes(8).toString('hex');
    const depRes = await client.query(`
      INSERT INTO deposits (id, "userId", amount, "binancePayId", "txId", status)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
    `, [depId, req.user.id, creditAmount, binancePayId, canonicalTxId, targetStatus]);

    if (shouldAutoCredit) {
      await client.query(
        'UPDATE users SET "walletBalance" = "walletBalance" + $1 WHERE id = $2',
        [creditAmount, req.user.id]
      );
    }

    await client.query('COMMIT');

    if (shouldAutoCredit) {
      io.to(`user_${req.user.id}`).emit('user_notification', {
        title: '💰 Deposit Verified by Binance API!',
        body: `+${creditAmount.toFixed(2)} USDT has been automatically credited to your wallet.`,
        url: '/dashboard',
        type: 'deposit_decision'
      });
    }

    (async () => {
      try {
        emailService.notifyDepositReceived({
          user: req.user,
          amount: creditAmount,
          txId: canonicalTxId,
          binancePayId
        });
      } catch (e) {
        console.warn("Error email top-up notification:", e.message);
      }
    })();

    return res.json({
      success: true,
      autoCredited: shouldAutoCredit,
      message: shouldAutoCredit
        ? `✅ Verified by Binance API! +${creditAmount.toFixed(2)} USDT has been credited to your balance immediately.`
        : verification.verified
          ? `✅ On-chain deposit of ${creditAmount.toFixed(2)} USDT detected on Binance! Queued for 1-click Admin security confirmation.`
          : `Deposit (${amount.toFixed(2)} USDT, TxID: ${txId}) recorded as PENDING. ${verification.reason}`,
      deposit: depRes.rows[0]
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Deposit submission error:", err.message);
    return res.status(500).json({ success: false, error: 'Unable to submit deposit request.' });
  } finally {
    client.release();
  }
});

// REST AJAX: Update Binance Pay ID / USDT Address & Bio
app.post('/api/wallet/update-binance', ensureAuthenticated, requireFreshIfAdmin, async (req, res) => {
  try {
    if (isDemoUser(req.user)) {
      return res.status(403).json({ success: false, error: 'Shared demo accounts cannot modify profile or payout settings.' });
    }
    const binanceId = req.body.binanceId ? String(req.body.binanceId).trim().slice(0, 100) : null;
    const bio = req.body.bio ? String(req.body.bio).trim().slice(0, 1000) : null;
    const skills = req.body.skills ? String(req.body.skills).trim().slice(0, 500) : null;

    if (binanceId && !/^[a-zA-Z0-9_@.-]{4,100}$/.test(binanceId)) {
      return res.status(400).json({ success: false, error: 'Invalid USDT Address or Binance Pay ID format.' });
    }

    // The administrator payout destination is locked in the web app (a stolen session can never redirect funds)
    if (binanceId && req.user.role === 'ADMIN' && binanceId !== req.user.binanceId) {
      adminAudit(req, 'ADMIN_PAYOUT_CHANGE_BLOCKED', { attempted: binanceId });
      return res.status(403).json({
        success: false,
        error: 'The administrator payout address is locked for security. Change it directly on the server.'
      });
    }

    await pool.query(`
      UPDATE users 
      SET "binanceId" = COALESCE($1, "binanceId"),
          bio = COALESCE($2, bio),
          skills = COALESCE($3, skills)
      WHERE id = $4
    `, [binanceId, bio, skills, req.user.id]);
    res.json({ success: true, binanceId });
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

// Admin: Approve, Auto-Verify via Binance API, or Reject a Pending Deposit
app.post('/admin/deposits/:id/decision', ensureAuthenticated, requireFreshAdmin, async (req, res) => {
  if (req.user.role !== 'ADMIN' || isDemoUser(req.user)) {
    return res.status(403).send("Unauthorized: Real Administrator account required.");
  }
  const { action } = req.body;
  if (!['APPROVE', 'REJECT', 'VERIFY_API'].includes(action)) {
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
    if (action === 'VERIFY_API') {
      const check = await binanceService.verifyIncomingDeposit({
        txId: deposit.txId,
        expectedAmount: deposit.amount
      });
      if (!check.verified) {
        await client.query('ROLLBACK');
        return res.status(400).send("Binance API Verification Failed: " + (check.reason || "Transaction not found."));
      }
      finalDecision = 'APPROVE';
    }

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
        ? `+${parseFloat(deposit.amount).toFixed(2)} USDT has been credited to your available balance.`
        : `Your deposit request (${parseFloat(deposit.amount).toFixed(2)} USDT) was rejected.`,
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

// Admin: Send via Binance API, Mark Approved, or Reject (and refund) a Pending Withdrawal
app.post('/admin/withdrawals/:id/decision', ensureAuthenticated, requireFreshAdmin, async (req, res) => {
  if (req.user.role !== 'ADMIN' || isDemoUser(req.user)) {
    return res.status(403).send("Unauthorized: Real Administrator account required.");
  }
  const { action } = req.body;
  if (!['APPROVE', 'REJECT', 'SEND_API'].includes(action)) {
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
    if (action === 'SEND_API') {
      const solvency = await verifyRealUserSolvency(client, targetUser);
      if (!solvency.solvent) {
        await client.query('ROLLBACK');
        return res.status(403).send("Security Alert: User wallet balance exceeds verified real-money ledger solvency.");
      }

      const apiOut = await binanceService.executeUsdtWithdrawal({
        destination: withdrawal.binanceId,
        amount: withdrawal.amount,
        withdrawalId: withdrawal.id
      });
      if (!apiOut.success) {
        await client.query('ROLLBACK');
        return res.status(400).send("Binance API Withdrawal Error: " + apiOut.error);
      }
      finalDecision = 'APPROVE';
    }

    if (finalDecision === 'APPROVE') {
      await client.query("UPDATE withdrawals SET status = 'COMPLETED', \"processedAt\" = CURRENT_TIMESTAMP WHERE id = $1", [withdrawal.id]);
    } else if (finalDecision === 'REJECT') {
      const amount = Math.round(parseFloat(withdrawal.amount) * 100) / 100;
      await client.query('UPDATE users SET "walletBalance" = "walletBalance" + $1 WHERE id = $2', [amount, withdrawal.userId]);
      await client.query("UPDATE withdrawals SET status = 'REJECTED', \"processedAt\" = CURRENT_TIMESTAMP WHERE id = $1", [withdrawal.id]);
    }

    await client.query('COMMIT');

    io.to(`user_${withdrawal.userId}`).emit('user_notification', {
      title: finalDecision === 'APPROVE' ? '💸 Withdrawal Sent!' : '↩️ Withdrawal Refunded',
      body: finalDecision === 'APPROVE'
        ? `Your withdrawal of ${parseFloat(withdrawal.amount).toFixed(2)} USDT has been processed.`
        : `Your withdrawal of ${parseFloat(withdrawal.amount).toFixed(2)} USDT was cancelled and refunded to your wallet.`,
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
  server.listen(PORT, HOST, () => {
    console.log(`\n🚀 TrustWork Server running on http://${HOST}:${PORT}`);
    console.log(`🛡️ Security: CSRF, HSTS, Magic-Byte Upload Filter, Protected /uploads Active`);
    console.log(`🐘 Database: PostgreSQL (ACID + Non-Negative Check Constraints Enabled)`);
    console.log(`🔒 Escrow & Admin Deposit Verification: Active\n`);
  });
}).catch(err => {
  console.error("❌ Error starting PostgreSQL / Server:", err);
});
