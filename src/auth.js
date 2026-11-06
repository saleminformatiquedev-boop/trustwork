// src/auth.js
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const crypto = require('crypto');

function generateId(prefix = 'usr_') {
  return prefix + crypto.randomBytes(8).toString('hex');
}

function isDemoModeEnabled() {
  return process.env.ENABLE_DEMO_MODE !== 'false';
}

function isDemoUser(userOrEmail) {
  if (!userOrEmail) return false;
  const email = typeof userOrEmail === 'string' ? userOrEmail : (userOrEmail.email || '');
  return String(email).toLowerCase().endsWith('.local');
}

function normalizeUser(u) {
  if (!u) return null;
  return {
    ...u,
    walletBalance: parseFloat(u.walletBalance || 0),
    escrowBalance: parseFloat(u.escrowBalance || 0)
  };
}

async function findOrCreateGoogleUser(pool, { googleId, email, displayName, avatar }) {
  if (!email) throw new Error("Email not provided by Google");
  const cleanEmail = String(email).trim().toLowerCase();
  const adminEmail = getAdminEmail();
  const targetRole = cleanEmail === adminEmail ? 'ADMIN' : 'USER';

  const existingRes = await pool.query(
    'SELECT * FROM users WHERE "googleId" = $1 OR LOWER(email) = $2',
    [googleId, cleanEmail]
  );
  let user = existingRes.rows[0];

  if (!user) {
    const newId = generateId('usr_');
    // Real accounts always start with 0.00 USDT balance
    const insertRes = await pool.query(`
      INSERT INTO users (id, "googleId", email, name, avatar, role, "walletBalance", "escrowBalance")
      VALUES ($1, $2, $3, $4, $5, $6, 0.00, 0.00)
      RETURNING *
    `, [newId, googleId, cleanEmail, displayName || cleanEmail.split('@')[0], avatar || null, targetRole]);
    user = insertRes.rows[0];
  } else {
    const updatedRole = cleanEmail === adminEmail ? 'ADMIN' : user.role;
    const updRes = await pool.query(
      'UPDATE users SET "googleId" = COALESCE("googleId", $1), avatar = COALESCE(avatar, $2), role = $3 WHERE id = $4 RETURNING *',
      [googleId, avatar || null, updatedRole, user.id]
    );
    user = updRes.rows[0];
  }

  return normalizeUser(user);
}

function getAdminEmail() {
  return (process.env.ADMIN_EMAIL || process.env.NOTIFICATION_EMAIL || 'saleminformatiquedev@gmail.com').trim().toLowerCase();
}

// ---- "Return to the page I came from" after sign-in (open-redirect safe) ----
const RETURN_COOKIE = 'trustwork.next';

// Only same-site relative paths are ever accepted (never //host, http://, backslashes or control chars)
function safeReturnPath(p) {
  if (typeof p !== 'string') return null;
  const v = p.trim();
  if (!v || v.length > 300) return null;
  if (!v.startsWith('/') || v.startsWith('//') || v.startsWith('/\\')) return null;
  if (/[\\\u0000-\u001f\u007f]/.test(v)) return null;
  if (/^\/(login|logout|auth)(\/|\?|$)/i.test(v)) return null;
  return v;
}

function readCookieValue(req, name) {
  const raw = req.headers.cookie || '';
  const match = raw.split(';').map(c => c.trim()).find(c => c.startsWith(name + '='));
  if (!match) return null;
  try { return decodeURIComponent(match.slice(name.length + 1)); } catch (_) { return null; }
}

function rememberReturnTo(req, res, target) {
  const safe = safeReturnPath(target);
  if (!safe) return;
  res.cookie(RETURN_COOKIE, safe, {
    httpOnly: true,
    sameSite: 'lax',
    secure: Boolean(req.secure || req.headers['x-forwarded-proto'] === 'https'),
    maxAge: 15 * 60 * 1000,
    path: '/'
  });
}

function consumeReturnTo(req, res) {
  const safe = safeReturnPath(readCookieValue(req, RETURN_COOKIE));
  res.clearCookie(RETURN_COOKIE, { path: '/' });
  return safe;
}

// Admin hardening: absolute session lifetime + "fresh login" required for sensitive money actions
const ADMIN_MAX_SESSION_MS = 4 * 60 * 60 * 1000; // real admin sessions last 4h max
const ADMIN_FRESH_LOGIN_MS = 30 * 60 * 1000;     // sensitive admin actions need a Google sign-in within 30 min

function isRealAdmin(user) {
  return Boolean(user && user.role === 'ADMIN' && !isDemoUser(user));
}

function wantsJson(req) {
  return req.path.startsWith('/api/') || req.xhr || (req.headers.accept || '').includes('application/json');
}

function destroySessionAndReply(req, res, message) {
  const done = () => {
    res.clearCookie('trustwork.sid');
    if (wantsJson(req)) {
      return res.status(401).json({ success: false, error: message, reauth: true });
    }
    return res.redirect('/login?msg=' + encodeURIComponent(message));
  };
  req.logout(() => {
    if (req.session) req.session.destroy(done);
    else done();
  });
}

// Global: a real admin session expires after 4h (or if it predates this protection)
function enforceAdminSessionLimit(req, res, next) {
  if (isRealAdmin(req.user)) {
    const at = req.session && req.session.loginAt;
    if (!at || Date.now() - at > ADMIN_MAX_SESSION_MS) {
      return destroySessionAndReply(req, res, 'Admin session expired. Please sign in again with Google.');
    }
  }
  next();
}

// Sensitive routes: optional admin IP allow-list + Google sign-in within the last 30 minutes
function requireFreshAdmin(req, res, next) {
  const u = req.user;
  if (!isRealAdmin(u)) {
    if (wantsJson(req)) return res.status(403).json({ success: false, error: 'Real administrator account required.' });
    return res.status(403).send('Unauthorized: Real Administrator account required.');
  }
  const allowed = (process.env.ADMIN_ALLOWED_IPS || '').split(',').map(s => s.trim()).filter(Boolean);
  if (allowed.length > 0 && !allowed.includes(req.ip)) {
    console.warn('[ADMIN-AUDIT] blocked admin action from non-allow-listed IP', req.ip);
    if (wantsJson(req)) return res.status(403).json({ success: false, error: 'Admin actions are not allowed from this IP address.' });
    return res.status(403).send('Admin actions are not allowed from this IP address.');
  }
  const at = req.session && req.session.loginAt;
  if (!at || Date.now() - at > ADMIN_FRESH_LOGIN_MS) {
    return destroySessionAndReply(req, res, 'For your security, please sign in again with Google to confirm this sensitive admin action.');
  }
  next();
}

// Same fresh-login rule, but only when the caller is the admin (regular users pass through)
function requireFreshIfAdmin(req, res, next) {
  if (req.user && req.user.role === 'ADMIN' && !isDemoUser(req.user)) {
    return requireFreshAdmin(req, res, next);
  }
  next();
}

function loginWithRegeneratedSession(req, user, cb) {
  const prevCsrf = req.session ? req.session.csrfToken : null;
  req.session.regenerate((regenErr) => {
    if (regenErr) return cb(regenErr);
    req.session.csrfToken = prevCsrf || crypto.randomBytes(32).toString('hex');
    req.login(user, (loginErr) => {
      if (loginErr) return cb(loginErr);
      req.session.loginAt = Date.now();
      req.session.save(cb);
    });
  });
}

function setupAuth(app, pool) {
  app.use((req, res, next) => {
    res.locals.demoModeEnabled = isDemoModeEnabled();
    res.locals.firebaseConfig = {
      apiKey: process.env.FIREBASE_API_KEY || "",
      authDomain: process.env.FIREBASE_AUTH_DOMAIN || "trustwork-7126c.firebaseapp.com",
      projectId: process.env.FIREBASE_PROJECT_ID || "trustwork-7126c",
      appId: process.env.FIREBASE_APP_ID || "1:491947716495:web:eea9fe4b920390f5c365fa"
    };
    next();
  });

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const res = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
      done(null, normalizeUser(res.rows[0]) || null);
    } catch (err) {
      done(err, null);
    }
  });

  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(
      new GoogleStrategy(
        {
          clientID: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          callbackURL: process.env.GOOGLE_CALLBACK_URL || "/auth/google/callback",
          state: true
        },
        async (accessToken, refreshToken, profile, done) => {
          try {
            const emailObj = profile.emails && profile.emails[0] ? profile.emails[0] : null;
            const email = emailObj ? emailObj.value : null;
            if (emailObj && emailObj.verified === false) {
              return done(new Error("Unverified Google email address"), null);
            }
            const avatar = profile.photos && profile.photos[0] ? profile.photos[0].value : null;
            const user = await findOrCreateGoogleUser(pool, {
              googleId: profile.id,
              email,
              displayName: profile.displayName || "Google User",
              avatar
            });
            return done(null, user);
          } catch (err) {
            return done(err, null);
          }
        }
      )
    );
  }

  app.post('/auth/firebase-google', async (req, res) => {
    try {
      const { idToken } = req.body || {};
      const apiKey = process.env.FIREBASE_API_KEY;
      if (!idToken || !apiKey) {
        return res.status(400).json({ success: false, error: "Missing token or API key." });
      }

      const verifyResp = await fetch(
        `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(apiKey)}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ idToken })
        }
      );

      if (!verifyResp.ok) {
        return res.status(401).json({ success: false, error: "Invalid or expired Google token." });
      }

      const verifyData = await verifyResp.json();
      const fbUser = verifyData.users && verifyData.users[0];
      if (!fbUser || !fbUser.email || fbUser.emailVerified === false) {
        return res.status(401).json({ success: false, error: "Unable to verify Google email." });
      }

      // The admin identity must come from a genuine Google sign-in (never email/password or any other provider)
      if (String(fbUser.email).trim().toLowerCase() === getAdminEmail()) {
        const viaGoogle = Array.isArray(fbUser.providerUserInfo) &&
          fbUser.providerUserInfo.some(p => p.providerId === 'google.com');
        if (!viaGoogle) {
          console.warn('[ADMIN-AUDIT] rejected admin-email login without Google provider from', req.ip);
          return res.status(401).json({ success: false, error: 'The administrator account must sign in with Google.' });
        }
        console.log('[ADMIN-AUDIT]', JSON.stringify({ ts: new Date().toISOString(), action: 'ADMIN_LOGIN', ip: req.ip, ua: String(req.headers['user-agent'] || '').slice(0, 120) }));
      }

      const user = await findOrCreateGoogleUser(pool, {
        googleId: fbUser.localId,
        email: fbUser.email,
        displayName: fbUser.displayName || fbUser.email.split('@')[0],
        avatar: fbUser.photoUrl || null
      });

      loginWithRegeneratedSession(req, user, (err) => {
        if (err) {
          return res.status(500).json({ success: false, error: "Session error." });
        }
        return res.json({ success: true, redirectUrl: consumeReturnTo(req, res) || '/dashboard' });
      });
    } catch (err) {
      console.error("Firebase Google Auth error:", err);
      return res.status(500).json({ success: false, error: "Server error during Google sign-in." });
    }
  });

  app.get('/auth/google', (req, res, next) => {
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
      return res.redirect('/login?msg=Google+OAuth+is+not+configured');
    }
    passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
  });

  app.get(
    '/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login?msg=Google+sign-in+failed' }),
    (req, res) => {
      req.session.loginAt = Date.now();
      if (isRealAdmin(req.user)) {
        console.log('[ADMIN-AUDIT]', JSON.stringify({ ts: new Date().toISOString(), action: 'ADMIN_LOGIN', ip: req.ip, via: 'oauth' }));
      }
      res.redirect(consumeReturnTo(req, res) || '/dashboard');
    }
  );

  app.get('/logout', (req, res, next) => {
    req.logout((err) => {
      if (err) return next(err);
      if (req.session) {
        req.session.destroy(() => {
          res.clearCookie('trustwork.sid');
          res.clearCookie('connect.sid');
          res.redirect('/');
        });
      } else {
        res.clearCookie('trustwork.sid');
        res.clearCookie('connect.sid');
        res.redirect('/');
      }
    });
  });

  app.get('/auth/demo-login/:role', async (req, res) => {
    try {
      if (!isDemoModeEnabled()) {
        return res.status(403).redirect('/login?msg=Demo+accounts+are+disabled+in+production+for+security');
      }

      const role = (req.params.role || '').toLowerCase();
      if (!['buyer', 'seller', 'admin'].includes(role)) {
        return res.status(400).send("Invalid demo role.");
      }

      let targetId = "usr_buyer_demo";
      let email = "buyer@demo.local";
      if (role === "seller") {
        targetId = "usr_seller_demo";
        email = "seller@demo.local";
      }
      if (role === "admin") {
        targetId = "usr_admin_demo";
        email = "admin@demo.local";
      }

      const userRes = await pool.query('SELECT * FROM users WHERE id = $1 OR email = $2 LIMIT 1', [targetId, email]);
      const user = userRes.rows[0];
      if (!user) return res.status(404).send("Demo account not found.");

      loginWithRegeneratedSession(req, normalizeUser(user), (err) => {
        if (err) return res.status(500).send("Session error");
        res.redirect(consumeReturnTo(req, res) || '/dashboard');
      });
    } catch (e) {
      console.error("Demo login error:", e);
      res.status(500).send("Authentication error.");
    }
  });
}

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }
  // Remember the page the visitor wanted so we send them back right after sign-in
  if (req.method === 'GET') {
    rememberReturnTo(req, res, req.originalUrl);
    const safe = safeReturnPath(req.originalUrl);
    return res.redirect(safe ? '/login?next=' + encodeURIComponent(safe) : '/login');
  }
  res.redirect('/login');
}

module.exports = {
  setupAuth,
  ensureAuthenticated,
  normalizeUser,
  isDemoModeEnabled,
  isDemoUser,
  enforceAdminSessionLimit,
  requireFreshAdmin,
  requireFreshIfAdmin,
  safeReturnPath,
  rememberReturnTo
};
