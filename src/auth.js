// src/auth.js
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const crypto = require('crypto');

function generateId(prefix = 'usr_') {
  return prefix + crypto.randomBytes(6).toString('hex');
}

function normalizeUser(u) {
  if (!u) return null;
  return {
    ...u,
    walletBalance: parseFloat(u.walletBalance || 0),
    escrowBalance: parseFloat(u.escrowBalance || 0)
  };
}

function setupAuth(app, pool) {
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

  // Google OAuth if configured in .env
  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(
      new GoogleStrategy(
        {
          clientID: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          callbackURL: process.env.GOOGLE_CALLBACK_URL || "/auth/google/callback"
        },
        async (accessToken, refreshToken, profile, done) => {
          try {
            const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
            if (!email) return done(new Error("Email not provided by Google"));

            const existingRes = await pool.query(
              'SELECT * FROM users WHERE "googleId" = $1 OR email = $2',
              [profile.id, email]
            );
            let user = existingRes.rows[0];

            if (!user) {
              const newId = generateId('usr_');
              const avatar = profile.photos && profile.photos[0] ? profile.photos[0].value : null;
              const insertRes = await pool.query(`
                INSERT INTO users (id, "googleId", email, name, avatar, "walletBalance", "escrowBalance")
                VALUES ($1, $2, $3, $4, $5, 150.00, 0.00)
                RETURNING *
              `, [newId, profile.id, email, profile.displayName || "Google User", avatar]);
              user = insertRes.rows[0];
            } else if (!user.googleId) {
              const updRes = await pool.query(
                'UPDATE users SET "googleId" = $1 WHERE id = $2 RETURNING *',
                [profile.id, user.id]
              );
              user = updRes.rows[0];
            }

            return done(null, normalizeUser(user));
          } catch (err) {
            return done(err, null);
          }
        }
      )
    );
  }

  // Google Routes
  app.get('/auth/google', (req, res, next) => {
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
      return res.redirect('/login?msg=Please+configure+Google+keys+in+.env+or+use+1-click+demo+mode+below');
    }
    passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
  });

  app.get(
    '/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login?error=auth_failed' }),
    (req, res) => {
      res.redirect('/dashboard');
    }
  );

  app.get('/logout', (req, res, next) => {
    req.logout((err) => {
      if (err) return next(err);
      if (req.session) {
        req.session.destroy(() => {
          res.clearCookie('connect.sid');
          res.redirect('/');
        });
      } else {
        res.redirect('/');
      }
    });
  });

  // Instant demo switch (can be disabled in production via ENABLE_DEMO_MODE=false)
  app.get('/auth/demo-login/:role', async (req, res) => {
    try {
      if (process.env.ENABLE_DEMO_MODE === 'false') {
        return res.status(403).send("Le mode démo est désactivé sur cet environnement.");
      }

      const role = (req.params.role || '').toLowerCase();
      if (!['buyer', 'seller', 'admin'].includes(role)) {
        return res.status(400).send("Rôle de démonstration invalide.");
      }

      let email = "buyer@demo.local";
      if (role === "seller") email = "seller@demo.local";
      if (role === "admin") email = "admin@demo.local";

      // Also check fallback to old french emails if database was already seeded
      let userRes = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      if (userRes.rows.length === 0) {
        if (role === "buyer") email = "acheteur@demo.local";
        if (role === "seller") email = "vendeur@demo.local";
        if (role === "admin") email = "admin@demo.local";
        userRes = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      }

      const user = userRes.rows[0];
      if (!user) return res.status(404).send("Demo account not found. Please restart the application.");

      req.login(normalizeUser(user), (err) => {
        if (err) return res.status(500).send("Session error");
        res.redirect('/dashboard');
      });
    } catch (e) {
      console.error("Demo login error:", e);
      res.status(500).send("Erreur d'authentification.");
    }
  });
}

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

module.exports = { setupAuth, ensureAuthenticated, normalizeUser };
