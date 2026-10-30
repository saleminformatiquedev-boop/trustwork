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

  // Google OAuth si configuré dans .env
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
            if (!email) return done(new Error("Email non fourni par Google"));

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
              `, [newId, profile.id, email, profile.displayName || "Utilisateur Google", avatar]);
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

  // Routes Google
  app.get('/auth/google', (req, res, next) => {
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
      return res.redirect('/login?msg=Veuillez+renseigner+vos+clés+Google+dans+.env+ou+utiliser+le+mode+démo+ci-dessous');
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
      res.redirect('/');
    });
  });

  // Switch démo instantané
  app.get('/auth/demo-login/:role', async (req, res) => {
    try {
      const role = req.params.role.toLowerCase();
      let email = "acheteur@demo.local";
      if (role === "seller") email = "vendeur@demo.local";
      if (role === "admin") email = "admin@demo.local";

      const userRes = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      const user = userRes.rows[0];
      if (!user) return res.status(404).send("Compte de démo non trouvé. Relancez l'application.");

      req.login(normalizeUser(user), (err) => {
        if (err) return res.status(500).send("Erreur de session");
        res.redirect('/dashboard');
      });
    } catch (e) {
      res.status(500).send("Erreur: " + e.message);
    }
  });
}

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

module.exports = { setupAuth, ensureAuthenticated, normalizeUser };
