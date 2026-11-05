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

async function findOrCreateGoogleUser(pool, { googleId, email, displayName, avatar }) {
  if (!email) throw new Error("Email non fourni par Google");

  const existingRes = await pool.query(
    'SELECT * FROM users WHERE "googleId" = $1 OR email = $2',
    [googleId, email]
  );
  let user = existingRes.rows[0];

  if (!user) {
    const newId = generateId('usr_');
    const insertRes = await pool.query(`
      INSERT INTO users (id, "googleId", email, name, avatar, "walletBalance", "escrowBalance")
      VALUES ($1, $2, $3, $4, $5, 150.00, 0.00)
      RETURNING *
    `, [newId, googleId, email, displayName || email.split('@')[0], avatar || null]);
    user = insertRes.rows[0];
  } else if (!user.googleId || (avatar && !user.avatar)) {
    const updRes = await pool.query(
      'UPDATE users SET "googleId" = COALESCE("googleId", $1), avatar = COALESCE(avatar, $2) WHERE id = $3 RETURNING *',
      [googleId, avatar || null, user.id]
    );
    user = updRes.rows[0];
  }

  return normalizeUser(user);
}

function setupAuth(app, pool) {
  // Expose Firebase web config to views (from existing project salemsaccounts)
  app.use((req, res, next) => {
    res.locals.firebaseConfig = {
      apiKey: process.env.FIREBASE_API_KEY || "",
      authDomain: process.env.FIREBASE_AUTH_DOMAIN || "salemsaccounts.firebaseapp.com",
      projectId: process.env.FIREBASE_PROJECT_ID || "salemsaccounts",
      appId: process.env.FIREBASE_APP_ID || "1:285875034313:web:a2cbb4b4a44906c43f5518"
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
            const avatar = profile.photos && profile.photos[0] ? profile.photos[0].value : null;
            const user = await findOrCreateGoogleUser(pool, {
              googleId: profile.id,
              email,
              displayName: profile.displayName || "Utilisateur Google",
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

  // Firebase Google Auth Verification Endpoint (uses existing Firebase GoogleAuthProvider config)
  app.post('/auth/firebase-google', async (req, res) => {
    try {
      const { idToken } = req.body || {};
      const apiKey = process.env.FIREBASE_API_KEY;
      if (!idToken || !apiKey) {
        return res.status(400).json({ success: false, error: "Token ou clé Firebase manquante." });
      }

      // Verify idToken directly against Google Identity Toolkit REST API
      const verifyResp = await fetch(
        `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(apiKey)}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ idToken })
        }
      );

      if (!verifyResp.ok) {
        return res.status(401).json({ success: false, error: "Jeton Google invalide ou expiré." });
      }

      const verifyData = await verifyResp.json();
      const fbUser = verifyData.users && verifyData.users[0];
      if (!fbUser || !fbUser.email) {
        return res.status(401).json({ success: false, error: "Impossible de récupérer l'email Google." });
      }

      const user = await findOrCreateGoogleUser(pool, {
        googleId: fbUser.localId,
        email: fbUser.email,
        displayName: fbUser.displayName || fbUser.email.split('@')[0],
        avatar: fbUser.photoUrl || null
      });

      req.login(user, (err) => {
        if (err) {
          return res.status(500).json({ success: false, error: "Erreur d'ouverture de session." });
        }
        return res.json({ success: true, redirectUrl: '/dashboard' });
      });
    } catch (err) {
      console.error("Firebase Google Auth error:", err);
      return res.status(500).json({ success: false, error: "Erreur serveur lors de la connexion Google." });
    }
  });

  // Classic Passport Google OAuth Routes
  app.get('/auth/google', (req, res, next) => {
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
      return res.redirect('/login?msg=Veuillez+utiliser+le+bouton+Google+ou+le+mode+démo+ci-dessous');
    }
    passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
  });

  app.get(
    '/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login?msg=Échec+de+la+connexion+Google' }),
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
      if (!user) return res.status(404).send("Compte démo introuvable.");

      req.login(normalizeUser(user), (err) => {
        if (err) return res.status(500).send("Erreur de session");
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
