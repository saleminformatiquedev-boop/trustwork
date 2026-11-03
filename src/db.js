// src/db.js
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://trustwork_user:TrustworkPass2026!@localhost:5432/trustwork',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

async function initDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(64) PRIMARY KEY,
        "googleId" VARCHAR(128) UNIQUE,
        email VARCHAR(255) UNIQUE NOT NULL,
        name VARCHAR(255) NOT NULL,
        avatar TEXT,
        bio TEXT,
        skills TEXT,
        role VARCHAR(32) DEFAULT 'USER',
        "walletBalance" NUMERIC(14, 2) DEFAULT 100.00,
        "escrowBalance" NUMERIC(14, 2) DEFAULT 0.00,
        "binanceId" VARCHAR(128),
        "binanceQr" TEXT,
        "cryptoAddress" VARCHAR(128),
        "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS services (
        id VARCHAR(64) PRIMARY KEY,
        "sellerId" VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        category VARCHAR(64) DEFAULT 'Méthodologie de Développement',
        price NUMERIC(14, 2) NOT NULL,
        "deliveryDays" INTEGER DEFAULT 1,
        "fileUrl" TEXT,
        "fileName" TEXT,
        "fileSize" TEXT,
        "pageCount" INTEGER DEFAULT 50,
        "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS orders (
        id VARCHAR(64) PRIMARY KEY,
        "serviceId" VARCHAR(64) NOT NULL REFERENCES services(id),
        "buyerId" VARCHAR(64) NOT NULL REFERENCES users(id),
        "sellerId" VARCHAR(64) NOT NULL REFERENCES users(id),
        amount NUMERIC(14, 2) NOT NULL,
        status VARCHAR(32) DEFAULT 'ESCROWED',
        requirements TEXT,
        "fileUrl" TEXT,
        "fileName" TEXT,
        "deliveryNote" TEXT,
        "deliveredAt" TIMESTAMP WITH TIME ZONE,
        "completedAt" TIMESTAMP WITH TIME ZONE,
        "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS disputes (
        id VARCHAR(64) PRIMARY KEY,
        "orderId" VARCHAR(64) UNIQUE NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
        "initiatorId" VARCHAR(64) NOT NULL REFERENCES users(id),
        reason VARCHAR(255) NOT NULL,
        details TEXT NOT NULL,
        status VARCHAR(32) DEFAULT 'OPEN',
        "resolutionNote" TEXT,
        "resolvedAt" TIMESTAMP WITH TIME ZONE,
        "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS messages (
        id VARCHAR(64) PRIMARY KEY,
        "orderId" VARCHAR(64) NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
        "senderId" VARCHAR(64) NOT NULL REFERENCES users(id),
        content TEXT NOT NULL,
        "fileUrl" TEXT,
        "fileName" TEXT,
        "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS reviews (
        id VARCHAR(64) PRIMARY KEY,
        "orderId" VARCHAR(64) UNIQUE NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
        "serviceId" VARCHAR(64) NOT NULL REFERENCES services(id) ON DELETE CASCADE,
        "buyerId" VARCHAR(64) NOT NULL REFERENCES users(id),
        "sellerId" VARCHAR(64) NOT NULL REFERENCES users(id),
        rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
        comment TEXT,
        "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS withdrawals (
        id VARCHAR(64) PRIMARY KEY,
        "userId" VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        amount NUMERIC(14, 2) NOT NULL,
        "binanceId" VARCHAR(128) NOT NULL,
        status VARCHAR(32) DEFAULT 'PENDING',
        "processedAt" TIMESTAMP WITH TIME ZONE,
        "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Migrations idempotentes pour le support des Méthodes PDF
    await client.query(`
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "fileUrl" TEXT;
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "fileName" TEXT;
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "fileSize" TEXT;
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "pageCount" INTEGER DEFAULT 25;
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "difficulty" VARCHAR(32) DEFAULT 'Intermédiaire';
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS "fileUrl" TEXT;
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS "fileName" TEXT;
    `);

    // Données de test initiales si la base est vide
    const res = await client.query('SELECT count(*) as total FROM users');
    if (parseInt(res.rows[0].total, 10) === 0) {
      console.log("🌱 Initialisation des données de démo dans PostgreSQL...");

      const buyerId = "usr_buyer_demo";
      await client.query(`
        INSERT INTO users (id, email, name, avatar, role, "walletBalance", "escrowBalance", bio, skills)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      `, [
        buyerId,
        "acheteur@demo.local",
        "Thomas Bernard (Acheteur)",
        "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80",
        "USER",
        250.00,
        0.00,
        "Développeur & créateur de projets à la recherche de méthodes fiables pour accomplir ses tâches.",
        "Gestion de projet, JavaScript, Python"
      ]);

      const sellerId = "usr_seller_demo";
      await client.query(`
        INSERT INTO users (id, email, name, avatar, role, "walletBalance", "escrowBalance", bio, skills, "binanceId")
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      `, [
        sellerId,
        "vendeur@demo.local",
        "Sarah Méthodes Dev",
        "https://images.unsplash.com/photo-1580489944761-15a19d654956?w=150&auto=format&fit=crop&q=80",
        "USER",
        45.00,
        0.00,
        "Architecte logicielle & Auteure de guides méthodologiques pas à pas.",
        "DevOps, Architecture, Sécurité, Clean Code",
        "BINANCE-PAY-789456"
      ]);

      const adminId = "usr_admin_demo";
      await client.query(`
        INSERT INTO users (id, email, name, avatar, role, "walletBalance", "escrowBalance")
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [
        adminId,
        "admin@demo.local",
        "Support Arbitrage",
        "https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=150&auto=format&fit=crop&q=80",
        "ADMIN",
        0.00,
        0.00
      ]);

      // Guides & Méthodes PDF orientés "Comment accomplir des tâches"
      await client.query(`
        INSERT INTO services (id, "sellerId", title, description, category, price, "deliveryDays", "fileUrl", "fileName", "fileSize", "pageCount", "difficulty")
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      `, [
        "srv_guide_aws_docker",
        sellerId,
        "Guide PDF : Comment déployer une application Web sur AWS avec Docker & HTTPS",
        "Méthode pas à pas pour accomplir cette tâche de A à Z : création de l'instance EC2, configuration Nginx, SSL Let's Encrypt automatique, Docker Compose, monitoring et gestion des pannes. Avec scripts shell prêts à copier-coller.",
        "Déploiement & Cloud",
        29.00,
        1,
        "/uploads/guide-methode-developpement-ideale.pdf",
        "methode-deploiement-aws-docker.pdf",
        "2.4 Mo",
        42,
        "Intermédiaire"
      ]);

      await client.query(`
        INSERT INTO services (id, "sellerId", title, description, category, price, "deliveryDays", "fileUrl", "fileName", "fileSize", "pageCount", "difficulty")
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      `, [
        "srv_guide_api_rest",
        sellerId,
        "Méthode PDF : Comment concevoir une API REST sécurisée avec JWT & PostgreSQL",
        "Fiche de procédure pratique pour réaliser une API robuste : validation stricte des entrées, hash des mots de passe avec bcrypt, gestion sécurisée des tokens JWT, middleware d'autorisation et transactions ACID protégées contre les doubles dépenses.",
        "Backend & API",
        19.00,
        1,
        "/uploads/guide-methode-developpement-ideale.pdf",
        "methode-api-rest-securisee.pdf",
        "1.8 Mo",
        35,
        "Débutant"
      ]);

      await client.query(`
        INSERT INTO services (id, "sellerId", title, description, category, price, "deliveryDays", "fileUrl", "fileName", "fileSize", "pageCount", "difficulty")
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      `, [
        "srv_guide_cicd_actions",
        sellerId,
        "Playbook PDF : Comment mettre en place une Pipeline CI/CD avec GitHub Actions",
        "Procédure pas à pas pour automatiser vos tests et déploiements : configuration des fichiers YAML, gestion sécurisée des secrets d'infrastructure, exécution des tests unitaires et intégration sans interruption de service.",
        "DevOps & CI/CD",
        39.00,
        1,
        "/uploads/guide-methode-developpement-ideale.pdf",
        "playbook-cicd-github-actions.pdf",
        "3.1 Mo",
        55,
        "Avancé"
      ]);

      console.log("✅ Base de données PostgreSQL initialisée avec succès !");
    } else {
      // S'assurer que les guides de démo existants ont des PDF attachés
      await client.query(`
        UPDATE services 
        SET "fileUrl" = '/uploads/guide-methode-developpement-ideale.pdf',
            "fileName" = 'methode-tache-developpement.pdf',
            "fileSize" = '2.4 Mo',
            "pageCount" = 45,
            "difficulty" = 'Intermédiaire'
        WHERE "fileUrl" IS NULL;
      `);
    }
  } finally {
    client.release();
  }
}

module.exports = { pool, initDatabase };
