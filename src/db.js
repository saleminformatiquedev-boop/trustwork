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
        category VARCHAR(64) DEFAULT 'Développement Web & Mobile',
        price NUMERIC(14, 2) NOT NULL,
        "deliveryDays" INTEGER DEFAULT 3,
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
        "Entrepreneur e-commerce à la recherche de prestataires talentueux.",
        "Gestion de projet, Marketing digital"
      ]);

      const sellerId = "usr_seller_demo";
      await client.query(`
        INSERT INTO users (id, email, name, avatar, role, "walletBalance", "escrowBalance", bio, skills, "binanceId")
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      `, [
        sellerId,
        "vendeur@demo.local",
        "Sarah Dev & Design",
        "https://images.unsplash.com/photo-1580489944761-15a19d654956?w=150&auto=format&fit=crop&q=80",
        "USER",
        45.00,
        0.00,
        "Développeuse Full-Stack & UI Designer spécialisée Node.js & Tailwind CSS.",
        "Node.js, PostgreSQL, Tailwind, React, UI/UX",
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

      await client.query(`
        INSERT INTO services (id, "sellerId", title, description, category, price, "deliveryDays")
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [
        "srv_landing_page",
        sellerId,
        "Je vais créer votre Landing Page moderne avec Tailwind CSS",
        "Conception complète d'une page d'atterrissage responsive, rapide et optimisée pour la conversion. Code propre en HTML/Tailwind CSS sous 48h.",
        "Développement Web & Mobile",
        65.00,
        2
      ]);

      await client.query(`
        INSERT INTO services (id, "sellerId", title, description, category, price, "deliveryDays")
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [
        "srv_logo_minimal",
        sellerId,
        "Je vais concevoir un Logo minimaliste et charte graphique",
        "Logo vectoriel haute résolution (SVG, PNG, PDF), 3 propositions initiales, révisions illimitées jusqu'à validation finale.",
        "Design & Graphisme",
        40.00,
        3
      ]);

      console.log("✅ Base de données PostgreSQL initialisée avec succès !");
    }
  } finally {
    client.release();
  }
}

module.exports = { pool, initDatabase };
