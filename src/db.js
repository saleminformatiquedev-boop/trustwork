// src/db.js
require('dotenv').config();
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.warn("⚠️ DATABASE_URL is not set in environment variables.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
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
        "walletBalance" NUMERIC(14, 2) DEFAULT 0.00 CHECK ("walletBalance" >= 0),
        "escrowBalance" NUMERIC(14, 2) DEFAULT 0.00 CHECK ("escrowBalance" >= 0),
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
        category VARCHAR(64) DEFAULT 'Development Methodology',
        price NUMERIC(14, 2) NOT NULL CHECK (price >= 1.00 AND price <= 50000.00),
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
        amount NUMERIC(14, 2) NOT NULL CHECK (amount > 0),
        "platformFee" NUMERIC(14, 2) DEFAULT 0.00 CHECK ("platformFee" >= 0),
        "sellerNetAmount" NUMERIC(14, 2) DEFAULT 0.00 CHECK ("sellerNetAmount" >= 0),
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
        amount NUMERIC(14, 2) NOT NULL CHECK (amount > 0),
        "binanceId" VARCHAR(128) NOT NULL,
        status VARCHAR(32) DEFAULT 'PENDING',
        "processedAt" TIMESTAMP WITH TIME ZONE,
        "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS deposits (
        id VARCHAR(64) PRIMARY KEY,
        "userId" VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        amount NUMERIC(14, 2) NOT NULL CHECK (amount > 0),
        "binancePayId" VARCHAR(128),
        "txId" VARCHAR(128) UNIQUE,
        status VARCHAR(32) DEFAULT 'PENDING',
        "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS conversations (
        id VARCHAR(64) PRIMARY KEY,
        type VARCHAR(32) DEFAULT 'DIRECT', -- 'DIRECT', 'SUPPORT', 'ORDER'
        "orderId" VARCHAR(64) REFERENCES orders(id) ON DELETE SET NULL,
        "serviceId" VARCHAR(64) REFERENCES services(id) ON DELETE SET NULL,
        subject VARCHAR(255),
        "lastMessageText" TEXT,
        "lastMessageAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS conversation_participants (
        "conversationId" VARCHAR(64) NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
        "userId" VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        "unreadCount" INTEGER DEFAULT 0,
        "lastReadAt" TIMESTAMP WITH TIME ZONE,
        "joinedAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY ("conversationId", "userId")
      );

      CREATE TABLE IF NOT EXISTS direct_messages (
        id VARCHAR(64) PRIMARY KEY,
        "conversationId" VARCHAR(64) NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
        "senderId" VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        content TEXT NOT NULL,
        "fileUrl" TEXT,
        "fileName" TEXT,
        "fileSize" TEXT,
        "fileType" TEXT,
        "isRead" BOOLEAN DEFAULT FALSE,
        "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_conv_participants_user ON conversation_participants("userId");
      CREATE INDEX IF NOT EXISTS idx_direct_messages_conv ON direct_messages("conversationId");
      CREATE INDEX IF NOT EXISTS idx_conversations_lastmsg ON conversations("lastMessageAt" DESC);
    `);

    // Migrations for Multi-format methods (PDF, ZIP, Text, Video)
    await client.query(`
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "fileUrl" TEXT;
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "fileName" TEXT;
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "fileSize" TEXT;
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "pageCount" INTEGER DEFAULT 25;
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "difficulty" VARCHAR(32) DEFAULT 'Intermediate';
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "formats" VARCHAR(255) DEFAULT 'PDF,ZIP,TEXT,VIDEO';
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "videoUrl" TEXT;
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "attachments" JSONB DEFAULT '[]'::jsonb;
      
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS "fileUrl" TEXT;
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS "fileName" TEXT;
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS "formats" VARCHAR(255) DEFAULT 'PDF,ZIP,TEXT,VIDEO';
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS "videoUrl" TEXT;
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS "attachments" JSONB DEFAULT '[]'::jsonb;
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS "platformFee" NUMERIC(14, 2) DEFAULT 0.00;
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS "sellerNetAmount" NUMERIC(14, 2) DEFAULT 0.00;

      UPDATE orders
      SET "platformFee" = ROUND(amount * 0.15, 2),
          "sellerNetAmount" = amount - ROUND(amount * 0.15, 2)
      WHERE "platformFee" IS NULL OR "platformFee" = 0;

      -- Enforce strict financial constraints on existing tables
      UPDATE users SET "walletBalance" = 0 WHERE "walletBalance" < 0;
      UPDATE users SET "escrowBalance" = 0 WHERE "escrowBalance" < 0;
      UPDATE services SET price = 1.00 WHERE price < 1.00;
      ALTER TABLE users ALTER COLUMN "walletBalance" SET DEFAULT 0.00;
      ALTER TABLE deposits ALTER COLUMN status SET DEFAULT 'PENDING';

      DO $$ BEGIN
        ALTER TABLE users ADD CONSTRAINT chk_users_wallet_non_neg CHECK ("walletBalance" >= 0);
      EXCEPTION WHEN duplicate_object THEN NULL; END $$;

      DO $$ BEGIN
        ALTER TABLE users ADD CONSTRAINT chk_users_escrow_non_neg CHECK ("escrowBalance" >= 0);
      EXCEPTION WHEN duplicate_object THEN NULL; END $$;

      DO $$ BEGIN
        ALTER TABLE services ADD CONSTRAINT chk_services_price_bounds CHECK (price >= 1.00 AND price <= 50000.00);
      EXCEPTION WHEN duplicate_object THEN NULL; END $$;

      DO $$ BEGIN
        ALTER TABLE orders ADD CONSTRAINT chk_orders_amount_pos CHECK (amount > 0);
      EXCEPTION WHEN duplicate_object THEN NULL; END $$;

      DO $$ BEGIN
        ALTER TABLE withdrawals ADD CONSTRAINT chk_withdrawals_amount_pos CHECK (amount > 0);
      EXCEPTION WHEN duplicate_object THEN NULL; END $$;

      DO $$ BEGIN
        ALTER TABLE deposits ADD CONSTRAINT chk_deposits_amount_pos CHECK (amount > 0);
      EXCEPTION WHEN duplicate_object THEN NULL; END $$;
    `);

    // Standard multi-file packages
    const defaultAttachments = JSON.stringify([
      { type: "pdf", name: "guide-method-step-by-step.pdf", url: "/uploads/guide-methode-developpement-ideale.pdf", size: "2.4 MB", label: "Complete Guide (PDF)" },
      { type: "zip", name: "source-code-project.zip", url: "/uploads/code-source-template.zip", size: "5.1 MB", label: "Source Code & Ready Files (ZIP)" },
      { type: "text", name: "commands-scripts.txt", url: "/uploads/commandes-scripts.txt", size: "15 KB", label: "Shell Scripts & .env Variables (Text)" },
      { type: "video", name: "video-tutorial.mp4", url: "https://www.youtube.com/watch?v=gAkwW2tuIqE", size: "18 min", label: "Demo Video Walkthrough (Video)" }
    ]);

    await client.query(`
      UPDATE services 
      SET "formats" = COALESCE("formats", 'PDF,ZIP,TEXT,VIDEO'),
          "videoUrl" = COALESCE("videoUrl", 'https://www.youtube.com/watch?v=gAkwW2tuIqE'),
          "attachments" = CASE WHEN "attachments" IS NULL OR "attachments" = '[]'::jsonb THEN $1::jsonb ELSE "attachments" END
    `, [defaultAttachments]);

    // Ensure if saleminformatiquedev@gmail.com already exists, it always has ADMIN role
    await client.query(`
      UPDATE users SET role = 'ADMIN' WHERE LOWER(email) = 'saleminformatiquedev@gmail.com';
    `);

    console.log("✅ PostgreSQL database schema verified (production mode, no demo seed data).");
  } finally {
    client.release();
  }
}

module.exports = { pool, initDatabase };
