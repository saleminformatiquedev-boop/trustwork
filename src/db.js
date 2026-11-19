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

      CREATE TABLE IF NOT EXISTS method_exchanges (
        id VARCHAR(64) PRIMARY KEY,
        "requesterId" VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
        "targetServiceId" VARCHAR(64) REFERENCES services(id) ON DELETE SET NULL,
        "requestType" VARCHAR(32) NOT NULL DEFAULT 'EXCHANGE',
        "offeredMethod" VARCHAR(255),
        quantity VARCHAR(64),
        "contactInfo" VARCHAR(255) NOT NULL,
        message TEXT,
        status VARCHAR(32) DEFAULT 'PENDING',
        "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_conv_participants_user ON conversation_participants("userId");
      CREATE INDEX IF NOT EXISTS idx_direct_messages_conv ON direct_messages("conversationId");
      CREATE INDEX IF NOT EXISTS idx_conversations_lastmsg ON conversations("lastMessageAt" DESC);
      CREATE INDEX IF NOT EXISTS idx_method_exchanges_created ON method_exchanges("createdAt" DESC);

      CREATE TABLE IF NOT EXISTS store_orders (
        id VARCHAR(64) PRIMARY KEY,
        "userId" VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
        "customerContact" VARCHAR(255) NOT NULL,
        items JSONB NOT NULL DEFAULT '[]'::jsonb,
        "totalAmount" NUMERIC(14, 2) NOT NULL CHECK ("totalAmount" > 0),
        "paymentMethod" VARCHAR(32) NOT NULL,
        "txId" VARCHAR(255) NOT NULL,
        note TEXT,
        status VARCHAR(32) DEFAULT 'PENDING',
        "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS exchange_requests (
        id VARCHAR(64) PRIMARY KEY,
        "userId" VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
        "senderName" VARCHAR(255) NOT NULL,
        contact VARCHAR(255) NOT NULL,
        "offeredMethod" TEXT NOT NULL,
        "wantedMethods" TEXT NOT NULL,
        details TEXT,
        status VARCHAR(32) DEFAULT 'NEW',
        "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Migrations for Digital Methods, Supplier Costs, Screen-Share Demos & Exchanges
    await client.query(`
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "fileUrl" TEXT;
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "fileName" TEXT;
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "fileSize" TEXT;
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "pageCount" INTEGER DEFAULT 25;
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "difficulty" VARCHAR(32) DEFAULT 'Intermediate';
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "formats" VARCHAR(255) DEFAULT 'PDF,ZIP,TEXT,VIDEO';
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "videoUrl" TEXT;
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "attachments" JSONB DEFAULT '[]'::jsonb;
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "unitCost" VARCHAR(255);
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "durationLabel" VARCHAR(128);
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "offerType" VARCHAR(64) DEFAULT 'METHOD';
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "screenShareDemo" BOOLEAN DEFAULT TRUE;
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "openToExchange" BOOLEAN DEFAULT TRUE;
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "bulkAvailable" BOOLEAN DEFAULT TRUE;
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "includesScript" BOOLEAN DEFAULT FALSE;
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "supplierHandle" VARCHAR(128) DEFAULT '@Melasbit';
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "whatsappNumber" VARCHAR(64) DEFAULT '+21627076373';
      ALTER TABLE services ADD COLUMN IF NOT EXISTS "telegramBot" VARCHAR(128) DEFAULT '@LicenzioChannel';
      
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

    // Ensure sole store owner saleminformatiquedev@gmail.com exists with ADMIN role
    const ownerRes = await client.query(
      `SELECT id FROM users WHERE LOWER(email) = 'saleminformatiquedev@gmail.com' LIMIT 1`
    );
    let ownerId;
    if (ownerRes.rows.length > 0) {
      ownerId = ownerRes.rows[0].id;
      await client.query(
        `UPDATE users SET role = 'ADMIN' WHERE id = $1`,
        [ownerId]
      );
    } else {
      ownerId = 'usr_owner_melasbit';
      await client.query(`
        INSERT INTO users (id, email, name, avatar, bio, skills, role, "walletBalance", "escrowBalance")
        VALUES (
          $1,
          'saleminformatiquedev@gmail.com',
          '@Melasbit',
          'https://api.dicebear.com/7.x/initials/svg?seed=Melasbit&backgroundColor=0f172a',
          'Owner & direct supplier for digital accounts, working methods & scripts. Channel: @LicenzioChannel',
          'Digital Accounts, Working Methods, Automation Scripts, Bulk Deals, Method Exchange',
          'ADMIN',
          0.00,
          0.00
        )
        ON CONFLICT (email) DO UPDATE SET role = 'ADMIN'
        RETURNING id;
      `, [ownerId]);
    }

    // Seed the official methods sold exclusively by saleminformatiquedev@gmail.com (@Melasbit)
    const coreOffers = [
      {
        id: 'srv_notion_edu_plus_1y',
        title: 'Notion Edu Plus (1 Year)',
        description: `Complete working method for Notion Edu Plus (1 Year).\n\n• Cost: only $0.02 / mail\n• Price: $10\n• Live Screen-Share: I will share my screen and show you how it works!\n• Direct supplier (@Melasbit) — also open to method exchanges & bulk deals.`,
        category: 'Featured',
        price: 10.00,
        difficulty: 'Beginner',
        formats: 'METHOD,SCREEN-SHARE',
        unitCost: 'only $0.02 / mail',
        durationLabel: '1 Year',
        offerType: 'METHOD',
        screenShareDemo: true,
        openToExchange: true,
        bulkAvailable: true
      },
      {
        id: 'srv_adobe_express_6m_script',
        title: 'Adobe Express (6 Months) + Script',
        description: `Complete working method + automation script for Adobe Express (6 Months).\n\n• Cost: $0.02 / mail & $0.07 / link\n• Price: $15\n• Live Screen-Share: I will share my screen and show you how it works!\n• Direct supplier (@Melasbit) — also open to method exchanges & bulk deals.`,
        category: 'Featured',
        price: 15.00,
        difficulty: 'Beginner',
        formats: 'METHOD,SCRIPT,SCREEN-SHARE',
        unitCost: '$0.02 / mail & $0.07 / link',
        durationLabel: '6 Months',
        offerType: 'METHOD',
        screenShareDemo: true,
        openToExchange: true,
        bulkAvailable: true
      },
      {
        id: 'srv_capcut_ready',
        title: 'CapCut — Ready to use',
        description: `CapCut ready to use immediately.\n\n• Status: Ready to use\n• Price: $5\n• Live Screen-Share: I will share my screen and show you how it works!\n• Direct supplier (@Melasbit) — also open to method exchanges & bulk deals.`,
        category: 'Featured',
        price: 5.00,
        difficulty: 'Beginner',
        formats: 'READY-TO-USE,SCREEN-SHARE',
        unitCost: 'Ready to use',
        durationLabel: 'Ready to use',
        offerType: 'READY_ACCOUNT',
        screenShareDemo: true,
        openToExchange: true,
        bulkAvailable: true
      }
    ];

    const officialIds = coreOffers.map(o => o.id);
    // Remove any non-official services that have no legacy orders attached
    await client.query(`
      DELETE FROM services
      WHERE id <> ALL($1::text[])
        AND NOT EXISTS (SELECT 1 FROM orders WHERE "serviceId" = services.id);
    `, [officialIds]);

    for (const offer of coreOffers) {
      await client.query(`
        INSERT INTO services (
          id, "sellerId", title, description, category, price, "deliveryDays",
          "pageCount", difficulty, formats, "attachments",
          "unitCost", "durationLabel", "offerType",
          "screenShareDemo", "openToExchange", "bulkAvailable",
          "supplierHandle", "whatsappNumber", "telegramBot"
        )
        VALUES (
          $1, $2, $3, $4, $5, $6, 1,
          10, $7, $8, $9::jsonb,
          $10, $11, $12,
          $13, $14, $15,
          '@Melasbit', '+21627076373', '@LicenzioChannel'
        )
        ON CONFLICT (id) DO UPDATE SET
          "sellerId" = EXCLUDED."sellerId",
          title = EXCLUDED.title,
          description = EXCLUDED.description,
          category = EXCLUDED.category,
          price = EXCLUDED.price,
          formats = EXCLUDED.formats,
          "unitCost" = EXCLUDED."unitCost",
          "durationLabel" = EXCLUDED."durationLabel",
          "offerType" = EXCLUDED."offerType",
          "screenShareDemo" = EXCLUDED."screenShareDemo",
          "openToExchange" = EXCLUDED."openToExchange",
          "bulkAvailable" = EXCLUDED."bulkAvailable",
          "supplierHandle" = EXCLUDED."supplierHandle",
          "whatsappNumber" = EXCLUDED."whatsappNumber",
          "telegramBot" = EXCLUDED."telegramBot";
      `, [
        offer.id,
        ownerId,
        offer.title,
        offer.description,
        offer.category,
        offer.price,
        offer.difficulty,
        offer.formats,
        defaultAttachments,
        offer.unitCost,
        offer.durationLabel,
        offer.offerType,
        offer.screenShareDemo,
        offer.openToExchange,
        offer.bulkAvailable
      ]);
    }

    console.log("✅ PostgreSQL database schema & single-seller store (saleminformatiquedev@gmail.com) verified.");
  } finally {
    client.release();
  }
}

module.exports = { pool, initDatabase };
