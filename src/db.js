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
        category VARCHAR(64) DEFAULT 'Development Methodology',
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

      CREATE TABLE IF NOT EXISTS deposits (
        id VARCHAR(64) PRIMARY KEY,
        "userId" VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        amount NUMERIC(14, 2) NOT NULL,
        "binancePayId" VARCHAR(128),
        "txId" VARCHAR(128),
        status VARCHAR(32) DEFAULT 'COMPLETED',
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

    // Initial demo data if table is empty
    const res = await client.query('SELECT count(*) as total FROM users');
    if (parseInt(res.rows[0].total, 10) === 0) {
      console.log("🌱 Initializing demo seed data in PostgreSQL...");

      const buyerId = "usr_buyer_demo";
      await client.query(`
        INSERT INTO users (id, email, name, avatar, role, "walletBalance", "escrowBalance", bio, skills)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      `, [
        buyerId,
        "buyer@demo.local",
        "Thomas Bernard (Buyer)",
        "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80",
        "USER",
        250.00,
        0.00,
        "Developer and project creator looking for reliable methods to accomplish technical tasks.",
        "Project Management, JavaScript, Python"
      ]);

      const sellerId = "usr_seller_demo";
      await client.query(`
        INSERT INTO users (id, email, name, avatar, role, "walletBalance", "escrowBalance", bio, skills, "binanceId")
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      `, [
        sellerId,
        "seller@demo.local",
        "Sarah Dev Methods",
        "https://images.unsplash.com/photo-1580489944761-15a19d654956?w=150&auto=format&fit=crop&q=80",
        "USER",
        45.00,
        0.00,
        "Software Architect and author of step-by-step developer guides.",
        "DevOps, Architecture, Security, Clean Code",
        "BINANCE-PAY-789456"
      ]);

      const adminId = "usr_admin_demo";
      await client.query(`
        INSERT INTO users (id, email, name, avatar, role, "walletBalance", "escrowBalance")
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [
        adminId,
        "admin@demo.local",
        "Arbitration Support",
        "https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=150&auto=format&fit=crop&q=80",
        "ADMIN",
        0.00,
        0.00
      ]);

      // PDF Guides & Methods
      await client.query(`
        INSERT INTO services (id, "sellerId", title, description, category, price, "deliveryDays", "fileUrl", "fileName", "fileSize", "pageCount", "difficulty")
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      `, [
        "srv_guide_aws_docker",
        sellerId,
        "PDF Guide: How to deploy a Web application to AWS with Docker & HTTPS",
        "Step-by-step method to accomplish this task from A to Z: EC2 instance creation, Nginx configuration, automated Let's Encrypt SSL, Docker Compose, monitoring, and failover management. With copy-paste ready shell scripts.",
        "Cloud & Deployment",
        29.00,
        1,
        "/uploads/guide-methode-developpement-ideale.pdf",
        "method-deployment-aws-docker.pdf",
        "2.4 MB",
        42,
        "Intermediate"
      ]);

      await client.query(`
        INSERT INTO services (id, "sellerId", title, description, category, price, "deliveryDays", "fileUrl", "fileName", "fileSize", "pageCount", "difficulty")
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      `, [
        "srv_guide_api_rest",
        sellerId,
        "PDF Method: How to design a secure REST API with JWT & PostgreSQL",
        "Practical procedure sheet to build a robust API: strict input validation, password hashing with bcrypt, secure JWT token management, authorization middleware, and ACID transactions protected against double-spending.",
        "Backend & API",
        19.00,
        1,
        "/uploads/guide-methode-developpement-ideale.pdf",
        "method-api-rest-secure.pdf",
        "1.8 MB",
        35,
        "Beginner"
      ]);

      await client.query(`
        INSERT INTO services (id, "sellerId", title, description, category, price, "deliveryDays", "fileUrl", "fileName", "fileSize", "pageCount", "difficulty")
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      `, [
        "srv_guide_cicd_actions",
        sellerId,
        "PDF Playbook: How to build a CI/CD Pipeline with GitHub Actions",
        "Step-by-step playbook to automate your tests and deployments: YAML configuration, secure infrastructure secrets management, automated unit test runs, and zero-downtime deployment.",
        "DevOps & CI/CD",
        39.00,
        1,
        "/uploads/guide-methode-developpement-ideale.pdf",
        "playbook-cicd-github-actions.pdf",
        "3.1 MB",
        55,
        "Advanced"
      ]);

      console.log("✅ PostgreSQL database successfully initialized!");
    } else {
      // Ensure existing records have English translations and files attached
      await client.query(`
        UPDATE users
        SET bio = 'Developer and project creator looking for reliable methods to accomplish technical tasks.',
            skills = 'Project Management, JavaScript, Python',
            name = 'Thomas Bernard (Buyer)'
        WHERE id = 'usr_buyer_demo';

        UPDATE users
        SET bio = 'Software Architect and author of step-by-step developer guides.',
            skills = 'DevOps, Architecture, Security, Clean Code',
            name = 'Sarah Dev Methods'
        WHERE id = 'usr_seller_demo';

        UPDATE users
        SET name = 'Arbitration Support'
        WHERE id = 'usr_admin_demo';

        UPDATE services
        SET title = 'PDF Guide: How to deploy a Web application to AWS with Docker & HTTPS',
            description = 'Step-by-step method to accomplish this task from A to Z: EC2 instance creation, Nginx configuration, automated Let''s Encrypt SSL, Docker Compose, monitoring, and failover management. With copy-paste ready shell scripts.',
            category = 'Cloud & Deployment',
            difficulty = 'Intermediate'
        WHERE id = 'srv_guide_aws_docker';

        UPDATE services
        SET title = 'PDF Method: How to design a secure REST API with JWT & PostgreSQL',
            description = 'Practical procedure sheet to build a robust API: strict input validation, password hashing with bcrypt, secure JWT token management, authorization middleware, and ACID transactions protected against double-spending.',
            category = 'Backend & API',
            difficulty = 'Beginner'
        WHERE id = 'srv_guide_api_rest';

        UPDATE services
        SET title = 'PDF Playbook: How to build a CI/CD Pipeline with GitHub Actions',
            description = 'Step-by-step playbook to automate your tests and deployments: YAML configuration, secure infrastructure secrets management, automated unit test runs, and zero-downtime deployment.',
            category = 'DevOps & CI/CD',
            difficulty = 'Advanced'
        WHERE id = 'srv_guide_cicd_actions';

        UPDATE services 
        SET "fileUrl" = COALESCE("fileUrl", '/uploads/guide-methode-developpement-ideale.pdf'),
            "fileName" = COALESCE("fileName", 'developer-task-method.pdf'),
            "fileSize" = COALESCE("fileSize", '2.4 MB'),
            "pageCount" = COALESCE("pageCount", 45),
            "difficulty" = CASE 
              WHEN "difficulty" = 'Intermédiaire' THEN 'Intermediate'
              WHEN "difficulty" = 'Débutant' THEN 'Beginner'
              WHEN "difficulty" = 'Avancé' THEN 'Advanced'
              ELSE COALESCE("difficulty", 'Intermediate')
            END,
            "category" = CASE
              WHEN "category" = 'Déploiement & Cloud' THEN 'Cloud & Deployment'
              WHEN "category" = 'Méthodologie de Développement' THEN 'Development Methodology'
              WHEN "category" = 'Sécurité & Blockchain' THEN 'Security & Blockchain'
              WHEN "category" = 'Architecture Logicielle' THEN 'Software Architecture'
              WHEN "category" = 'Design & Graphisme' THEN 'Software Architecture'
              WHEN "category" = 'Développement Web & Mobile' THEN 'Backend & API'
              ELSE "category"
            END;

        UPDATE services
        SET title = 'PDF Guide: How to deploy a Web application to AWS with Docker & HTTPS',
            description = 'Step-by-step method to accomplish this task from A to Z: EC2 instance creation, Nginx configuration, automated Let''s Encrypt SSL, Docker Compose, monitoring, and failover management. With copy-paste ready shell scripts.',
            category = 'Cloud & Deployment'
        WHERE id = 'srv_logo_minimal';

        UPDATE services
        SET title = 'PDF Method: How to design a secure REST API with JWT & PostgreSQL',
            description = 'Practical procedure sheet to build a robust API: strict input validation, password hashing with bcrypt, secure JWT token management, authorization middleware, and ACID transactions protected against double-spending.',
            category = 'Backend & API'
        WHERE id = 'srv_landing_page';

        INSERT INTO services (id, "sellerId", title, description, category, price, "deliveryDays", "fileUrl", "fileName", "fileSize", "pageCount", "difficulty")
        SELECT 'srv_guide_cicd_actions', 'usr_seller_demo',
               'PDF Playbook: How to build a CI/CD Pipeline with GitHub Actions',
               'Step-by-step playbook to automate your tests and deployments: YAML configuration, secure infrastructure secrets management, automated unit test runs, and zero-downtime deployment.',
               'DevOps & CI/CD', 39.00, 1, '/uploads/guide-methode-developpement-ideale.pdf', 'playbook-cicd-github-actions.pdf', '3.1 MB', 55, 'Advanced'
        WHERE EXISTS (SELECT 1 FROM users WHERE id = 'usr_seller_demo')
          AND NOT EXISTS (SELECT 1 FROM services WHERE id = 'srv_guide_cicd_actions');

        UPDATE conversations
        SET subject = 'Questions about the method & files',
            "lastMessageText" = 'Thank you for the clarification!'
        WHERE id = 'conv_buyer_seller';

        UPDATE direct_messages
        SET content = 'Thank you for the clarification!'
        WHERE content LIKE 'Merci pour les%';

        UPDATE messages
        SET content = 'Order confirmed! Your USDT payment is securely locked in escrow and your package files are ready for download.'
        WHERE content LIKE 'Commande confirm%' OR content LIKE '%Commande valid%';

        UPDATE orders
        SET "deliveryNote" = 'Instant access: Your complete method package (PDF Guide, ZIP Source Code, Shell Scripts, and Video Walkthrough) is ready to download above.',
            requirements = 'Instant purchase of method package'
        WHERE "deliveryNote" LIKE '%Accès immédiat%' OR requirements LIKE 'Achat%';
      `);
    }

    // Initialize demo conversations if empty
    const convCountRes = await client.query('SELECT count(*) as total FROM conversations');
    if (parseInt(convCountRes.rows[0].total, 10) === 0) {
      console.log("💬 Initializing demo conversations...");

      const buyerId = "usr_buyer_demo";
      const sellerId = "usr_seller_demo";
      const adminId = "usr_admin_demo";

      const srvCheck = await client.query('SELECT id FROM services LIMIT 1');
      const sampleSrvId = srvCheck.rows.length > 0 ? srvCheck.rows[0].id : null;

      // 1. Direct discussion Buyer <-> Author
      const conv1Id = "conv_buyer_seller";
      await client.query(`
        INSERT INTO conversations (id, type, "serviceId", subject, "lastMessageText", "lastMessageAt")
        VALUES ($1, 'DIRECT', $2, $3, $4, CURRENT_TIMESTAMP - INTERVAL '15 minutes')
      `, [
        conv1Id,
        sampleSrvId,
        "Questions about the method & files",
        "My pleasure! If you have any questions while running the playbook, feel free to ask here."
      ]);

      await client.query(`
        INSERT INTO conversation_participants ("conversationId", "userId", "unreadCount")
        VALUES ($1, $2, 0), ($1, $3, 0)
      `, [conv1Id, buyerId, sellerId]);

      await client.query(`
        INSERT INTO direct_messages (id, "conversationId", "senderId", content, "isRead", "createdAt")
        VALUES 
        ('dmsg_1_1', $1, $2, 'Hello Sarah! I am very interested in your AWS Docker deployment method. Do the provided scripts also handle automatic Let''s Encrypt SSL renewal?', true, CURRENT_TIMESTAMP - INTERVAL '45 minutes'),
        ('dmsg_1_2', $1, $3, 'Hello Thomas! Yes absolutely, everything is automated with Certbot and an Nginx reverse proxy container. A single bash command is all it takes to set up secure SSL.', true, CURRENT_TIMESTAMP - INTERVAL '30 minutes'),
        ('dmsg_1_3', $1, $2, 'Awesome, thank you so much! Placing the order for the guide now.', true, CURRENT_TIMESTAMP - INTERVAL '20 minutes'),
        ('dmsg_1_4', $1, $3, 'My pleasure! If you have any questions while running the playbook, feel free to ask here.', true, CURRENT_TIMESTAMP - INTERVAL '15 minutes')
      `, [conv1Id, buyerId, sellerId]);

      // 2. Support discussion Buyer <-> Admin
      const conv2Id = "conv_buyer_admin";
      await client.query(`
        INSERT INTO conversations (id, type, subject, "lastMessageText", "lastMessageAt")
        VALUES ($1, 'SUPPORT', $2, $3, CURRENT_TIMESTAMP - INTERVAL '1 hour')
      `, [
        conv2Id,
        "Escrow Protection & Top-Up Assistance",
        "Always at your service! Let us know if you need any assistance."
      ]);

      await client.query(`
        INSERT INTO conversation_participants ("conversationId", "userId", "unreadCount")
        VALUES ($1, $2, 0), ($1, $3, 0)
      `, [conv2Id, buyerId, adminId]);

      await client.query(`
        INSERT INTO direct_messages (id, "conversationId", "senderId", content, "isRead", "createdAt")
        VALUES 
        ('dmsg_2_1', $1, $2, 'Hello TrustWork team, I wanted to double-check how the guarantee works if there''s any issue with a guide?', true, CURRENT_TIMESTAMP - INTERVAL '2 hours'),
        ('dmsg_2_2', $1, $3, 'Hello Thomas! Your USDT funds are held securely in escrow. The author is never credited until you approve the deliverable. In case of non-compliance, our arbitration team resolves disputes within 24 hours.', true, CURRENT_TIMESTAMP - INTERVAL '1 hour 30 minutes'),
        ('dmsg_2_3', $1, $2, 'Perfect, that is very clear and reassuring. Thank you for the quick reply!', true, CURRENT_TIMESTAMP - INTERVAL '1 hour 15 minutes'),
        ('dmsg_2_4', $1, $3, 'Always at your service! Let us know if you need any assistance.', true, CURRENT_TIMESTAMP - INTERVAL '1 hour')
      `, [conv2Id, buyerId, adminId]);

      // 3. Discussion Author <-> Admin
      const conv3Id = "conv_seller_admin";
      await client.query(`
        INSERT INTO conversations (id, type, subject, "lastMessageText", "lastMessageAt")
        VALUES ($1, 'DIRECT', $2, $3, CURRENT_TIMESTAMP - INTERVAL '3 hours')
      `, [
        conv3Id,
        "Author Account Verification & Binance Pay Payouts",
        "Exactly, payouts to your Binance Pay ID are processed quickly. Happy selling on TrustWork!"
      ]);

      await client.query(`
        INSERT INTO conversation_participants ("conversationId", "userId", "unreadCount")
        VALUES ($1, $2, 0), ($1, $3, 0)
      `, [conv3Id, sellerId, adminId]);

      await client.query(`
        INSERT INTO direct_messages (id, "conversationId", "senderId", content, "isRead", "createdAt")
        VALUES 
        ('dmsg_3_1', $1, $3, 'Hello Sarah, your author profile has been verified successfully. Your method packages are now live.', true, CURRENT_TIMESTAMP - INTERVAL '4 hours'),
        ('dmsg_3_2', $1, $2, 'Thank you so much! For Binance Pay withdrawals, are USDT payouts processed automatically upon request?', true, CURRENT_TIMESTAMP - INTERVAL '3 hours 30 minutes'),
        ('dmsg_3_3', $1, $3, 'Exactly, payouts to your Binance Pay ID are processed quickly. Happy selling on TrustWork!', true, CURRENT_TIMESTAMP - INTERVAL '3 hours')
      `, [conv3Id, sellerId, adminId]);

      console.log("✅ Demo conversations initialized successfully!");
    }
  } finally {
    client.release();
  }
}

module.exports = { pool, initDatabase };
