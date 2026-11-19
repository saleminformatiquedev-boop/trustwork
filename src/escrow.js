// src/escrow.js
const crypto = require('crypto');
const emailService = require('./services/email');

const PLATFORM_FEE_RATE = 0.15; // 15% Admin commission on all transactions
const VALIDATION_WINDOW_MS = 2 * 24 * 60 * 60 * 1000; // 2 days (48 hours) to validate method

function generateId(prefix = 'ord_') {
  return prefix + crypto.randomBytes(6).toString('hex');
}

/**
 * Create order and lock funds in escrow (PostgreSQL ACID Transaction)
 */
async function createOrderWithEscrow(pool, { buyerId, serviceId, requirements }) {
  const client = await pool.connect();
  let createdOrder = null;
  let srv = null;
  let buyerUser = null;
  let sellerUser = null;

  try {
    await client.query('BEGIN');

    // 1. Lock service and buyer
    const srvRes = await client.query('SELECT * FROM services WHERE id = $1 FOR UPDATE', [serviceId]);
    srv = srvRes.rows[0];
    if (!srv) throw new Error("Service not found");
    if (srv.sellerId === buyerId) throw new Error("You cannot purchase your own guide");

    const buyerRes = await client.query('SELECT * FROM users WHERE id = $1 FOR UPDATE', [buyerId]);
    buyerUser = buyerRes.rows[0];
    if (!buyerUser) throw new Error("Buyer not found");

    const sellerRes = await client.query('SELECT * FROM users WHERE id = $1', [srv.sellerId]);
    sellerUser = sellerRes.rows[0];
    if (!sellerUser) throw new Error("Seller not found");

    const buyerIsDemo = String(buyerUser.email || '').toLowerCase().endsWith('.local');
    const sellerIsDemo = String(sellerUser.email || '').toLowerCase().endsWith('.local');
    if (buyerIsDemo !== sellerIsDemo) {
      throw new Error("Sandbox isolation: Demo test accounts can only transact with other demo test accounts.");
    }

    const price = Math.round(parseFloat(srv.price) * 100) / 100;
    const balance = Math.round(parseFloat(buyerUser.walletBalance) * 100) / 100;

    if (!Number.isFinite(price) || price < 1.00 || price > 50000.00) {
      throw new Error("Invalid service price");
    }

    if (balance < price) {
      throw new Error(`Insufficient balance. You have ${balance.toFixed(2)} USDT and this guide costs ${price.toFixed(2)} USDT`);
    }

    // 2. Move funds from wallet to escrow
    await client.query(`
      UPDATE users 
      SET "walletBalance" = "walletBalance" - $1, 
          "escrowBalance" = "escrowBalance" + $1 
      WHERE id = $2
    `, [price, buyerId]);

    // 3. Create order with ESCROWED or DELIVERED status
    const orderId = generateId('ord_');
    const isInstantDelivery = !!srv.fileUrl || (srv.attachments && srv.attachments.length > 0);
    const initialStatus = isInstantDelivery ? 'DELIVERED' : 'ESCROWED';
    const deliveryNote = isInstantDelivery ? `Your method pack (${srv.fileName || 'file-pack'}) and resources (PDF, ZIP, scripts, video) are available for instant download.` : null;
    const deliveredAt = isInstantDelivery ? new Date() : null;

    const attachmentsJson = srv.attachments ? JSON.stringify(srv.attachments) : '[]';
    const platformFee = Math.round(price * PLATFORM_FEE_RATE * 100) / 100;
    const sellerNetAmount = Math.round((price - platformFee) * 100) / 100;

    const orderRes = await client.query(`
      INSERT INTO orders (id, "serviceId", "buyerId", "sellerId", amount, "platformFee", "sellerNetAmount", status, requirements, "fileUrl", "fileName", "deliveryNote", "deliveredAt", "formats", "videoUrl", "attachments")
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16::jsonb)
      RETURNING *
    `, [
      orderId,
      srv.id,
      buyerUser.id,
      srv.sellerId,
      price,
      platformFee,
      sellerNetAmount,
      initialStatus,
      requirements || "Method pack purchase",
      srv.fileUrl || null,
      srv.fileName || null,
      deliveryNote,
      deliveredAt,
      srv.formats || 'PDF,ZIP,TEXT,VIDEO',
      srv.videoUrl || null,
      attachmentsJson
    ]);
    createdOrder = orderRes.rows[0];

    // 4. Initial confirmation message
    const msgId = generateId('msg_');
    await client.query(`
      INSERT INTO messages (id, "orderId", "senderId", content, "fileUrl", "fileName")
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [
      msgId,
      orderId,
      buyerUser.id,
      isInstantDelivery 
        ? `🎉 Order confirmed! Your method pack "${srv.title}" (PDF, ZIP, Scripts & Video) is ready for instant download. Your ${price.toFixed(2)} USDT are protected in escrow.\n⏱️ Only 2 days (48h) to validate if the method is good or not. After 2 days, the review will be for the Admin.`
        : `Order confirmed! An amount of ${price.toFixed(2)} USDT has been charged and secured in escrow.\n⏱️ Only 2 days (48h) after delivery to validate if the method is good or not. After 2 days, the review will be for the Admin.`,
      srv.fileUrl || null,
      srv.fileName || null
    ]);

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  // Non-blocking email notifications
  if (createdOrder && srv && buyerUser && sellerUser) {
    emailService.notifyNewOrder({
      order: createdOrder,
      service: srv,
      buyer: buyerUser,
      seller: sellerUser
    }).catch(e => console.error("Error email notifyNewOrder:", e));
  }

  return createdOrder;
}

/**
 * The author delivers the order
 */
async function deliverOrder(pool, { orderId, sellerId, deliveryNote }) {
  const client = await pool.connect();
  let updatedOrder = null;
  let buyerUser = null;
  let sellerUser = null;

  try {
    await client.query('BEGIN');

    const ordRes = await client.query('SELECT * FROM orders WHERE id = $1 FOR UPDATE', [orderId]);
    const order = ordRes.rows[0];
    if (!order) throw new Error("Order not found");
    if (order.sellerId !== sellerId) throw new Error("Unauthorized (you are not the author)");
    if (order.status !== "ESCROWED") throw new Error(`Cannot deliver an order with status ${order.status}`);

    const updatedRes = await client.query(`
      UPDATE orders 
      SET status = 'DELIVERED', 
          "deliveryNote" = $1, 
          "deliveredAt" = CURRENT_TIMESTAMP 
      WHERE id = $2
      RETURNING *
    `, [deliveryNote, orderId]);
    updatedOrder = updatedRes.rows[0];

    const msgId = generateId('msg_');
    await client.query(`
      INSERT INTO messages (id, "orderId", "senderId", content)
      VALUES ($1, $2, $3, $4)
    `, [
      msgId,
      orderId,
      sellerId,
      `📦 The author has submitted deliverables!\n\nDelivery note: ${deliveryNote}`
    ]);

    const bRes = await client.query('SELECT * FROM users WHERE id = $1', [order.buyerId]);
    const sRes = await client.query('SELECT * FROM users WHERE id = $1', [order.sellerId]);
    buyerUser = bRes.rows[0];
    sellerUser = sRes.rows[0];

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  if (updatedOrder && buyerUser && sellerUser) {
    emailService.notifyOrderDelivered({
      order: updatedOrder,
      buyer: buyerUser,
      seller: sellerUser
    }).catch(e => console.error("Error email notifyOrderDelivered:", e));
  }

  return updatedOrder;
}

/**
 * Buyer (within 2 days) or Admin approves delivery -> Release escrow funds to author
 */
async function completeOrderAndReleaseFunds(pool, { orderId, buyerId, isAdmin = false, adminUser = null }) {
  const client = await pool.connect();
  let updatedOrder = null;
  let buyerUser = null;
  let sellerUser = null;

  try {
    await client.query('BEGIN');

    const ordRes = await client.query('SELECT * FROM orders WHERE id = $1 FOR UPDATE', [orderId]);
    const order = ordRes.rows[0];
    if (!order) throw new Error("Order not found");
    if (!isAdmin) {
      if (order.buyerId !== buyerId) throw new Error("Only the buyer or Admin can approve delivery");
      const baseTime = new Date(order.deliveredAt || order.createdAt).getTime();
      if (Date.now() - baseTime > VALIDATION_WINDOW_MS) {
        throw new Error("Only 2 days to validate if the method is good or not. After 2 days, the review is for the Admin.");
      }
    }
    if (order.status !== "DELIVERED" && order.status !== "ESCROWED") {
      throw new Error(`Cannot complete an order with status ${order.status}`);
    }

    const amount = Math.round(parseFloat(order.amount) * 100) / 100;
    if (!Number.isFinite(amount) || amount <= 0) {
      throw new Error("Invalid order amount");
    }

    const platformFee = Math.round(amount * PLATFORM_FEE_RATE * 100) / 100;
    const sellerNetAmount = Math.round((amount - platformFee) * 100) / 100;

    // Determine matching Admin wallet (Demo Admin for demo transactions, Real Admin for real transactions)
    const bEmailRes = await client.query('SELECT email FROM users WHERE id = $1', [order.buyerId]);
    const sEmailRes = await client.query('SELECT email FROM users WHERE id = $1', [order.sellerId]);
    const buyerIsDemo = bEmailRes.rows[0] && String(bEmailRes.rows[0].email || '').toLowerCase().endsWith('.local');
    const sellerIsDemo = sEmailRes.rows[0] && String(sEmailRes.rows[0].email || '').toLowerCase().endsWith('.local');
    const isDemoTx = buyerIsDemo && sellerIsDemo;

    if (isAdmin && adminUser && String(adminUser.email || '').toLowerCase().endsWith('.local') && !isDemoTx) {
      throw new Error("Sandbox isolation: Demo Admin cannot approve or release real users' orders.");
    }

    let adminRes = await client.query(
      "SELECT id FROM users WHERE role = 'ADMIN' AND LOWER(email) = 'saleminformatiquedev@gmail.com' LIMIT 1"
    );
    if (adminRes.rows.length === 0) {
      adminRes = await client.query(`
        INSERT INTO users (id, email, name, role, "walletBalance", "escrowBalance", bio)
        VALUES ('usr_real_admin', 'saleminformatiquedev@gmail.com', 'Platform Admin', 'ADMIN', 0.00, 0.00, 'Official TrustWork Platform Administrator')
        ON CONFLICT (email) DO UPDATE SET role = 'ADMIN'
        RETURNING id
      `);
    }
    const adminId = adminRes.rows[0] ? adminRes.rows[0].id : null;

    // Lock all involved user accounts in deterministic order to prevent deadlocks
    const lockIds = Array.from(new Set([order.buyerId, order.sellerId, ...(adminId ? [adminId] : [])])).sort();
    for (const uid of lockIds) {
      await client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [uid]);
    }

    const bCheck = await client.query('SELECT "escrowBalance" FROM users WHERE id = $1', [order.buyerId]);
    if (!bCheck.rows[0] || parseFloat(bCheck.rows[0].escrowBalance) < amount) {
      throw new Error("Insufficient escrow balance to complete this transaction");
    }

    // 1. Deduct 100% from buyer escrow
    await client.query(`
      UPDATE users 
      SET "escrowBalance" = "escrowBalance" - $1 
      WHERE id = $2
    `, [amount, order.buyerId]);

    // 2. Credit 85% net payout to author wallet
    await client.query(`
      UPDATE users 
      SET "walletBalance" = "walletBalance" + $1 
      WHERE id = $2
    `, [sellerNetAmount, order.sellerId]);

    // 3. Credit 15% platform commission to Admin wallet
    if (adminId && platformFee > 0) {
      await client.query(`
        UPDATE users 
        SET "walletBalance" = "walletBalance" + $1 
        WHERE id = $2
      `, [platformFee, adminId]);
    }

    // 4. Mark COMPLETED with exact fee breakdown
    const updatedRes = await client.query(`
      UPDATE orders 
      SET status = 'COMPLETED', 
          "platformFee" = $1,
          "sellerNetAmount" = $2,
          "completedAt" = CURRENT_TIMESTAMP 
      WHERE id = $3
      RETURNING *
    `, [platformFee, sellerNetAmount, orderId]);
    updatedOrder = updatedRes.rows[0];

    const msgId = generateId('msg_');
    await client.query(`
      INSERT INTO messages (id, "orderId", "senderId", content)
      VALUES ($1, $2, $3, $4)
    `, [
      msgId,
      orderId,
      buyerId,
      `✅ Order approved by buyer! ${sellerNetAmount.toFixed(2)} USDT (85% net payout) has been transferred to the author, and ${platformFee.toFixed(2)} USDT (15% platform commission) has been credited to Admin.`
    ]);

    const bRes = await client.query('SELECT * FROM users WHERE id = $1', [order.buyerId]);
    const sRes = await client.query('SELECT * FROM users WHERE id = $1', [order.sellerId]);
    buyerUser = bRes.rows[0];
    sellerUser = sRes.rows[0];

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  if (updatedOrder && buyerUser && sellerUser) {
    emailService.notifyOrderCompleted({
      order: updatedOrder,
      buyer: buyerUser,
      seller: sellerUser
    }).catch(e => console.error("Error email notifyOrderCompleted:", e));
  }

  return updatedOrder;
}

/**
 * Open a dispute / investigation
 */
async function openDispute(pool, { orderId, userId, reason, details }) {
  const client = await pool.connect();
  let createdDispute = null;
  let ord = null;
  let initiatorUser = null;
  let otherPartyUser = null;

  try {
    await client.query('BEGIN');

    const ordRes = await client.query('SELECT * FROM orders WHERE id = $1 FOR UPDATE', [orderId]);
    ord = ordRes.rows[0];
    if (!ord) throw new Error("Order not found");
    if (ord.buyerId !== userId && ord.sellerId !== userId) {
      throw new Error("Only transaction participants can open an investigation");
    }
    if (ord.status === "COMPLETED" || ord.status === "REFUNDED" || ord.status === "DISPUTED") {
      throw new Error("Cannot open a dispute on an already completed, refunded, or disputed order");
    }

    await client.query("UPDATE orders SET status = 'DISPUTED' WHERE id = $1", [orderId]);

    const disputeId = generateId('disp_');
    const dispRes = await client.query(`
      INSERT INTO disputes (id, "orderId", "initiatorId", reason, details, status)
      VALUES ($1, $2, $3, $4, $5, 'OPEN')
      RETURNING *
    `, [disputeId, orderId, userId, reason, details]);
    createdDispute = dispRes.rows[0];

    const msgId = generateId('msg_');
    await client.query(`
      INSERT INTO messages (id, "orderId", "senderId", content)
      VALUES ($1, $2, $3, $4)
    `, [
      msgId,
      orderId,
      userId,
      `⚠️ INVESTIGATION OPENED!\nReason: ${reason}\nDetails: ${details}\n\n🔒 Funds remain fully locked and protected by the platform until an arbitration decision is made.`
    ]);

    const otherPartyId = ord.buyerId === userId ? ord.sellerId : ord.buyerId;
    const initRes = await client.query('SELECT * FROM users WHERE id = $1', [userId]);
    const otherRes = await client.query('SELECT * FROM users WHERE id = $1', [otherPartyId]);
    initiatorUser = initRes.rows[0];
    otherPartyUser = otherRes.rows[0];

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  if (createdDispute && ord && initiatorUser && otherPartyUser) {
    emailService.notifyDisputeOpened({
      order: ord,
      dispute: createdDispute,
      initiator: initiatorUser,
      otherParty: otherPartyUser
    }).catch(e => console.error("Error email notifyDisputeOpened:", e));
  }

  return createdDispute;
}

/**
 * Arbitrate dispute (Refund buyer or Pay seller)
 */
async function resolveDispute(pool, { disputeId, resolution, resolutionNote, adminUser }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const dispRes = await client.query('SELECT * FROM disputes WHERE id = $1 FOR UPDATE', [disputeId]);
    const dispute = dispRes.rows[0];
    if (!dispute) throw new Error("Dispute not found");
    if (dispute.status !== "OPEN") throw new Error("This dispute has already been resolved");

    const ordRes = await client.query('SELECT * FROM orders WHERE id = $1 FOR UPDATE', [dispute.orderId]);
    const order = ordRes.rows[0];
    if (!order) throw new Error("Associated order not found");
    if (order.status === 'COMPLETED' || order.status === 'REFUNDED') {
      throw new Error("Order has already been finalized");
    }

    if (adminUser && String(adminUser.email || '').toLowerCase().endsWith('.local')) {
      const bRes = await client.query('SELECT email FROM users WHERE id = $1', [order.buyerId]);
      const sRes = await client.query('SELECT email FROM users WHERE id = $1', [order.sellerId]);
      const buyerIsDemo = bRes.rows[0] && String(bRes.rows[0].email || '').toLowerCase().endsWith('.local');
      const sellerIsDemo = sRes.rows[0] && String(sRes.rows[0].email || '').toLowerCase().endsWith('.local');
      if (!buyerIsDemo || !sellerIsDemo) {
        throw new Error("Sandbox isolation: Demo Admin can only arbitrate disputes between demo test accounts.");
      }
    }

    const amount = Math.round(parseFloat(order.amount) * 100) / 100;
    if (!Number.isFinite(amount) || amount <= 0) {
      throw new Error("Invalid order amount");
    }

    if (resolution !== "REFUND_BUYER" && resolution !== "PAY_SELLER") {
      throw new Error("Invalid arbitration resolution");
    }

    const bEmailRes = await client.query('SELECT email FROM users WHERE id = $1', [order.buyerId]);
    const isDemoTx = bEmailRes.rows[0] && String(bEmailRes.rows[0].email || '').toLowerCase().endsWith('.local');
    const adminRes = await client.query(
      isDemoTx
        ? "SELECT id FROM users WHERE role = 'ADMIN' AND email LIKE '%.local' ORDER BY \"createdAt\" ASC LIMIT 1"
        : "SELECT id FROM users WHERE role = 'ADMIN' AND email NOT LIKE '%.local' ORDER BY \"createdAt\" ASC LIMIT 1"
    );
    const targetAdminId = adminRes.rows[0] ? adminRes.rows[0].id : null;

    const lockIds = Array.from(new Set([order.buyerId, order.sellerId, ...(targetAdminId ? [targetAdminId] : [])])).sort();
    for (const uid of lockIds) {
      await client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [uid]);
    }

    const bCheck = await client.query('SELECT "escrowBalance" FROM users WHERE id = $1', [order.buyerId]);
    if (!bCheck.rows[0] || parseFloat(bCheck.rows[0].escrowBalance) < amount) {
      throw new Error("Insufficient escrow balance on buyer account");
    }

    if (resolution === "REFUND_BUYER") {
      // 1. Refund buyer
      await client.query(`
        UPDATE users 
        SET "walletBalance" = "walletBalance" + $1, 
            "escrowBalance" = "escrowBalance" - $1 
        WHERE id = $2
      `, [amount, order.buyerId]);

      await client.query("UPDATE orders SET status = 'REFUNDED' WHERE id = $1", [order.id]);

      await client.query(`
        UPDATE disputes 
        SET status = 'RESOLVED_REFUNDED', 
            "resolutionNote" = $1, 
            "resolvedAt" = CURRENT_TIMESTAMP 
        WHERE id = $2
      `, [resolutionNote, disputeId]);

      const msgId = generateId('msg_');
      await client.query(`
        INSERT INTO messages (id, "orderId", "senderId", content)
        VALUES ($1, $2, $3, $4)
      `, [
        msgId,
        order.id,
        order.buyerId,
        `⚖️ ARBITRATION COMPLETED: Investigation resolved in favor of the buyer.\nDecision: ${resolutionNote}\nThe full amount of ${amount.toFixed(2)} USDT has been refunded to the buyer's wallet.`
      ]);
    } else if (resolution === "PAY_SELLER") {
      const platformFee = Math.round(amount * PLATFORM_FEE_RATE * 100) / 100;
      const sellerNetAmount = Math.round((amount - platformFee) * 100) / 100;

      // 1. Deduct 100% from buyer escrow
      await client.query(`
        UPDATE users 
        SET "escrowBalance" = "escrowBalance" - $1 
        WHERE id = $2
      `, [amount, order.buyerId]);

      // 2. Pay 85% net to author
      await client.query(`
        UPDATE users 
        SET "walletBalance" = "walletBalance" + $1 
        WHERE id = $2
      `, [sellerNetAmount, order.sellerId]);

      // 3. Pay 15% commission to Admin
      if (targetAdminId && platformFee > 0) {
        await client.query(`
          UPDATE users 
          SET "walletBalance" = "walletBalance" + $1 
          WHERE id = $2
        `, [platformFee, targetAdminId]);
      }

      await client.query(`
        UPDATE orders 
        SET status = 'COMPLETED', 
            "platformFee" = $1,
            "sellerNetAmount" = $2,
            "completedAt" = CURRENT_TIMESTAMP 
        WHERE id = $3
      `, [platformFee, sellerNetAmount, order.id]);

      await client.query(`
        UPDATE disputes 
        SET status = 'RESOLVED_PAID', 
            "resolutionNote" = $1, 
            "resolvedAt" = CURRENT_TIMESTAMP 
        WHERE id = $2
      `, [resolutionNote, disputeId]);

      const msgId = generateId('msg_');
      await client.query(`
        INSERT INTO messages (id, "orderId", "senderId", content)
        VALUES ($1, $2, $3, $4)
      `, [
        msgId,
        order.id,
        order.sellerId,
        `⚖️ ARBITRATION COMPLETED: Investigation resolved in favor of the author.\nDecision: ${resolutionNote}\n${sellerNetAmount.toFixed(2)} USDT (85% net) has been released to the author, and ${platformFee.toFixed(2)} USDT (15% platform fee) has been credited to Admin.`
      ]);
    }

    await client.query('COMMIT');
    return true;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = {
  createOrderWithEscrow,
  deliverOrder,
  completeOrderAndReleaseFunds,
  openDispute,
  resolveDispute
};
