// src/escrow.js
const crypto = require('crypto');
const emailService = require('./services/email');

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

    const orderRes = await client.query(`
      INSERT INTO orders (id, "serviceId", "buyerId", "sellerId", amount, status, requirements, "fileUrl", "fileName", "deliveryNote", "deliveredAt", "formats", "videoUrl", "attachments")
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb)
      RETURNING *
    `, [
      orderId,
      srv.id,
      buyerUser.id,
      srv.sellerId,
      price,
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
        ? `🎉 Order confirmed! Your method pack "${srv.title}" (PDF, ZIP, Scripts & Video) is ready for instant download. Your ${price.toFixed(2)} USDT are protected in escrow until your validation.`
        : `Order confirmed! An amount of ${price.toFixed(2)} USDT has been charged and secured in escrow.`,
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
 * Buyer approves delivery -> Release escrow funds to author
 */
async function completeOrderAndReleaseFunds(pool, { orderId, buyerId }) {
  const client = await pool.connect();
  let updatedOrder = null;
  let buyerUser = null;
  let sellerUser = null;

  try {
    await client.query('BEGIN');

    const ordRes = await client.query('SELECT * FROM orders WHERE id = $1 FOR UPDATE', [orderId]);
    const order = ordRes.rows[0];
    if (!order) throw new Error("Order not found");
    if (order.buyerId !== buyerId) throw new Error("Only the buyer can approve delivery");
    if (order.status !== "DELIVERED" && order.status !== "ESCROWED") {
      throw new Error(`Cannot complete an order with status ${order.status}`);
    }

    const amount = Math.round(parseFloat(order.amount) * 100) / 100;
    if (!Number.isFinite(amount) || amount <= 0) {
      throw new Error("Invalid order amount");
    }

    // Lock buyer and seller in deterministic order to prevent deadlocks
    const [firstId, secondId] = [order.buyerId, order.sellerId].sort();
    await client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [firstId]);
    await client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [secondId]);

    const bCheck = await client.query('SELECT "escrowBalance" FROM users WHERE id = $1', [order.buyerId]);
    if (!bCheck.rows[0] || parseFloat(bCheck.rows[0].escrowBalance) < amount) {
      throw new Error("Insufficient escrow balance to complete this transaction");
    }

    // 1. Deduct from buyer escrow
    await client.query(`
      UPDATE users 
      SET "escrowBalance" = "escrowBalance" - $1 
      WHERE id = $2
    `, [amount, order.buyerId]);

    // 2. Credit author wallet
    await client.query(`
      UPDATE users 
      SET "walletBalance" = "walletBalance" + $1 
      WHERE id = $2
    `, [amount, order.sellerId]);

    // 3. Mark COMPLETED
    const updatedRes = await client.query(`
      UPDATE orders 
      SET status = 'COMPLETED', 
          "completedAt" = CURRENT_TIMESTAMP 
      WHERE id = $1
      RETURNING *
    `, [orderId]);
    updatedOrder = updatedRes.rows[0];

    const msgId = generateId('msg_');
    await client.query(`
      INSERT INTO messages (id, "orderId", "senderId", content)
      VALUES ($1, $2, $3, $4)
    `, [
      msgId,
      orderId,
      buyerId,
      `✅ Order approved by buyer! The escrow funds (${amount.toFixed(2)} USDT) have been successfully transferred to the author.`
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
    if (ord.status === "COMPLETED" || ord.status === "REFUNDED") {
      throw new Error("Cannot open a dispute on an already completed or refunded order");
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
async function resolveDispute(pool, { disputeId, resolution, resolutionNote }) {
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

    const amount = Math.round(parseFloat(order.amount) * 100) / 100;
    if (!Number.isFinite(amount) || amount <= 0) {
      throw new Error("Invalid order amount");
    }

    if (resolution !== "REFUND_BUYER" && resolution !== "PAY_SELLER") {
      throw new Error("Invalid arbitration resolution");
    }

    const [firstId, secondId] = [order.buyerId, order.sellerId].sort();
    await client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [firstId]);
    await client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [secondId]);

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
      // 2. Pay author
      await client.query(`
        UPDATE users 
        SET "escrowBalance" = "escrowBalance" - $1 
        WHERE id = $2
      `, [amount, order.buyerId]);

      await client.query(`
        UPDATE users 
        SET "walletBalance" = "walletBalance" + $1 
        WHERE id = $2
      `, [amount, order.sellerId]);

      await client.query("UPDATE orders SET status = 'COMPLETED', \"completedAt\" = CURRENT_TIMESTAMP WHERE id = $1", [order.id]);

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
        `⚖️ ARBITRATION COMPLETED: Investigation resolved in favor of the author.\nDecision: ${resolutionNote}\nThe funds (${amount.toFixed(2)} USDT) have been released to the author.`
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
