// src/escrow.js
const crypto = require('crypto');

function generateId(prefix = 'ord_') {
  return prefix + crypto.randomBytes(6).toString('hex');
}

/**
 * Créer une commande et bloquer l'argent sous séquestre (Transaction ACID PostgreSQL)
 */
async function createOrderWithEscrow(pool, { buyerId, serviceId, requirements }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Verrouiller le service et l'acheteur (FOR UPDATE pour éviter toute race condition)
    const srvRes = await client.query('SELECT * FROM services WHERE id = $1 FOR UPDATE', [serviceId]);
    const service = srvRes.rows[0];
    if (!service) throw new Error("Service introuvable");
    if (service.sellerId === buyerId) throw new Error("Vous ne pouvez pas acheter votre propre service");

    const buyerRes = await client.query('SELECT * FROM users WHERE id = $1 FOR UPDATE', [buyerId]);
    const buyer = buyerRes.rows[0];
    if (!buyer) throw new Error("Acheteur introuvable");

    const price = parseFloat(service.price);
    const balance = parseFloat(buyer.walletBalance);

    if (balance < price) {
      throw new Error(`Solde insuffisant. Vous avez ${balance.toFixed(2)} USDT et ce service coûte ${price.toFixed(2)} USDT`);
    }

    // 2. Déplacer l'argent du solde disponible vers le séquestre
    await client.query(`
      UPDATE users 
      SET "walletBalance" = "walletBalance" - $1, 
          "escrowBalance" = "escrowBalance" + $1 
      WHERE id = $2
    `, [price, buyerId]);

    // 3. Créer la commande en statut ESCROWED
    const orderId = generateId('ord_');
    const orderRes = await client.query(`
      INSERT INTO orders (id, "serviceId", "buyerId", "sellerId", amount, status, requirements)
      VALUES ($1, $2, $3, $4, $5, 'ESCROWED', $6)
      RETURNING *
    `, [orderId, service.id, buyer.id, service.sellerId, price, requirements || "Aucune consigne spécifique"]);

    // 4. Message initial de confirmation
    const msgId = generateId('msg_');
    await client.query(`
      INSERT INTO messages (id, "orderId", "senderId", content)
      VALUES ($1, $2, $3, $4)
    `, [
      msgId,
      orderId,
      buyer.id,
      `Commande confirmée ! Un montant de ${price.toFixed(2)} USDT a été prélevé et sécurisé sous séquestre. Le travailleur a été notifié.`
    ]);

    await client.query('COMMIT');
    return orderRes.rows[0];
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Le travailleur livre le travail
 */
async function deliverOrder(pool, { orderId, sellerId, deliveryNote }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const ordRes = await client.query('SELECT * FROM orders WHERE id = $1 FOR UPDATE', [orderId]);
    const order = ordRes.rows[0];
    if (!order) throw new Error("Commande introuvable");
    if (order.sellerId !== sellerId) throw new Error("Non autorisé (vous n'êtes pas le vendeur)");
    if (order.status !== "ESCROWED") throw new Error(`Impossible de livrer une commande au statut ${order.status}`);

    const updatedRes = await client.query(`
      UPDATE orders 
      SET status = 'DELIVERED', 
          "deliveryNote" = $1, 
          "deliveredAt" = CURRENT_TIMESTAMP 
      WHERE id = $2
      RETURNING *
    `, [deliveryNote, orderId]);

    const msgId = generateId('msg_');
    await client.query(`
      INSERT INTO messages (id, "orderId", "senderId", content)
      VALUES ($1, $2, $3, $4)
    `, [
      msgId,
      orderId,
      sellerId,
      `📦 Le vendeur a soumis sa livraison !\n\nNote de livraison : ${deliveryNote}`
    ]);

    await client.query('COMMIT');
    return updatedRes.rows[0];
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * L'acheteur valide la réception -> Déblocage de l'argent vers le travailleur
 */
async function completeOrderAndReleaseFunds(pool, { orderId, buyerId }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const ordRes = await client.query('SELECT * FROM orders WHERE id = $1 FOR UPDATE', [orderId]);
    const order = ordRes.rows[0];
    if (!order) throw new Error("Commande introuvable");
    if (order.buyerId !== buyerId) throw new Error("Seul l'acheteur peut valider la réception du service");
    if (order.status !== "DELIVERED" && order.status !== "ESCROWED") {
      throw new Error(`Impossible de clôturer une commande au statut ${order.status}`);
    }

    const amount = parseFloat(order.amount);

    // 1. Déduire du séquestre de l'acheteur
    await client.query(`
      UPDATE users 
      SET "escrowBalance" = GREATEST(0, "escrowBalance" - $1) 
      WHERE id = $2
    `, [amount, order.buyerId]);

    // 2. Créditer le travailleur
    await client.query(`
      UPDATE users 
      SET "walletBalance" = "walletBalance" + $1 
      WHERE id = $2
    `, [amount, order.sellerId]);

    // 3. Passer la commande à COMPLETED
    const updatedRes = await client.query(`
      UPDATE orders 
      SET status = 'COMPLETED', 
          "completedAt" = CURRENT_TIMESTAMP 
      WHERE id = $1
      RETURNING *
    `, [orderId]);

    const msgId = generateId('msg_');
    await client.query(`
      INSERT INTO messages (id, "orderId", "senderId", content)
      VALUES ($1, $2, $3, $4)
    `, [
      msgId,
      orderId,
      buyerId,
      `✅ Commande validée par l'acheteur ! Les fonds sous séquestre (${amount.toFixed(2)} USDT) ont été transférés avec succès au travailleur.`
    ]);

    await client.query('COMMIT');
    return updatedRes.rows[0];
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Ouvrir un litige / enquête
 */
async function openDispute(pool, { orderId, userId, reason, details }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const ordRes = await client.query('SELECT * FROM orders WHERE id = $1 FOR UPDATE', [orderId]);
    const order = ordRes.rows[0];
    if (!order) throw new Error("Commande introuvable");
    if (order.buyerId !== userId && order.sellerId !== userId) {
      throw new Error("Seules les parties de la transaction peuvent ouvrir une enquête");
    }
    if (order.status === "COMPLETED" || order.status === "REFUNDED") {
      throw new Error("Impossible d'ouvrir un litige sur une commande déjà finalisée");
    }

    await client.query("UPDATE orders SET status = 'DISPUTED' WHERE id = $1", [orderId]);

    const disputeId = generateId('disp_');
    const dispRes = await client.query(`
      INSERT INTO disputes (id, "orderId", "initiatorId", reason, details, status)
      VALUES ($1, $2, $3, $4, $5, 'OPEN')
      RETURNING *
    `, [disputeId, orderId, userId, reason, details]);

    const msgId = generateId('msg_');
    await client.query(`
      INSERT INTO messages (id, "orderId", "senderId", content)
      VALUES ($1, $2, $3, $4)
    `, [
      msgId,
      orderId,
      userId,
      `⚠️ ENQUÊTE OUVERTE !\nMotif : ${reason}\nDétails : ${details}\n\n🔒 Les fonds restent entièrement bloqués et protégés par la plateforme jusqu'à décision d'arbitrage.`
    ]);

    await client.query('COMMIT');
    return dispRes.rows[0];
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Arbitrage du litige (Remboursement Acheteur ou Paiement Vendeur)
 */
async function resolveDispute(pool, { disputeId, resolution, resolutionNote }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const dispRes = await client.query('SELECT * FROM disputes WHERE id = $1 FOR UPDATE', [disputeId]);
    const dispute = dispRes.rows[0];
    if (!dispute) throw new Error("Litige introuvable");
    if (dispute.status !== "OPEN") throw new Error("Ce litige a déjà été traité");

    const ordRes = await client.query('SELECT * FROM orders WHERE id = $1 FOR UPDATE', [dispute.orderId]);
    const order = ordRes.rows[0];
    const amount = parseFloat(order.amount);

    if (resolution === "REFUND_BUYER") {
      // 1. Rembourser l'acheteur
      await client.query(`
        UPDATE users 
        SET "walletBalance" = "walletBalance" + $1, 
            "escrowBalance" = GREATEST(0, "escrowBalance" - $1) 
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
        `⚖️ ARBITRAGE TERMINÉ : Enquête résolue en faveur de l'acheteur.\nDécision : ${resolutionNote}\nL'intégralité des ${amount.toFixed(2)} USDT a été recréditée sur le portefeuille de l'acheteur.`
      ]);
    } else if (resolution === "PAY_SELLER") {
      // 2. Débloquer au travailleur
      await client.query(`
        UPDATE users 
        SET "escrowBalance" = GREATEST(0, "escrowBalance" - $1) 
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
        `⚖️ ARBITRAGE TERMINÉ : Enquête résolue en faveur du travailleur.\nDécision : ${resolutionNote}\nLes fonds (${amount.toFixed(2)} USDT) ont été versés au travailleur.`
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
