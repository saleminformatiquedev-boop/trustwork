// src/escrow.js
const crypto = require('crypto');
const emailService = require('./services/email');

function generateId(prefix = 'ord_') {
  return prefix + crypto.randomBytes(6).toString('hex');
}

/**
 * Créer une commande et bloquer l'argent sous séquestre (Transaction ACID PostgreSQL)
 */
async function createOrderWithEscrow(pool, { buyerId, serviceId, requirements }) {
  const client = await pool.connect();
  let createdOrder = null;
  let srv = null;
  let buyerUser = null;
  let sellerUser = null;

  try {
    await client.query('BEGIN');

    // 1. Verrouiller le service et l'acheteur
    const srvRes = await client.query('SELECT * FROM services WHERE id = $1 FOR UPDATE', [serviceId]);
    srv = srvRes.rows[0];
    if (!srv) throw new Error("Service introuvable");
    if (srv.sellerId === buyerId) throw new Error("Vous ne pouvez pas acheter votre propre service");

    const buyerRes = await client.query('SELECT * FROM users WHERE id = $1 FOR UPDATE', [buyerId]);
    buyerUser = buyerRes.rows[0];
    if (!buyerUser) throw new Error("Acheteur introuvable");

    const sellerRes = await client.query('SELECT * FROM users WHERE id = $1', [srv.sellerId]);
    sellerUser = sellerRes.rows[0];

    const price = parseFloat(srv.price);
    const balance = parseFloat(buyerUser.walletBalance);

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

    // 3. Créer la commande en statut ESCROWED ou DELIVERED si méthode immédiatement disponible
    const orderId = generateId('ord_');
    const isInstantDelivery = !!srv.fileUrl || (srv.attachments && srv.attachments.length > 0);
    const initialStatus = isInstantDelivery ? 'DELIVERED' : 'ESCROWED';
    const deliveryNote = isInstantDelivery ? `Votre pack méthode (${srv.fileName || 'pack-fichiers'}) avec ses ressources (PDF, ZIP, scripts, vidéo) est accessible en téléchargement immédiat.` : null;
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
      requirements || "Achat du pack méthode",
      srv.fileUrl || null,
      srv.fileName || null,
      deliveryNote,
      deliveredAt,
      srv.formats || 'PDF,ZIP,TEXT,VIDEO',
      srv.videoUrl || null,
      attachmentsJson
    ]);
    createdOrder = orderRes.rows[0];

    // 4. Message initial de confirmation
    const msgId = generateId('msg_');
    await client.query(`
      INSERT INTO messages (id, "orderId", "senderId", content, "fileUrl", "fileName")
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [
      msgId,
      orderId,
      buyerUser.id,
      isInstantDelivery 
        ? `🎉 Commande validée ! Votre pack méthode "${srv.title}" (PDF, ZIP, Scripts & Vidéo) est prêt au téléchargement immédiat. Vos ${price.toFixed(2)} USDT sont sécurisés sous séquestre jusqu'à votre validation.`
        : `Commande confirmée ! Un montant de ${price.toFixed(2)} USDT a été prélevé et sécurisé sous séquestre.`,
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

  // Envoi asynchrone des emails (non bloquant pour la transaction)
  if (createdOrder && srv && buyerUser && sellerUser) {
    emailService.notifyNewOrder({
      order: createdOrder,
      service: srv,
      buyer: buyerUser,
      seller: sellerUser
    }).catch(e => console.error("Erreur email notifyNewOrder:", e));
  }

  return createdOrder;
}

/**
 * Le travailleur livre le travail
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
    updatedOrder = updatedRes.rows[0];

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

  // Envoi email notification livraison à l'acheteur
  if (updatedOrder && buyerUser && sellerUser) {
    emailService.notifyOrderDelivered({
      order: updatedOrder,
      buyer: buyerUser,
      seller: sellerUser
    }).catch(e => console.error("Erreur email notifyOrderDelivered:", e));
  }

  return updatedOrder;
}

/**
 * L'acheteur valide la réception -> Déblocage de l'argent vers le travailleur
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
    updatedOrder = updatedRes.rows[0];

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

  // Envoi email gain débloqué au travailleur
  if (updatedOrder && buyerUser && sellerUser) {
    emailService.notifyOrderCompleted({
      order: updatedOrder,
      buyer: buyerUser,
      seller: sellerUser
    }).catch(e => console.error("Erreur email notifyOrderCompleted:", e));
  }

  return updatedOrder;
}

/**
 * Ouvrir un litige / enquête
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
    if (!ord) throw new Error("Commande introuvable");
    if (ord.buyerId !== userId && ord.sellerId !== userId) {
      throw new Error("Seules les parties de la transaction peuvent ouvrir une enquête");
    }
    if (ord.status === "COMPLETED" || ord.status === "REFUNDED") {
      throw new Error("Impossible d'ouvrir un litige sur une commande déjà finalisée");
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
      `⚠️ ENQUÊTE OUVERTE !\nMotif : ${reason}\nDétails : ${details}\n\n🔒 Les fonds restent entièrement bloqués et protégés par la plateforme jusqu'à décision d'arbitrage.`
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

  // Alerte email litige
  if (createdDispute && ord && initiatorUser && otherPartyUser) {
    emailService.notifyDisputeOpened({
      order: ord,
      dispute: createdDispute,
      initiator: initiatorUser,
      otherParty: otherPartyUser
    }).catch(e => console.error("Erreur email notifyDisputeOpened:", e));
  }

  return createdDispute;
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
