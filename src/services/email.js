// src/services/email.js
const nodemailer = require('nodemailer');
require('dotenv').config();

const SMTP_USER = process.env.SMTP_USER || 'saleminformatiquedev@gmail.com';
const SMTP_PASS = process.env.SMTP_PASS || 'zelcssnlnwpluzxv';
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '465', 10);
const SMTP_SECURE = process.env.SMTP_SECURE !== undefined
  ? process.env.SMTP_SECURE === 'true'
  : (SMTP_PORT === 465);

const NOTIFICATION_EMAIL = process.env.NOTIFICATION_EMAIL || 'saleminformatiquedev@gmail.com';

let transporter = null;

function getTransporter() {
  if (!SMTP_PASS) {
    return null;
  }
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_SECURE,
      auth: {
        user: SMTP_USER,
        pass: SMTP_PASS
      },
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 15000
    });
  }
  return transporter;
}

/**
 * Envoie un email stylisé HTML avec fallback texte brut (non-bloquant)
 */
async function sendEmail({ to, subject, html, text }) {
  const client = getTransporter();
  if (!client) {
    console.warn(`[EmailService] ⚠️ SMTP_PASS non configuré. Email vers ${to} non envoyé.`);
    return { success: false, reason: 'SMTP_NOT_CONFIGURED' };
  }

  try {
    const info = await client.sendMail({
      from: `"TrustWork Escrow" <${SMTP_USER}>`,
      to: to || NOTIFICATION_EMAIL,
      subject: subject,
      text: text || '',
      html: html
    });
    console.log(`[EmailService] 📧 Email envoyé à ${to} (${info.messageId}) - Objet : "${subject}"`);
    return { success: true, messageId: info.messageId };
  } catch (err) {
    console.error(`[EmailService] ❌ Erreur lors de l'envoi de l'email vers ${to}:`, err.message);
    return { success: false, error: err.message };
  }
}

/**
 * Modèle HTML élégant pour TrustWork
 */
function getEmailTemplate({ title, badge, content, ctaText, ctaUrl }) {
  return `
  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="utf-8">
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; margin: 0; padding: 20px; color: #1e293b; }
      .container { max-width: 580px; margin: 0 auto; background: #ffffff; border-radius: 16px; overflow: hidden; border: 1px solid #e2e8f0; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); }
      .header { background: linear-gradient(135deg, #059669 0%, #10b981 100%); padding: 32px 24px; text-align: center; color: #ffffff; }
      .logo { font-size: 24px; font-weight: 800; letter-spacing: -0.5px; }
      .body { padding: 32px 28px; line-height: 1.6; }
      .badge { display: inline-block; background-color: #ecfdf5; color: #047857; font-weight: 700; font-size: 11px; padding: 4px 12px; border-radius: 9999px; text-transform: uppercase; margin-bottom: 16px; border: 1px solid #a7f3d0; }
      .title { font-size: 20px; font-weight: 800; margin: 0 0 16px 0; color: #0f172a; }
      .box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px; margin: 20px 0; font-size: 13px; }
      .cta-btn { display: inline-block; background-color: #059669; color: #ffffff !important; font-weight: 700; text-decoration: none; padding: 12px 28px; border-radius: 10px; font-size: 13px; text-align: center; margin: 20px 0; }
      .footer { background: #f8fafc; border-top: 1px solid #e2e8f0; padding: 20px; text-align: center; font-size: 11px; color: #64748b; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <div class="logo">🛡️ TrustWork</div>
        <div style="font-size: 13px; opacity: 0.9; margin-top: 4px;">Système de Séquestre Garanti & Binance Pay</div>
      </div>
      <div class="body">
        ${badge ? `<div class="badge">${badge}</div>` : ''}
        <h2 class="title">${title}</h2>
        <div>${content}</div>
        ${ctaText && ctaUrl ? `<div style="text-align: center;"><a href="${ctaUrl}" class="cta-btn">${ctaText}</a></div>` : ''}
      </div>
      <div class="footer">
        Ceci est une notification automatique de sécurité TrustWork.<br>
        Plateforme d'échange de services avec protection des fonds sous séquestre.
      </div>
    </div>
  </body>
  </html>
  `;
}

// ==========================================
// NOTIFICATIONS ÉVÉNEMENTIELLES
// ==========================================

/**
 * 1. Nouvelle commande créée (Fonds sous séquestre)
 */
async function notifyNewOrder({ order, service, buyer, seller }) {
  const amount = parseFloat(order.amount).toFixed(2);
  const orderUrl = `https://51.20.182.245/orders/${order.id}`;

  // Notification Vendeur
  if (seller && seller.email && !seller.email.endsWith('.local')) {
    sendEmail({
      to: seller.email,
      subject: `🎉 Nouvelle commande reçue (#${order.id}) - ${amount} USDT sous séquestre`,
      html: getEmailTemplate({
        title: `Vous avez reçu une nouvelle commande !`,
        badge: 'Fonds Séquestrés (Garantis)',
        content: `
          Bonjour <strong>${seller.name}</strong>,<br><br>
          L'acheteur <strong>${buyer.name}</strong> vient de passer commande pour votre service :<br>
          <div class="box">
            <strong>Service :</strong> ${service.title}<br>
            <strong>Montant bloqué :</strong> ${amount} USDT<br>
            <strong>Consignes de l'acheteur :</strong> <em>${order.requirements || 'Aucune'}</em>
          </div>
          🔒 <strong>Les ${amount} USDT sont d'ores et déjà bloqués sur la plateforme.</strong> Vous pouvez commencer à travailler en toute sérénité.
        `,
        ctaText: 'Accéder à la commande & Livrer',
        ctaUrl: orderUrl
      })
    });
  }

  // Confirmation Acheteur
  if (buyer && buyer.email && !buyer.email.endsWith('.local')) {
    sendEmail({
      to: buyer.email,
      subject: `🔒 Confirmation de votre commande (#${order.id}) - Fonds sécurisés`,
      html: getEmailTemplate({
        title: `Votre commande est confirmée`,
        badge: 'Séquestre Actif',
        content: `
          Bonjour <strong>${buyer.name}</strong>,<br><br>
          Votre commande a été transmise au travailleur <strong>${seller.name}</strong>.<br>
          <div class="box">
            <strong>Montant sous séquestre :</strong> ${amount} USDT<br>
            <strong>Délai de réalisation :</strong> ${service.deliveryDays} jours ouvrés
          </div>
          Votre argent reste protégé jusqu'à ce que vous validiez personnellement la livraison.
        `,
        ctaText: 'Suivre ma commande en direct',
        ctaUrl: orderUrl
      })
    });
  }

  // Copie d'administration
  sendEmail({
    to: NOTIFICATION_EMAIL,
    subject: `[Admin TrustWork] Nouvelle commande #${order.id} (${amount} USDT)`,
    html: getEmailTemplate({
      title: `Nouvelle commande enregistrée sur la plateforme`,
      badge: 'Admin Alert',
      content: `Acheteur : ${buyer.name} (${buyer.email})<br>Vendeur : ${seller.name} (${seller.email})<br>Montant : ${amount} USDT<br>Service : ${service.title}`,
      ctaText: 'Voir la commande',
      ctaUrl: orderUrl
    })
  });
}

/**
 * 2. Travail livré par le vendeur
 */
async function notifyOrderDelivered({ order, buyer, seller }) {
  const orderUrl = `https://51.20.182.245/orders/${order.id}`;

  if (buyer && buyer.email && !buyer.email.endsWith('.local')) {
    sendEmail({
      to: buyer.email,
      subject: `📦 Votre commande #${order.id} a été livrée !`,
      html: getEmailTemplate({
        title: `Le travailleur a livré votre prestation`,
        badge: 'Livraison à valider',
        content: `
          Bonjour <strong>${buyer.name}</strong>,<br><br>
          <strong>${seller.name}</strong> a terminé la mission et a déposé les livrables.<br>
          <div class="box">
            <strong>Note de livraison :</strong><br>
            ${order.deliveryNote || 'Consultez les fichiers et liens sur le site.'}
          </div>
          Prenez le temps d'examiner le travail. Si tout est parfait, cliquez ci-dessous pour libérer les <strong>${parseFloat(order.amount).toFixed(2)} USDT</strong>.
        `,
        ctaText: 'Vérifier & Valider la livraison',
        ctaUrl: orderUrl
      })
    });
  }
}

/**
 * 3. Commande validée et fonds débloqués
 */
async function notifyOrderCompleted({ order, buyer, seller }) {
  const amount = parseFloat(order.amount).toFixed(2);
  const orderUrl = `https://51.20.182.245/orders/${order.id}`;

  if (seller && seller.email && !seller.email.endsWith('.local')) {
    sendEmail({
      to: seller.email,
      subject: `💰 Paiement libéré ! +${amount} USDT reçus (Commande #${order.id})`,
      html: getEmailTemplate({
        title: `Félicitations ! Vos gains sont disponibles`,
        badge: 'Paiement Effectué',
        content: `
          Bonjour <strong>${seller.name}</strong>,<br><br>
          L'acheteur a validé la commande. Le séquestre de <strong>${amount} USDT</strong> a été libéré et crédité sur votre solde disponible.<br>
          Vous pouvez retirer vos fonds sur votre portefeuille Binance Pay à tout moment.
        `,
        ctaText: 'Voir mon portefeuille',
        ctaUrl: `https://51.20.182.245/dashboard`
      })
    });
  }
}

/**
 * 4. Ouverture d'un litige / enquête
 */
async function notifyDisputeOpened({ order, dispute, initiator, otherParty }) {
  const orderUrl = `https://51.20.182.245/orders/${order.id}`;

  // Notification aux parties
  const emailContent = `
    Un dossier d'enquête (litige) a été ouvert par <strong>${initiator.name}</strong> sur la commande #${order.id}.<br>
    <div class="box">
      <strong>Motif :</strong> ${dispute.reason}<br>
      <strong>Détails :</strong> ${dispute.details}
    </div>
    🔒 <strong>Protection active :</strong> Les fonds restent intégralement gelés sous séquestre jusqu'à décision d'arbitrage.
  `;

  if (otherParty && otherParty.email && !otherParty.email.endsWith('.local')) {
    sendEmail({
      to: otherParty.email,
      subject: `⚠️ Enquête ouverte sur la commande #${order.id}`,
      html: getEmailTemplate({
        title: `Dossier de litige ouvert`,
        badge: 'Fonds Gelés',
        content: emailContent,
        ctaText: 'Participer à l\'échange',
        ctaUrl: orderUrl
      })
    });
  }

  // Alerte Administrateur urgente
  sendEmail({
    to: NOTIFICATION_EMAIL,
    subject: `🚨 [Alerte Litige Admin] Enquête ouverte sur commande #${order.id}`,
    html: getEmailTemplate({
      title: `Nouveau litige nécessitant un arbitrage`,
      badge: 'Action Requise',
      content: `
        <strong>Initié par :</strong> ${initiator.name} (${initiator.email})<br>
        <strong>Motif :</strong> ${dispute.reason}<br>
        <strong>Montant gelé :</strong> ${parseFloat(order.amount).toFixed(2)} USDT<br>
        <strong>Explications :</strong> ${dispute.details}
      `,
      ctaText: 'Arbitrer le dossier',
      ctaUrl: `https://51.20.182.245/admin/disputes`
    })
  });
}

module.exports = {
  sendEmail,
  notifyNewOrder,
  notifyOrderDelivered,
  notifyOrderCompleted,
  notifyDisputeOpened
};
