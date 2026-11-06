// src/services/email.js
const nodemailer = require('nodemailer');
require('dotenv').config();

const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '465', 10);
const SMTP_SECURE = process.env.SMTP_SECURE !== undefined
  ? process.env.SMTP_SECURE === 'true'
  : (SMTP_PORT === 465);

const NOTIFICATION_EMAIL = process.env.NOTIFICATION_EMAIL || process.env.SMTP_USER || '';
const BASE_URL = process.env.BASE_URL || 'https://trustwork.duckdns.org';

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
 * Send styled HTML email with plain text fallback (non-blocking)
 */
async function sendEmail({ to, subject, html, text }) {
  const client = getTransporter();
  if (!client) {
    console.warn(`[EmailService] ⚠️ SMTP_PASS not configured. Email to ${to} not sent.`);
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
    console.log(`[EmailService] 📧 Email sent to ${to} (${info.messageId}) - Subject: "${subject}"`);
    return { success: true, messageId: info.messageId };
  } catch (err) {
    console.error(`[EmailService] ❌ Error sending email to ${to}:`, err.message);
    return { success: false, error: err.message };
  }
}

/**
 * Elegant HTML template for TrustWork
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
        <div style="font-size: 13px; opacity: 0.9; margin-top: 4px;">Guaranteed Escrow System & Binance Pay</div>
      </div>
      <div class="body">
        ${badge ? `<div class="badge">${badge}</div>` : ''}
        <h2 class="title">${title}</h2>
        <div>${content}</div>
        ${ctaText && ctaUrl ? `<div style="text-align: center;"><a href="${ctaUrl}" class="cta-btn">${ctaText}</a></div>` : ''}
      </div>
      <div class="footer">
        This is an automated security notification from TrustWork.<br>
        Developer method platform with guaranteed escrow fund protection.
      </div>
    </div>
  </body>
  </html>
  `;
}

// ==========================================
// EVENT NOTIFICATIONS
// ==========================================

/**
 * 1. New order created (Funds in escrow)
 */
async function notifyNewOrder({ order, service, buyer, seller }) {
  const amount = parseFloat(order.amount).toFixed(2);
  const orderUrl = `${BASE_URL}/orders/${order.id}`;

  // Seller Notification
  if (seller && seller.email && !seller.email.endsWith('.local')) {
    sendEmail({
      to: seller.email,
      subject: `🎉 New order received (#${order.id}) - ${amount} USDT in escrow`,
      html: getEmailTemplate({
        title: `You have received a new order!`,
        badge: 'Escrow Protected (Guaranteed)',
        content: `
          Hello <strong>${seller.name}</strong>,<br><br>
          Buyer <strong>${buyer.name}</strong> just placed an order for your guide:<br>
          <div class="box">
            <strong>Guide:</strong> ${service.title}<br>
            <strong>Locked amount:</strong> ${amount} USDT<br>
            <strong>Buyer instructions:</strong> <em>${order.requirements || 'None'}</em>
          </div>
          🔒 <strong>The ${amount} USDT are already locked on the platform.</strong> You can proceed with full confidence.
        `,
        ctaText: 'Access Order & Deliver',
        ctaUrl: orderUrl
      })
    });
  }

  // Buyer Confirmation
  if (buyer && buyer.email && !buyer.email.endsWith('.local')) {
    sendEmail({
      to: buyer.email,
      subject: `🔒 Order Confirmation (#${order.id}) - Funds Secured`,
      html: getEmailTemplate({
        title: `Your order is confirmed`,
        badge: 'Escrow Active',
        content: `
          Hello <strong>${buyer.name}</strong>,<br><br>
          Your order has been transmitted to author <strong>${seller.name}</strong>.<br>
          <div class="box">
            <strong>Amount in escrow:</strong> ${amount} USDT<br>
            <strong>Delivery timeframe:</strong> ${service.deliveryDays} business day(s)
          </div>
          Your funds remain protected until you validate the delivery.
        `,
        ctaText: 'Track Order Live',
        ctaUrl: orderUrl
      })
    });
  }

  // Admin Copy
  sendEmail({
    to: NOTIFICATION_EMAIL,
    subject: `[TrustWork Admin] New order #${order.id} (${amount} USDT)`,
    html: getEmailTemplate({
      title: `New order registered on the platform`,
      badge: 'Admin Alert',
      content: `Buyer: ${buyer.name} (${buyer.email})<br>Author: ${seller.name} (${seller.email})<br>Amount: ${amount} USDT<br>Guide: ${service.title}`,
      ctaText: 'View Order',
      ctaUrl: orderUrl
    })
  });
}

/**
 * 2. Deliverables submitted by author
 */
async function notifyOrderDelivered({ order, buyer, seller }) {
  const orderUrl = `${BASE_URL}/orders/${order.id}`;

  if (buyer && buyer.email && !buyer.email.endsWith('.local')) {
    sendEmail({
      to: buyer.email,
      subject: `📦 Your order #${order.id} has been delivered!`,
      html: getEmailTemplate({
        title: `The author has delivered your work`,
        badge: 'Review Deliverables',
        content: `
          Hello <strong>${buyer.name}</strong>,<br><br>
          <strong>${seller.name}</strong> has submitted the deliverables.<br>
          <div class="box">
            <strong>Delivery note:</strong><br>
            ${order.deliveryNote || 'Check the files and links on the website.'}
          </div>
          Please take the time to review the work. If everything is complete, click below to release the <strong>${parseFloat(order.amount).toFixed(2)} USDT</strong>.
        `,
        ctaText: 'Verify & Approve Delivery',
        ctaUrl: orderUrl
      })
    });
  }
}

/**
 * 3. Order completed and funds released
 */
async function notifyOrderCompleted({ order, buyer, seller }) {
  const gross = parseFloat(order.amount || 0);
  const fee = order.platformFee !== undefined && parseFloat(order.platformFee) > 0
    ? parseFloat(order.platformFee)
    : Math.round(gross * 0.15 * 100) / 100;
  const net = order.sellerNetAmount !== undefined && parseFloat(order.sellerNetAmount) > 0
    ? parseFloat(order.sellerNetAmount)
    : Math.round((gross - fee) * 100) / 100;

  if (seller && seller.email && !seller.email.endsWith('.local')) {
    sendEmail({
      to: seller.email,
      subject: `💰 Payment Released! +${net.toFixed(2)} USDT net received (Order #${order.id})`,
      html: getEmailTemplate({
        title: `Congratulations! Your earnings are available`,
        badge: 'Payment Released (85% Net)',
        content: `
          Hello <strong>${seller.name}</strong>,<br><br>
          The buyer has approved the order. Your net payout of <strong>${net.toFixed(2)} USDT (85%)</strong> has been released and credited to your available balance (Gross: ${gross.toFixed(2)} USDT, Platform Fee 15%: ${fee.toFixed(2)} USDT).<br>
          You can withdraw your funds to your Binance Pay wallet at any time.
        `,
        ctaText: 'View My Wallet',
        ctaUrl: `${BASE_URL}/dashboard`
      })
    });
  }
}

/**
 * 4. Dispute / investigation opened
 */
async function notifyDisputeOpened({ order, dispute, initiator, otherParty }) {
  const orderUrl = `${BASE_URL}/orders/${order.id}`;

  const emailContent = `
    An investigation (dispute) has been opened by <strong>${initiator.name}</strong> regarding order #${order.id}.<br>
    <div class="box">
      <strong>Reason:</strong> ${dispute.reason}<br>
      <strong>Details:</strong> ${dispute.details}
    </div>
    🔒 <strong>Active Protection:</strong> Funds remain completely frozen in escrow until an arbitration decision is made.
  `;

  if (otherParty && otherParty.email && !otherParty.email.endsWith('.local')) {
    sendEmail({
      to: otherParty.email,
      subject: `⚠️ Investigation opened on order #${order.id}`,
      html: getEmailTemplate({
        title: `Dispute Case Opened`,
        badge: 'Funds Frozen',
        content: emailContent,
        ctaText: 'Join the Discussion',
        ctaUrl: orderUrl
      })
    });
  }

  // Admin alert
  sendEmail({
    to: NOTIFICATION_EMAIL,
    subject: `🚨 [Admin Dispute Alert] Investigation opened on order #${order.id}`,
    html: getEmailTemplate({
      title: `New dispute requiring arbitration`,
      badge: 'Action Required',
      content: `
        <strong>Initiated by:</strong> ${initiator.name} (${initiator.email})<br>
        <strong>Reason:</strong> ${dispute.reason}<br>
        <strong>Frozen amount:</strong> ${parseFloat(order.amount).toFixed(2)} USDT<br>
        <strong>Details:</strong> ${dispute.details}
      `,
      ctaText: 'Arbitrate Case',
      ctaUrl: `${BASE_URL}/admin/disputes`
    })
  });
}

/**
 * 5. Withdrawal request
 */
async function notifyWithdrawalRequested({ user, amount, binanceId }) {
  const amtStr = parseFloat(amount).toFixed(2);
  
  if (user && user.email && !user.email.endsWith('.local')) {
    sendEmail({
      to: user.email,
      subject: `📤 Withdrawal request received - ${amtStr} USDT to Binance Pay`,
      html: getEmailTemplate({
        title: `Your withdrawal request is being processed`,
        badge: 'Withdrawal Pending',
        content: `
          Hello <strong>${user.name}</strong>,<br><br>
          Your withdrawal request of <strong>${amtStr} USDT</strong> to Binance Pay ID <code>${binanceId}</code> has been recorded.<br>
          The transfer will be processed shortly.
        `,
        ctaText: 'Go to Dashboard',
        ctaUrl: `${BASE_URL}/dashboard`
      })
    });
  }

  sendEmail({
    to: NOTIFICATION_EMAIL,
    subject: `[Admin Withdrawal] Request of ${amtStr} USDT by ${user.name}`,
    html: getEmailTemplate({
      title: `Binance Pay withdrawal request received`,
      badge: 'Withdrawal Request',
      content: `User: ${user.name} (${user.email})<br>Amount: ${amtStr} USDT<br>Binance Pay ID: <code>${binanceId}</code>`,
      ctaText: 'Check on Admin Dashboard',
      ctaUrl: `${BASE_URL}/dashboard`
    })
  });
}

/**
 * 6. Review submitted
 */
async function notifyReviewSubmitted({ review, order, seller, buyer }) {
  if (seller && seller.email && !seller.email.endsWith('.local')) {
    sendEmail({
      to: seller.email,
      subject: `⭐ New review received from ${buyer.name} (${review.rating}/5)`,
      html: getEmailTemplate({
        title: `You received a new client rating!`,
        badge: 'Client Review',
        content: `
          Hello <strong>${seller.name}</strong>,<br><br>
          <strong>${buyer.name}</strong> left a review on your order:<br>
          <div class="box">
            <strong>Rating:</strong> ${review.rating} / 5 ⭐<br>
            <strong>Comment:</strong> <em>"${review.comment}"</em>
          </div>
        `,
        ctaText: 'View Public Profile',
        ctaUrl: `${BASE_URL}/profile/${seller.id}`
      })
    });
  }
}

/**
 * 7. Deposit confirmation via Binance Pay
 */
async function notifyDepositReceived({ user, amount, txId, binancePayId }) {
  const amtStr = parseFloat(amount).toFixed(2);
  
  if (user && user.email && !user.email.endsWith('.local')) {
    sendEmail({
      to: user.email,
      subject: `💰 Deposit confirmed: +${amtStr} USDT in your account`,
      html: getEmailTemplate({
        title: `Your account has been credited!`,
        badge: 'Binance Pay Deposit',
        content: `
          Hello <strong>${user.name}</strong>,<br><br>
          Your deposit of <strong>${amtStr} USDT</strong> via Binance Pay has been validated successfully.<br>
          <div class="box">
            <strong>Amount credited:</strong> ${amtStr} USDT<br>
            <strong>Transaction ID (TxID):</strong> <code>${txId || 'N/A'}</code><br>
            <strong>Binance Pay ID:</strong> <code>${binancePayId || 'N/A'}</code>
          </div>
          Your funds are immediately available to purchase guides and methods.
        `,
        ctaText: 'View My Dashboard',
        ctaUrl: `${BASE_URL}/dashboard`
      })
    });
  }

  sendEmail({
    to: NOTIFICATION_EMAIL,
    subject: `[Admin Deposit] Deposit of ${amtStr} USDT received (${user.name})`,
    html: getEmailTemplate({
      title: `New Binance Pay deposit recorded`,
      badge: 'Client Deposit',
      content: `User: ${user.name} (${user.email})<br>Amount: ${amtStr} USDT<br>TxID: <code>${txId || 'N/A'}</code><br>Binance Pay ID: <code>${binancePayId || 'N/A'}</code>`,
      ctaText: 'Admin Dashboard',
      ctaUrl: `${BASE_URL}/dashboard`
    })
  });
}

/**
 * 8. Unread chat message notification
 */
async function notifyUnreadChatMessage({ recipient, sender, conversationId, messageText }) {
  if (!recipient || !recipient.email) return;

  if (recipient.email.endsWith('.local')) {
    console.log(`[EmailService] 💬 [Demo Simulation] Unread chat notification for ${recipient.email} (${recipient.name}) from ${sender.name}: "${messageText}"`);
    return;
  }

  const roleLabel = sender.role === 'ADMIN' ? 'Support & Moderation' : (sender.role === 'USER' ? 'User' : sender.role);

  sendEmail({
    to: recipient.email,
    subject: `💬 New message from ${sender.name} on TrustWork`,
    html: getEmailTemplate({
      title: `You have received a new private message`,
      badge: 'Direct Messaging',
      content: `
        Hello <strong>${recipient.name}</strong>,<br><br>
        <strong>${sender.name}</strong> (${roleLabel}) sent you a message on TrustWork:
        <div class="box" style="border-left: 4px solid #059669; font-style: italic; color: #1e293b; background: #f0fdf4;">
          "${messageText}"
        </div>
        Log in to your account to reply or view any attachments.
      `,
      ctaText: 'Open Conversation',
      ctaUrl: `${BASE_URL}/chat?conversationId=${conversationId}`
    })
  });
}

module.exports = {
  sendEmail,
  notifyNewOrder,
  notifyOrderDelivered,
  notifyOrderCompleted,
  notifyDisputeOpened,
  notifyWithdrawalRequested,
  notifyReviewSubmitted,
  notifyDepositReceived,
  notifyUnreadChatMessage
};
