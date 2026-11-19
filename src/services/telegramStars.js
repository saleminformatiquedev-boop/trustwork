// src/services/telegramStars.js
// Telegram Stars (XTR) checkout for digital goods — Bot API implementation.
// Docs: https://core.telegram.org/bots/payments-stars
require('dotenv').config();

const BOT_TOKEN = (process.env.TELEGRAM_BOT_TOKEN || '').trim();
const BOT_USERNAME = (process.env.TELEGRAM_BOT_USERNAME || '').trim().replace(/^@/, '');
const WEBHOOK_SECRET = (process.env.TELEGRAM_WEBHOOK_SECRET || '').trim();
const WEBHOOK_URL = (process.env.TELEGRAM_WEBHOOK_URL || '').trim();
const POLLING_ENABLED = String(process.env.TELEGRAM_POLLING || 'true').toLowerCase() !== 'false';

// Telegram pays bot owners about $0.013 per Star. 1 USD ≈ 76.92 Stars.
// 77 Stars per $1 keeps the platform close to break-even after Telegram's payout conversion.
// Adjust with TG_STARS_PER_USD if you prefer to absorb or pass on the app-store markup.
const parsedRate = parseFloat(process.env.TG_STARS_PER_USD || '77');
const STARS_PER_USD = Number.isFinite(parsedRate) && parsedRate >= 1 ? parsedRate : 77;

const API_BASE = 'https://api.telegram.org';

function isConfigured() {
  return Boolean(BOT_TOKEN);
}

function getBotUrl() {
  return BOT_USERNAME ? `https://t.me/${BOT_USERNAME}` : '';
}

/**
 * Convert a USD ledger amount into a whole number of Telegram Stars.
 */
function usdToStars(usd) {
  const value = Number(usd);
  if (!Number.isFinite(value) || value <= 0) return 0;
  return Math.max(1, Math.ceil(value * STARS_PER_USD));
}

/**
 * Value of Stars at Telegram's developer payout rate ($0.013 / Star).
 */
function starsToUsd(stars) {
  const value = Number(stars);
  if (!Number.isFinite(value) || value <= 0) return 0;
  return Math.round((value / STARS_PER_USD) * 100) / 100;
}

/**
 * Raw Bot API call with timeout + clear errors.
 */
async function call(method, params = {}, { timeoutMs = 15000 } = {}) {
  if (!BOT_TOKEN) {
    throw new Error('TELEGRAM_BOT_TOKEN is not configured on the server.');
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let response;
    try {
      response = await fetch(`${API_BASE}/bot${BOT_TOKEN}/${method}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
        signal: controller.signal
      });
    } catch (fetchErr) {
      if (fetchErr.name === 'AbortError') {
        throw new Error(`Telegram API timeout while calling ${method}.`);
      }
      throw fetchErr;
    }

    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.ok) {
      const err = new Error(data.description || `Telegram API HTTP ${response.status}`);
      err.telegramCode = data.error_code;
      err.description = data.description;
      throw err;
    }
    return data.result;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Create a Stars invoice link.
 * provider_token must be omitted/empty and currency must be "XTR".
 */
async function createInvoiceLink({ title, description, payload, stars, photoUrl }) {
  const amount = Math.max(1, Math.floor(Number(stars) || 0));
  const safePayload = String(payload || '').trim().slice(0, 128);
  if (!safePayload) throw new Error('A non-empty invoice payload is required.');
  const params = {
    title: String(title || 'Digital method').slice(0, 32),
    description: String(description || 'Digital goods and services').slice(0, 255),
    payload: safePayload,
    currency: 'XTR',
    prices: [{ label: String(title || 'Digital method').slice(0, 32), amount }]
  };
  if (photoUrl) params.photo_url = photoUrl;
  return call('createInvoiceLink', params);
}

async function answerPreCheckoutQuery(preCheckoutQueryId, ok, errorMessage) {
  const params = { pre_checkout_query_id: preCheckoutQueryId, ok: Boolean(ok) };
  if (!ok && errorMessage) params.error_message = String(errorMessage).slice(0, 200);
  return call('answerPreCheckoutQuery', params);
}

async function refundStarPayment(userId, telegramPaymentChargeId) {
  return call('refundStarPayment', {
    user_id: userId,
    telegram_payment_charge_id: telegramPaymentChargeId
  });
}

async function getMyStarBalance() {
  return call('getMyStarBalance', {});
}

async function getStarTransactions({ offset = 0, limit = 20 } = {}) {
  const safeOffset = Math.max(0, Math.floor(Number(offset) || 0));
  const safeLimit = Math.min(100, Math.max(1, Math.floor(Number(limit) || 20)));
  return call('getStarTransactions', { offset: safeOffset, limit: safeLimit });
}

async function sendMessage(chatId, text, extra = {}) {
  return call('sendMessage', {
    chat_id: chatId,
    text: String(text || '').slice(0, 4096),
    disable_web_page_preview: true,
    ...extra
  });
}

async function getMe() {
  return call('getMe', {});
}

async function setWebhook(url, secretToken) {
  const params = {
    url,
    allowed_updates: ['message', 'pre_checkout_query'],
    drop_pending_updates: false
  };
  if (secretToken) params.secret_token = secretToken;
  return call('setWebhook', params);
}

async function getWebhookInfo() {
  return call('getWebhookInfo', {});
}

async function deleteWebhook() {
  return call('deleteWebhook', { drop_pending_updates: false });
}

// Long polling fallback for local development (no public HTTPS webhook).
let polling = false;
let pollOffset = 0;

async function startPolling(onUpdate) {
  if (polling || !isConfigured() || !POLLING_ENABLED) return false;

  // Do not poll when a webhook is already registered (Telegram returns 409).
  try {
    const info = await getWebhookInfo();
    if (info && info.url) {
      console.log('[Telegram Stars] Webhook already configured; long polling disabled.');
      return false;
    }
  } catch (err) {
    console.warn('[Telegram Stars] getWebhookInfo failed:', err.message);
  }

  polling = true;
  console.log('[Telegram Stars] Long polling started.');

  (async () => {
    while (polling) {
      try {
        const updates = await call('getUpdates', {
          offset: pollOffset || undefined,
          timeout: 30,
          allowed_updates: ['message', 'pre_checkout_query']
        }, { timeoutMs: 40000 });

        for (const update of updates || []) {
          if (update.update_id) pollOffset = update.update_id + 1;
          try {
            await onUpdate(update);
          } catch (err) {
            console.error('[Telegram Stars] Update handler error:', err.message);
          }
        }
      } catch (err) {
        if (err.telegramCode === 409) {
          console.warn('[Telegram Stars] Webhook is active, stopping long polling.');
          polling = false;
          break;
        }
        console.warn('[Telegram Stars] Polling error:', err.message);
        await new Promise(resolve => setTimeout(resolve, 3000));
      }
    }
  })();

  return true;
}

function stopPolling() {
  polling = false;
}

module.exports = {
  BOT_TOKEN,
  BOT_USERNAME,
  WEBHOOK_SECRET,
  WEBHOOK_URL,
  POLLING_ENABLED,
  STARS_PER_USD,
  isConfigured,
  getBotUrl,
  usdToStars,
  starsToUsd,
  call,
  createInvoiceLink,
  answerPreCheckoutQuery,
  refundStarPayment,
  getMyStarBalance,
  getStarTransactions,
  sendMessage,
  getMe,
  setWebhook,
  getWebhookInfo,
  deleteWebhook,
  startPolling,
  stopPolling
};
