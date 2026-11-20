// src/services/prodseller.js
// ProdSeller supplier API client (same API, pricing rule and cache as the Telegram bot).
const https = require('https');
require('dotenv').config();

const BASE_URL = process.env.PRODSELLER_BASE_URL || 'https://51.77.244.194/v1';
const PRODUCTS_CACHE_TTL = 10 * 60 * 1000;
const REQUEST_TIMEOUT_MS = 20000;

// The supplier serves a certificate that does not match its bare IP, so TLS
// verification is relaxed for this agent only (never globally).
const agent = new https.Agent({ rejectUnauthorized: false, keepAlive: true });

function getApiKey() {
  return (process.env.PRODSELLER_API_KEY || '').trim();
}

function isConfigured() {
  return Boolean(getApiKey());
}

function getPriceMultiplier() {
  const parsed = Number(process.env.PRODSELLER_PRICE_MULTIPLIER);
  return Number.isFinite(parsed) && parsed >= 1 && parsed <= 10 ? parsed : 1.2;
}

// Same exclusions as the bot
const HIDDEN_PRODUCT_NAMES = new Set(['test api']);
function isHiddenProduct(product) {
  const name = String(product?.name || '').trim().toLowerCase();
  return HIDDEN_PRODUCT_NAMES.has(name) || name.includes('canva') || name.includes('office 365') || name.includes('outlook');
}

const KNOWN_BULK_PRICES = {
  'premium rotating proxy': [{ minQuantity: 10, supplierUnitPrice: 0.08 }]
};

function supplierBulkRules(product) {
  const raw = product.bulkPricing || product.bulkPrices || product.quantityPrices || product.priceTiers || product.pricingTiers || product.tiers;
  if (Array.isArray(raw)) return raw;
  const description = String(product.description || '');
  const parsed = [];
  const pattern = /(?:≥|>=|minimum|min)\s*(\d+)\s*(?:items?|units?).*?\$?\s*(\d+(?:\.\d+)?)\s*\/?\s*(?:unit|item)/gi;
  let match;
  while ((match = pattern.exec(description))) parsed.push({ minQuantity: Number(match[1]), supplierUnitPrice: Number(match[2]) });
  if (parsed.length) return parsed;
  return KNOWN_BULK_PRICES[String(product.name || '').trim().toLowerCase()] || [];
}

function applyClientPrice(product, multiplier = getPriceMultiplier()) {
  if (!product) return product;
  const supplierCost = Number(product.finalPrice ?? product.price);
  const publicPrice = Number(product.publicPrice ?? product.finalPrice ?? product.price);
  if (Number.isFinite(supplierCost)) product.apiPrice = supplierCost;
  if (Number.isFinite(publicPrice)) {
    product.publicPrice = publicPrice;
    product.price = Math.round(publicPrice * multiplier * 100) / 100;
  }
  product.bulkPricing = supplierBulkRules(product).map(tier => {
    const quantity = Number(tier.minQuantity ?? tier.minQty ?? tier.quantity ?? tier.qty ?? tier.from);
    const rawPrice = Number(tier.supplierUnitPrice ?? tier.price ?? tier.unitPrice ?? tier.amount ?? tier.value);
    if (!Number.isInteger(quantity) || quantity < 2 || !Number.isFinite(rawPrice) || rawPrice <= 0) return null;
    const unitPrice = Math.round(rawPrice * multiplier * 100) / 100;
    return unitPrice <= product.price ? { minQuantity: quantity, unitPrice } : null;
  }).filter(Boolean).sort((a, b) => a.minQuantity - b.minQuantity);
  for (const key of ['bulkPrices', 'quantityPrices', 'priceTiers', 'pricingTiers', 'tiers']) delete product[key];
  return product;
}

function getUnitPrice(product, quantity = 1) {
  const base = Number(product?.price || 0);
  const tiers = Array.isArray(product?.bulkPricing) ? product.bulkPricing : [];
  const eligible = tiers.filter(t => Number(t.minQuantity) <= Number(quantity) && Number(t.unitPrice) > 0 && Number(t.unitPrice) <= base);
  if (!eligible.length) return base;
  return Number(eligible[eligible.length - 1].unitPrice) || base;
}

function request(method, path, { body = null, idempotencyKey = null } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const headers = { 'X-API-Key': getApiKey(), 'Content-Type': 'application/json', Accept: 'application/json' };
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
    if (payload) headers['Content-Length'] = Buffer.byteLength(payload);

    const req = https.request(`${BASE_URL}${path}`, { method, headers, agent, timeout: REQUEST_TIMEOUT_MS }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let data = null;
        try { data = text ? JSON.parse(text) : null; } catch (_) { data = null; }
        if (res.statusCode >= 200 && res.statusCode < 300) return resolve(data);
        const err = new Error(`ProdSeller HTTP ${res.statusCode}`);
        err.status = res.statusCode;
        err.data = data;
        reject(err);
      });
    });
    req.on('timeout', () => req.destroy(new Error('ProdSeller request timed out')));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

let productsCache = null;
let productsRequest = null;

async function getProduct(productId) {
  if (!isConfigured()) return null;
  try {
    const data = await request('GET', `/products/${encodeURIComponent(productId)}`);
    if (!data || isHiddenProduct(data)) return null;
    applyClientPrice(data);
    if (data.inStock === undefined) data.inStock = Number(data.stock) > 0;
    return data;
  } catch (err) {
    console.error(`[ProdSeller] Error fetching product ${productId}:`, err.message);
    return null;
  }
}

function getProducts({ forceRefresh = false } = {}) {
  if (!isConfigured()) return Promise.resolve([]);
  if (!forceRefresh && productsCache && Date.now() - productsCache.checkedAt < PRODUCTS_CACHE_TTL) {
    return Promise.resolve(productsCache.products.map(p => ({ ...p })));
  }
  if (!forceRefresh && productsRequest) return productsRequest;

  productsRequest = (async () => {
    try {
      const data = await request('GET', '/products');
      const list = (data && data.products) || [];
      // The list omits stock; the detail endpoint carries it (same as the bot)
      const detailed = await Promise.all(list.map(async (p) => {
        try {
          const d = await request('GET', `/products/${encodeURIComponent(p.id || p._id)}`);
          if (d) {
            if (d.stock !== undefined) p.stock = d.stock;
            if (d.inStock !== undefined) p.inStock = d.inStock;
            if (d.description) p.description = d.description;
            p.price = d.price; p.publicPrice = d.publicPrice; p.finalPrice = d.finalPrice;
            if (d.bulkPricing) p.bulkPricing = d.bulkPricing;
          }
        } catch (_) { /* keep list data */ }
        return applyClientPrice(p);
      }));
      const products = detailed.filter(p => p && p.name && !isHiddenProduct(p));
      productsCache = { checkedAt: Date.now(), products };
      return products.map(p => ({ ...p }));
    } catch (err) {
      console.error('[ProdSeller] Error fetching products:', err.message);
      return productsCache ? productsCache.products.map(p => ({ ...p })) : [];
    } finally {
      productsRequest = null;
    }
  })();
  return productsRequest;
}

async function createOrder(productId, idempotencyKey, quantity = 1) {
  try {
    return await request('POST', '/orders', { body: { productId, quantity }, idempotencyKey });
  } catch (err) {
    const errData = err.data || null;
    console.error(`[ProdSeller] Error creating order for ${productId}:`, errData || err.message);
    const errMsg = errData && errData.error ? String(errData.error).toLowerCase() : '';
    if (errMsg.includes('solde insuffisant') || errMsg.includes('insufficient balance')) {
      return { insufficientSupplierBalance: true };
    }
    return null;
  }
}

function extractKeys(order) {
  if (!order) return [];
  if (Array.isArray(order.keys)) return order.keys.map(String);
  if (Array.isArray(order.deliveredKeys)) return order.deliveredKeys.map(String);
  if (order.deliveredKey) return [String(order.deliveredKey)];
  if (order.data) return Array.isArray(order.data) ? order.data.map(String) : [JSON.stringify(order.data)];
  return [JSON.stringify(order)];
}

function isAvailable(product) {
  if (!product) return false;
  if (product.stock !== undefined && product.stock !== null) return Number(product.stock) > 0;
  return product.inStock !== false;
}

module.exports = {
  isConfigured,
  getProducts,
  getProduct,
  createOrder,
  getUnitPrice,
  extractKeys,
  isAvailable,
  getPriceMultiplier
};
