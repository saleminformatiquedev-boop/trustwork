// src/services/binance.js
const crypto = require('crypto');
require('dotenv').config();

const BINANCE_API_BASE = 'https://api.binance.com';
const PLATFORM_BINANCE_PAY_ID = process.env.PLATFORM_BINANCE_PAY_ID || process.env.BINANCE_PAY_ID || '1229901779';
const DEFAULT_USDT_TRC20 = process.env.USDT_TRC20_ADDRESS || 'TNw9pxbxwf6qtvymRSnr2quaWxVCi5fwqu';
const DEFAULT_USDT_BEP20 = process.env.USDT_BEP20_ADDRESS || '0x284b2c731c9a9449f88f42bc707c05511bb9b222';
// Reject any historical Binance transaction created before the platform API integration
const MIN_DEPOSIT_TIMESTAMP = 1793956460000;
const MAX_DEPOSIT_AGE_MS = 48 * 60 * 60 * 1000; // 48 hours max age for automatic verification

function getCredentials() {
  return {
    apiKey: (process.env.BINANCE_API_KEY || '').trim(),
    apiSecret: (process.env.BINANCE_API_SECRET || '').trim()
  };
}

function isConfigured() {
  const { apiKey, apiSecret } = getCredentials();
  return Boolean(apiKey && apiSecret);
}

/**
 * Signed request helper for Binance Spot/Wallet/Pay API (/sapi/v1/*)
 */
async function signedBinanceRequest(method, endpoint, params = {}) {
  const { apiKey, apiSecret } = getCredentials();
  if (!apiKey || !apiSecret) {
    throw new Error('Binance API credentials are not configured on the server.');
  }

  const timestamp = Date.now();
  const cleanParams = {};
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') {
      cleanParams[k] = String(v);
    }
  }
  cleanParams.timestamp = String(timestamp);
  cleanParams.recvWindow = '10000';

  const queryString = new URLSearchParams(cleanParams).toString();
  const signature = crypto
    .createHmac('sha256', apiSecret)
    .update(queryString)
    .digest('hex');

  const url = `${BINANCE_API_BASE}${endpoint}?${queryString}&signature=${signature}`;
  const response = await fetch(url, {
    method,
    headers: {
      'X-MBX-APIKEY': apiKey,
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok || (data && data.code && data.code !== '000000' && Number(data.code) < 0)) {
    const errMsg = data.msg || data.message || `Binance API HTTP ${response.status}`;
    const err = new Error(errMsg);
    err.binanceCode = data.code;
    err.httpStatus = response.status;
    throw err;
  }

  return data;
}

/**
 * Verify an incoming USDT deposit (via Binance Pay OR On-Chain Deposit) directly with Binance API.
 * Security rules:
 * - Must be an INCOMING transaction (amount > 0 for Binance Pay, status 1 or 6 for On-Chain)
 * - Currency/Coin must be strictly 'USDT'
 * - Received amount must be >= expectedAmount
 * - Returns canonicalTransactionId so the caller can enforce strict uniqueness in PostgreSQL
 */
async function verifyIncomingDeposit({ txId, expectedAmount }) {
  if (!isConfigured()) {
    return { verified: false, reason: 'Binance API not configured; queued for manual admin review.' };
  }

  const cleanTx = String(txId || '').trim();
  const cleanLower = cleanTx.toLowerCase();
  const minAmount = Math.round(parseFloat(expectedAmount) * 100) / 100;

  if (!cleanTx || !Number.isFinite(minAmount) || minAmount <= 0) {
    return { verified: false, reason: 'Invalid transaction ID or amount.' };
  }

  // 1. Check Binance Pay Transactions (/sapi/v1/pay/transactions)
  try {
    const payRes = await signedBinanceRequest('GET', '/sapi/v1/pay/transactions', { limit: 100 });
    const payList = Array.isArray(payRes.data) ? payRes.data : [];

    for (const item of payList) {
      const orderId = String(item.orderId || '').trim();
      const transactionId = String(item.transactionId || '').trim();
      const txTime = Number(item.transactionTime || 0);

      // Strict exact match on private Binance Pay Order ID or Transaction ID only (never match user-controlled note)
      const idMatches =
        (orderId && orderId.toLowerCase() === cleanLower) ||
        (transactionId && transactionId.toLowerCase() === cleanLower);

      if (idMatches) {
        if (txTime < MIN_DEPOSIT_TIMESTAMP || (Date.now() - txTime > MAX_DEPOSIT_AGE_MS)) {
          return {
            verified: false,
            reason: 'This Binance Pay transaction is expired or predates platform integration.'
          };
        }

        const currency = String(item.currency || '').toUpperCase();
        const rawAmt = parseFloat(item.amount || 0);

        if (currency !== 'USDT') {
          return {
            verified: false,
            reason: `Transaction found on Binance Pay, but currency is ${currency} instead of USDT.`
          };
        }

        // Critical Security Check: positive amount means funds RECEIVED by Admin (1229901779)
        if (rawAmt <= 0) {
          return {
            verified: false,
            reason: 'This transaction is an outgoing payment, not an incoming deposit.'
          };
        }

        const receivedAmount = Math.round(rawAmt * 100) / 100;
        if (Math.abs(receivedAmount - minAmount) > 0.01) {
          return {
            verified: false,
            reason: `Binance Pay amount (${receivedAmount.toFixed(2)} USDT) does not match the declared deposit amount (${minAmount.toFixed(2)} USDT).`
          };
        }

        return {
          verified: true,
          autoCreditAllowed: true,
          method: 'BINANCE_PAY',
          canonicalTxId: orderId || transactionId,
          actualAmount: receivedAmount,
          payerName: item.payerInfo?.name || 'Binance User'
        };
      }
    }
  } catch (err) {
    console.warn('[Binance API] Pay history check warning:', err.message);
  }

  // 2. Check On-Chain USDT Deposits (/sapi/v1/capital/deposit/hisrec)
  try {
    const depList = await signedBinanceRequest('GET', '/sapi/v1/capital/deposit/hisrec', {
      coin: 'USDT',
      limit: 100
    });

    if (Array.isArray(depList)) {
      for (const dep of depList) {
        const chainTxId = String(dep.txId || '').trim();
        const depId = String(dep.id || '').trim();

        // Allow exact txId match or suffix match if Binance prefixes with "Internal transfer "
        const cleanChainTx = chainTxId.replace(/^Internal transfer\s+/i, '').trim();
        const isMatch =
          cleanChainTx.toLowerCase() === cleanLower ||
          chainTxId.toLowerCase() === cleanLower ||
          depId.toLowerCase() === cleanLower;

        if (isMatch) {
          const insertTime = Number(dep.insertTime || 0);
          if (insertTime < MIN_DEPOSIT_TIMESTAMP || (Date.now() - insertTime > MAX_DEPOSIT_AGE_MS)) {
            return {
              verified: false,
              reason: 'This on-chain deposit is expired or predates platform integration.'
            };
          }

          const coin = String(dep.coin || '').toUpperCase();
          if (coin !== 'USDT') {
            return { verified: false, reason: `Deposit found, but coin is ${coin} instead of USDT.` };
          }

          // status: 0 = pending, 6 = credited but cannot withdraw, 1 = success
          if (dep.status !== 1 && dep.status !== 6) {
            return {
              verified: false,
              reason: 'Deposit detected on blockchain, waiting for final network confirmations.'
            };
          }

          const receivedAmount = Math.round(parseFloat(dep.amount || 0) * 100) / 100;
          if (Math.abs(receivedAmount - minAmount) > 0.01) {
            return {
              verified: false,
              reason: `On-chain deposit amount (${receivedAmount.toFixed(2)} USDT) does not match declared amount (${minAmount.toFixed(2)} USDT).`
            };
          }

          // Note: Public blockchain txIds are visible on TronScan/BscScan, so autoCreditAllowed is false for user submissions
          // (Admin can approve in 1 click via VERIFY_API, preventing blockchain explorer front-running!)
          return {
            verified: true,
            autoCreditAllowed: false,
            method: `ON_CHAIN_${dep.network || 'USDT'}`,
            canonicalTxId: cleanChainTx || depId,
            actualAmount: receivedAmount
          };
        }
      }
    }
  } catch (err) {
    console.warn('[Binance API] On-chain deposit check warning:', err.message);
  }

  return {
    verified: false,
    reason: 'Transaction not yet visible in Binance API (may take 1-2 minutes). Saved as PENDING for verification.'
  };
}

/**
 * Detect blockchain network from destination address or explicit network string
 */
function resolveWithdrawalNetwork(address, preferredNetwork) {
  const addr = String(address || '').trim();
  if (preferredNetwork && ['TRX', 'BSC', 'ETH', 'MATIC', 'SOL', 'ARBITRUM', 'OPTIMISM'].includes(preferredNetwork.toUpperCase())) {
    return preferredNetwork.toUpperCase();
  }
  if (/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(addr)) {
    return 'TRX'; // TRC20
  }
  if (/^0x[a-fA-F0-9]{40}$/.test(addr)) {
    return 'BSC'; // Default EVM low-fee network BEP20 (BSC)
  }
  return null;
}

/**
 * Execute a real USDT withdrawal via Binance API (/sapi/v1/capital/withdraw/apply).
 * Attempts Funding Wallet (walletType=1) first, then Spot Wallet (walletType=0).
 */
async function executeUsdtWithdrawal({ destination, network, amount, withdrawalId }) {
  const cleanDest = String(destination || '').trim();
  const resolvedNet = resolveWithdrawalNetwork(cleanDest, network);

  if (!resolvedNet) {
    return {
      success: false,
      isManualPayId: true,
      error: `Destination "${cleanDest}" is a Binance Pay ID (not an on-chain TRX/BSC address). Please send ${Number(amount).toFixed(2)} USDT via Binance Pay to ID ${cleanDest} or ask the user for a TRC20/BEP20 address.`
    };
  }

  const formattedAmount = (Math.round(parseFloat(amount) * 100) / 100).toFixed(2);

  // Try Funding Wallet (1) first since Binance Pay credits Funding Wallet, then Spot Wallet (0)
  let lastError = null;
  for (const walletType of [1, 0]) {
    try {
      const res = await signedBinanceRequest('POST', '/sapi/v1/capital/withdraw/apply', {
        coin: 'USDT',
        withdrawOrderId: withdrawalId,
        network: resolvedNet,
        address: cleanDest,
        amount: formattedAmount,
        walletType
      });

      if (res && res.id) {
        return {
          success: true,
          binanceWithdrawId: res.id,
          network: resolvedNet,
          walletType
        };
      }
    } catch (err) {
      lastError = err;
    }
  }

  return {
    success: false,
    isManualPayId: false,
    error: lastError ? lastError.message : 'Unable to execute withdrawal via Binance API.'
  };
}

/**
 * Get current API permissions & status for Admin dashboard
 */
async function getApiStatus() {
  try {
    if (!isConfigured()) return { connected: false };
    const restrictions = await signedBinanceRequest('GET', '/sapi/v1/account/apiRestrictions');
    return {
      connected: true,
      enableReading: Boolean(restrictions.enableReading),
      enableWithdrawals: Boolean(restrictions.enableWithdrawals),
      ipRestrict: Boolean(restrictions.ipRestrict),
      binancePayId: PLATFORM_BINANCE_PAY_ID,
      trc20Address: DEFAULT_USDT_TRC20,
      bep20Address: DEFAULT_USDT_BEP20
    };
  } catch (err) {
    return {
      connected: false,
      error: err.message,
      binancePayId: PLATFORM_BINANCE_PAY_ID,
      trc20Address: DEFAULT_USDT_TRC20,
      bep20Address: DEFAULT_USDT_BEP20
    };
  }
}

module.exports = {
  PLATFORM_BINANCE_PAY_ID,
  DEFAULT_USDT_TRC20,
  DEFAULT_USDT_BEP20,
  isConfigured,
  verifyIncomingDeposit,
  executeUsdtWithdrawal,
  getApiStatus
};
