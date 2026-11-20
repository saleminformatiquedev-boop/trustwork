// src/services/txclaims.js
// Atomic "one payment = one purchase" locks. When SHARED_DATABASE_URL is set the claims
// live in the same database as the Telegram bot, so a payment used by the bot cannot be reused here.
const { Pool } = require('pg');
const { pool: localPool } = require('../db');
require('dotenv').config();

const SOURCE_NAME = process.env.BOT_SOURCE_NAME || 'website';
const claimsPool = process.env.SHARED_DATABASE_URL
  ? new Pool({ connectionString: process.env.SHARED_DATABASE_URL })
  : localPool;

const TABLES = { BINANCE_PAY: 'used_binance_tx', USDT_BEP20: 'used_bsc_tx' };
let ready = null;

function ensureTables() {
  if (!ready) {
    ready = (async () => {
      for (const table of Object.values(TABLES)) {
        await claimsPool.query(`CREATE TABLE IF NOT EXISTS ${table} (
          tx_id TEXT PRIMARY KEY,
          claimed_by TEXT NOT NULL DEFAULT 'website',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
      }
    })().catch(err => { ready = null; throw err; });
  }
  return ready;
}

function tableFor(method) {
  const table = TABLES[method];
  if (!table) throw new Error('Unknown payment method');
  return table;
}

async function claim(method, txId) {
  await ensureTables();
  const res = await claimsPool.query(
    `INSERT INTO ${tableFor(method)} (tx_id, claimed_by) VALUES ($1, $2) ON CONFLICT (tx_id) DO NOTHING RETURNING tx_id`,
    [txId, SOURCE_NAME]
  );
  return res.rows.length > 0;
}

async function release(method, txId) {
  await ensureTables();
  await claimsPool.query(`DELETE FROM ${tableFor(method)} WHERE tx_id = $1 AND claimed_by = $2`, [txId, SOURCE_NAME]);
}

module.exports = { claim, release };
