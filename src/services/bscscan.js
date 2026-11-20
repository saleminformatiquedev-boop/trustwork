// src/services/bscscan.js
// Verifies a BSC USDT (BEP20) transfer to the platform address through a public RPC (same as the bot).
const USDT_CONTRACT = '0x55d398326f99059fF775485246999027B3197955'.toLowerCase();
const RECEIVER_ADDRESS = (process.env.USDT_BEP20_ADDRESS || '0x284b2c731c9a9449f88f42bc707c05511bb9b222').toLowerCase();
const TRANSFER_EVENT_SIG = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const RPC_URL = 'https://bsc-dataseed.binance.org/';

async function verifyBscTransaction(txHash) {
  if (!/^0x[A-Fa-f0-9]{64}$/.test(txHash)) {
    return { success: false, message: 'Invalid TxID format. It must start with 0x.' };
  }
  try {
    const response = await fetch(RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'eth_getTransactionReceipt', params: [txHash], id: 1 }),
      signal: AbortSignal.timeout(15000)
    });
    const json = await response.json();
    const receipt = json && json.result;
    if (!receipt) return { success: false, message: 'Transaction not found on the BSC network (it may still be pending).' };
    if (receipt.status !== '0x1') return { success: false, message: 'The transaction failed or is still pending.' };

    const expectedTopic2 = '0x000000000000000000000000' + RECEIVER_ADDRESS.replace('0x', '');
    let amount = 0;
    let found = false;
    for (const log of receipt.logs || []) {
      if (
        String(log.address).toLowerCase() === USDT_CONTRACT &&
        log.topics && log.topics[0] === TRANSFER_EVENT_SIG &&
        log.topics.length >= 3 &&
        String(log.topics[2]).toLowerCase() === expectedTopic2
      ) {
        amount += Number(BigInt(log.data)) / 1e18;
        found = true;
      }
    }
    if (!found) return { success: false, message: 'No USDT transfer to our BEP20 address found in this transaction.' };
    return { success: true, amount };
  } catch (err) {
    console.error('[BSC] RPC verification error:', err.message);
    return { success: false, message: 'Unable to reach the BSC network right now. Please retry.' };
  }
}

module.exports = { verifyBscTransaction, RECEIVER_ADDRESS };
