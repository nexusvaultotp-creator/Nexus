require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3');
const sqlite = require('sqlite');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3000;

// Central addresses
const BTC_ADDRESS = process.env.BTC_ADDRESS;
const ETH_ADDRESS = process.env.ETH_ADDRESS;
const USDT_CONTRACT = process.env.USDT_CONTRACT;

// ---------- Database ----------
let db;
(async () => {
  db = await sqlite.open({ filename: './nexus.db', driver: sqlite3.Database });
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      phrase_hash TEXT,
      created_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS deposit_orders (
      id TEXT PRIMARY KEY,
      user_id INTEGER,
      asset TEXT,
      amount REAL,
      status TEXT,
      created_at INTEGER,
      received_at INTEGER,
      scheduled_credit_at INTEGER,
      credited_at INTEGER,
      txid TEXT,
      swift_ref TEXT
    );
  `);
  console.log('Database ready');
})();

// ---------- Helper: generate 7 random words ----------
const wordList = [
  "abandon", "ability", "able", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access",
  "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act", "action",
  "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit", "adult",
  "advance", "advice", "aerobic", "affair", "afford", "afraid", "africa", "africa", "after", "again",
  "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol",
  "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter",
  "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger",
  "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
  "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area",
  "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest", "arrive", "arrow",
  "art", "artifact", "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma",
  "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt",
  "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful",
  "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo",
  "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket", "battle", "beach"
];
function generatePhrase() {
  const words = [];
  for (let i = 0; i < 7; i++) {
    const randomIndex = crypto.randomInt(0, wordList.length);
    words.push(wordList[randomIndex]);
  }
  return words.join(' ');
}

// ---------- Routes ----------
app.post('/api/register', async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required' });
  const existing = await db.get(`SELECT id FROM users WHERE email = ?`, [email]);
  if (existing) return res.status(400).json({ error: 'Email already registered' });
  const phrase = generatePhrase();
  const phrase_hash = await bcrypt.hash(phrase, 10);
  await db.run(`INSERT INTO users (email, phrase_hash, created_at) VALUES (?, ?, ?)`, [email, phrase_hash, Date.now()]);
  res.json({ message: 'Registration successful', phrase });
});

app.post('/api/login', async (req, res) => {
  const { email, phrase } = req.body;
  const user = await db.get(`SELECT id, email, phrase_hash FROM users WHERE email = ?`, [email]);
  if (!user) return res.status(401).json({ error: 'Invalid email or phrase' });
  const valid = await bcrypt.compare(phrase, user.phrase_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid email or phrase' });
  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, secure: false, maxAge: 7 * 24 * 3600000 });
  res.json({ user: { email: user.email } });
});

app.get('/api/me', authMiddleware, async (req, res) => {
  const orders = await db.all(`SELECT * FROM deposit_orders WHERE user_id = ? ORDER BY created_at DESC`, [req.user.userId]);
  res.json({ user: { email: req.user.email }, orders });
});

app.post('/api/create-order', authMiddleware, async (req, res) => {
  const { asset, amount } = req.body;
  if (!['BTC', 'ETH', 'USDT'].includes(asset)) return res.status(400).json({ error: 'Invalid asset' });
  if (!amount || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });
  const orderId = crypto.randomBytes(8).toString('hex').toUpperCase();
  await db.run(`
    INSERT INTO deposit_orders (id, user_id, asset, amount, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `, [orderId, req.user.userId, asset, amount, 'pending_match', Date.now()]);
  const address = asset === 'BTC' ? BTC_ADDRESS : ETH_ADDRESS;
  res.json({ orderId, asset, amount, address });
});

app.post('/api/check-transaction', authMiddleware, async (req, res) => {
  const { orderId } = req.body;
  const order = await db.get(`SELECT * FROM deposit_orders WHERE id = ? AND user_id = ?`, [orderId, req.user.userId]);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  if (order.status !== 'pending_match') return res.json({ message: 'Already processed', order });

  let tx = null;
  if (order.asset === 'BTC') {
    try {
      const url = `https://api.blockchair.com/bitcoin/dashboards/address/${BTC_ADDRESS}?transaction_details=true&limit=5`;
      const { data } = await axios.get(url);
      const txs = data.data[BTC_ADDRESS]?.transactions || [];
      tx = txs.find(t => Math.abs((t.result / 1e8) - order.amount) / order.amount < 0.01);
      if (tx) tx.txid = tx.hash;
    } catch(e) { console.error(e); }
  } else {
    const etherscanKey = process.env.ETHERSCAN_API_KEY;
    if (order.asset === 'ETH') {
      const url = `https://api.etherscan.io/api?module=account&action=txlist&address=${ETH_ADDRESS}&sort=desc&apikey=${etherscanKey}`;
      const { data } = await axios.get(url);
      if (data.status === '1') {
        tx = data.result.find(t => Math.abs((t.value / 1e18) - order.amount) / order.amount < 0.01);
        if (tx) tx.txid = tx.hash;
      }
    } else if (order.asset === 'USDT') {
      const url = `https://api.etherscan.io/api?module=account&action=tokentx&contractaddress=${USDT_CONTRACT}&address=${ETH_ADDRESS}&sort=desc&apikey=${etherscanKey}`;
      const { data } = await axios.get(url);
      if (data.status === '1') {
        tx = data.result.find(t => Math.abs((t.value / 1e6) - order.amount) / order.amount < 0.01);
        if (tx) tx.txid = tx.hash;
      }
    }
  }

  if (tx) {
    const now = Date.now();
    const creditDelay = 48 * 60 * 60 * 1000;
    await db.run(`
      UPDATE deposit_orders
      SET status = 'received', received_at = ?, scheduled_credit_at = ?, txid = ?
      WHERE id = ?
    `, [now, now + creditDelay, tx.txid, order.id]);
    res.json({ status: 'received', order: { ...order, status: 'received', received_at: now, scheduled_credit_at: now + creditDelay, txid: tx.txid } });
  } else {
    res.json({ status: 'pending_match', message: 'No matching transaction found yet' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out' });
});

// ---------- Background credit processor ----------
async function processCredits() {
  const now = Date.now();
  const toCredit = await db.all(`SELECT * FROM deposit_orders WHERE status = 'received' AND scheduled_credit_at <= ?`, [now]);
  for (const order of toCredit) {
    const swiftRef = 'SWIFT' + crypto.randomBytes(4).toString('hex').toUpperCase();
    await db.run(`UPDATE deposit_orders SET status = 'credited', credited_at = ?, swift_ref = ? WHERE id = ?`, [now, swiftRef, order.id]);
    console.log(`Bank credited order ${order.id}, SWIFT: ${swiftRef}`);
  }
}
setInterval(processCredits, 60000);

// ---------- Keep Render awake (self-ping every 4 minutes) ----------
const keepAlive = () => {
  const url = `http://localhost:${PORT}`;
  axios.get(url).catch(e => console.log('Keep-alive ping failed', e.message));
};
setInterval(keepAlive, 4 * 60 * 1000);

function authMiddleware(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch(e) { res.status(401).json({ error: 'Invalid token' }); }
}

const path = require('path');
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Nexus Vault running on http://localhost:${PORT}`);
  console.log(`Monitoring BTC: ${BTC_ADDRESS}`);
  console.log(`Monitoring ETH & USDT: ${ETH_ADDRESS}`);
});