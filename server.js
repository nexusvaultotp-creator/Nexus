require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3');
const sqlite = require('sqlite');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const axios = require('axios');
const cron = require('node-cron');
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

// Database setup
let db;
(async () => {
  db = await sqlite.open({
    filename: './nexus.db',
    driver: sqlite3.Database
  });
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      password_hash TEXT,
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
    CREATE TABLE IF NOT EXISTS email_otp (
      email TEXT PRIMARY KEY,
      otp TEXT,
      expires_at INTEGER
    );
  `);
  console.log('✅ Database ready');
})();

// Email transporter (Gmail with app password)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  }
});

// Verify transporter connection on startup
transporter.verify((error, success) => {
  if (error) {
    console.error('❌ Gmail transporter error:', error);
  } else {
    console.log('✅ Gmail transporter ready');
  }
});

async function sendOtpEmail(toEmail, otpCode) {
  try {
    const info = await transporter.sendMail({
      from: `"Nexus Vault" <${process.env.GMAIL_USER}>`,
      to: toEmail,
      subject: 'Your Nexus Settlement OTP',
      text: `Your OTP is: ${otpCode}. Valid for 5 minutes.`,
      html: `<h3>OTP: ${otpCode}</h3><p>Valid for 5 minutes.</p>`
    });
    console.log(`📧 OTP sent to ${toEmail} - Message ID: ${info.messageId}`);
    return true;
  } catch (err) {
    console.error(`❌ Failed to send OTP to ${toEmail}:`, err.message);
    return false;
  }
}

function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Routes
app.post('/api/request-otp', async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email required' });
  }
  const otp = generateOtp();
  const expiresAt = Date.now() + 5 * 60 * 1000;
  await db.run(`INSERT OR REPLACE INTO email_otp (email, otp, expires_at) VALUES (?, ?, ?)`, [email, otp, expiresAt]);
  const sent = await sendOtpEmail(email, otp);
  if (sent) {
    res.json({ message: 'OTP sent to your email' });
  } else {
    res.status(500).json({ error: 'Failed to send OTP. Check server logs.' });
  }
});

app.post('/api/register', async (req, res) => {
  const { email, password, otp } = req.body;
  const otpRecord = await db.get(`SELECT otp, expires_at FROM email_otp WHERE email = ?`, [email]);
  if (!otpRecord || otpRecord.otp !== otp || Date.now() > otpRecord.expires_at) {
    return res.status(400).json({ error: 'Invalid or expired OTP' });
  }
  const existing = await db.get(`SELECT id FROM users WHERE email = ?`, [email]);
  if (existing) return res.status(400).json({ error: 'Email already registered' });
  const hashed = await bcrypt.hash(password, 10);
  await db.run(`INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)`, [email, hashed, Date.now()]);
  await db.run(`DELETE FROM email_otp WHERE email = ?`, [email]);
  res.json({ message: 'Registration successful' });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await db.get(`SELECT id, email, password_hash FROM users WHERE email = ?`, [email]);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, secure: false, maxAge: 7 * 24 * 3600000 });
  res.json({ user: { email: user.email } });
});

function authMiddleware(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch(e) { res.status(401).json({ error: 'Invalid token' }); }
}

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

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out' });
});

// Background jobs with slower polling
async function fetchBTCTransactions() {
  try {
    const url = `https://api.blockchair.com/bitcoin/dashboards/address/${BTC_ADDRESS}?transaction_details=true&limit=5`;
    const { data } = await axios.get(url);
    const addrData = data.data[BTC_ADDRESS];
    if (!addrData || !addrData.transactions) return [];
    return addrData.transactions.map(tx => ({
      txid: tx.hash,
      amount: tx.result / 1e8,
      timestamp: tx.time * 1000,
      asset: 'BTC'
    }));
  } catch(e) {
    console.error('BTC fetch error:', e.message);
    return [];
  }
}

async function fetchETHTransactions() {
  try {
    const url = `https://api.etherscan.io/api?module=account&action=txlist&address=${ETH_ADDRESS}&sort=desc&apikey=${process.env.ETHERSCAN_API_KEY}`;
    const { data } = await axios.get(url);
    if (data.status !== '1') return [];
    return data.result.slice(0, 5).map(tx => ({
      txid: tx.hash,
      amount: tx.value / 1e18,
      timestamp: tx.timeStamp * 1000,
      asset: 'ETH'
    }));
  } catch(e) { console.error('ETH error:', e.message); return []; }
}

async function fetchUSDTTransactions() {
  try {
    const url = `https://api.etherscan.io/api?module=account&action=tokentx&contractaddress=${USDT_CONTRACT}&address=${ETH_ADDRESS}&sort=desc&apikey=${process.env.ETHERSCAN_API_KEY}`;
    const { data } = await axios.get(url);
    if (data.status !== '1') return [];
    return data.result.slice(0, 5).map(tx => ({
      txid: tx.hash,
      amount: tx.value / 1e6,
      timestamp: tx.timeStamp * 1000,
      asset: 'USDT'
    }));
  } catch(e) { console.error('USDT error:', e.message); return []; }
}

async function matchIncomingTransactions() {
  const [btcTxs, ethTxs, usdtTxs] = await Promise.all([
    fetchBTCTransactions(),
    fetchETHTransactions(),
    fetchUSDTTransactions()
  ]);
  const allTxs = [...btcTxs, ...ethTxs, ...usdtTxs];
  const twoHoursAgo = Date.now() - 2 * 60 * 60 * 1000;
  const pendingOrders = await db.all(`
    SELECT * FROM deposit_orders 
    WHERE status = 'pending_match' AND created_at > ?
  `, [twoHoursAgo]);
  
  for (const tx of allTxs) {
    const existing = await db.get(`SELECT id FROM deposit_orders WHERE txid = ?`, [tx.txid]);
    if (existing) continue;
    const match = pendingOrders.find(order => 
      order.asset === tx.asset && 
      Math.abs(order.amount - tx.amount) / order.amount < 0.01
    );
    if (match) {
      const now = Date.now();
      const creditDelay = 48 * 60 * 60 * 1000; // 48 hours
      await db.run(`
        UPDATE deposit_orders 
        SET status = 'received', received_at = ?, scheduled_credit_at = ?, txid = ?
        WHERE id = ?
      `, [now, now + creditDelay, tx.txid, match.id]);
      console.log(`✅ Matched ${tx.asset} ${tx.amount} for order ${match.id}`);
    }
  }
}

async function processCredits() {
  const now = Date.now();
  const toCredit = await db.all(`
    SELECT * FROM deposit_orders WHERE status = 'received' AND scheduled_credit_at <= ?
  `, [now]);
  for (const order of toCredit) {
    const swiftRef = 'SWIFT' + crypto.randomBytes(4).toString('hex').toUpperCase();
    await db.run(`
      UPDATE deposit_orders SET status = 'credited', credited_at = ?, swift_ref = ? WHERE id = ?
    `, [now, swiftRef, order.id]);
    console.log(`🏦 Bank credited order ${order.id}, SWIFT: ${swiftRef}`);
  }
}

// Poll every 60 seconds (instead of 30) to avoid 430 error
cron.schedule('*/60 * * * * *', matchIncomingTransactions);
cron.schedule('* * * * *', processCredits);

// Serve frontend
const path = require('path');
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Nexus Settlement running on http://localhost:${PORT}`);
  console.log(`📡 Monitoring BTC: ${BTC_ADDRESS}`);
  console.log(`📡 Monitoring ETH & USDT: ${ETH_ADDRESS}`);
});