// server.js
// NovaHub unified server: OAuth (Discord + Google), email verification, obfuscation storage, ALU logs, Discord presence, file uploads, rate-limiting.
//
// Make sure to set required ENV variables (listed at the bottom of this file).
// Dependencies: express, pg, axios, multer, dotenv, cors, jsonwebtoken, bcrypt, express-rate-limit, nodemailer, uuid, child_process

require('dotenv').config();

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Basic middleware ----------
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));
app.use(express.static('public'));

// ---------- Rate limiter ----------
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 250,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', apiLimiter);

// ---------- DB: Postgres ----------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

async function ensureTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT UNIQUE,
      password_hash TEXT,
      discord_id TEXT,
      google_id TEXT,
      role TEXT DEFAULT 'user',
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
      verified BOOLEAN DEFAULT FALSE
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scripts (
      key VARCHAR(64) PRIMARY KEY,
      user_id UUID,
      title TEXT,
      script TEXT,
      uses INTEGER DEFAULT 0,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
      last_used_at TIMESTAMP WITH TIME ZONE
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS alu_logs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID,
      script_key VARCHAR(64),
      event_type TEXT,
      ip TEXT,
      user_agent TEXT,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS email_verifications (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT,
      code TEXT,
      expires_at TIMESTAMP WITH TIME ZONE
    );
  `);
}
ensureTables().catch(err => console.error('DB init error', err));

// ---------- Utilities ----------
const JWT_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

function signToken(payload, expires = '7d') {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: expires });
}

function requireAuth(req, res, next) {
  const auth = (req.headers.authorization || '').split(' ');
  if (auth.length !== 2 || auth[0] !== 'Bearer') return res.status(401).json({ error: 'Missing token' });
  try {
    const decoded = jwt.verify(auth[1], JWT_SECRET);
    req.user = decoded;
    req.userId = decoded.id;
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

async function isAdmin(userId) {
  if (!userId) return false;
  const r = await pool.query('SELECT role FROM users WHERE id=$1', [userId]);
  return r.rows.length && r.rows[0].role === 'admin';
}

function generateUniqueId() {
  return crypto.randomBytes(16).toString('hex');
}

// ---------- Email transporter (nodemailer) ----------
let transporter = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: (process.env.SMTP_SECURE === 'true'),
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
} else {
  console.warn('Nodemailer SMTP not configured. Email verification will fail until SMTP env provided.');
}

// ---------- Multer for uploads ----------
const upload = multer({ dest: path.join(__dirname, 'uploads/') });

// ---------- Obfuscator: spawn CLI (assumes lua obfuscator available at src/cli.lua) ----------
const WATERMARK = "--[[ v0.1.0 NovaHub Lua Obfuscator ]] ";
const FALLBACK_WATERMARK = "--[[ OBFUSCATION FAILED: Returning raw Lua. Check your syntax. ]] ";

async function runObfuscator(rawLua, preset = 'Medium') {
  const timestamp = Date.now();
  const tempFile = `/tmp/novahub_temp_${timestamp}.lua`;
  const outputFile = `/tmp/novahub_out_${timestamp}.lua`;
  try {
    fs.writeFileSync(tempFile, rawLua, 'utf8');
    const cmd = `lua src/cli.lua --preset ${preset} --out ${outputFile} ${tempFile}`;
    // Use a Promise wrapper to wait
    await new Promise((resolve) => {
      exec(cmd, { timeout: 30_000 }, (err, stdout, stderr) => {
        try { fs.unlinkSync(tempFile); } catch {}
        if (err || stderr || !fs.existsSync(outputFile)) {
          if (fs.existsSync(outputFile)) try { fs.unlinkSync(outputFile); } catch {}
          resolve(); // fallback later
          return;
        }
        resolve();
      });
    });
    if (fs.existsSync(outputFile)) {
      const obf = fs.readFileSync(outputFile, 'utf8');
      try { fs.unlinkSync(outputFile); } catch {}
      return { success: true, obfuscatedCode: WATERMARK + obf };
    } else {
      return { success: false, obfuscatedCode: FALLBACK_WATERMARK + "\n" + rawLua };
    }
  } catch (err) {
    return { success: false, obfuscatedCode: FALLBACK_WATERMARK + "\n" + rawLua };
  }
}

// ---------- ALU log helper ----------
async function recordAluLog({ script_key = null, user_id = null, event_type = 'access', ip = '0.0.0.0', user_agent = '' }) {
  try {
    await pool.query('INSERT INTO alu_logs(user_id, script_key, event_type, ip, user_agent) VALUES($1,$2,$3,$4,$5)', [user_id, script_key, event_type, ip, user_agent]);
  } catch (err) { console.error('ALU log error', err); }
}

// ---------- Public API endpoints ----------

/**
 * POST /auth/signup
 * { email, password }
 * => sends verification code via email
 */
app.post('/auth/signup', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });

  // Check if user exists
  const exists = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
  if (exists.rows.length) return res.status(400).json({ error: 'Email already registered' });

  // generate code
  const code = crypto.randomBytes(12).toString('hex'); // like bf1c8d...
  const expiresAt = new Date(Date.now() + 1000 * 60 * 15); // 15 min

  await pool.query('INSERT INTO email_verifications(email, code, expires_at) VALUES($1,$2,$3)', [email, code, expiresAt]);

  if (!transporter) {
    return res.status(500).json({ error: 'SMTP not configured (cannot send verification email)' });
  }

  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || `"NovaHub" <no-reply@novahub.local>`,
      to: email,
      subject: 'NovaHub verification code',
      text: `Your NovaHub verification code: ${code}\n\nIt expires in 15 minutes.`,
      html: `<p>Your NovaHub verification code: <b>${code}</b></p><p>It expires in 15 minutes.</p>`
    });
    return res.json({ ok: true, message: 'Verification email sent' });
  } catch (err) {
    console.error('Email send error', err);
    return res.status(500).json({ error: 'Failed to send email' });
  }
});

/**
 * POST /auth/verify
 * { email, code, username, password }
 * => verifies code and creates user account
 */
app.post('/auth/verify', async (req, res) => {
  const { email, code, username, password } = req.body || {};
  if (!email || !code || !password) return res.status(400).json({ error: 'Missing required fields' });

  const r = await pool.query('SELECT id, expires_at FROM email_verifications WHERE email=$1 AND code=$2', [email, code]);
  if (r.rows.length === 0) return res.status(400).json({ error: 'Invalid code' });
  if (new Date(r.rows[0].expires_at) < new Date()) {
    return res.status(400).json({ error: 'Code expired' });
  }

  const passwordHash = await bcrypt.hash(password, 10);

  try {
    const userId = uuidv4();
    await pool.query('INSERT INTO users(id, email, password_hash, verified, created_at) VALUES($1,$2,$3,$4,NOW())', [userId, email, passwordHash, true]);
    // delete verification row
    await pool.query('DELETE FROM email_verifications WHERE id=$1', [r.rows[0].id]);
    const token = signToken({ id: userId, email });
    return res.json({ ok: true, token });
  } catch (err) {
    console.error('Signup create user error', err);
    return res.status(500).json({ error: 'Failed to create user' });
  }
});

/**
 * POST /auth/login
 * { email, password }
 * => returns JWT token
 */
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });

  const r = await pool.query('SELECT id, password_hash, verified FROM users WHERE email=$1', [email]);
  if (!r.rows.length) return res.status(400).json({ error: 'Invalid credentials' });
  const u = r.rows[0];
  const ok = await bcrypt.compare(password, u.password_hash || '');
  if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
  if (!u.verified) return res.status(403).json({ error: 'Email not verified' });

  const token = signToken({ id: u.id, email });
  res.json({ ok: true, token });
});

/* ============================
   Discord OAuth (simple)
   ============================ */

// redirect to Discord's authorize URL
app.get('/auth/discord', (req, res) => {
  const clientId = process.env.DISCORD_CLIENT_ID;
  const redirect = process.env.DISCORD_REDIRECT_URI || `${process.env.BASE_URL || process.env.APP_URL || `https://localhost:${PORT}`}/auth/discord/callback`;
  if (!clientId) return res.status(500).send('Discord OAuth not configured.');

  const state = crypto.randomBytes(8).toString('hex');
  const scope = 'identify email';
  const url = `https://discord.com/oauth2/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirect)}&response_type=code&scope=${encodeURIComponent(scope)}&state=${state}`;
  res.redirect(url);
});

// callback
app.get('/auth/discord/callback', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.status(400).send('Missing code');

    const tokenRes = await axios.post('https://discord.com/api/oauth2/token', new URLSearchParams({
      client_id: process.env.DISCORD_CLIENT_ID,
      client_secret: process.env.DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: process.env.DISCORD_REDIRECT_URI
    }).toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const { access_token } = tokenRes.data;
    const userRes = await axios.get('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${access_token}` }
    });

    const profile = userRes.data;
    // Find or create user by discord id
    const q = await pool.query('SELECT id FROM users WHERE discord_id=$1', [profile.id]);
    let userId;
    if (q.rows.length) {
      userId = q.rows[0].id;
    } else {
      userId = uuidv4();
      await pool.query('INSERT INTO users(id, discord_id, email, verified, created_at) VALUES($1,$2,$3,$4,NOW())', [userId, profile.id, profile.email || null, true]);
    }

    const token = signToken({ id: userId, discord: profile.id, email: profile.email });
    // Pass token to popup or redirect with script to communicate to opener
    return res.send(`<script>window.opener.postMessage(${JSON.stringify({ accessToken: token })}, "*"); window.close();</script>`);
  } catch (err) {
    console.error('Discord OAuth failed', err.response?.data || err.message);
    return res.status(500).send('Discord OAuth failed.');
  }
});

/* ============================
   Google OAuth
   ============================ */

app.get('/auth/google', (req, res) => {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const redirect = process.env.GOOGLE_REDIRECT_URI;
  if (!clientId || !redirect) return res.status(500).send('Google OAuth not configured on server.');

  const state = crypto.randomBytes(8).toString('hex');
  const scope = ['openid','email','profile'].join(' ');
  const url = `https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirect)}&scope=${encodeURIComponent(scope)}&state=${state}&prompt=consent&access_type=offline`;
  res.redirect(url);
});

const qs = require('querystring');

app.get('/auth/google/callback', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.status(400).send('Missing code');

    // Exchange code for tokens
    const tokenResp = await axios.post('https://oauth2.googleapis.com/token',
      qs.stringify({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: process.env.GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code'
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const tokens = tokenResp.data;
    const profileResp = await axios.get('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });

    const profile = profileResp.data;
    // find or create user by google id or email
    let q = await pool.query('SELECT id FROM users WHERE google_id=$1 OR email=$2', [profile.sub, profile.email]);
    let userId;
    if (q.rows.length) {
      userId = q.rows[0].id;
      // update google_id if missing
      await pool.query('UPDATE users SET google_id=$1 WHERE id=$2', [profile.sub, userId]);
    } else {
      userId = uuidv4();
      await pool.query('INSERT INTO users(id, google_id, email, verified, created_at) VALUES($1,$2,$3,$4,NOW())', [userId, profile.sub, profile.email, true]);
    }

    const token = signToken({ id: userId, google: profile.sub, email: profile.email });
    return res.send(`<script>window.opener.postMessage(${JSON.stringify({ accessToken: token })}, "*"); window.close();</script>`);
  } catch (err) {
    console.error('GOOGLE ERROR:', err.response?.data || err.message);
    return res.status(500).send('Google OAuth failed.');
  }
});

/* ============================
   Obfuscator endpoints
   ============================ */

/**
 * POST /obfuscate
 * { code, preset }
 * Returns obfuscated code (no storage)
 */
app.post('/obfuscate', async (req, res) => {
  try {
    const { code, preset } = req.body || {};
    if (!code) return res.status(400).json({ error: 'Missing code' });
    const result = await runObfuscator(code, preset || 'Medium');
    return res.json({ obfuscatedCode: result.obfuscatedCode, success: result.success });
  } catch (err) {
    console.error('obfuscate error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

/**
 * POST /obfuscate-and-store
 * Authenticated: stores obfuscated script in DB and returns key
 * { script, preset, title }
 */
app.post('/obfuscate-and-store', requireAuth, async (req, res) => {
  try {
    const { script, preset, title } = req.body || {};
    if (!script) return res.status(400).json({ error: 'Missing script' });

    const obf = await runObfuscator(script, preset || 'Medium');
    const key = generateUniqueId();
    await pool.query('INSERT INTO scripts(key, user_id, title, script) VALUES($1,$2,$3,$4)', [key, req.userId, title || null, obf.obfuscatedCode]);
    return res.status(201).json({ key, success: obf.success });
  } catch (err) {
    console.error('store error', err);
    return res.status(500).json({ error: 'Storage Failure' });
  }
});

/**
 * GET /retrieve/:key
 * Roblox-only: serves plaintext script but only if User-Agent contains Roblox
 */
app.get('/retrieve/:key', async (req, res) => {
  try {
    const key = req.params.key;
    const ua = req.headers['user-agent'] || '';
    if (!ua.includes('Roblox')) {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(403).send('-- Access Denied: Not Roblox user agent.');
    }

    const q = await pool.query('SELECT script FROM scripts WHERE key=$1', [key]);
    if (!q.rows.length) return res.status(404).send('-- Script Not Found.');
    // increment uses, update last_used
    await pool.query('UPDATE scripts SET uses = COALESCE(uses,0)+1, last_used_at = NOW() WHERE key=$1', [key]);
    await recordAluLog({ script_key: key, user_id: null, event_type: 'retrieve', ip: req.ip, user_agent: ua });
    res.setHeader('Content-Type', 'text/plain');
    res.send(q.rows[0].script);
  } catch (err) {
    console.error('/retrieve error', err);
    res.status(500).send('-- Internal Server Error.');
  }
});

/* ============================
   Script management endpoints (protected)
   ============================ */

/**
 * GET /api/scripts
 * returns list of user's scripts with metadata
 */
app.get('/api/scripts', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT key, title, uses, created_at, last_used_at FROM scripts WHERE user_id=$1 ORDER BY created_at DESC', [req.userId]);
    res.json(r.rows);
  } catch (err) {
    console.error('/api/scripts', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * GET /api/scripts/:key
 * get single script metadata (owner only)
 */
app.get('/api/scripts/:key', requireAuth, async (req, res) => {
  try {
    const key = req.params.key;
    const r = await pool.query('SELECT key, title, uses, created_at, last_used_at, script FROM scripts WHERE key=$1 AND user_id=$2', [key, req.userId]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    res.json(r.rows[0]);
  } catch (err) {
    console.error('/api/scripts/:key', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * DELETE /api/scripts/:key
 */
app.delete('/api/scripts/:key', requireAuth, async (req, res) => {
  try {
    const key = req.params.key;
    const r = await pool.query('DELETE FROM scripts WHERE key=$1 AND user_id=$2', [key, req.userId]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'Not found or not owned' });

    await recordAluLog({ script_key: key, user_id: req.userId, event_type: 'delete', ip: req.ip, user_agent: req.headers['user-agent'] });
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/scripts/:key', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- ALU logs and stats endpoints (admin / user) ----------
/**
 * GET /api/alu/logs?limit=50
 * Admin only: see all logs (simple role check)
 */
app.get('/api/alu/logs', requireAuth, async (req, res) => {
  try {
    const user = await pool.query('SELECT role FROM users WHERE id=$1', [req.userId]);
    if (user.rows.length === 0) return res.status(401).json({ error: 'User not found' });
    if (user.rows[0].role !== 'admin') return res.status(403).json({ error: 'Admin only' });

    const limit = Math.min(200, Number(req.query.limit || 50));
    const r = await pool.query('SELECT * FROM alu_logs ORDER BY created_at DESC LIMIT $1', [limit]);
    res.json(r.rows);
  } catch (err) {
    console.error('/api/alu/logs', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * GET /api/alu/stats
 * Admin only: show basic stats (scripts count, total accesses, top scripts)
 */
app.get('/api/alu/stats', requireAuth, async (req, res) => {
  try {
    const user = await pool.query('SELECT role FROM users WHERE id=$1', [req.userId]);
    if (user.rows.length === 0) return res.status(401).json({ error: 'User not found' });
    if (user.rows[0].role !== 'admin') return res.status(403).json({ error: 'Admin only' });

    const totalScriptsR = await pool.query('SELECT COUNT(*) FROM scripts');
    const totalAccessR = await pool.query('SELECT COUNT(*) FROM alu_logs');
    const topScriptsR = await pool.query('SELECT script_key, COUNT(*) AS hits FROM alu_logs WHERE script_key IS NOT NULL GROUP BY script_key ORDER BY hits DESC LIMIT 10');

    res.json({
      totalScripts: Number(totalScriptsR.rows[0].count),
      totalAccessLogs: Number(totalAccessR.rows[0].count),
      topScripts: topScriptsR.rows
    });
  } catch (err) {
    console.error('/api/alu/stats', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * GET /api/user/activity
 * returns recent ALU logs for scripts owned by the user
 */
app.get('/api/user/activity', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM alu_logs WHERE user_id=$1 ORDER BY created_at DESC LIMIT 200', [req.userId]);
    res.json(r.rows);
  } catch (err) {
    console.error('/api/user/activity', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Discord presence webhook (basic) ----------
/**
 * POST /api/discord/presence
 * Headers: Authorization: Bearer <admin token>
 * Body: { userId, statusText, avatarUrl (optional) }
 * This is a simplified webhook to store presence or forward to a Discord bot.
 */
app.post('/api/discord/presence', requireAuth, async (req, res) => {
  try {
    const { userId, statusText, avatarUrl } = req.body || {};
    // Broadcast / store presence: For now we just log and store ALU log record (custom)
    await pool.query('INSERT INTO alu_logs(user_id, event_type, ip, user_agent) VALUES($1,$2,$3,$4)', [req.userId, 'presence_update', req.ip, req.headers['user-agent']]);
    // If you run a discord bot that changes presence, you'd forward this to bot with a webhook or IPC.
    res.json({ ok: true });
  } catch (err) {
    console.error('/api/discord/presence', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- File uploads (obfuscated file upload etc) ----------
app.post('/api/upload', requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Missing file' });
    const content = fs.readFileSync(req.file.path, 'utf8');
    // cleanup file
    fs.unlinkSync(req.file.path);
    // return file content quickly
    res.json({ ok: true, content });
  } catch (err) {
    console.error('upload error', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// ---------- Root and health ----------
app.get('/', (req, res) => res.send('NovaHub Unified Backend (auth + obfuscation + ALU)'));

// ---------- Start server ----------
app.listen(PORT, () => {
  console.log(`NovaHub server listening on port ${PORT}`);
  console.log('JWT secret (first 8 chars):', JWT_SECRET.slice(0,8));
});

/* ============================
   ENV variables checklist
   ============================
Required (for various features to work):
- DATABASE_URL        (Postgres connection)
- SESSION_SECRET      (optional, auto-generated otherwise)
- DISCORD_CLIENT_ID
- DISCORD_CLIENT_SECRET
- DISCORD_REDIRECT_URI
- GOOGLE_CLIENT_ID
- GOOGLE_CLIENT_SECRET
- GOOGLE_REDIRECT_URI
- SMTP_HOST           (for email verification via nodemailer)
- SMTP_PORT
- SMTP_USER
- SMTP_PASS
- SMTP_FROM           (optional, default will be used if not provided)
- BASE_URL or APP_URL (used for building redirects if you want)
Optional but recommended:
- NODE_ENV=production
- PORT
Notes:
- If you deploy to Render, set these environment variables in the Render dashboard.
- Be sure the redirect URIs you configured in Discord and Google exactly match the environment values.

Security note:
- Never share client secrets publicly. Treat them as secret environment variables.
*/
