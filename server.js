/**
 * server.js
 * NovaHub Unified Backend:
 * - Auth (email + Google + Discord)
 * - Obfuscator integration (CLI)
 * - Storage + scripts
 * - ALU logs
 * - Roblox restriction on /retrieve/:key
 * - File uploads
 *
 * Required env:
 * DATABASE_URL, JWT_SECRET, JWT_REFRESH_SECRET, SESSION_SECRET,
 * DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI,
 * GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI,
 * SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS,
 * CLI_LAUNCH_CMD, TEMP_DIR (optional)
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const nodemailer = require('nodemailer');

const app = express();
const PORT = Number(process.env.PORT || 4000);
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_access_secret_change_me';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev_refresh_secret_change_me';
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev_session_secret_change_me';
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '';
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || '';
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || 'https://novahub-zd14.onrender.com/auth/discord/callback';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || 'https://novahub-zd14.onrender.com/auth/google/callback';
const CLI_LAUNCH_CMD = process.env.CLI_LAUNCH_CMD || 'lua src/cli.lua';
const TEMP_DIR = process.env.TEMP_DIR || require('os').tmpdir();
const MAX_CONCURRENCY = Number(process.env.MAX_CONCURRENCY || 2);
const ACCESS_EXP = process.env.ACCESS_EXP || '1h';
const REFRESH_EXP = process.env.REFRESH_EXP || '30d';

if (!DATABASE_URL) {
  console.error('DATABASE_URL is required');
  process.exit(1);
}

const pool = new Pool({ connectionString: DATABASE_URL });

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Email transporter
const smtpTransport = nodemailer.createTransport({
  host: process.env.SMTP_HOST || '',
  port: Number(process.env.SMTP_PORT || 587),
  secure: Number(process.env.SMTP_PORT || 587) === 465,
  auth: {
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || ''
  }
});

// ensure tables
async function ensureTables() {
  const c = await pool.connect();
  try {
    await c.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE,
        email_verified BOOLEAN DEFAULT false,
        username TEXT,
        password_hash TEXT,
        discord_id TEXT UNIQUE,
        discord_avatar TEXT,
        google_id TEXT UNIQUE,
        role TEXT DEFAULT 'user',
        refresh_token TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    await c.query(`
      CREATE TABLE IF NOT EXISTS scripts (
        key VARCHAR(64) PRIMARY KEY,
        script TEXT NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        uses INTEGER DEFAULT 0,
        last_used_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        title TEXT
      );
    `);
    await c.query(`
      CREATE TABLE IF NOT EXISTS alu_logs (
        id SERIAL PRIMARY KEY,
        script_key VARCHAR(64),
        user_id INTEGER,
        event_type TEXT,
        ip TEXT,
        user_agent TEXT,
        extra JSONB,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    await c.query(`CREATE TABLE IF NOT EXISTS email_codes ( id SERIAL PRIMARY KEY, user_id INTEGER, code TEXT, expires_at TIMESTAMPTZ );`);
    console.log('DB tables ensured');
  } finally {
    c.release();
  }
}
ensureTables().catch(e => { console.error(e); process.exit(1); });

// utils
const genId = (bytes = 16) => crypto.randomBytes(bytes).toString('hex');
function signAccess(userId) { return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: ACCESS_EXP }); }
function signRefresh(userId) { return jwt.sign({ id: userId }, JWT_REFRESH_SECRET, { expiresIn: REFRESH_EXP }); }
function verifyAccess(token) { try { return jwt.verify(token, JWT_SECRET); } catch { return null; } }
function verifyRefresh(token) { try { return jwt.verify(token, JWT_REFRESH_SECRET); } catch { return null; } }
async function recordAluLog({ script_key = null, user_id = null, event_type = 'access', ip = null, user_agent = null, extra = {} } = {}) {
  try { await pool.query('INSERT INTO alu_logs(script_key, user_id, event_type, ip, user_agent, extra) VALUES($1,$2,$3,$4,$5,$6)', [script_key, user_id, event_type, ip, user_agent, extra]); }
  catch (e) { console.error('ALU log failed', e); }
}

// rate limiting
const authLimiter = rateLimit({ windowMs: 60*1000, max: 10 });
const obfLimiter = rateLimit({ windowMs: 60*1000, max: 6 });

// job queue for CLI concurrency
let activeJobs = 0;
const jobQueue = [];
function enqueueJob(fn) {
  return new Promise((resolve, reject) => {
    const job = async () => {
      try { activeJobs++; const result = await fn(); resolve(result); }
      catch (err) { reject(err); }
      finally { activeJobs--; if (jobQueue.length > 0 && activeJobs < MAX_CONCURRENCY) { const next = jobQueue.shift(); setImmediate(next); } }
    };
    if (activeJobs < MAX_CONCURRENCY) job();
    else jobQueue.push(job);
  });
}

// multer for file uploads
const upload = multer({ dest: path.join(TEMP_DIR, 'uploads'), limits: { fileSize: 10*1024*1024 } });

// find user helpers
async function findUserByEmail(email) {
  const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  return r.rows[0] || null;
}
async function findUserById(id) {
  const r = await pool.query('SELECT id,email,username,discord_id,discord_avatar,google_id,role,created_at,email_verified FROM users WHERE id=$1', [id]);
  return r.rows[0] || null;
}

async function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Missing Authorization header' });
  const token = (auth.split(' ')[1] || '').trim();
  if (!token) return res.status(401).json({ error: 'Missing token' });
  const payload = verifyAccess(token);
  if (!payload) return res.status(401).json({ error: 'Invalid or expired token' });
  req.userId = payload.id;
  next();
}

// --- Auth: email sign-up + verification code ---
app.post('/auth/register', authLimiter, async (req, res) => {
  try {
    const { email, password, username } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email & password required' });
    const exists = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
    if (exists.rows.length) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 12);
    const ins = await pool.query('INSERT INTO users(email, username, password_hash, email_verified) VALUES($1,$2,$3,$4) RETURNING id,email,username', [email, username || null, hash, false]);
    const user = ins.rows[0];
    // generate verification code
    const code = genId(12);
    const expires = new Date(Date.now() + (1000 * 60 * 60)); // 1 hour
    await pool.query('INSERT INTO email_codes(user_id, code, expires_at) VALUES($1,$2,$3)', [user.id, code, expires]);
    // send email
    try {
      const verifyUrl = `${process.env.SITE_ORIGIN || 'https://novahub-zd14.onrender.com'}/verify-email?code=${code}&uid=${user.id}`;
      await smtpTransport.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: user.email,
        subject: 'NovaHub Email Verification',
        text: `Your verification code: ${code}\nVisit ${verifyUrl} to verify.`,
        html: `<p>Your verification code: <b>${code}</b></p><p>Or click: <a href="${verifyUrl}">${verifyUrl}</a></p>`
      });
    } catch (e) {
      console.error('Failed to send verification email', e);
    }

    const access = signAccess(user.id);
    const refresh = signRefresh(user.id);
    await pool.query('UPDATE users SET refresh_token=$1 WHERE id=$2', [refresh, user.id]);
    res.status(201).json({ user: { id: user.id, email: user.email, username: user.username }, accessToken: access, refreshToken: refresh });
  } catch (err) { console.error('/auth/register', err); res.status(500).json({ error: 'Server error' }); }
});

app.post('/auth/verify-email', async (req, res) => {
  try {
    const { uid, code } = req.body || {};
    if (!uid || !code) return res.status(400).json({ error: 'Missing' });
    const r = await pool.query('SELECT * FROM email_codes WHERE user_id=$1 AND code=$2 AND expires_at > NOW()', [uid, code]);
    if (r.rows.length === 0) return res.status(400).json({ error: 'Invalid or expired code' });
    await pool.query('UPDATE users SET email_verified=true WHERE id=$1', [uid]);
    await pool.query('DELETE FROM email_codes WHERE user_id=$1', [uid]);
    res.json({ ok: true });
  } catch (err) { console.error('/auth/verify-email', err); res.status(500).json({ error: 'Server error' }); }
});

// login
app.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email & password required' });
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (r.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = r.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash || '');
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const access = signAccess(user.id);
    const refresh = signRefresh(user.id);
    await pool.query('UPDATE users SET refresh_token=$1 WHERE id=$2', [refresh, user.id]);
    res.json({ user: { id: user.id, email: user.email, username: user.username, role: user.role, email_verified: user.email_verified }, accessToken: access, refreshToken: refresh });
  } catch (err) { console.error('/auth/login', err); res.status(500).json({ error: 'Server error' }); }
});

app.post('/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return res.status(400).json({ error: 'Missing refreshToken' });
    const payload = verifyRefresh(refreshToken);
    if (!payload) return res.status(401).json({ error: 'Invalid refresh token' });
    const userId = payload.id;
    const r = await pool.query('SELECT refresh_token FROM users WHERE id=$1', [userId]);
    if (r.rows.length === 0) return res.status(401).json({ error: 'User not found' });
    if (r.rows[0].refresh_token !== refreshToken) return res.status(401).json({ error: 'Refresh token mismatch' });
    const newAccess = signAccess(userId);
    const newRefresh = signRefresh(userId);
    await pool.query('UPDATE users SET refresh_token=$1 WHERE id=$2', [newRefresh, userId]);
    res.json({ accessToken: newAccess, refreshToken: newRefresh });
  } catch (err) { console.error('/auth/refresh', err); res.status(500).json({ error: 'Server error' }); }
});

app.post('/auth/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return res.json({ ok: true });
    const payload = verifyRefresh(refreshToken);
    if (!payload) return res.json({ ok: true });
    const userId = payload.id;
    await pool.query('UPDATE users SET refresh_token=NULL WHERE id=$1', [userId]);
    res.json({ ok: true });
  } catch (err) { console.error('/auth/logout', err); res.status(500).json({ error: 'Server error' }); }
});

app.get('/auth/me', requireAuth, async (req, res) => {
  try {
    const u = await findUserById(req.userId);
    if (!u) return res.status(404).json({ error: 'User not found' });
    res.json(u);
  } catch (err) { console.error('/auth/me', err); res.status(500).json({ error: 'Server error' }); }
});

// ---------- Discord OAuth ----------
app.get('/auth/discord', (req, res) => {
  if (!DISCORD_CLIENT_ID || !DISCORD_REDIRECT_URI) return res.status(400).send('Discord OAuth not configured on server.');
  const state = genId(8);
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope: 'identify email',
    state
  });
  res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`);
});

app.get('/auth/discord/callback', async (req, res) => {
  if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !DISCORD_REDIRECT_URI) return res.status(400).send('Discord OAuth not configured.');
  const code = req.query.code;
  if (!code) return res.status(400).send('Missing code parameter.');
  try {
    const form = new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      client_secret: DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: DISCORD_REDIRECT_URI
    });
    const tokenResp = await fetch('https://discord.com/api/oauth2/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form.toString() });
    const tokenJson = await tokenResp.json();
    if (!tokenJson.access_token) { console.error('Discord token exchange failed', tokenJson); return res.status(500).send('Discord token exchange failed'); }
    const userResp = await fetch('https://discord.com/api/users/@me', { headers: { Authorization: `Bearer ${tokenJson.access_token}` } });
    const discordUser = await userResp.json();
    let user = (await pool.query('SELECT * FROM users WHERE discord_id=$1', [discordUser.id])).rows[0];
    if (!user) {
      const insert = await pool.query('INSERT INTO users (discord_id, username, discord_avatar) VALUES ($1,$2,$3) RETURNING id,discord_id,username,discord_avatar', [discordUser.id, discordUser.username, discordUser.avatar || null]);
      user = insert.rows[0];
    } else {
      await pool.query('UPDATE users SET username=$1, discord_avatar=$2 WHERE id=$3', [discordUser.username, discordUser.avatar || null, user.id]);
    }
    const access = signAccess(user.id);
    const refresh = signRefresh(user.id);
    await pool.query('UPDATE users SET refresh_token=$1 WHERE id=$2', [refresh, user.id]);
    res.send(`
      <html>
        <body>
          <script>
            (function(){
              const data = ${JSON.stringify({ accessToken: access, refreshToken: refresh, user: { id: user.id, discord_id: user.discord_id, username: user.username } })};
              if (window.opener && window.opener.postMessage) {
                window.opener.postMessage(data, '*');
              }
              document.write('Discord sign-in successful. You can close this window.');
            })();
          </script>
        </body>
      </html>
    `);
  } catch (err) {
    console.error('Discord callback error', err);
    res.status(500).send('Discord OAuth failed.');
  }
});

// ---------- Google OAuth ----------
app.get('/auth/google', (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_REDIRECT_URI) return res.status(400).send('Google OAuth not configured on server.');
  const state = genId(8);
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline',
    prompt: 'consent',
    state
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
});

app.get('/auth/google/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send('Missing code parameter.');
  try {
    const form = new URLSearchParams({
      code,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: GOOGLE_REDIRECT_URI,
      grant_type: 'authorization_code'
    });
    const tokenResp = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form.toString() });
    const tokenJson = await tokenResp.json();
    if (!tokenJson.id_token && !tokenJson.access_token) { console.error('Google token exchange failed', tokenJson); return res.status(500).send('Google token exchange failed'); }
    // Get user info
    const userInfoResp = await fetch(`https://www.googleapis.com/oauth2/v3/userinfo?access_token=${tokenJson.access_token}`);
    const googleUser = await userInfoResp.json();
    let user = (await pool.query('SELECT * FROM users WHERE google_id=$1 OR email=$2', [googleUser.sub, googleUser.email])).rows[0];
    if (!user) {
      const insert = await pool.query('INSERT INTO users (google_id, email, username, email_verified) VALUES ($1,$2,$3,$4) RETURNING id,google_id,email,username', [googleUser.sub, googleUser.email, googleUser.name, true]);
      user = insert.rows[0];
    } else {
      await pool.query('UPDATE users SET google_id=$1, email_verified=$2 WHERE id=$3', [googleUser.sub, true, user.id]);
    }
    const access = signAccess(user.id);
    const refresh = signRefresh(user.id);
    await pool.query('UPDATE users SET refresh_token=$1 WHERE id=$2', [refresh, user.id]);
    res.send(`
      <html><body><script>
        (function(){
          const data = ${JSON.stringify({ accessToken: access, refreshToken: refresh, user: { id: user.id, email: user.email, username: user.username } })};
          if (window.opener && window.opener.postMessage) { window.opener.postMessage(data, '*'); }
          document.write('Google sign-in successful. You can close this window.');
        })();
      </script></body></html>
    `);
  } catch (err) {
    console.error('Google callback error', err);
    res.status(500).send('Google OAuth failed.');
  }
});

// ---------- Obfuscator CLI integration ----------
function sanitizeFilename(name) { return name.replace(/[^a-zA-Z0-9_.-]/g, '_'); }
async function callObfuscatorCLI(rawLua, preset = 'Medium') {
  const ts = Date.now();
  const tmpIn = path.join(TEMP_DIR, `novahub_in_${ts}_${genId(4)}.lua`);
  const tmpOut = path.join(TEMP_DIR, `novahub_out_${ts}_${genId(4)}.lua`);
  try {
    fs.writeFileSync(tmpIn, rawLua, 'utf8');
    const cmd = `${CLI_LAUNCH_CMD} --preset ${sanitizeFilename(preset)} --out ${tmpOut} ${tmpIn}`;
    console.log('Running obfuscator CLI:', cmd);
    const execPromise = () => new Promise((resolve) => {
      const proc = exec(cmd, { timeout: 30_000, maxBuffer: 10*1024*1024 }, (err, stdout, stderr) => {
        try { if (fs.existsSync(tmpIn)) fs.unlinkSync(tmpIn); } catch {}
        if (err || stderr) {
          try { if (fs.existsSync(tmpOut)) fs.unlinkSync(tmpOut); } catch {}
          return resolve({ success: false, output: null, error: (err && err.message) || stderr });
        }
        if (!fs.existsSync(tmpOut)) return resolve({ success: false, output: null, error: 'No output produced' });
        try {
          const out = fs.readFileSync(tmpOut, 'utf8');
          try { fs.unlinkSync(tmpOut); } catch {}
          return resolve({ success: true, output: out, error: null });
        } catch (e) {
          return resolve({ success: false, output: null, error: e.message });
        }
      });
    });
    const result = await enqueueJob(execPromise);
    return result;
  } catch (err) {
    try { if (fs.existsSync(tmpIn)) fs.unlinkSync(tmpIn); } catch {}
    try { if (fs.existsSync(tmpOut)) fs.unlinkSync(tmpOut); } catch {}
    return { success: false, output: null, error: err.message || String(err) };
  }
}

const WATERMARK = '--[[ v0.1.0 NovaHub Lua Obfuscator ]] ';
const FALLBACK = '--[[ OBFUSCATION FAILED: returning raw ]]';
function applyFallback(raw) { return `${FALLBACK}\n${raw}`; }

// Obfuscate (no store)
app.post('/obfuscate', obfLimiter, requireAuth, async (req, res) => {
  const { code, preset } = req.body || {};
  if (!code || typeof code !== 'string') return res.status(400).json({ error: 'Missing code' });
  try {
    const r = await callObfuscatorCLI(code, preset || 'Medium');
    if (!r.success) { const fallback = applyFallback(code); return res.json({ obfuscatedCode: WATERMARK + fallback, success: false, error: r.error }); }
    const obf = WATERMARK + r.output;
    res.json({ obfuscatedCode: obf, success: true });
  } catch (err) { console.error('/obfuscate error', err); res.status(500).json({ error: 'Server error' }); }
});

// Obfuscate and store (create key)
app.post('/obfuscate-and-store', obfLimiter, requireAuth, async (req, res) => {
  const { script, preset, title } = req.body || {};
  if (!script || typeof script !== 'string') return res.status(400).json({ error: 'Missing script' });
  try {
    const r = await callObfuscatorCLI(script, preset || 'Medium');
    let obf; let success = false;
    if (!r.success) { obf = applyFallback(script); success = false; } else { obf = WATERMARK + r.output; success = true; }
    const key = genId(16);
    await pool.query('INSERT INTO scripts(key, script, user_id, title) VALUES($1,$2,$3,$4)', [key, obf, req.userId, title || null]);
    await recordAluLog({ script_key: key, user_id: req.userId, event_type: 'create', ip: req.ip, user_agent: req.headers['user-agent'], extra: { preset: preset || 'Medium', success } });
    res.status(201).json({ key, success });
  } catch (err) { console.error('/obfuscate-and-store error', err); res.status(500).json({ error: 'Server error' }); }
});

// Retrieve (Roblox UA restricted)
app.get('/retrieve/:key', async (req, res) => {
  const key = req.params.key;
  if (!key) return res.status(400).send('-- Invalid key');
  const ua = req.headers['user-agent'] || '';
  const ip = req.ip || req.connection?.remoteAddress || '';
  try {
    const r = await pool.query('SELECT script, user_id FROM scripts WHERE key=$1', [key]);
    if (r.rows.length === 0) { await recordAluLog({ script_key: key, event_type: 'retrieve_not_found', ip, user_agent: ua, extra: {} }); res.setHeader('Content-Type', 'text/plain'); return res.status(404).send('-- Script Not Found.'); }
    const scriptRow = r.rows[0];
    // Roblox UA restriction - allow if header contains 'Roblox' OR a query override secret (not recommended public)
    if (!ua.includes('Roblox')) {
      // For loaders you may want to allow via a short-lived token; here we strictly enforce Roblox UA
      await recordAluLog({ script_key: key, user_id: scriptRow.user_id, event_type: 'retrieve_blocked_non_roblox', ip, user_agent: ua });
      res.setHeader('Content-Type', 'text/plain');
      return res.status(403).send('-- Access Denied. Retrieve only allowed to Roblox clients.');
    }
    await pool.query('UPDATE scripts SET uses = uses + 1, last_used_at = NOW() WHERE key=$1', [key]);
    await recordAluLog({ script_key: key, user_id: scriptRow.user_id, event_type: 'retrieve', ip, user_agent: ua, extra: { maybeRoblox: ua.includes('Roblox') } });
    res.setHeader('Content-Type', 'text/plain');
    return res.send(scriptRow.script);
  } catch (err) { console.error('/retrieve error', err); res.setHeader('Content-Type', 'text/plain'); return res.status(500).send('-- Internal Server Error.'); }
});

// Script management endpoints (protected)
app.get('/api/scripts', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT key, title, uses, created_at, last_used_at, script FROM scripts WHERE user_id=$1 ORDER BY created_at DESC', [req.userId]);
    res.json(r.rows);
  } catch (err) { console.error('/api/scripts', err); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/scripts/:key', requireAuth, async (req, res) => {
  try {
    const key = req.params.key;
    const r = await pool.query('SELECT key, title, uses, created_at, last_used_at, script FROM scripts WHERE key=$1 AND user_id=$2', [key, req.userId]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    res.json(r.rows[0]);
  } catch (err) { console.error('/api/scripts/:key', err); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/scripts/:key', requireAuth, async (req, res) => {
  try {
    const key = req.params.key;
    const r = await pool.query('DELETE FROM scripts WHERE key=$1 AND user_id=$2', [key, req.userId]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'Not found or not owned' });
    await recordAluLog({ script_key: key, user_id: req.userId, event_type: 'delete', ip: req.ip, user_agent: req.headers['user-agent'] });
    res.json({ ok: true });
  } catch (err) { console.error('DELETE /api/scripts/:key', err); res.status(500).json({ error: 'Server error' }); }
});

// ALU logs & stats (admin)
app.get('/api/alu/logs', requireAuth, async (req, res) => {
  try {
    const user = await pool.query('SELECT role FROM users WHERE id=$1', [req.userId]);
    if (user.rows.length === 0) return res.status(401).json({ error: 'User not found' });
    if (user.rows[0].role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    const limit = Math.min(200, Number(req.query.limit || 50));
    const r = await pool.query('SELECT * FROM alu_logs ORDER BY created_at DESC LIMIT $1', [limit]);
    res.json(r.rows);
  } catch (err) { console.error('/api/alu/logs', err); res.status(500).json({ error: 'Server error' }); }
});

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
  } catch (err) { console.error('/api/alu/stats', err); res.status(500).json({ error: 'Server error' }); }
});

// user activity
app.get('/api/user/activity', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM alu_logs WHERE user_id=$1 ORDER BY created_at DESC LIMIT 200', [req.userId]);
    res.json(r.rows);
  } catch (err) { console.error('/api/user/activity', err); res.status(500).json({ error: 'Server error' }); }
});

// Basic file upload endpoint (obfuscator helper)
app.post('/api/upload', requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const content = fs.readFileSync(req.file.path, 'utf8');
    fs.unlinkSync(req.file.path);
    res.json({ content });
  } catch (err) { console.error('/api/upload', err); res.status(500).json({ error: 'Server error' }); }
});

// simple health + root
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`NovaHub server listening on port ${PORT}`));
