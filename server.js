/**
 * server.js
 * Unified NovaHub backend (auth, obfuscation, ALU, uploads, Discord/Google OAuth, email verification via Gmail SMTP)
 *
 * Keep src/cli.lua available for the obfuscator CLI.
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
const nodemailer = require('nodemailer');
const multer = require('multer');
const os = require('os');
const fetch = (...args) => import('node-fetch').then(m => m.default(...args));

// ---------- Config ----------
const app = express();
const PORT = process.env.PORT ? Number(process.env.PORT) : 4000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-access-secret';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev-refresh-secret';
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '';
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || '';
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || '';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || '';
const CLI_LAUNCH_CMD = process.env.CLI_LAUNCH_CMD || 'lua src/cli.lua';
const TEMP_DIR = process.env.TEMP_DIR || os.tmpdir();
const MAX_CONCURRENCY = process.env.MAX_CONCURRENCY ? Number(process.env.MAX_CONCURRENCY) : 2;
const ACCESS_EXP = process.env.ACCESS_EXP || '1h';
const REFRESH_EXP = process.env.REFRESH_EXP || '30d';

// SMTP config (Gmail)
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 465;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const EMAIL_FROM = process.env.EMAIL_FROM || SMTP_USER || 'novahub@example.com';

// Optional Discord webhook to broadcast presence/alerts
const DISCORD_WEBHOOK = process.env.DISCORD_WEBHOOK || '';

// basic checks
if (!DATABASE_URL) {
  console.error('DATABASE_URL is required');
  process.exit(1);
}
if (!SMTP_USER || !SMTP_PASS) {
  console.warn('Warning: SMTP_USER or SMTP_PASS not set — email verification will not send real emails.');
}

// ---------- DB ----------
const pool = new Pool({ connectionString: DATABASE_URL });

// ---------- Middlewares ----------
app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Logger ----------
function log(...args) { console.log(new Date().toISOString(), ...args); }

// ---------- Utilities ----------
const genId = (b = 16) => crypto.randomBytes(b).toString('hex');
function signAccess(id) { return jwt.sign({ id }, JWT_SECRET, { expiresIn: ACCESS_EXP }); }
function signRefresh(id) { return jwt.sign({ id }, JWT_REFRESH_SECRET, { expiresIn: REFRESH_EXP }); }
function verifyAccess(token) { try { return jwt.verify(token, JWT_SECRET); } catch (e) { return null; } }
function verifyRefresh(token) { try { return jwt.verify(token, JWT_REFRESH_SECRET); } catch (e) { return null; } }
function sanitizeFilename(n) { return n.replace(/[^a-zA-Z0-9_.-]/g, '_'); }

// Nodemailer transport (Gmail)
const mailer = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_PORT === 465,
  auth: SMTP_USER && SMTP_PASS ? { user: SMTP_USER, pass: SMTP_PASS } : undefined
});

// send verification email (async)
async function sendVerificationEmail(toEmail, code) {
  if (!mailer) return false;
  const verifyUrl = ''; // optionally you can include an URL with code as param
  const html = `
    <div>
      <p>Hi —</p>
      <p>Your NovaHub verification code is <b>${code}</b></p>
      <p>If you did not request this, ignore this email.</p>
    </div>
  `;
  try {
    await mailer.sendMail({
      from: EMAIL_FROM,
      to: toEmail,
      subject: 'NovaHub — Email verification code',
      html
    });
    return true;
  } catch (err) {
    console.error('sendVerificationEmail error', err);
    return false;
  }
}

// ---------- Ensure DB tables ----------
async function ensureTables() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE,
        username TEXT,
        password_hash TEXT,
        discord_id TEXT UNIQUE,
        discord_avatar TEXT,
        google_id TEXT UNIQUE,
        role TEXT DEFAULT 'user',
        refresh_token TEXT,
        email_verified BOOLEAN DEFAULT FALSE,
        email_verif_code TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    await client.query(`
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

    await client.query(`
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

    log('DB tables ensured.');
  } finally {
    client.release();
  }
}
ensureTables().catch(err => { console.error('ensureTables err', err); process.exit(1); });

// ---------- Rate limiters ----------
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 12,
  message: { error: 'Too many auth attempts, slow down.' }
});
const obfLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 8,
  message: { error: 'Too many obfuscation requests, try later.' }
});

// ---------- Job concurrency for CLI ----------
let activeJobs = 0;
const jobQueue = [];
function enqueueJob(fn) {
  return new Promise((resolve, reject) => {
    const job = async () => {
      try {
        activeJobs++;
        const result = await fn();
        resolve(result);
      } catch (err) {
        reject(err);
      } finally {
        activeJobs--;
        if (jobQueue.length > 0 && activeJobs < MAX_CONCURRENCY) {
          const next = jobQueue.shift();
          setImmediate(next);
        }
      }
    };
    if (activeJobs < MAX_CONCURRENCY) job();
    else jobQueue.push(job);
  });
}

// ---------- ALU log helper ----------
async function recordAluLog({ script_key = null, user_id = null, event_type = 'access', ip = null, user_agent = null, extra = {} } = {}) {
  try {
    await pool.query('INSERT INTO alu_logs(script_key, user_id, event_type, ip, user_agent, extra) VALUES($1,$2,$3,$4,$5,$6)', [script_key, user_id, event_type, ip, user_agent, extra]);
  } catch (err) {
    console.error('recordAluLog error', err);
  }
}

// ---------- Auth middleware ----------
async function requireAuth(req, res, next) {
  try {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'Missing Authorization header' });
    const token = (auth.split(' ')[1] || '').trim();
    if (!token) return res.status(401).json({ error: 'Missing token' });
    const payload = verifyAccess(token);
    if (!payload) return res.status(401).json({ error: 'Invalid or expired token' });
    req.userId = payload.id;
    next();
  } catch (err) {
    console.error('requireAuth err', err); res.status(401).json({ error: 'Unauthorized' });
  }
}

// ---------- Helper user lookups ----------
async function findUserByEmail(email) {
  const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  return r.rows[0] || null;
}
async function findUserById(id) {
  const r = await pool.query('SELECT id,email,username,discord_id,discord_avatar,google_id,role,email_verified,created_at FROM users WHERE id=$1', [id]);
  return r.rows[0] || null;
}
async function findUserByDiscordId(did) {
  const r = await pool.query('SELECT * FROM users WHERE discord_id=$1', [did]);
  return r.rows[0] || null;
}
async function findUserByGoogleId(gid) {
  const r = await pool.query('SELECT * FROM users WHERE google_id=$1', [gid]);
  return r.rows[0] || null;
}

// ---------- AUTH endpoints ----------

/**
 * POST /auth/register
 * { email, password, username }
 * sends verification code to email (hex)
 */
app.post('/auth/register', authLimiter, async (req, res) => {
  try {
    const { email, password, username } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email & password required' });

    const exists = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
    if (exists.rows.length) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 12);
    const verCode = genId(12); // hex verification code
    const insert = await pool.query('INSERT INTO users(email, username, password_hash, email_verif_code) VALUES($1,$2,$3,$4) RETURNING id,email,username', [email, username || null, hash, verCode]);
    const user = insert.rows[0];

    // send email verification
    const sent = await sendVerificationEmail(email, verCode);
    if (!sent) log('Warning: verification email not sent (SMTP may be misconfigured)');

    res.status(201).json({ user: { id: user.id, email: user.email, username: user.username }, message: sent ? 'Verification email sent' : 'Verification code generated (email not sent)' });
  } catch (err) {
    console.error('/auth/register err', err); res.status(500).json({ error: 'Server error' });
  }
});

/**
 * POST /auth/verify-email
 * { email, code }
 */
app.post('/auth/verify-email', async (req, res) => {
  try {
    const { email, code } = req.body || {};
    if (!email || !code) return res.status(400).json({ error: 'email & code required' });
    const r = await pool.query('SELECT id, email_verif_code FROM users WHERE email=$1', [email]);
    if (r.rows.length === 0) return res.status(400).json({ error: 'User not found' });
    if (r.rows[0].email_verif_code !== code) return res.status(400).json({ error: 'Invalid code' });

    await pool.query('UPDATE users SET email_verified = TRUE, email_verif_code = NULL WHERE id=$1', [r.rows[0].id]);
    res.json({ ok: true, message: 'Email verified' });
  } catch (err) {
    console.error('/auth/verify-email err', err); res.status(500).json({ error: 'Server error' });
  }
});

/**
 * POST /auth/login
 * { email, password }  (only works if email_verified === true)
 */
app.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email & password required' });

    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (r.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = r.rows[0];

    const ok = await bcrypt.compare(password, user.password_hash || '');
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    if (!user.email_verified) return res.status(403).json({ error: 'Email not verified' });

    const access = signAccess(user.id);
    const refresh = signRefresh(user.id);
    await pool.query('UPDATE users SET refresh_token=$1 WHERE id=$2', [refresh, user.id]);

    res.json({ user: { id: user.id, email: user.email, username: user.username, role: user.role }, accessToken: access, refreshToken: refresh });
  } catch (err) {
    console.error('/auth/login err', err); res.status(500).json({ error: 'Server error' });
  }
});

/**
 * POST /auth/refresh
 * { refreshToken }
 */
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
  } catch (err) { console.error('/auth/refresh err', err); res.status(500).json({ error: 'Server error' }); }
});

/**
 * POST /auth/logout
 */
app.post('/auth/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return res.json({ ok: true });
    const payload = verifyRefresh(refreshToken);
    if (!payload) return res.json({ ok: true });
    const userId = payload.id;
    await pool.query('UPDATE users SET refresh_token = NULL WHERE id=$1', [userId]);
    res.json({ ok: true });
  } catch (err) { console.error('/auth/logout err', err); res.status(500).json({ error: 'Server error' }); }
});

/**
 * GET /auth/me
 */
app.get('/auth/me', requireAuth, async (req, res) => {
  try {
    const u = await findUserById(req.userId);
    if (!u) return res.status(404).json({ error: 'User not found' });
    res.json(u);
  } catch (err) { console.error('/auth/me err', err); res.status(500).json({ error: 'Server error' }); }
});

// ---------- OAuth: Discord ----------
app.get('/auth/discord', (req, res) => {
  if (!DISCORD_CLIENT_ID || !DISCORD_REDIRECT_URI) return res.status(400).send('Discord OAuth not configured.');
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
  if (!code) return res.status(400).send('Missing code.');

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
    if (!tokenJson.access_token) {
      console.error('Discord token exchange failed', tokenJson);
      return res.status(500).send('Discord token exchange failed');
    }

    const userResp = await fetch('https://discord.com/api/users/@me', { headers: { Authorization: `Bearer ${tokenJson.access_token}` } });
    const discordUser = await userResp.json();
    let user = await findUserByDiscordId(discordUser.id);

    if (!user) {
      const insert = await pool.query('INSERT INTO users (discord_id, username, discord_avatar, email_verified) VALUES ($1,$2,$3,$4) RETURNING id,discord_id,username,discord_avatar', [discordUser.id, discordUser.username, discordUser.avatar || null, true]);
      user = insert.rows[0];
    } else {
      await pool.query('UPDATE users SET username=$1, discord_avatar=$2 WHERE id=$3', [discordUser.username, discordUser.avatar || null, user.id]);
    }

    const access = signAccess(user.id);
    const refresh = signRefresh(user.id);
    await pool.query('UPDATE users SET refresh_token=$1 WHERE id=$2', [refresh, user.id]);

    // Post tokens back to opener (popup flow)
    res.send(`
      <html>
        <body>
          <script>
            (function(){
              const data = ${JSON.stringify({ accessToken: access, refreshToken: refresh, user: { id: user.id, username: user.username, discord_id: user.discord_id } })};
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
    console.error('Discord callback err', err);
    res.status(500).send('Discord OAuth failed.');
  }
});

// ---------- OAuth: Google (basic flow) ----------
app.get('/auth/google', (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_REDIRECT_URI) return res.status(400).send('Google OAuth not configured.');
  const state = genId(8);
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline',
    state
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
});

app.get('/auth/google/callback', async (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_REDIRECT_URI) return res.status(400).send('Google OAuth not configured.');
  const code = req.query.code;
  if (!code) return res.status(400).send('Missing code.');
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
    if (!tokenJson.access_token) { console.error('Google token failed', tokenJson); return res.status(500).send('Google token failed'); }

    const userResp = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', { headers: { Authorization: `Bearer ${tokenJson.access_token}` } });
    const guser = await userResp.json();

    // upsert by google id or email
    let user = await findUserByGoogleId(guser.id);
    if (!user) {
      // check by email first
      const byEmail = await pool.query('SELECT * FROM users WHERE email=$1', [guser.email]);
      if (byEmail.rows.length) {
        const existing = byEmail.rows[0];
        await pool.query('UPDATE users SET google_id=$1, email_verified=TRUE WHERE id=$2', [guser.id, existing.id]);
        user = { id: existing.id, username: existing.username || guser.name, email: existing.email };
      } else {
        const insert = await pool.query('INSERT INTO users (google_id, email, username, email_verified) VALUES ($1,$2,$3,$4) RETURNING id, email, username', [guser.id, guser.email, guser.name || null, true]);
        user = insert.rows[0];
      }
    } else {
      await pool.query('UPDATE users SET username=$1, email=$2 WHERE id=$3', [guser.name || null, guser.email || null, user.id]);
    }

    const access = signAccess(user.id);
    const refresh = signRefresh(user.id);
    await pool.query('UPDATE users SET refresh_token=$1 WHERE id=$2', [refresh, user.id]);

    res.send(`
      <html>
        <body>
          <script>
            (function(){
              const data = ${JSON.stringify({ accessToken: access, refreshToken: refresh, user: { id: user.id, email: user.email, username: user.username } })};
              if (window.opener && window.opener.postMessage) {
                window.opener.postMessage(data, '*');
              }
              document.write('Google sign-in successful. You can close this window.');
            })();
          </script>
        </body>
      </html>
    `);
  } catch (err) {
    console.error('Google callback err', err); res.status(500).send('Google OAuth failed.');
  }
});

// ---------- Obfuscation helpers ----------
async function callObfuscatorCLI(rawLua, preset = 'Medium') {
  const ts = Date.now();
  const tmpIn = path.join(TEMP_DIR, `novahub_in_${ts}_${genId(4)}.lua`);
  const tmpOut = path.join(TEMP_DIR, `novahub_out_${ts}_${genId(4)}.lua`);
  try {
    fs.writeFileSync(tmpIn, rawLua, 'utf8');
    const cmd = `${CLI_LAUNCH_CMD} --preset ${sanitizeFilename(preset)} --out ${tmpOut} ${tmpIn}`;
    log('Obf CMD', cmd);
    const execPromise = () => new Promise((resolve) => {
      exec(cmd, { timeout: 30_000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
        try { if (fs.existsSync(tmpIn)) fs.unlinkSync(tmpIn); } catch (e) {}
        if (err || stderr) {
          try { if (fs.existsSync(tmpOut)) fs.unlinkSync(tmpOut); } catch (e) {}
          return resolve({ success: false, output: null, error: (err && err.message) || stderr });
        }
        if (!fs.existsSync(tmpOut)) return resolve({ success: false, output: null, error: 'No output produced' });
        try {
          const out = fs.readFileSync(tmpOut, 'utf8');
          try { fs.unlinkSync(tmpOut); } catch (e) {}
          return resolve({ success: true, output: out, error: null });
        } catch (e) {
          return resolve({ success: false, output: null, error: e.message });
        }
      });
    });
    return await enqueueJob(execPromise);
  } catch (err) {
    try { if (fs.existsSync(tmpIn)) fs.unlinkSync(tmpIn); } catch (e) {}
    try { if (fs.existsSync(tmpOut)) fs.unlinkSync(tmpOut); } catch (e) {}
    return { success: false, output: null, error: err.message || String(err) };
  }
}
const WATERMARK = "--[[ v0.1.0 NovaHub Lua Obfuscator ]] ";
const FALLBACK = "--[[ OBFUSCATION FAILED: returning raw ]]";
function applyFallback(raw) { return `${FALLBACK}\n${raw}`; }

// ---------- Obfuscation endpoints ----------
app.post('/obfuscate', obfLimiter, requireAuth, async (req, res) => {
  const { code, preset } = req.body || {};
  if (!code || typeof code !== 'string') return res.status(400).json({ error: 'Missing code' });
  try {
    const r = await callObfuscatorCLI(code, preset || 'Medium');
    if (!r.success) return res.json({ obfuscatedCode: WATERMARK + applyFallback(code), success: false, error: r.error });
    res.json({ obfuscatedCode: WATERMARK + r.output, success: true });
  } catch (err) { console.error('/obfuscate err', err); res.status(500).json({ error: 'Server error' }); }
});

app.post('/obfuscate-and-store', obfLimiter, requireAuth, async (req, res) => {
  const { script, preset, title } = req.body || {};
  if (!script || typeof script !== 'string') return res.status(400).json({ error: 'Missing script' });
  try {
    const r = await callObfuscatorCLI(script, preset || 'Medium');
    let obf, success = false;
    if (!r.success) { obf = applyFallback(script); success = false; }
    else { obf = WATERMARK + r.output; success = true; }
    const key = genId(16);
    await pool.query('INSERT INTO scripts(key, script, user_id, title) VALUES($1,$2,$3,$4)', [key, obf, req.userId, title || null]);
    await recordAluLog({ script_key: key, user_id: req.userId, event_type: 'create', ip: req.ip, user_agent: req.headers['user-agent'], extra: { preset: preset || 'Medium', success } });
    res.status(201).json({ key, success });
  } catch (err) { console.error('/obfuscate-and-store err', err); res.status(500).json({ error: 'Server error' }); }
});

// ---------- Retrieve endpoint (Roblox restriction) ----------
app.get('/retrieve/:key', async (req, res) => {
  const key = req.params.key;
  if (!key) return res.status(400).send('-- Invalid key');
  const ua = req.headers['user-agent'] || '';
  const ip = req.ip || req.connection?.remoteAddress || '';

  // check UA: if not Roblox allow only if request includes debug param ?allow=true (for testing)
  const allowNonRoblox = req.query.allow === 'true';
  if (!ua.includes('Roblox') && !allowNonRoblox) {
    await recordAluLog({ script_key: key, event_type: 'retrieve_blocked_ua', ip, user_agent: ua, extra: {} });
    res.setHeader('Content-Type', 'text/plain');
    return res.status(403).send('-- Access Denied: loader endpoint restricted to Roblox UA.');
  }

  try {
    const r = await pool.query('SELECT script, user_id FROM scripts WHERE key=$1', [key]);
    if (r.rows.length === 0) {
      await recordAluLog({ script_key: key, event_type: 'retrieve_not_found', ip, user_agent: ua });
      res.setHeader('Content-Type', 'text/plain'); return res.status(404).send('-- Script Not Found.');
    }
    const scriptRow = r.rows[0];
    await pool.query('UPDATE scripts SET uses = uses + 1, last_used_at = NOW() WHERE key=$1', [key]);
    await recordAluLog({ script_key: key, user_id: scriptRow.user_id, event_type: 'retrieve', ip, user_agent: ua, extra: { maybeRoblox: ua.includes('Roblox') } });

    res.setHeader('Content-Type', 'text/plain');
    return res.send(scriptRow.script);
  } catch (err) {
    console.error('/retrieve err', err);
    res.setHeader('Content-Type', 'text/plain'); return res.status(500).send('-- Internal Server Error.');
  }
});

// ---------- Script management endpoints (protected) ----------
app.get('/api/scripts', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT key, title, uses, created_at, last_used_at FROM scripts WHERE user_id=$1 ORDER BY created_at DESC', [req.userId]);
    res.json(r.rows);
  } catch (err) { console.error('/api/scripts err', err); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/scripts/:key', requireAuth, async (req, res) => {
  try {
    const key = req.params.key;
    const r = await pool.query('SELECT key, title, uses, created_at, last_used_at, script FROM scripts WHERE key=$1 AND user_id=$2', [key, req.userId]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    res.json(r.rows[0]);
  } catch (err) { console.error('/api/scripts/:key err', err); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/scripts/:key', requireAuth, async (req, res) => {
  try {
    const key = req.params.key;
    const r = await pool.query('DELETE FROM scripts WHERE key=$1 AND user_id=$2', [key, req.userId]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'Not found or not owned' });
    await recordAluLog({ script_key: key, user_id: req.userId, event_type: 'delete', ip: req.ip, user_agent: req.headers['user-agent'] });
    res.json({ ok: true });
  } catch (err) { console.error('DELETE /api/scripts/:key err', err); res.status(500).json({ error: 'Server error' }); }
});

// ---------- ALU / admin endpoints ----------
app.get('/api/alu/logs', requireAuth, async (req, res) => {
  try {
    const user = await pool.query('SELECT role FROM users WHERE id=$1', [req.userId]);
    if (user.rows.length === 0) return res.status(401).json({ error: 'User not found' });
    if (user.rows[0].role !== 'admin') return res.status(403).json({ error: 'Admin only' });

    const limit = Math.min(200, Number(req.query.limit || 50));
    const r = await pool.query('SELECT * FROM alu_logs ORDER BY created_at DESC LIMIT $1', [limit]);
    res.json(r.rows);
  } catch (err) { console.error('/api/alu/logs err', err); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/alu/stats', requireAuth, async (req, res) => {
  try {
    const user = await pool.query('SELECT role FROM users WHERE id=$1', [req.userId]);
    if (user.rows.length === 0) return res.status(401).json({ error: 'User not found' });
    if (user.rows[0].role !== 'admin') return res.status(403).json({ error: 'Admin only' });

    const totalScriptsR = await pool.query('SELECT COUNT(*) FROM scripts');
    const totalAccessR = await pool.query('SELECT COUNT(*) FROM alu_logs');
    const topScriptsR = await pool.query(`SELECT script_key AS key, COUNT(*) AS hits FROM alu_logs WHERE script_key IS NOT NULL GROUP BY script_key ORDER BY hits DESC LIMIT 10`);

    res.json({
      totalScripts: Number(totalScriptsR.rows[0].count),
      totalAccessLogs: Number(totalAccessR.rows[0].count),
      topScripts: topScriptsR.rows
    });
  } catch (err) { console.error('/api/alu/stats err', err); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/user/activity', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM alu_logs WHERE user_id=$1 ORDER BY created_at DESC LIMIT 200', [req.userId]);
    res.json(r.rows);
  } catch (err) { console.error('/api/user/activity err', err); res.status(500).json({ error: 'Server error' }); }
});

// ---------- File uploads (optional) ----------
const upload = multer({ dest: path.join(TEMP_DIR, 'uploads') });
app.post('/api/upload', requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const content = fs.readFileSync(req.file.path, 'utf8');
    try { fs.unlinkSync(req.file.path); } catch (e) {}
    res.json({ ok: true, content });
  } catch (err) { console.error('/api/upload err', err); res.status(500).json({ error: 'Server error' }); }
});

// ---------- Presence endpoint (optional webhook) ----------
app.post('/api/presence', requireAuth, async (req, res) => {
  try {
    const { status, details } = req.body || {};
    // optionally send to discord webhook
    if (DISCORD_WEBHOOK) {
      try {
        await fetch(DISCORD_WEBHOOK, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content: `Presence update: user ${req.userId} — ${status || 'unknown'} — ${details || ''}` })
        });
      } catch (e) { console.error('webhook send err', e); }
    }
    res.json({ ok: true });
  } catch (err) { console.error('/api/presence err', err); res.status(500).json({ error: 'Server error' }); }
});

// ---------- Root / Health ----------
app.get('/', (req, res) => res.send('NovaHub Unified Backend (auth + obfuscation + ALU)'));

// ---------- Start ----------
app.listen(PORT, () => log(`NovaHub server listening on ${PORT}`));
