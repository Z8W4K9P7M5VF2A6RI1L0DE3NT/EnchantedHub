/**
 * server.js
 * Unified NovaHub backend (single-file).
 *
 * Features:
 *  - Email/password auth (bcrypt) + JWT access & refresh
 *  - Discord OAuth + Google OAuth
 *  - Discord bot presence backend (updates status when scripts are created)
 *  - Obfuscator CLI integration (safe temp files, concurrency limiter)
 *  - Postgres storage for scripts + ALU logs
 *  - /retrieve/:key restricted (Roblox UA recommended)
 *  - Rate limiting, file uploads (multer)
 *  - Serves frontend from public/
 *
 * NOTE: configure .env (see README in comments above)
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
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));
const os = require('os');
const multer = require('multer');
const axios = require('axios');

// If you want Discord bot presence:
let Discord;
try { Discord = require('discord.js'); } catch (e) { Discord = null; }

const app = express();
const PORT = process.env.PORT ? Number(process.env.PORT) : 4000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_change_me';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev_jwt_refresh_change_me';
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '';
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || '';
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || '';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || '';
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || '';
const CLI_LAUNCH_CMD = process.env.CLI_LAUNCH_CMD || 'lua src/cli.lua';
const TEMP_DIR = process.env.TEMP_DIR || os.tmpdir();
const MAX_CONCURRENCY = process.env.MAX_CONCURRENCY ? Number(process.env.MAX_CONCURRENCY) : 2;
const ACCESS_EXP = process.env.ACCESS_EXP || '1h';
const REFRESH_EXP = process.env.REFRESH_EXP || '30d';

// minimal env check
if (!DATABASE_URL) {
  console.error('ERROR: DATABASE_URL is required in environment.');
  process.exit(1);
}

// ---------- DB ----------
const pool = new Pool({ connectionString: DATABASE_URL });

// ---------- Express setup ----------
app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));
app.use(express.static('public'));

// ---------- Logger ----------
function log(...args) { console.log(new Date().toISOString(), ...args); }

// ---------- Helpers ----------
const genId = (bytes = 16) => crypto.randomBytes(bytes).toString('hex');

function signAccess(userId) { return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: ACCESS_EXP }); }
function signRefresh(userId) { return jwt.sign({ id: userId }, JWT_REFRESH_SECRET, { expiresIn: REFRESH_EXP }); }
function verifyAccess(token) { try { return jwt.verify(token, JWT_SECRET); } catch (e) { return null; } }
function verifyRefresh(token) { try { return jwt.verify(token, JWT_REFRESH_SECRET); } catch (e) { return null; } }

// ---------- Ensure tables ----------
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
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS scripts (
        key VARCHAR(64) PRIMARY KEY,
        script TEXT NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
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
    await client.query(`CREATE INDEX IF NOT EXISTS idx_alu_script_key ON alu_logs(script_key);`);
    log('DB: tables ensured');
  } finally {
    client.release();
  }
}
ensureTables().catch(err => {
  console.error('Failed to ensure DB tables:', err);
  process.exit(1);
});

// ---------- Rate limiters ----------
const authLimiter = rateLimit({ windowMs: 60 * 1000, max: 10, message: { error: 'Too many requests, slow down.' } });
const obfLimiter = rateLimit({ windowMs: 60 * 1000, max: 6, message: { error: 'Too many obfuscation requests, try again later.' } });

// ---------- Concurrency limiter ----------
let activeJobs = 0;
const jobQueue = [];
function enqueueJob(fn) {
  return new Promise((resolve, reject) => {
    const job = async () => {
      try {
        activeJobs++;
        const r = await fn();
        resolve(r);
      } catch (e) { reject(e); }
      finally {
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

// ---------- Middleware: requireAuth ----------
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

// ---------- Small DB helpers ----------
async function findUserByEmail(email) {
  const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  return r.rows[0] || null;
}
async function findUserById(id) {
  const r = await pool.query('SELECT id,email,username,discord_id,discord_avatar,google_id,role,created_at FROM users WHERE id=$1', [id]);
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

// ---------- ALU logging ----------
async function recordAluLog({ script_key = null, user_id = null, event_type = 'access', ip = null, user_agent = null, extra = {} } = {}) {
  try {
    await pool.query(`INSERT INTO alu_logs(script_key, user_id, event_type, ip, user_agent, extra) VALUES($1,$2,$3,$4,$5,$6)`, [script_key, user_id, event_type, ip, user_agent, extra]);
  } catch (err) {
    console.error('ALU log failed:', err);
  }
}

// ---------- Auth endpoints ----------
/**
 * POST /auth/register
 * body: { email, password, username? }
 */
app.post('/auth/register', authLimiter, async (req, res) => {
  try {
    const { email, password, username } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email & password required' });

    const exists = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
    if (exists.rows.length) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 12);
    const insert = await pool.query('INSERT INTO users(email, username, password_hash) VALUES($1,$2,$3) RETURNING id,email,username', [email, username || null, hash]);
    const user = insert.rows[0];

    const access = signAccess(user.id);
    const refresh = signRefresh(user.id);
    await pool.query('UPDATE users SET refresh_token=$1 WHERE id=$2', [refresh, user.id]);

    res.status(201).json({ user: { id: user.id, email: user.email, username: user.username }, accessToken: access, refreshToken: refresh });
  } catch (err) {
    console.error('/auth/register error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * POST /auth/login
 * body: { email, password }
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

    const access = signAccess(user.id);
    const refresh = signRefresh(user.id);
    await pool.query('UPDATE users SET refresh_token=$1 WHERE id=$2', [refresh, user.id]);

    res.json({ user: { id: user.id, email: user.email, username: user.username, role: user.role }, accessToken: access, refreshToken: refresh });
  } catch (err) {
    console.error('/auth/login error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * POST /auth/refresh
 * body { refreshToken }
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
  } catch (err) {
    console.error('/auth/refresh error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * POST /auth/logout
 * body { refreshToken? }
 */
app.post('/auth/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return res.json({ ok: true });
    const payload = verifyRefresh(refreshToken);
    if (!payload) return res.json({ ok: true });
    const userId = payload.id;
    await pool.query('UPDATE users SET refresh_token=NULL WHERE id=$1', [userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error('/auth/logout', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * GET /auth/me
 */
app.get('/auth/me', requireAuth, async (req, res) => {
  try {
    const u = await findUserById(req.userId);
    if (!u) return res.status(404).json({ error: 'User not found' });
    res.json(u);
  } catch (err) {
    console.error('/auth/me', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Discord OAuth (server side) ----------
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
  // In prod, store 'state' in cookie/redis to validate on callback (omitted for brevity)
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
    if (!tokenJson.access_token) {
      console.error('Discord token exchange failed', tokenJson);
      return res.status(500).send('Discord token exchange failed');
    }
    const userResp = await fetch('https://discord.com/api/users/@me', { headers: { Authorization: `Bearer ${tokenJson.access_token}` } });
    const discordUser = await userResp.json();

    let user = await findUserByDiscordId(discordUser.id);
    if (!user) {
      const insert = await pool.query('INSERT INTO users (discord_id, username, discord_avatar) VALUES ($1,$2,$3) RETURNING id,discord_id,username,discord_avatar', [discordUser.id, discordUser.username, discordUser.avatar || null]);
      user = insert.rows[0];
    } else {
      await pool.query('UPDATE users SET username=$1, discord_avatar=$2 WHERE id=$3', [discordUser.username, discordUser.avatar || null, user.id]);
    }

    const access = signAccess(user.id);
    const refresh = signRefresh(user.id);
    await pool.query('UPDATE users SET refresh_token=$1 WHERE id=$2', [refresh, user.id]);

    // send simple page that posts data to opener (useful for popup flows)
    res.send(`
      <html><body>
      <script>
        (function(){
          const data = ${JSON.stringify({ accessToken: access, refreshToken: refresh, user: { id: user.id, discord_id: user.discord_id, username: user.username } })};
          if (window.opener && window.opener.postMessage) {
            window.opener.postMessage(data, '*');
          }
          document.write('Discord sign-in successful. You can close this window.');
        })();
      </script>
      </body></html>
    `);
  } catch (err) {
    console.error('Discord callback error', err);
    res.status(500).send('Discord OAuth failed.');
  }
});

// ---------- Google OAuth (server side) ----------
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
  if (!code) return res.status(400).send('Missing code parameter.');
  try {
    const form = new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: GOOGLE_REDIRECT_URI
    });
    const tokenResp = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form.toString() });
    const tokenJson = await tokenResp.json();
    if (!tokenJson.id_token) {
      console.error('Google token exchange failed', tokenJson);
      return res.status(500).send('Google token exchange failed');
    }
    // decode ID token (minimal)
    const idTokenParts = tokenJson.id_token.split('.');
    const payload = JSON.parse(Buffer.from(idTokenParts[1], 'base64').toString('utf8'));
    const googleId = payload.sub;
    const email = payload.email;
    const name = payload.name;

    let user = await findUserByGoogleId(googleId);
    if (!user) {
      const insert = await pool.query('INSERT INTO users (google_id, email, username) VALUES ($1,$2,$3) RETURNING id,google_id,email,username', [googleId, email, name || null]);
      user = insert.rows[0];
    } else {
      await pool.query('UPDATE users SET email=$1, username=$2 WHERE id=$3', [email, name || null, user.id]);
    }

    const access = signAccess(user.id);
    const refresh = signRefresh(user.id);
    await pool.query('UPDATE users SET refresh_token=$1 WHERE id=$2', [refresh, user.id]);

    res.send(`
      <html><body>
      <script>
        (function(){
          const data = ${JSON.stringify({ accessToken: access, refreshToken: refresh, user: { id: user.id, google_id: user.google_id, username: user.username } })};
          if (window.opener && window.opener.postMessage) window.opener.postMessage(data, '*');
          document.write('Google sign-in successful. You can close this window.');
        })();
      </script>
      </body></html>
    `);
  } catch (err) {
    console.error('Google callback error', err);
    res.status(500).send('Google OAuth failed.');
  }
});

// ---------- Obfuscator integration ----------
function sanitizeFilename(name) { return name.replace(/[^a-zA-Z0-9_.-]/g, '_'); }

async function callObfuscatorCLI(rawLua, preset = 'Medium') {
  const ts = Date.now();
  const tmpIn = path.join(TEMP_DIR, `novahub_in_${ts}_${genId(4)}.lua`);
  const tmpOut = path.join(TEMP_DIR, `novahub_out_${ts}_${genId(4)}.lua`);
  try {
    fs.writeFileSync(tmpIn, rawLua, 'utf8');
    const cmd = `${CLI_LAUNCH_CMD} --preset ${sanitizeFilename(preset)} --out ${tmpOut} ${tmpIn}`;
    log('CLI:', cmd);

    const execPromise = () => new Promise((resolve) => {
      exec(cmd, { timeout: 30_000, maxBuffer: 20 * 1024 * 1024 }, (err, stdout, stderr) => {
        try { if (fs.existsSync(tmpIn)) fs.unlinkSync(tmpIn); } catch (e) {}
        if (err || stderr) {
          log('Obfuscator error', err ? err.message : stderr);
          try { if (fs.existsSync(tmpOut)) fs.unlinkSync(tmpOut); } catch (e) {}
          return resolve({ success: false, output: null, error: (err && err.message) || stderr });
        }
        if (!fs.existsSync(tmpOut)) {
          log('No output file produced by CLI');
          return resolve({ success: false, output: null, error: 'No output produced' });
        }
        try {
          const out = fs.readFileSync(tmpOut, 'utf8');
          try { fs.unlinkSync(tmpOut); } catch (e) {}
          return resolve({ success: true, output: out, error: null });
        } catch (e) {
          log('Failed to read output', e);
          return resolve({ success: false, output: null, error: e.message });
        }
      });
    });

    const result = await enqueueJob(execPromise);
    return result;
  } catch (err) {
    try { if (fs.existsSync(tmpIn)) fs.unlinkSync(tmpIn); } catch (e) {}
    try { if (fs.existsSync(tmpOut)) fs.unlinkSync(tmpOut); } catch (e) {}
    return { success: false, output: null, error: err.message || String(err) };
  }
}

const WATERMARK = "--[[ v0.1.0 NovaHub Lua Obfuscator ]] ";
const FALLBACK = "--[[ OBFUSCATION FAILED: returning raw ]]";
function applyFallback(raw) { return `${FALLBACK}\n${raw}`; }

/**
 * POST /obfuscate
 * Auth required
 * body { code, preset? }
 */
app.post('/obfuscate', obfLimiter, requireAuth, async (req, res) => {
  const { code, preset } = req.body || {};
  if (!code || typeof code !== 'string') return res.status(400).json({ error: 'Missing code' });
  try {
    const r = await callObfuscatorCLI(code, preset || 'Medium');
    if (!r.success) {
      const fallback = applyFallback(code);
      return res.json({ obfuscatedCode: WATERMARK + fallback, success: false, error: r.error });
    }
    const obf = WATERMARK + r.output;
    res.json({ obfuscatedCode: obf, success: true });
  } catch (err) {
    console.error('/obfuscate error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * POST /obfuscate-and-store
 * Auth required
 * body { script, preset?, title? }
 * returns { key }
 */
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

    // if discord bot present, set presence briefly (update)
    if (discordClient && discordReady) {
      try {
        discordClient.user.setActivity({ name: `+${key.slice(0,6)} (scripts: updating)`, type: 3 });
      } catch (e) { /* ignore */ }
    }

    res.status(201).json({ key, success });
  } catch (err) {
    console.error('/obfuscate-and-store error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Retrieve endpoint (Roblox restriction + ALU logging) ----------
/**
 * GET /retrieve/:key
 * Logs access, increments uses
 * Returns script text/plain
 */
app.get('/retrieve/:key', async (req, res) => {
  const key = req.params.key;
  if (!key) return res.status(400).send('-- Invalid key');

  const ua = req.headers['user-agent'] || '';
  const ip = req.ip || (req.connection && req.connection.remoteAddress) || '';

  try {
    const r = await pool.query('SELECT script, user_id FROM scripts WHERE key=$1', [key]);
    if (r.rows.length === 0) {
      await recordAluLog({ script_key: key, event_type: 'retrieve_not_found', ip, user_agent: ua, extra: {} });
      res.setHeader('Content-Type', 'text/plain'); return res.status(404).send('-- Script Not Found.');
    }

    const scriptRow = r.rows[0];

    // Optional restriction: only serve to Roblox (recommended)
    // If you want to require Roblox UA, uncomment:
    // if (!ua.includes('Roblox')) { res.setHeader('Content-Type','text/plain'); return res.status(403).send('-- Access Denied.'); }

    await pool.query('UPDATE scripts SET uses = uses + 1, last_used_at = NOW() WHERE key=$1', [key]);

    await recordAluLog({ script_key: key, user_id: scriptRow.user_id, event_type: 'retrieve', ip, user_agent: ua, extra: { maybeRoblox: ua.includes('Roblox') } });

    res.setHeader('Content-Type', 'text/plain');
    return res.send(scriptRow.script);
  } catch (err) {
    console.error('/retrieve error', err);
    res.setHeader('Content-Type', 'text/plain');
    return res.status(500).send('-- Internal Server Error.');
  }
});

// ---------- Script management endpoints (protected) ----------
/**
 * GET /api/scripts - user's scripts
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
 * GET /api/scripts/:key - script metadata (owner only)
 */
app.get('/api/scripts/:key', requireAuth, async (req, res) => {
  try {
    const key = req.params.key;
    const r = await pool.query('SELECT key, title, uses, created_at, last_used_at FROM scripts WHERE key=$1 AND user_id=$2', [key, req.userId]);
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

// ---------- ALU endpoints ----------
/**
 * GET /api/alu/logs - admin only
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
 * GET /api/alu/stats - admin only
 */
app.get('/api/alu/stats', requireAuth, async (req, res) => {
  try {
    const user = await pool.query('SELECT role FROM users WHERE id=$1', [req.userId]);
    if (user.rows.length === 0) return res.status(401).json({ error: 'User not found' });
    if (user.rows[0].role !== 'admin') return res.status(403).json({ error: 'Admin only' });

    const totalScriptsR = await pool.query('SELECT COUNT(*) FROM scripts');
    const totalAccessR = await pool.query('SELECT COUNT(*) FROM alu_logs');
    const topScriptsR = await pool.query(`SELECT script_key, COUNT(*) AS hits FROM alu_logs WHERE script_key IS NOT NULL GROUP BY script_key ORDER BY hits DESC LIMIT 10`);

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
 * GET /api/user/activity - user's ALU logs
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

// ---------- File uploads (multer) ----------
const upload = multer({ dest: path.join(os.tmpdir(), 'uploads'), limits: { fileSize: 5 * 1024 * 1024 } });
app.post('/upload', requireAuth, upload.single('file'), async (req, res) => {
  // Accepts .lua/text files for convenience; returns text content to client
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const content = fs.readFileSync(req.file.path, 'utf8');
    fs.unlinkSync(req.file.path);
    res.json({ content });
  } catch (err) {
    console.error('/upload error', err);
    res.status(500).json({ error: 'File processing failed' });
  }
});

// ---------- Simple health/root ----------
app.get('/', (req, res) => res.send('NovaHub Unified Backend (auth + obfuscation + ALU)'));

// ---------- Discord Bot / Presence Integration ----------
let discordClient = null;
let discordReady = false;

if (Discord && DISCORD_BOT_TOKEN) {
  try {
    discordClient = new Discord.Client({ intents: [Discord.GatewayIntentBits.Guilds] });
    discordClient.once('ready', () => {
      discordReady = true;
      log('Discord bot ready:', discordClient.user.tag);
      // initial activity
      try {
        discordClient.user.setActivity({ name: 'NovaHub', type: 3 });
      } catch (e) { /* ignore */ }
    });
    discordClient.on('error', (e) => log('Discord client error', e));
    discordClient.login(DISCORD_BOT_TOKEN).catch(err => log('Discord login failed:', err));
  } catch (err) {
    console.warn('Discord not started (discord.js missing or failed init).', err);
  }
} else {
  log('Discord bot not configured (missing DISCORD_BOT_TOKEN or discord.js).');
}

// ---------- Helpful dev/admin endpoint to set presence (admin only) ----------
app.post('/admin/presence', requireAuth, async (req, res) => {
  try {
    const { activity } = req.body || {};
    const user = await pool.query('SELECT role FROM users WHERE id=$1', [req.userId]);
    if (user.rows.length === 0) return res.status(401).json({ error: 'User not found' });
    if (user.rows[0].role !== 'admin') return res.status(403).json({ error: 'Admin only' });

    if (!discordClient || !discordReady) return res.status(503).json({ error: 'Discord client not ready' });
    await discordClient.user.setActivity({ name: activity || 'NovaHub', type: 3 });
    res.json({ ok: true });
  } catch (err) {
    console.error('/admin/presence error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Start server ----------
app.listen(PORT, () => {
  log(`NovaHub server listening on port ${PORT}`);
});
