// bot.js — NovaHub Discord Bot (single-file)
// Requires: node 18+, discord.js v14+, axios, pg, dotenv
require('dotenv').config();

const fs = require('fs');
const path = require('path');
const axios = require('axios');

const {
  Client,
  GatewayIntentBits,
  Partials,
  AttachmentBuilder,
  EmbedBuilder,
  SlashCommandBuilder,
  REST,
  Routes
} = require('discord.js');

const { Pool } = require('pg');

/* ============================
   Configuration (from .env)
   ============================ */
const DISCORD_TOKEN = process.env.DISCORD_TOKEN;
const CLIENT_ID = process.env.CLIENT_ID;
const DATABASE_URL = process.env.DATABASE_URL;
const OWNER_ID = process.env.OWNER_ID || '';
const STORAGE_CHANNEL_ID = process.env.STORAGE_CHANNEL_ID || '';
const LOG_WEBHOOK = process.env.LOG_WEBHOOK || ''; // optional webhook to log actions
const API_SECRET = process.env.API_SECRET || ''; // optional secret for your API

if (!DISCORD_TOKEN || !CLIENT_ID || !DATABASE_URL) {
  console.error('Missing required env vars. Set DISCORD_TOKEN, CLIENT_ID, DATABASE_URL.');
  process.exit(1);
}

/* Primary (your) API */
const API_BASE = process.env.API_BASE || 'https://novahub-zd14.onrender.com';
const API_OBF_STORE = `${API_BASE}/obfuscate-and-store`; // expects { script }
const API_OBF = `${API_BASE}/obfuscate`;                 // expects { code }

/* External fallback obfuscation API (must accept { code } and return { obfuscatedCode }) */
const EXTERNAL_OBF_API = process.env.EXTERNAL_OBF_API || process.env.FALLBACK_OBF_API || ''; // set in .env if you have one

const RETRIEVE_URL = (key) => `${API_BASE}/retrieve/${key}`;

/* Runtime constants */
const TEMP_DIR = path.join(__dirname, 'Temp_files');
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });

const API_TIMEOUT = Number(process.env.API_TIMEOUT_MS || 120000); // ms
const TOKEN_COST = Number(process.env.TOKEN_COST || 5);
const DAILY_TOKENS = Number(process.env.DAILY_TOKENS || 15);

const GIFT_MAX_PER_GIFT = Number(process.env.GIFT_MAX_PER_GIFT || 30);
const GIFT_MAX_COUNT = Number(process.env.GIFT_MAX_COUNT || 3);
const GIFT_WINDOW_MS = Number(process.env.GIFT_WINDOW_MS || 6 * 60 * 60 * 1000); // 6 hours

/* ============================
   Postgres pool & DB init
   ============================ */
const pool = new Pool({ connectionString: DATABASE_URL });

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      tokens INTEGER NOT NULL,
      last_refresh BIGINT NOT NULL,
      verified BOOLEAN NOT NULL DEFAULT FALSE,
      whitelisted BOOLEAN NOT NULL DEFAULT FALSE
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS gifts (
      id SERIAL PRIMARY KEY,
      giver TEXT NOT NULL,
      receiver TEXT NOT NULL,
      amount INTEGER NOT NULL,
      created_at BIGINT NOT NULL
    );
  `);

  // scripts for server (if you manage them here, keep consistent)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scripts (
      key VARCHAR(64) PRIMARY KEY,
      script TEXT NOT NULL,
      created_at BIGINT NOT NULL
    );
  `);
}

/* ============================
   DB helper functions
   ============================ */
async function ensureUserRow(userId) {
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
  if (rows.length === 0) {
    const now = Date.now();
    await pool.query(
      'INSERT INTO users(id,tokens,last_refresh,verified,whitelisted) VALUES($1,$2,$3,$4,$5)',
      [userId, DAILY_TOKENS, now, false, false]
    );
    return { id: userId, tokens: DAILY_TOKENS, last_refresh: now, verified: false, whitelisted: false };
  }
  return rows[0];
}

async function getUser(userId) {
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
  if (rows.length === 0) return ensureUserRow(userId);
  return rows[0];
}

async function refreshTokensIfNeeded(userId) {
  const user = await ensureUserRow(userId);
  const now = Date.now();
  const dayMs = 24 * 60 * 60 * 1000;
  if ((now - Number(user.last_refresh)) >= dayMs) {
    await pool.query('UPDATE users SET tokens=$1,last_refresh=$2 WHERE id=$3', [DAILY_TOKENS, now, userId]);
    return DAILY_TOKENS;
  }
  return Number(user.tokens);
}

async function consumeTokens(userId, amount) {
  // Owner and whitelisted => infinite tokens
  if (String(userId) === String(OWNER_ID)) return true;
  const row = await getUser(userId);
  if (row.whitelisted) return true;
  await refreshTokensIfNeeded(userId);
  const fresh = await getUser(userId);
  if (Number(fresh.tokens) < amount) return false;
  await pool.query('UPDATE users SET tokens = tokens - $1 WHERE id = $2', [amount, userId]);
  return true;
}

async function addTokens(userId, amount) {
  await ensureUserRow(userId);
  await pool.query('UPDATE users SET tokens = tokens + $1 WHERE id = $2', [amount, userId]);
}

async function setVerified(userId) {
  await ensureUserRow(userId);
  await pool.query('UPDATE users SET verified = TRUE WHERE id = $1', [userId]);
}

async function setWhitelist(userId, flag) {
  await ensureUserRow(userId);
  await pool.query('UPDATE users SET whitelisted = $1 WHERE id = $2', [flag, userId]);
}

async function countRecentGifts(giverId) {
  const cutoff = Date.now() - GIFT_WINDOW_MS;
  const { rows } = await pool.query('SELECT COUNT(*)::int AS cnt FROM gifts WHERE giver=$1 AND created_at >= $2', [giverId, cutoff]);
  return rows[0]?.cnt || 0;
}

async function logGift(giverId, receiverId, amount) {
  await pool.query('INSERT INTO gifts(giver, receiver, amount, created_at) VALUES($1,$2,$3,$4)', [giverId, receiverId, amount, Date.now()]);
}

/* ============================
   File helpers
   ============================ */
async function downloadAttachment(url, destPath) {
  const res = await axios({ url, method: 'GET', responseType: 'stream', timeout: API_TIMEOUT });
  const writer = fs.createWriteStream(destPath);
  res.data.pipe(writer);
  await new Promise((resolve, reject) => {
    writer.on('finish', resolve);
    writer.on('error', reject);
    res.data.on('error', reject);
  });
}

function cleanupFile(p) {
  try { if (p && fs.existsSync(p)) fs.unlinkSync(p); } catch (e) {}
}

async function uploadToStorageChannel(client, filePath, fileName) {
  if (!STORAGE_CHANNEL_ID) return null;
  try {
    const ch = await client.channels.fetch(STORAGE_CHANNEL_ID).catch(() => null);
    if (!ch || !ch.send) return null;
    const msg = await ch.send({ files: [new AttachmentBuilder(filePath, { name: fileName })] });
    return msg.attachments.first().url;
  } catch (e) {
    console.warn('uploadToStorageChannel error:', e?.message || e);
    return null;
  }
}

/* ============================
   Slash commands registration
   ============================ */
const commands = [
  new SlashCommandBuilder().setName('info').setDescription('Show usage and information about the bot.'),
  new SlashCommandBuilder().setName('verify').setDescription('Accept the rules to verify yourself.'),
  new SlashCommandBuilder().setName('view').setDescription('View your current token balance.'),
  new SlashCommandBuilder()
    .setName('wl')
    .setDescription('Whitelist a user (owner only).')
    .addUserOption(opt => opt.setName('user').setDescription('User to whitelist').setRequired(true)),
  new SlashCommandBuilder()
    .setName('bl')
    .setDescription('Remove user from whitelist (owner only).')
    .addUserOption(opt => opt.setName('user').setDescription('User to remove from whitelist').setRequired(true)),
  new SlashCommandBuilder()
    .setName('gift')
    .setDescription('Gift tokens to another user (owner/whitelisted only).')
    .addUserOption(opt => opt.setName('user').setDescription('Recipient').setRequired(true))
    .addIntegerOption(opt => opt.setName('amount').setDescription('Amount to gift').setRequired(true)),
  new SlashCommandBuilder()
    .setName('apiservice')
    .setDescription('(Whitelist only) Obfuscate & store. Raw input visible only to you; public output posted.')
    .addAttachmentOption(opt => opt.setName('file').setDescription('.lua or .txt file').setRequired(false))
    .addStringOption(opt => opt.setName('code').setDescription('Paste Lua code').setRequired(false)),
  new SlashCommandBuilder()
    .setName('obf')
    .setDescription('Obfuscate only. Raw input visible only to you; public output posted.')
    .addAttachmentOption(opt => opt.setName('file').setDescription('.lua or .txt file').setRequired(false))
    .addStringOption(opt => opt.setName('code').setDescription('Paste Lua code').setRequired(false)),
  new SlashCommandBuilder()
    .setName('clean_ast')
    .setDescription('Proxy to AST cleaner backend (ephemeral input).')
    .addStringOption(opt => opt.setName('payload').setDescription('JSON payload (string)').setRequired(true))
].map(c => c.toJSON());

const rest = new REST({ version: '10' }).setToken(DISCORD_TOKEN);
(async () => {
  try {
    await rest.put(Routes.applicationCommands(CLIENT_ID), { body: commands });
    console.log('Slash commands registered.');
  } catch (err) {
    console.error('Slash registration failed:', err);
  }
})();

/* ============================
   Client init
   ============================ */
const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent],
  partials: [Partials.Channel]
});

client.once('ready', async () => {
  console.log('Bot ready:', client.user.tag);
  try {
    await initDb();
    console.log('DB initialized.');
  } catch (e) {
    console.error('DB init error:', e);
  }
});

/* ============================
   Helper to collect code from options
   ============================ */
async function collectCodeFromInteraction(interaction) {
  const attachment = interaction.options.getAttachment('file');
  if (attachment) {
    const ext = path.extname(attachment.name).toLowerCase();
    if (!['.lua', '.txt'].includes(ext)) throw new Error('Only .lua or .txt attachments supported.');
    const tmp = path.join(TEMP_DIR, `input_${Date.now()}_${attachment.name}`);
    try {
      await downloadAttachment(attachment.url, tmp);
      const content = fs.readFileSync(tmp, 'utf8');
      cleanupFile(tmp);
      return { code: content, filename: attachment.name };
    } catch (e) {
      cleanupFile(tmp);
      throw new Error('Failed to download attachment.');
    }
  }
  const code = interaction.options.getString('code');
  if (code && code.trim().length > 0) return { code, filename: `code_${Date.now()}.lua` };
  throw new Error('No code provided. Attach a .lua/.txt file or use the code option.');
}

/* ============================
   API / Obfuscation helpers (Option C fallback)
   ============================ */
/**
 * Try your own API's obfuscate-and-store first.
 * If that fails, try EXTERNAL_OBF_API to obfuscate, then store using your obfuscate-and-store.
 *
 * Returns: { success: true, key, obfuscatedCode? } or throws.
 */
async function obfuscateAndStoreWithFallback(rawCode) {
  // 1) Try your API obfuscate-and-store (preferred)
  try {
    const body = { script: rawCode };
    if (API_SECRET) body.api_secret = API_SECRET;
    const r = await axios.post(API_OBF_STORE, body, { timeout: API_TIMEOUT });
    if (r?.data?.key) {
      return { success: true, key: r.data.key, obfuscatedCode: r.data.obfuscatedCode || null, used: 'primary_store' };
    }
    // If primary returned 2xx but no key, treat as failure
    throw new Error('Primary API did not return a key.');
  } catch (errPrimary) {
    // Log and continue to fallback
    console.warn('Primary obfuscate-and-store failed:', errPrimary?.message || errPrimary);

    // 2) If we have an external obfuscation API configured, attempt obfuscation there
    if (!EXTERNAL_OBF_API) {
      throw new Error(`Primary API failed and no external fallback configured: ${errPrimary.message || errPrimary}`);
    }

    try {
      const r2 = await axios.post(EXTERNAL_OBF_API, { code: rawCode }, { timeout: API_TIMEOUT });
      const obf = r2?.data?.obfuscatedCode || r2?.data?.code || null;
      if (!obf) throw new Error('External obfuscation API did not return obfuscated code.');

      // Now attempt to store the obfuscated code in your store endpoint (as script).
      const storeBody = { script: obf };
      if (API_SECRET) storeBody.api_secret = API_SECRET;
      const r3 = await axios.post(API_OBF_STORE, storeBody, { timeout: API_TIMEOUT });
      if (r3?.data?.key) {
        return { success: true, key: r3.data.key, obfuscatedCode: obf, used: 'fallback_external' };
      }
      throw new Error('Failed to store obfuscated script on primary after external obfuscation.');
    } catch (errFallback) {
      console.warn('Fallback external obfuscation/store failed:', errFallback?.message || errFallback);
      throw new Error(`Both primary and fallback obfuscation/storage failed. Primary: ${errPrimary.message || errPrimary}. Fallback: ${errFallback.message || errFallback}`);
    }
  }
}

/**
 * Try to obfuscate the code only (no store). Prefer primary /obfuscate, fallback to EXTERNAL_OBF_API.
 * Returns { obfuscatedCode } or throws.
 */
async function obfuscateOnlyWithFallback(rawCode) {
  // try primary obfuscate first
  try {
    const body = { code: rawCode };
    if (API_SECRET) body.api_secret = API_SECRET;
    const r = await axios.post(API_OBF, body, { timeout: API_TIMEOUT });
    if (r?.data?.obfuscatedCode) return { obfuscatedCode: r.data.obfuscatedCode, used: 'primary_obf' };
    throw new Error('Primary obfuscate returned no obfuscatedCode.');
  } catch (errPrimary) {
    console.warn('Primary /obfuscate failed:', errPrimary?.message || errPrimary);
    if (!EXTERNAL_OBF_API) throw new Error(`Primary obfuscate failed and no external fallback is configured: ${errPrimary.message || errPrimary}`);
    try {
      const r2 = await axios.post(EXTERNAL_OBF_API, { code: rawCode }, { timeout: API_TIMEOUT });
      const obf = r2?.data?.obfuscatedCode || r2?.data?.code || null;
      if (!obf) throw new Error('External obfuscation API returned no obfuscatedCode.');
      return { obfuscatedCode: obf, used: 'fallback_external' };
    } catch (errFallback) {
      console.warn('External obfuscation failed:', errFallback?.message || errFallback);
      throw new Error(`Both primary and external obfuscation failed. Primary: ${errPrimary.message || errPrimary}. External: ${errFallback.message || errFallback}`);
    }
  }
}

/* ============================
   Interaction handler
   ============================ */
client.on('interactionCreate', async (interaction) => {
  if (!interaction.isChatInputCommand()) return;
  const cmd = interaction.commandName;
  const uid = interaction.user.id;

  // make sure user exists in DB and tokens are refreshed
  await ensureUserRow(uid);
  await refreshTokensIfNeeded(uid);
  const userRow = await getUser(uid);

  try {
    // --- /info (public) ---
    if (cmd === 'info') {
      const embed = new EmbedBuilder()
        .setTitle('NovaHub — Info (BETA)')
        .setColor('Blue')
        .setDescription('This service is in **BETA**. Use /verify to accept the rules. Commands cost tokens (5 each). Whitelisted users and owner have infinite tokens.')
        .addFields(
          { name: '/verify', value: 'Verify to use commands (ephemeral)', inline: true },
          { name: '/view', value: 'View token balance (ephemeral)', inline: true },
          { name: '/apiservice', value: 'Whitelist-only: obfuscate & store (public output)', inline: false },
          { name: '/obf', value: 'Obfuscate only (public output)', inline: false },
          { name: '/gift', value: `Owner/whitelisted: gift tokens (whitelisted limit ${GIFT_MAX_PER_GIFT} per gift, ${GIFT_MAX_COUNT} gifts per ${GIFT_WINDOW_MS/3600000}h).`, inline: false },
          { name: '/wl', value: 'Owner: whitelist user (public)', inline: false },
          { name: '/bl', value: 'Owner: unwhitelist user (public)', inline: false }
        ).setFooter({ text: 'NovaHub' });
      return interaction.reply({ embeds: [embed], ephemeral: false });
    }

    // --- /verify ---
    if (cmd === 'verify') {
      await setVerified(uid);
      if (LOG_WEBHOOK) {
        axios.post(LOG_WEBHOOK, { content: `User verified: <@${uid}> (${uid})` }).catch(() => {});
      }
      return interaction.reply({ content: '✅ Verified. You can now use commands (if whitelisted).', ephemeral: true });
    }

    // --- /view ---
    if (cmd === 'view') {
      const refreshed = await refreshTokensIfNeeded(uid);
      const display = (String(uid) === String(OWNER_ID) || userRow.whitelisted) ? '∞ (owner/whitelisted)' : `${refreshed}`;
      return interaction.reply({ content: `💠 You have **${display}** tokens. Tokens refresh every 24 hours.`, ephemeral: true });
    }

    // --- /wl (owner) ---
    if (cmd === 'wl') {
      if (String(uid) !== String(OWNER_ID)) return interaction.reply({ content: '❌ Only owner can whitelist.', ephemeral: true });
      const target = interaction.options.getUser('user');
      if (!target) return interaction.reply({ content: '❌ No user provided.', ephemeral: true });
      await setWhitelist(target.id, true);
      return interaction.reply({ content: `✅ ${target.tag} has been whitelisted (infinite tokens).`, ephemeral: false });
    }

    // --- /bl (owner) ---
    if (cmd === 'bl') {
      if (String(uid) !== String(OWNER_ID)) return interaction.reply({ content: '❌ Only owner can un-whitelist.', ephemeral: true });
      const target = interaction.options.getUser('user');
      if (!target) return interaction.reply({ content: '❌ No user provided.', ephemeral: true });
      await setWhitelist(target.id, false);
      return interaction.reply({ content: `✅ ${target.tag} has been removed from whitelist.`, ephemeral: false });
    }

    // --- /gift ---
    if (cmd === 'gift') {
      const target = interaction.options.getUser('user');
      const amount = interaction.options.getInteger('amount');
      if (!target || !amount || amount <= 0) return interaction.reply({ content: '❌ Invalid target or amount.', ephemeral: true });

      const giverRow = await getUser(uid);
      if (String(uid) !== String(OWNER_ID) && !giverRow.whitelisted) {
        return interaction.reply({ content: '❌ Only the owner or whitelisted users can gift tokens.', ephemeral: true });
      }

      if (String(uid) !== String(OWNER_ID) && giverRow.whitelisted) {
        if (amount > GIFT_MAX_PER_GIFT) return interaction.reply({ content: `❌ Whitelisted users can gift at most ${GIFT_MAX_PER_GIFT} tokens per gift.`, ephemeral: true });
        const recent = await countRecentGifts(uid);
        if (recent >= GIFT_MAX_COUNT) return interaction.reply({ content: `❌ You've reached the gift limit (${GIFT_MAX_COUNT}) for the last ${GIFT_WINDOW_MS/3600000} hours.`, ephemeral: true });
      }

      await ensureUserRow(target.id);
      await addTokens(target.id, amount);
      await logGift(uid, target.id, amount);
      if (LOG_WEBHOOK) axios.post(LOG_WEBHOOK, { content: `<@${uid}> gifted ${amount} tokens to <@${target.id}>` }).catch(() => {});

      try { await interaction.channel.send({ content: `<@${target.id}> you were gifted **${amount}** tokens.` }); } catch (e) {}
      return interaction.reply({ content: `🎁 Gifted **${amount}** tokens to ${target.tag}.`, ephemeral: false });
    }

    // --- /clean_ast ---
    if (cmd === 'clean_ast') {
      await interaction.deferReply({ ephemeral: true });
      const payloadStr = interaction.options.getString('payload');
      if (!payloadStr) return interaction.editReply({ content: '❌ Missing payload' });
      let payload;
      try { payload = JSON.parse(payloadStr); } catch (e) { return interaction.editReply({ content: '❌ Payload must be valid JSON' }); }

      try {
        const upstream = await axios.post('http://localhost:5001/clean_ast', payload, { timeout: API_TIMEOUT });
        const embed = new EmbedBuilder()
          .setTitle('AST Cleaner Result')
          .setDescription(`<@${uid}> AST cleanup result (truncated):`)
          .addFields({ name: 'Result', value: '```json\n' + JSON.stringify(upstream.data).slice(0, 1900) + '\n```' });
        await interaction.channel.send({ content: `<@${uid}>`, embeds: [embed] });
        return interaction.editReply({ content: '✅ AST cleaned and posted publicly.' });
      } catch (err) {
        return interaction.editReply({ content: `❌ AST proxy error: ${err.message}` });
      }
    }

    // --- /apiservice (whitelist-only) ---
    if (cmd === 'apiservice') {
      await interaction.deferReply({ ephemeral: true });

      const verifiedRow = await getUser(uid);
      if (!verifiedRow.verified) return interaction.editReply({ content: '❌ You must run /verify first.' });
      if (!verifiedRow.whitelisted) return interaction.editReply({ content: '❌ This command requires whitelist access.' });

      // For owner/whitelisted: no token deduction
      if (String(uid) !== String(OWNER_ID) && !verifiedRow.whitelisted) {
        const tokensNow = await refreshTokensIfNeeded(uid);
        if (tokensNow < TOKEN_COST) return interaction.editReply({ content: `❌ Not enough tokens (${tokensNow}).` });
      }

      // collect code
      let collected;
      try { collected = await collectCodeFromInteraction(interaction); } catch (err) { return interaction.editReply({ content: `❌ ${err.message}` }); }

      // Attempt primary store (and fallback external obfuscation if needed)
      let storeResult;
      try {
        storeResult = await obfuscateAndStoreWithFallback(collected.code);
      } catch (err) {
        return interaction.editReply({ content: `❌ Obfuscation/store failed: ${err.message}` });
      }

      // Deduct tokens for non-owner/non-whitelisted
      if (String(uid) !== String(OWNER_ID) && !verifiedRow.whitelisted) {
        const ok = await consumeTokens(uid, TOKEN_COST);
        if (!ok) return interaction.editReply({ content: '❌ Failed to deduct tokens.' });
      }

      const key = storeResult.key;
      const loader = `loadstring(game:HttpGet('${RETRIEVE_URL(key)}'))()`;

      const publicEmbed = new EmbedBuilder()
        .setTitle('🔐 NovaHub — File Stored')
        .setColor('Blurple')
        .setDescription(`<@${uid}> your file was processed and stored.`)
        .addFields(
          { name: 'Retrieve URL', value: RETRIEVE_URL(key) },
          { name: 'Loader (copyable)', value: '```lua\n' + loader + '\n```' },
          { name: 'Key', value: `\`${key}\`` }
        ).setFooter({ text: 'NovaHub' });

      // If obfuscated code available, upload to storage channel and add download link.
      try {
        if (storeResult.obfuscatedCode) {
          const tmpPath = path.join(TEMP_DIR, `obf_${Date.now()}.lua`);
          fs.writeFileSync(tmpPath, storeResult.obfuscatedCode, 'utf8');
          const publicUrl = await uploadToStorageChannel(client, tmpPath, collected.filename || `obf_${Date.now()}.lua`);
          if (publicUrl) publicEmbed.addFields({ name: 'Download', value: publicUrl });
          cleanupFile(tmpPath);
        }
      } catch (e) { /* ignore upload errors */ }

      // Post public embed (visible to channel)
      try { await interaction.channel.send({ content: `<@${uid}>`, embeds: [publicEmbed] }); } catch (e) {}
      return interaction.editReply({ content: '✅ Processed and public output posted.' });
    }

    // --- /obf (obfuscate only) ---
    if (cmd === 'obf') {
      await interaction.deferReply({ ephemeral: true });

      const verifiedRow = await getUser(uid);
      if (!verifiedRow.verified) return interaction.editReply({ content: '❌ You must run /verify first.' });

      if (String(uid) !== String(OWNER_ID) && !verifiedRow.whitelisted) {
        const tokensNow = await refreshTokensIfNeeded(uid);
        if (tokensNow < TOKEN_COST) return interaction.editReply({ content: `❌ Not enough tokens (${tokensNow}).` });
      }

      // collect code
      let collected;
      try { collected = await collectCodeFromInteraction(interaction); } catch (err) { return interaction.editReply({ content: `❌ ${err.message}` }); }

      // Try obfuscation with fallback
      let obfResult;
      try {
        obfResult = await obfuscateOnlyWithFallback(collected.code);
      } catch (err) {
        return interaction.editReply({ content: `❌ Obfuscation failed: ${err.message}` });
      }

      // Deduct tokens for non-owner/non-whitelisted
      if (String(uid) !== String(OWNER_ID) && !verifiedRow.whitelisted) {
        const ok = await consumeTokens(uid, TOKEN_COST);
        if (!ok) return interaction.editReply({ content: '❌ Failed to deduct tokens.' });
      }

      // Save obfuscated output to temp, upload to storage channel, post public embed
      const tmp = path.join(TEMP_DIR, `obf_${Date.now()}.lua`);
      try {
        fs.writeFileSync(tmp, obfResult.obfuscatedCode, 'utf8');
        const publicUrl = await uploadToStorageChannel(client, tmp, collected.filename || `obf_${Date.now()}.lua`);
        const embed = new EmbedBuilder()
          .setTitle('Obfuscation Complete')
          .setColor('Purple')
          .setDescription(`<@${uid}> your obfuscated script is ready.`)
          .addFields({ name: 'Preview', value: '```lua\n' + obfResult.obfuscatedCode.slice(0, 1900) + '\n```' });

        if (publicUrl) embed.addFields({ name: 'Download', value: publicUrl });
        await interaction.channel.send({ content: `<@${uid}>`, embeds: [embed] });
        cleanupFile(tmp);
        return interaction.editReply({ content: '✅ Obfuscation complete — public output posted.' });
      } catch (e) {
        cleanupFile(tmp);
        return interaction.editReply({ content: `❌ Failed to prepare obfuscated file: ${e.message}` });
      }
    }

    // Unknown
    return interaction.reply({ content: 'Unknown command', ephemeral: true });

  } catch (err) {
    console.error('Command error:', err);
    try {
      if (interaction.deferred || interaction.replied) await interaction.editReply({ content: '❌ Unexpected error occurred.', ephemeral: true });
      else await interaction.reply({ content: '❌ Unexpected error occurred.', ephemeral: true });
    } catch (e) {}
  }
});

/* ============================
   Login
   ============================ */
client.login(DISCORD_TOKEN).catch(err => {
  console.error('Discord login failed:', err);
});
