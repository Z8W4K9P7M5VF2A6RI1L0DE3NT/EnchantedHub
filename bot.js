// bot.js — Final single-file bot
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

//////////////////////////////////////////////////////////////////////////////
// CONFIG
//////////////////////////////////////////////////////////////////////////////

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('ERROR: DATABASE_URL is required in env');
  process.exit(1);
}

const pool = new Pool({ connectionString: DATABASE_URL });

const DOMAIN = process.env.API_BASE || 'https://novahub-zd14.onrender.com';
const API_OBF_STORE = `${DOMAIN}/obfuscate-and-store`;
const API_OBF = `${DOMAIN}/obfuscate`;
const RETRIEVE_URL = (key) => `${DOMAIN}/retrieve/${key}`; // <-- final format

const TEMP_DIR = path.join(__dirname, 'Temp_files');
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });

const OWNER_ID = process.env.OWNER_ID || '';
const STORAGE_CHANNEL_ID = process.env.STORAGE_CHANNEL_ID || '';
const LOG_WEBHOOK = process.env.LOG_WEBHOOK || '';

const API_SECRET = process.env.API_SECRET || '';

const TOKEN_COST = Number(process.env.TOKEN_COST || 5);
const DAILY_TOKENS = Number(process.env.DEFAULT_TOKENS || 15);
const API_TIMEOUT = 120000; // 2 minutes

// Gift policy for whitelisted users (owner exempt)
const GIFT_MAX_PER_GIFT = Number(process.env.GIFT_MAX_PER_GIFT || 30);
const GIFT_MAX_COUNT = Number(process.env.GIFT_MAX_COUNT || 3);
const GIFT_WINDOW_MS = Number(process.env.GIFT_WINDOW_MS || 6 * 60 * 60 * 1000); // 6 hours

//////////////////////////////////////////////////////////////////////////////
// DATABASE INIT + HELPERS
//////////////////////////////////////////////////////////////////////////////

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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS stored_scripts (
      key TEXT PRIMARY KEY,
      script TEXT NOT NULL,
      created_at BIGINT NOT NULL
    );
  `);
}

async function ensureUserRow(userId) {
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
  if (rows.length === 0) {
    const now = Date.now();
    await pool.query(
      'INSERT INTO users(id, tokens, last_refresh, verified, whitelisted) VALUES($1, $2, $3, $4, $5)',
      [userId, DAILY_TOKENS, now, false, false]
    );
    return { id: userId, tokens: DAILY_TOKENS, last_refresh: now, verified: false, whitelisted: false };
  }
  return rows[0];
}

async function refreshTokensIfNeeded(userId) {
  const user = await ensureUserRow(userId);
  const now = Date.now();
  const dayMs = 24 * 60 * 60 * 1000;
  if ((now - Number(user.last_refresh)) >= dayMs) {
    await pool.query('UPDATE users SET tokens = $1, last_refresh = $2 WHERE id = $3', [DAILY_TOKENS, now, userId]);
    return DAILY_TOKENS;
  }
  return Number(user.tokens);
}

async function getUser(userId) {
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
  if (rows.length === 0) return ensureUserRow(userId);
  return rows[0];
}

// consumeTokens respects infinite tokens for owner/whitelisted
async function consumeTokens(userId, amount) {
  const user = await getUser(userId);
  if (String(userId) === String(OWNER_ID) || user.whitelisted) {
    // infinite tokens: do not deduct
    return true;
  }
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
  const { rows } = await pool.query('SELECT COUNT(*)::int AS cnt FROM gifts WHERE giver = $1 AND created_at >= $2', [giverId, cutoff]);
  return rows[0]?.cnt || 0;
}

async function logGift(giverId, receiverId, amount) {
  await pool.query('INSERT INTO gifts (giver, receiver, amount, created_at) VALUES ($1,$2,$3,$4)', [giverId, receiverId, amount, Date.now()]);
}

//////////////////////////////////////////////////////////////////////////////
// HELPERS: file download + storage upload
//////////////////////////////////////////////////////////////////////////////

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
    console.warn('uploadToStorageChannel failed:', e?.message || e);
    return null;
  }
}

//////////////////////////////////////////////////////////////////////////////
// Slash commands
//////////////////////////////////////////////////////////////////////////////

const commands = [
  new SlashCommandBuilder().setName('info').setDescription('Show usage and information about the bot.'),
  new SlashCommandBuilder().setName('verify').setDescription('Accept the rules to verify yourself.'),
  new SlashCommandBuilder().setName('view').setDescription('View your current token balance.'),
  new SlashCommandBuilder()
    .setName('wl')
    .setDescription('Owner-only: whitelist a user (gives infinite tokens).')
    .addUserOption(opt => opt.setName('user').setDescription('User to whitelist').setRequired(true)),
  new SlashCommandBuilder()
    .setName('bl')
    .setDescription('Owner-only: remove a user from whitelist (blacklist from whitelist).')
    .addUserOption(opt => opt.setName('user').setDescription('User to remove from whitelist').setRequired(true)),
  new SlashCommandBuilder()
    .setName('gift')
    .setDescription('Owner or whitelisted users: gift tokens to another user.')
    .addUserOption(opt => opt.setName('user').setDescription('Recipient to receive tokens').setRequired(true))
    .addIntegerOption(opt => opt.setName('amount').setDescription('Amount of tokens to gift (max 30 for whitelisted)').setRequired(true)),
  new SlashCommandBuilder()
    .setName('apiservice')
    .setDescription('(Whitelist only) Obfuscate & store; costs tokens. Raw input is private.')
    .addAttachmentOption(opt => opt.setName('file').setDescription('Upload .lua or .txt file (optional)').setRequired(false))
    .addStringOption(opt => opt.setName('code').setDescription('Paste Lua code (optional)').setRequired(false)),
  new SlashCommandBuilder()
    .setName('obf')
    .setDescription('Obfuscate code only. Raw input is private.')
    .addAttachmentOption(opt => opt.setName('file').setDescription('Upload .lua or .txt file (optional)').setRequired(false))
    .addStringOption(opt => opt.setName('code').setDescription('Paste Lua code (optional)').setRequired(false)),
  new SlashCommandBuilder()
    .setName('clean_ast')
    .setDescription('Proxy to AST cleaner service (raw payload).')
    .addStringOption(opt => opt.setName('payload').setDescription('JSON body to forward to AST service').setRequired(true))
].map(c => c.toJSON());

const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN);
(async () => {
  try {
    await rest.put(Routes.applicationCommands(process.env.CLIENT_ID), { body: commands });
    console.log('Slash commands registered.');
  } catch (err) {
    console.error('Failed to register commands:', err);
  }
})();

//////////////////////////////////////////////////////////////////////////////
// BOT
//////////////////////////////////////////////////////////////////////////////

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

client.on('interactionCreate', async (interaction) => {
  if (!interaction.isChatInputCommand()) return;

  const cmd = interaction.commandName;
  const userId = interaction.user.id;

  // Ensure user row & refresh tokens
  await ensureUserRow(userId);
  await refreshTokensIfNeeded(userId);
  const user = await getUser(userId);

  // helper: collect code (attachment or code string)
  async function collectCodeFromInteraction(interaction) {
    const file = interaction.options.getAttachment('file');
    if (file) {
      const ext = path.extname(file.name).toLowerCase();
      if (!['.lua', '.txt'].includes(ext)) throw new Error('Unsupported file type. Use .lua or .txt');
      const tmp = path.join(TEMP_DIR, `input_${Date.now()}_${file.name}`);
      try {
        await downloadAttachment(file.url, tmp);
        const content = fs.readFileSync(tmp, 'utf8');
        cleanupFile(tmp);
        return { code: content, filename: file.name };
      } catch (e) {
        cleanupFile(tmp);
        throw new Error('Failed to download attachment');
      }
    }
    const codeStr = interaction.options.getString('code');
    if (codeStr && codeStr.trim().length > 0) return { code: codeStr, filename: `code_${Date.now()}.lua` };
    throw new Error('No code provided. Attach a file or use the code option.');
  }

  try {
    // ---------------- /info ----------------
    if (cmd === 'info') {
      const embed = new EmbedBuilder()
        .setTitle('NovaHub Bot — Info (BETA)')
        .setColor('Blue')
        .setDescription('Welcome! This service is in BETA. Use /verify to accept the rules. Premium commands cost tokens. Use /view to check balance.')
        .addFields(
          { name: '/verify', value: 'Accept rules & verify (required before using commands)', inline: true },
          { name: '/view', value: 'Show token balance (tokens refresh every 24h)', inline: true },
          { name: '/apiservice', value: 'Whitelist only — obfuscate & store. Raw input private; public embed posted.', inline: false },
          { name: '/obf', value: 'Obfuscate only. Raw input private; public embed posted.', inline: false },
          { name: '/gift', value: `Owner or whitelisted users can gift tokens (whitelisted: max ${GIFT_MAX_PER_GIFT} per gift, ${GIFT_MAX_COUNT} gifts per ${Math.floor(GIFT_WINDOW_MS/3600000)}h).`, inline: false },
          { name: '/wl', value: 'Owner-only: whitelist a user', inline: false },
          { name: '/bl', value: 'Owner-only: remove whitelist (blacklist)', inline: false },
          { name: '/clean_ast', value: 'Proxy to AST cleaner', inline: false }
        );
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ---------------- /verify ----------------
    if (cmd === 'verify') {
      await setVerified(userId);
      if (LOG_WEBHOOK) { try { await axios.post(LOG_WEBHOOK, { content: `🟢 User Verified: <@${userId}> (${userId})` }); } catch (e) {} }
      return interaction.reply({ content: '✅ You are now verified. Use /info to learn more.', ephemeral: true });
    }

    // ---------------- /view ----------------
    if (cmd === 'view') {
      const refreshed = await refreshTokensIfNeeded(userId);
      const display = (String(userId) === String(OWNER_ID) || user.whitelisted) ? '∞ (whitelisted/owner)' : `${refreshed}`;
      return interaction.reply({ content: `💠 You have **${display}** tokens. Tokens refresh every 24 hours.`, ephemeral: true });
    }

    // ---------------- /wl ----------------
    if (cmd === 'wl') {
      if (String(userId) !== String(OWNER_ID)) return interaction.reply({ content: '❌ Only the owner can whitelist users.', ephemeral: true });
      const target = interaction.options.getUser('user');
      if (!target) return interaction.reply({ content: '❌ No user provided.', ephemeral: true });
      await ensureUserRow(target.id);
      await setWhitelist(target.id, true);
      return interaction.reply({ content: `✅ ${target.tag} is now whitelisted (infinite tokens).`, ephemeral: true });
    }

    // ---------------- /bl ----------------
    if (cmd === 'bl') {
      if (String(userId) !== String(OWNER_ID)) return interaction.reply({ content: '❌ Only the owner can remove whitelist.', ephemeral: true });
      const target = interaction.options.getUser('user');
      if (!target) return interaction.reply({ content: '❌ No user provided.', ephemeral: true });
      await ensureUserRow(target.id);
      await setWhitelist(target.id, false);
      return interaction.reply({ content: `✅ ${target.tag} removed from whitelist.`, ephemeral: true });
    }

    // ---------------- /gift ----------------
    if (cmd === 'gift') {
      const target = interaction.options.getUser('user');
      const amount = interaction.options.getInteger('amount');
      if (!target || !amount || amount <= 0) return interaction.reply({ content: '❌ Invalid target or amount.', ephemeral: true });

      // only owner OR whitelisted can gift
      if (String(userId) !== String(OWNER_ID) && !user.whitelisted) {
        return interaction.reply({ content: '❌ Only the owner or whitelisted users can gift tokens.', ephemeral: true });
      }

      // if giver is whitelisted (not owner) apply gift rules
      if (String(userId) !== String(OWNER_ID) && user.whitelisted) {
        if (amount > GIFT_MAX_PER_GIFT) return interaction.reply({ content: `❌ Whitelisted users may give at most ${GIFT_MAX_PER_GIFT} tokens per gift.`, ephemeral: true });
        const recent = await countRecentGifts(userId);
        if (recent >= GIFT_MAX_COUNT) return interaction.reply({ content: `❌ You have reached the gift limit (${GIFT_MAX_COUNT}) for the last ${Math.floor(GIFT_WINDOW_MS/3600000)} hours. Try later.`, ephemeral: true });
      }

      // perform gift: gifting does NOT deduct from whitelisted or owner
      await ensureUserRow(target.id);
      await addTokens(target.id, amount);
      await logGift(userId, target.id, amount);

      // optional logging webhook
      try { if (LOG_WEBHOOK) await axios.post(LOG_WEBHOOK, { content: `🎁 <@${userId}> gifted ${amount} to <@${target.id}>` }); } catch (e) {}

      // notify recipient publicly
      try {
        const ch = await client.channels.fetch(interaction.channelId).catch(()=>null);
        if (ch && ch.send) await ch.send({ content: `<@${target.id}> you were gifted **${amount}** tokens.` });
      } catch (e) {}

      return interaction.reply({ content: `🎁 Gifted **${amount}** tokens to ${target.tag}.`, ephemeral: true });
    }

    // ---------------- /clean_ast ----------------
    if (cmd === 'clean_ast') {
      await interaction.deferReply({ ephemeral: true });
      const payloadStr = interaction.options.getString('payload');
      if (!payloadStr) return interaction.editReply({ content: '❌ Missing payload.' });
      let payload;
      try { payload = JSON.parse(payloadStr); } catch (e) { return interaction.editReply({ content: '❌ Payload must be valid JSON.' }); }

      try {
        const upstream = await axios.post('http://localhost:5001/clean_ast', payload, { timeout: API_TIMEOUT });
        const publicEmbed = new EmbedBuilder()
          .setTitle('AST Cleaner Result')
          .setDescription(`<@${userId}> cleaned AST output:`)
          .addFields({ name: 'Result (truncated)', value: '```json\n' + JSON.stringify(upstream.data).slice(0, 1900) + '\n```' })
          .setFooter({ text: 'AST Cleaner' });

        await interaction.channel.send({ content: `<@${userId}>`, embeds: [publicEmbed] });
        return interaction.editReply({ content: '✅ AST cleaned and public output posted.' });
      } catch (err) {
        return interaction.editReply({ content: `❌ AST proxy error: ${err.message}` });
      }
    }

    // ---------------- /apiservice (whitelist only) ----------------
    if (cmd === 'apiservice') {
      await interaction.deferReply({ ephemeral: true });

      if (!user.verified) return interaction.editReply({ content: '❌ You must run /verify first.' });
      if (!user.whitelisted) return interaction.editReply({ content: '❌ This command requires whitelist access.' });

      // If not owner and not whitelisted (shouldn't happen), check tokens
      const userRow = await getUser(userId);
      if (String(userId) !== String(OWNER_ID) && !userRow.whitelisted) {
        const refreshed = await refreshTokensIfNeeded(userId);
        if (refreshed < TOKEN_COST) return interaction.editReply({ content: `❌ Not enough tokens. You have ${refreshed}.` });
      }

      // collect code (ephemeral)
      let collected;
      try { collected = await collectCodeFromInteraction(interaction); } catch (err) { return interaction.editReply({ content: `❌ ${err.message}` }); }

      // call backend obfuscate-and-store (include api_secret)
      let apiResp;
      try {
        apiResp = await axios.post(API_OBF_STORE, { code: collected.code, api_secret: API_SECRET }, { timeout: API_TIMEOUT });
      } catch (err) {
        return interaction.editReply({ content: `❌ API error: ${err.message}` });
      }

      const key = apiResp?.data?.key;
      if (!key) return interaction.editReply({ content: '❌ API did not return a key.' });

      // Deduct tokens for non-owner/non-whitelisted users only
      if (String(userId) !== String(OWNER_ID) && !userRow.whitelisted) {
        const ok = await consumeTokens(userId, TOKEN_COST);
        if (!ok) return interaction.editReply({ content: '❌ Failed to deduct tokens. Try again later.' });
      }

      // Build loader and public embed
      const loader = `return loadstring(game:HttpGet("${RETRIEVE_URL(key)}"))()`;
      const publicEmbed = new EmbedBuilder()
        .setTitle('🔐 NovaHub API — File Stored')
        .setColor('Blurple')
        .setDescription(`<@${userId}> your file has been processed and stored.`)
        .addFields(
          { name: 'Retrieve URL', value: RETRIEVE_URL(key) },
          { name: 'Loader (copyable)', value: '```lua\n' + loader + '\n```' },
          { name: 'Key', value: `\`${key}\`` }
        )
        .setFooter({ text: 'NovaHub API' });

      // If API returned obfuscatedCode, upload to storage channel for download link
      if (apiResp.data && apiResp.data.obfuscatedCode) {
        const tmpPath = path.join(TEMP_DIR, `obf_${Date.now()}.lua`);
        try {
          fs.writeFileSync(tmpPath, apiResp.data.obfuscatedCode, 'utf8');
          const publicUrl = await uploadToStorageChannel(client, tmpPath, collected.filename || `obf_${Date.now()}.lua`);
          if (publicUrl) publicEmbed.addFields({ name: 'Download', value: publicUrl });
        } catch (e) { /* ignore */ } finally { cleanupFile(tmpPath); }
      }

      // Publicly post embed and ping user
      try { await interaction.channel.send({ content: `<@${userId}>`, embeds: [publicEmbed] }); } catch (e) {}
      return interaction.editReply({ content: '✅ Processed — public output posted.' });
    }

    // ---------------- /obf (public obfuscate only) ----------------
    if (cmd === 'obf') {
      await interaction.deferReply({ ephemeral: true });

      if (!user.verified) return interaction.editReply({ content: '❌ You must run /verify first.' });

      const userRow = await getUser(userId);
      if (String(userId) !== String(OWNER_ID) && !userRow.whitelisted) {
        const refreshed = await refreshTokensIfNeeded(userId);
        if (refreshed < TOKEN_COST) return interaction.editReply({ content: `❌ Not enough tokens. You have ${refreshed}.` });
      }

      let collected;
      try { collected = await collectCodeFromInteraction(interaction); } catch (err) { return interaction.editReply({ content: `❌ ${err.message}` }); }

      let apiResp;
      try { apiResp = await axios.post(API_OBF, { code: collected.code, api_secret: API_SECRET }, { timeout: API_TIMEOUT }); } catch (err) { return interaction.editReply({ content: `❌ API error: ${err.message}` }); }

      const obf = apiResp?.data?.obfuscatedCode;
      if (!obf) return interaction.editReply({ content: '❌ API did not return obfuscated code.' });

      // Deduct tokens only non-owner/non-whitelisted
      if (String(userId) !== String(OWNER_ID) && !userRow.whitelisted) {
        const ok = await consumeTokens(userId, TOKEN_COST);
        if (!ok) return interaction.editReply({ content: '❌ Failed to deduct tokens. Try again later.' });
      }

      // Save obfuscated file to temp and optionally upload to storage channel
      const tmpPath = path.join(TEMP_DIR, `obf_${Date.now()}.lua`);
      try {
        fs.writeFileSync(tmpPath, obf, 'utf8');
        const publicUrl = await uploadToStorageChannel(client, tmpPath, collected.filename || `obf_${Date.now()}.lua`);

        const embed = new EmbedBuilder()
          .setTitle('Obfuscation Complete')
          .setColor('Purple')
          .setDescription(`<@${userId}> your obfuscated script is ready.`)
          .addFields({ name: 'Preview', value: '```lua\n' + obf.slice(0, 1900) + '\n```' });

        if (publicUrl) embed.addFields({ name: 'Download', value: publicUrl });

        try { await interaction.channel.send({ content: `<@${userId}>`, embeds: [embed] }); } catch (e) {}
        return interaction.editReply({ content: '✅ Obfuscation complete — public output posted.' });

      } catch (e) {
        return interaction.editReply({ content: `❌ Failed to prepare obfuscated file: ${e.message}` });
      } finally {
        cleanupFile(tmpPath);
      }
    }

    // unknown command
    return interaction.reply({ content: 'Unknown command', ephemeral: true });

  } catch (err) {
    console.error('Interaction error:', err);
    try {
      if (interaction.deferred || interaction.replied) {
        await interaction.editReply({ content: '❌ Unexpected error occurred.', ephemeral: true });
      } else {
        await interaction.reply({ content: '❌ Unexpected error occurred.', ephemeral: true });
      }
    } catch (e) { /* ignore */ }
  }
});

client.login(process.env.DISCORD_TOKEN).catch(err => {
  console.error('Login failed:', err);
});
