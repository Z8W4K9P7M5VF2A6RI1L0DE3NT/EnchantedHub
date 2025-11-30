// bot.js
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

///////////////////////////////////////////////////////////////////////////////
// Configuration
///////////////////////////////////////////////////////////////////////////////

// Use env DATABASE_URL if provided, otherwise default to the string you gave
const DEFAULT_DB =
  process.env.DATABASE_URL ||
  'postgresql://novahub_storage_db_user:cAwES98xEKyjilfQUErUJsuF9qoVMVS4@dpg-d4a99875r7bs73e9iobg-a/novahub_storage_db';

const pool = new Pool({
  connectionString: DEFAULT_DB,
  // If your provider requires SSL, uncomment next lines.
  // ssl: {
  //   rejectUnauthorized: false
  // }
});

const DOMAIN = 'https://novahub-zd14.onrender.com';
const API_OBF_STORE = `${DOMAIN}/obfuscate-and-store`;
const API_OBF = `${DOMAIN}/obfuscate`;
const RETRIEVE_URL = (key) => `${DOMAIN}/retrieve/${key}`;

const TEMP_DIR = path.join(__dirname, 'Temp_files');
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });

const OWNER_ID = process.env.OWNER_ID || '';
const TOKEN_COST = 5;
const DAILY_TOKENS = 15;
const API_TIMEOUT = 120000; // 2 minutes

///////////////////////////////////////////////////////////////////////////////
// Database Init / Helpers
///////////////////////////////////////////////////////////////////////////////

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
      giver TEXT,
      receiver TEXT,
      amount INTEGER,
      created_at BIGINT
    );
  `);

  // Optional scripts table for local copies (not required but handy)
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
    await pool.query(
      'INSERT INTO users(id, tokens, last_refresh, verified, whitelisted) VALUES($1, $2, $3, $4, $5)',
      [userId, DAILY_TOKENS, Date.now(), false, false]
    );
    return {
      id: userId,
      tokens: DAILY_TOKENS,
      last_refresh: Date.now(),
      verified: false,
      whitelisted: false
    };
  }
  return rows[0];
}

async function refreshTokensIfNeeded(userId) {
  const user = await ensureUserRow(userId);
  const now = Date.now();
  const diff = now - Number(user.last_refresh);
  const dayMs = 24 * 60 * 60 * 1000;
  if (diff >= dayMs) {
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

async function consumeTokens(userId, amount) {
  await refreshTokensIfNeeded(userId);
  const user = await getUser(userId);
  if (Number(user.tokens) < amount) return false;
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

///////////////////////////////////////////////////////////////////////////////
// File download helper
///////////////////////////////////////////////////////////////////////////////

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

///////////////////////////////////////////////////////////////////////////////
// Slash commands definition
///////////////////////////////////////////////////////////////////////////////

const commands = [
  new SlashCommandBuilder()
    .setName('info')
    .setDescription('Show usage and information'),
  new SlashCommandBuilder()
    .setName('verify')
    .setDescription('Accept rules & verify'),
  new SlashCommandBuilder()
    .setName('view')
    .setDescription('View your token balance'),
  new SlashCommandBuilder()
    .setName('gift')
    .setDescription('Owner-only: gift tokens')
    .addUserOption(opt => opt.setName('user').setDescription('Recipient').setRequired(true))
    .addIntegerOption(opt => opt.setName('amount').setDescription('Amount').setRequired(true)),
  new SlashCommandBuilder()
    .setName('wl')
    .setDescription('Owner-only: whitelist management')
    .addSubcommand(sc => sc.setName('add').setDescription('Add user to whitelist').addUserOption(o => o.setName('user').setRequired(true)))
    .addSubcommand(sc => sc.setName('remove').setDescription('Remove user from whitelist').addUserOption(o => o.setName('user').setRequired(true)))
    .addSubcommand(sc => sc.setName('list').setDescription('List whitelisted users')),
  new SlashCommandBuilder()
    .setName('apiservice')
    .setDescription('(Whitelist only) Obfuscate & store; costs 5 tokens')
    .addAttachmentOption(opt => opt.setName('file').setDescription('Lua or .txt file').setRequired(false))
    .addStringOption(opt => opt.setName('code').setDescription('Or paste Lua code').setRequired(false)),
  new SlashCommandBuilder()
    .setName('obf')
    .setDescription('Obfuscate code only; costs 5 tokens')
    .addAttachmentOption(opt => opt.setName('file').setDescription('Lua or .txt file').setRequired(false))
    .addStringOption(opt => opt.setName('code').setDescription('Or paste Lua code').setRequired(false))
].map(c => c.toJSON());

///////////////////////////////////////////////////////////////////////////////
// Register slash commands
///////////////////////////////////////////////////////////////////////////////

const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN);
(async () => {
  try {
    await rest.put(Routes.applicationCommands(process.env.CLIENT_ID), { body: commands });
    console.log('Slash commands registered.');
  } catch (err) {
    console.error('Failed to register commands:', err);
  }
})();

///////////////////////////////////////////////////////////////////////////////
// Bot client
///////////////////////////////////////////////////////////////////////////////

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

  // Ensure user row + refresh tokens as needed
  await ensureUserRow(userId);
  await refreshTokensIfNeeded(userId);
  const user = await getUser(userId);

  try {
    // ----- /info -----
    if (cmd === 'info') {
      const embed = new EmbedBuilder()
        .setTitle('NovaHub Bot — Info (BETA)')
        .setColor('Blue')
        .setDescription('Welcome! This bot is in **BETA**. Use /verify to accept rules. Premium commands cost tokens (5 each). Use /view to check balance.')
        .addFields(
          { name: '/verify', value: 'Accept rules & verify', inline: true },
          { name: '/view', value: 'View your token balance', inline: true },
          { name: '/apiservice', value: 'Whitelist only — obfuscate & store (5 tokens)', inline: false },
          { name: '/obf', value: 'Obfuscate code only (5 tokens)', inline: false },
          { name: '/gift', value: 'Owner only: gift tokens', inline: false },
          { name: '/wl', value: 'Owner only: manage whitelist', inline: false }
        )
        .addFields({ name: 'Notes', value: 'Tokens refresh every 24 hours based on your last refresh timestamp.' });

      await interaction.reply({ embeds: [embed], ephemeral: true });
      return;
    }

    // ----- /verify -----
    if (cmd === 'verify') {
      await setVerified(userId);

      // optional: send webhook / log (you can set LOG_WEBHOOK env var)
      if (process.env.LOG_WEBHOOK) {
        try {
          await axios.post(process.env.LOG_WEBHOOK, {
            content: `🟢 User Verified: <@${userId}> (${userId})`
          });
        } catch (e) { /* ignore */ }
      }

      await interaction.reply({ content: '✅ You are now verified. You may use commands (if whitelisted).', ephemeral: true });
      return;
    }

    // ----- /view -----
    if (cmd === 'view') {
      const refreshed = await refreshTokensIfNeeded(userId);
      await interaction.reply({ content: `💠 You have **${refreshed}** tokens. Tokens refresh every 24 hours.`, ephemeral: true });
      return;
    }

    // ----- /gift -----
    if (cmd === 'gift') {
      if (String(userId) !== String(OWNER_ID)) return interaction.reply({ content: '❌ Only the bot owner can gift tokens.', ephemeral: true });
      const target = interaction.options.getUser('user');
      const amount = interaction.options.getInteger('amount');
      if (!target || !amount || amount <= 0) return interaction.reply({ content: '❌ Invalid target or amount.', ephemeral: true });

      await ensureUserRow(target.id);
      await addTokens(target.id, amount);
      await pool.query('INSERT INTO gifts(giver, receiver, amount, created_at) VALUES($1,$2,$3,$4)', [userId, target.id, amount, Date.now()]);

      // notify
      try { await interaction.channel.send({ content: `<@${target.id}> you were gifted **${amount}** tokens by the owner.` }); } catch (e) {}
      await interaction.reply({ content: `🎁 Gifted **${amount}** tokens to ${target.tag}.`, ephemeral: true });
      return;
    }

    // ----- /wl (add/remove/list) -----
    if (cmd === 'wl') {
      if (String(userId) !== String(OWNER_ID)) return interaction.reply({ content: '❌ Only the owner can manage whitelist.', ephemeral: true });
      const sub = interaction.options.getSubcommand();
      if (sub === 'add') {
        const u = interaction.options.getUser('user');
        await ensureUserRow(u.id);
        await setWhitelist(u.id, true);
        await interaction.reply({ content: `✅ ${u.tag} added to whitelist.`, ephemeral: true });
        return;
      } else if (sub === 'remove') {
        const u = interaction.options.getUser('user');
        await ensureUserRow(u.id);
        await setWhitelist(u.id, false);
        await interaction.reply({ content: `✅ ${u.tag} removed from whitelist.`, ephemeral: true });
        return;
      } else {
        const { rows } = await pool.query('SELECT id FROM users WHERE whitelisted = TRUE');
        const list = rows.map(r => `<@${r.id}>`).join(', ') || 'None';
        await interaction.reply({ content: `Whitelisted: ${list}`, ephemeral: true });
        return;
      }
    }

    // Helper: collect code input (attachment or code string)
    async function collectCodeFromInteraction(interaction) {
      // check attachment option
      const file = interaction.options.getAttachment('file');
      if (file) {
        const ext = path.extname(file.name).toLowerCase();
        if (!['.lua', '.txt'].includes(ext)) throw new Error('Unsupported file type. Use .lua or .txt');
        const tempPath = path.join(TEMP_DIR, `input_${Date.now()}_${file.name}`);
        try {
          await downloadAttachment(file.url, tempPath);
          const content = fs.readFileSync(tempPath, 'utf8');
          cleanupFile(tempPath);
          return { code: content, filename: file.name };
        } catch (e) {
          cleanupFile(tempPath);
          throw new Error('Failed to download attachment');
        }
      }

      const codeStr = interaction.options.getString('code');
      if (codeStr && codeStr.trim().length > 0) return { code: codeStr, filename: `code_${Date.now()}.lua` };

      throw new Error('No code provided. Attach a file or use the code option.');
    }

    // ----- /apiservice (whitelist required, 5 tokens) -----
    if (cmd === 'apiservice') {
      // ephemeral input step
      await interaction.deferReply({ ephemeral: true });

      if (!user.verified) return interaction.editReply({ content: '❌ You must run /verify first.' });
      if (!user.whitelisted) return interaction.editReply({ content: '❌ This command requires whitelist access.' });

      const tokensNow = await refreshTokensIfNeeded(userId);
      if (tokensNow < TOKEN_COST) return interaction.editReply({ content: `❌ Not enough tokens. You have ${tokensNow}.` });

      // collect code
      let collected;
      try {
        collected = await collectCodeFromInteraction(interaction);
      } catch (err) {
        return interaction.editReply({ content: `❌ ${err.message}` });
      }

      // call API: obfuscate-and-store
      let apiResp;
      try {
        apiResp = await axios.post(API_OBF_STORE, { code: collected.code }, { timeout: API_TIMEOUT });
      } catch (err) {
        return interaction.editReply({ content: `❌ API error: ${err.message}` });
      }

      const key = apiResp?.data?.key;
      if (!key) {
        return interaction.editReply({ content: '❌ API did not return a key.' });
      }

      // consume tokens
      await consumeTokens(userId, TOKEN_COST);

      // build loader
      const loader = `return loadstring(game:HttpGet("${RETRIEVE_URL(key)}"))()`;

      const publicEmbed = new EmbedBuilder()
        .setColor('Blurple')
        .setTitle('🔐 NovaHub API — File Stored')
        .setDescription(`<@${userId}> your file has been processed and stored.`)
        .addFields(
          { name: 'Retrieve URL', value: RETRIEVE_URL(key) },
          { name: 'Key', value: `\`${key}\`` },
          { name: 'Roblox Loader', value: '```lua\n' + loader + '\n```' }
        )
        .setFooter({ text: 'NovaHub API' });

      // public message (ping user)
      try { await interaction.channel.send({ content: `<@${userId}>`, embeds: [publicEmbed] }); } catch (e) {}

      await interaction.editReply({ content: '✅ Processed — public output posted.' });
      return;
    }

    // ----- /obf (public obfuscate, 5 tokens) -----
    if (cmd === 'obf') {
      await interaction.deferReply({ ephemeral: true });

      if (!user.verified) return interaction.editReply({ content: '❌ You must run /verify first.' });

      const tokensNow = await refreshTokensIfNeeded(userId);
      if (tokensNow < TOKEN_COST) return interaction.editReply({ content: `❌ Not enough tokens. You have ${tokensNow}.` });

      // collect code
      let collected;
      try {
        collected = await collectCodeFromInteraction(interaction);
      } catch (err) {
        return interaction.editReply({ content: `❌ ${err.message}` });
      }

      // call API: /obfuscate
      let apiResp;
      try {
        apiResp = await axios.post(API_OBF, { code: collected.code }, { timeout: API_TIMEOUT });
      } catch (err) {
        return interaction.editReply({ content: `❌ API error: ${err.message}` });
      }

      const obf = apiResp?.data?.obfuscatedCode;
      if (!obf) {
        return interaction.editReply({ content: '❌ API did not return obfuscated code.' });
      }

      // consume tokens
      await consumeTokens(userId, TOKEN_COST);

      // Prepare public embed with preview and optionally upload to storage channel if desired
      const embed = new EmbedBuilder()
        .setColor('Purple')
        .setTitle('Obfuscation Complete')
        .setDescription('Preview (first 1900 chars):')
        .addFields({ name: 'Obfuscated (preview)', value: '```lua\n' + (obf.slice(0, 1900)) + '\n```' });

      // Public message
      try { await interaction.channel.send({ content: `<@${userId}>`, embeds: [embed] }); } catch (e) {}
      await interaction.editReply({ content: '✅ Obfuscation complete — public output posted.' });
      return;
    }

    // Unknown command fallback
    await interaction.reply({ content: 'Unknown command', ephemeral: true });

  } catch (err) {
    console.error('Interaction error:', err);
    try { await interaction.editReply({ content: '❌ Unexpected error occurred.', ephemeral: true }); } catch (e) {}
  }
});

client.login(process.env.DISCORD_TOKEN).catch(err => {
  console.error('Login failed:', err);
});
