// bot.js
// NovaHub single-file bot
// - Uses data/user.json for persistence (creates if missing)
// - /info -> /verify (or /vf) required (DMs user on successful verify)
// - /obf, /store, /api accept pasted code or .lua/.txt attachment
// - /obf posts public file named <original>_obf.lua (option B)
// - /api posts public embed with loader (user copies it)
// - Token system, gifting, whitelist, owner bypass (env-driven)

require("dotenv").config();
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const {
  Client,
  GatewayIntentBits,
  SlashCommandBuilder,
  Routes,
  REST,
  EmbedBuilder
} = require("discord.js");

// ========== CONFIG (env) ==========
const DISCORD_TOKEN = process.env.DISCORD_TOKEN;
const CLIENT_ID = process.env.CLIENT_ID;
const OWNER_ID = process.env.OWNER_ID || "";
const API_BASE = process.env.API_BASE || "https://novahub-zd14.onrender.com";

// Data file (you asked for data/user.json)
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, "data", "user.json");

// Tokens & limits
const INITIAL_TOKENS = parseInt(process.env.INITIAL_TOKENS || "15", 10);
const COMMAND_COST = parseInt(process.env.COMMAND_COST || "5", 10);

const GIFT_LIMIT = parseInt(process.env.GIFT_LIMIT || "30", 10);
const GIFT_TIMES = parseInt(process.env.GIFT_TIMES || "3", 10);
const GIFT_RESET_HOURS = parseInt(process.env.GIFT_RESET_HOURS || "6", 10);

// Command lists
const COMMANDS_WITH_COST = (process.env.COMMANDS_WITH_COST || "/obf,/store,/api").split(",").filter(Boolean);
const FREE_COMMANDS = (process.env.FREE_COMMANDS || "/info,/verify,/vf,/view,/help,/ping,/retrieve").split(",").filter(Boolean);
const PREMIUM_COMMANDS = (process.env.PREMIUM_COMMANDS || "/ApiService").split(",").filter(Boolean);

const REQUIRE_VERIFY = (process.env.REQUIRE_VERIFY || "true").toLowerCase() === "true";

// sanity
if (!DISCORD_TOKEN || !CLIENT_ID) {
  console.error("DISCORD_TOKEN and CLIENT_ID must be set in .env");
  process.exit(1);
}

// ========== STORAGE (JSON file) ==========
function ensureDataFile() {
  const dir = path.dirname(DATA_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, "{}", "utf8");
}
ensureDataFile();

function loadUsers() {
  try {
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    if (!raw) return {};
    return JSON.parse(raw);
  } catch (e) {
    console.error("Failed to load user data — resetting:", e);
    return {};
  }
}
function saveUsers(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
}

function ensureUser(userId) {
  const db = loadUsers();
  if (!db[userId]) {
    db[userId] = {
      verified: false,
      tokens: INITIAL_TOKENS,
      whitelisted: false,
      giftsGiven: [],
      seenInfo: false,
      createdAt: Date.now()
    };
    saveUsers(db);
  }
  return db[userId];
}

function isOwner(userId) { return OWNER_ID && String(userId) === String(OWNER_ID); }
function isWhitelisted(userId) {
  const db = loadUsers();
  return !!(db[userId] && db[userId].whitelisted);
}
function hasInfinite(userId) { return isOwner(userId) || isWhitelisted(userId); }

function giftsInWindow(timestamps) {
  const now = Date.now();
  const cutoff = now - GIFT_RESET_HOURS * 60 * 60 * 1000;
  return (timestamps || []).filter(ts => ts >= cutoff).length;
}
function recordGiftTimestamp(userId) {
  const db = loadUsers();
  ensureUser(userId);
  db[userId].giftsGiven = db[userId].giftsGiven || [];
  db[userId].giftsGiven.push(Date.now());
  // trim old
  const cutoff = Date.now() - GIFT_RESET_HOURS * 60 * 60 * 1000;
  db[userId].giftsGiven = db[userId].giftsGiven.filter(t => t >= cutoff);
  saveUsers(db);
}

function chargeTokens(userId, amount) {
  const db = loadUsers();
  ensureUser(userId);
  if (hasInfinite(userId)) return { ok: true, remaining: Infinity };
  const u = db[userId];
  u.tokens = u.tokens || 0;
  if (u.tokens >= amount) {
    u.tokens -= amount;
    saveUsers(db);
    return { ok: true, remaining: u.tokens };
  } else {
    return { ok: false, reason: "Insufficient tokens" };
  }
}
function addTokens(userId, amount) {
  const db = loadUsers();
  ensureUser(userId);
  if (hasInfinite(userId)) return;
  db[userId].tokens = (db[userId].tokens || 0) + amount;
  saveUsers(db);
}

// ========== Discord setup ==========
const client = new Client({ intents: [GatewayIntentBits.Guilds] });

// Slash commands (attachments allowed for obf/store/api)
const commands = [
  new SlashCommandBuilder()
    .setName("obf")
    .setDescription("Obfuscate Lua code — accepts code or .lua/.txt attachment")
    .addStringOption(o => o.setName("code").setDescription("Paste Lua code"))
    .addAttachmentOption(a => a.setName("file").setDescription("Upload .lua or .txt file")),

  new SlashCommandBuilder()
    .setName("store")
    .setDescription("Obfuscate+store script → returns key (accepts code or file)")
    .addStringOption(o => o.setName("code").setDescription("Paste Lua code"))
    .addAttachmentOption(a => a.setName("file").setDescription("Upload .lua or .txt file")),

  new SlashCommandBuilder()
    .setName("api")
    .setDescription("Obfuscate+store and generate loader (accepts code or file)")
    .addStringOption(o => o.setName("code").setDescription("Paste Lua code"))
    .addAttachmentOption(a => a.setName("file").setDescription("Upload .lua or .txt file")),

  new SlashCommandBuilder()
    .setName("retrieve")
    .setDescription("Retrieve stored script by key")
    .addStringOption(o => o.setName("key").setDescription("script key").setRequired(true)),

  new SlashCommandBuilder().setName("ping").setDescription("Check API response speed"),
  new SlashCommandBuilder().setName("info").setDescription("Show commands, explain rules & beta details"),
  new SlashCommandBuilder().setName("verify").setDescription("Accept rules and enable commands"),
  new SlashCommandBuilder().setName("vf").setDescription("Alias for /verify"),
  new SlashCommandBuilder().setName("view").setDescription("View your remaining tokens"),

  new SlashCommandBuilder()
    .setName("gift")
    .setDescription("Gift tokens to a user (owner & whitelisted only)")
    .addUserOption(o => o.setName("user").setDescription("Recipient").setRequired(true))
    .addIntegerOption(o => o.setName("amount").setDescription("Amount").setRequired(true)),

  new SlashCommandBuilder()
    .setName("wl")
    .setDescription("Whitelist a user (owner only)")
    .addUserOption(o => o.setName("user").setDescription("User to whitelist").setRequired(true)),

  new SlashCommandBuilder()
    .setName("bl")
    .setDescription("Remove user from whitelist (owner only)")
    .addUserOption(o => o.setName("user").setDescription("User to remove").setRequired(true)),

  new SlashCommandBuilder().setName("help").setDescription("Show NovaHub command list")
];

const rest = new REST({ version: "10" }).setToken(DISCORD_TOKEN);
(async () => {
  try {
    await rest.put(Routes.applicationCommands(CLIENT_ID), { body: commands });
    console.log("Slash commands registered.");
  } catch (err) {
    console.error("Failed to register commands:", err);
  }
})();

function infoEmbed() {
  return new EmbedBuilder()
    .setTitle("📘 NovaHub — Info & Rules (BETA)")
    .setColor("Blue")
    .setDescription(
`Welcome to NovaHub (BETA). You must run /verify (or /vf) to accept the rules before using most commands.

Commands:
• /obf — Obfuscate Lua (costs tokens). Accepts pasted code or .lua/.txt file.
• /store — Obfuscate + store (costs tokens). Accepts file or code.
• /api — Obfuscate + store + loader (costs tokens). Accepts file or code.
• /retrieve — Retrieve a stored script by key.
• /view — Show your tokens.
• /gift — Owner / whitelisted users can gift tokens.
• /wl / /bl — Owner only: whitelist / remove whitelist.
• /help — Show this menu.

Notes:
• Charged commands cost ${COMMAND_COST} tokens (configurable).
• New users start with ${INITIAL_TOKENS} tokens.
• Whitelisted users and owner have infinite tokens.
• /gift: max ${GIFT_LIMIT} tokens per gift, up to ${GIFT_TIMES} gifts per ${GIFT_RESET_HOURS} hours (non-owner).
• Input is private (only you see your uploaded source). Output is public in the channel.
• This bot is in BETA — use responsibly.
`
    );
}

async function fetchAttachmentText(attachment) {
  if (!attachment || !attachment.url) throw new Error("No attachment provided.");
  const name = attachment.name || "";
  if (!name.endsWith(".lua") && !name.endsWith(".txt")) {
    throw new Error("Invalid file type — only .lua and .txt allowed.");
  }
  const res = await axios.get(attachment.url, { responseType: "text" });
  return { text: res.data, name: name };
}

client.on("interactionCreate", async (interaction) => {
  if (!interaction.isChatInputCommand()) return;
  const name = interaction.commandName;
  const uid = interaction.user.id;

  ensureUser(uid);
  const user = ensureUser(uid);

  const isFreeCmd = FREE_COMMANDS.includes(`/${name}`);
  if (REQUIRE_VERIFY && !user.verified && !isFreeCmd) {
    await interaction.reply({ content: "🔒 You must run `/info` and then `/verify` (or `/vf`) before using that command.", ephemeral: true });
    return;
  }

  // /info
  if (name === "info") {
    const db = loadUsers();
    db[uid] = db[uid] || {};
    db[uid].seenInfo = true;
    saveUsers(db);
    await interaction.reply({ embeds: [infoEmbed()], ephemeral: true });
    return;
  }

  // /verify or /vf  <-- UPDATED: mark verified, save, send ephemeral reply and DM user on success
  if (name === "verify" || name === "vf") {
    const db = loadUsers();
    db[uid] = db[uid] || {};
    if (db[uid].verified) {
      await interaction.reply({ content: "✅ You are already verified.", ephemeral: true });
      return;
    }
    db[uid].verified = true;
    saveUsers(db);

    // ephemeral reply in channel
    await interaction.reply({ content: "✅ Verified — you can now use commands.", ephemeral: true });

    // DM the user confirming verification (silently ignore if DMs closed)
    try {
      await interaction.user.send("✅ Successfully verified — you may now use NovaHub commands.");
    } catch (err) {
      // user may have DMs closed; don't error
      console.log(`Could not DM ${interaction.user.tag} (${uid}) — they may have DMs disabled.`);
    }
    return;
  }

  // /view
  if (name === "view") {
    const db = loadUsers();
    const u = db[uid] || ensureUser(uid);
    const tokens = hasInfinite(uid) ? "∞ (whitelisted/owner)" : (u.tokens || 0);
    await interaction.reply({ content: `🪙 You have **${tokens}** tokens.`, ephemeral: true });
    return;
  }

  // /gift
  if (name === "gift") {
    const target = interaction.options.getUser("user");
    const amount = interaction.options.getInteger("amount");
    if (!target || typeof amount !== "number") {
      await interaction.reply({ content: "❌ Invalid options.", ephemeral: true });
      return;
    }
    if (amount <= 0) { await interaction.reply({ content: "❌ Amount must be positive.", ephemeral: true }); return; }
    if (amount > GIFT_LIMIT && !isOwner(uid)) { await interaction.reply({ content: `❌ Max per-gift is ${GIFT_LIMIT} tokens.`, ephemeral: true }); return; }

    if (!isOwner(uid) && !isWhitelisted(uid)) {
      await interaction.reply({ content: "❌ Only the owner or whitelisted users can gift tokens.", ephemeral: true });
      return;
    }

    if (!isOwner(uid)) {
      const giver = ensureUser(uid);
      const count = giftsInWindow(giver.giftsGiven || []);
      if (count >= GIFT_TIMES) {
        await interaction.reply({ content: `❌ You reached the gifting limit (${GIFT_TIMES}) for the last ${GIFT_RESET_HOURS} hours.`, ephemeral: true });
        return;
      }
    }

    addTokens(target.id, amount);
    if (!isOwner(uid)) recordGiftTimestamp(uid);

    await interaction.reply({ content: `✅ Gifted **${amount}** tokens to ${target.tag}.`, ephemeral: true });
    try { await target.send(`🎁 You received **${amount}** tokens from ${interaction.user.tag}.`); } catch (e) {}
    return;
  }

  // /wl (owner-only)
  if (name === "wl") {
    if (!isOwner(uid)) { await interaction.reply({ content: "❌ Only the owner can whitelist users.", ephemeral: true }); return; }
    const target = interaction.options.getUser("user");
    if (!target) { await interaction.reply({ content: "❌ Provide a user.", ephemeral: true }); return; }
    const db = loadUsers();
    db[target.id] = db[target.id] || {};
    db[target.id].whitelisted = true;
    saveUsers(db);
    await interaction.reply({ content: `✅ ${target.tag} is now whitelisted (infinite tokens).`, ephemeral: true });
    return;
  }

  // /bl (owner-only)
  if (name === "bl") {
    if (!isOwner(uid)) { await interaction.reply({ content: "❌ Only the owner can remove whitelist.", ephemeral: true }); return; }
    const target = interaction.options.getUser("user");
    if (!target) { await interaction.reply({ content: "❌ Provide a user.", ephemeral: true }); return; }
    const db = loadUsers();
    db[target.id] = db[target.id] || {};
    db[target.id].whitelisted = false;
    saveUsers(db);
    await interaction.reply({ content: `✅ ${target.tag} removed from whitelist.`, ephemeral: true });
    return;
  }

  // charge tokens for costed commands
  const commandPath = `/${name}`;
  const costs = COMMANDS_WITH_COST.includes(commandPath);
  if (costs) {
    const charged = chargeTokens(uid, COMMAND_COST);
    if (!charged.ok) {
      await interaction.reply({ content: `❌ You need ${COMMAND_COST} tokens to run this command. Use /view or ask for a gift.`, ephemeral: true });
      return;
    }
  }

  // helper: read code from string or attachment
  async function getCodeFromInteraction() {
    const codeOption = interaction.options.getString("code");
    const att = interaction.options.getAttachment("file");
    if (att) {
      const res = await fetchAttachmentText(att);
      return { code: res.text, filename: res.name };
    }
    if (codeOption) return { code: codeOption, filename: null };
    throw new Error("No code provided. Please paste code or upload a .lua/.txt file.");
  }

  // /obf
  if (name === "obf") {
    await interaction.reply({ content: "🔄 Processing your input privately...", ephemeral: true });

    let payload;
    try {
      payload = await getCodeFromInteraction();
    } catch (e) {
      await interaction.followUp({ content: `❌ ${e.message}`, ephemeral: true });
      return;
    }

    const code = payload.code;
    const originalName = payload.filename || "output.lua";
    const base = path.basename(originalName, path.extname(originalName));
    const outName = `${base}_obf.lua`;

    try {
      const res = await axios.post(`${API_BASE}/obfuscate`, { code });
      const obf = res.data.obfuscatedCode || res.data.obfuscated || String(res.data || "");
      await interaction.followUp({
        content: `✅ Obfuscation complete! (requested by <@${uid}>)`,
        files: [{ attachment: Buffer.from(obf), name: outName }],
        ephemeral: false
      });
    } catch (err) {
      console.error("Obfuscate error:", err?.response?.data || err?.message || err);
      await interaction.followUp({ content: "❌ API error while obfuscating.", ephemeral: true });
    }
    return;
  }

  // /store
  if (name === "store") {
    await interaction.reply({ content: "🔄 Processing your input privately...", ephemeral: true });

    let payload;
    try {
      payload = await getCodeFromInteraction();
    } catch (e) {
      await interaction.followUp({ content: `❌ ${e.message}`, ephemeral: true });
      return;
    }

    try {
      const res = await axios.post(`${API_BASE}/obfuscate-and-store`, { script: payload.code });
      const key = res.data.key;
      await interaction.followUp({ content: `✅ Stored Successfully by <@${uid}> — Key: \`${key}\``, ephemeral: false });
    } catch (err) {
      console.error("Store error:", err?.response?.data || err?.message || err);
      await interaction.followUp({ content: "❌ Storage failed.", ephemeral: true });
    }
    return;
  }

  // /api
  if (name === "api") {
    await interaction.reply({ content: "🔄 Processing your input privately...", ephemeral: true });

    let payload;
    try {
      payload = await getCodeFromInteraction();
    } catch (e) {
      await interaction.followUp({ content: `❌ ${e.message}`, ephemeral: true });
      return;
    }

    try {
      const res = await axios.post(`${API_BASE}/obfuscate-and-store`, { script: payload.code });
      const key = res.data.key;
      const loader = `loadstring(game:HttpGet("${API_BASE}/retrieve/${key}"))()`;

      const embed = new EmbedBuilder()
        .setTitle("API Loader (copy this)")
        .setDescription(`**Key:** \`${key}\`\n\n**Loader:**\n\`\`\`lua\n${loader}\n\`\`\``)
        .setFooter({ text: `Requested by ${interaction.user.tag}` });

      await interaction.followUp({ content: `✅ API Loader Created by <@${uid}>`, embeds: [embed], ephemeral: false });
    } catch (err) {
      console.error("API store error:", err?.response?.data || err?.message || err);
      await interaction.followUp({ content: "❌ API Loader failed.", ephemeral: true });
    }
    return;
  }

  // /retrieve
  if (name === "retrieve") {
    const key = interaction.options.getString("key");
    await interaction.reply({ content: "🔎 Fetching script...", ephemeral: true });
    try {
      const res = await axios.get(`${API_BASE}/retrieve/${key}`, { responseType: "arraybuffer", headers: { "User-Agent": "Roblox" } });
      const buf = Buffer.from(res.data);
      await interaction.followUp({
        content: `✅ Script retrieved by <@${uid}>`,
        files: [{ attachment: buf, name: "retrieved.lua" }],
        ephemeral: false
      });
    } catch (err) {
      console.error("Retrieve error:", err?.response?.data || err?.message || err);
      await interaction.followUp({ content: "❌ Key not found.", ephemeral: true });
    }
    return;
  }

  // /ping
  if (name === "ping") {
    const start = Date.now();
    try { await axios.get(`${API_BASE}/`); } catch (_) {}
    const ms = Date.now() - start;
    await interaction.reply({ content: `🏓 API Pong! **${ms}ms**`, ephemeral: true });
    return;
  }

  // /help
  if (name === "help") {
    const embed = new EmbedBuilder()
      .setTitle("📘 NovaHub Command List")
      .setColor("Blue")
      .setDescription(`
**/info** — Show info & rules (first-run)
**/verify / vf** — Accept rules
**/obf** — Obfuscate Lua (costs tokens) — accepts code or .lua/.txt
**/store** — Obfuscate + Save (costs tokens)
**/api** — Obfuscate + Save + Generate Loader (costs tokens)
**/retrieve** — Get stored script
**/view** — Show token balance
**/gift** — Owner/whitelist gift tokens
**/wl / bl** — Owner whitelist / remove whitelist
**/ping** — API ping
**/help** — Show this menu
      `);
    await interaction.reply({ embeds: [embed], ephemeral: false });
    return;
  }

  // fallback
  await interaction.reply({ content: "Unhandled command.", ephemeral: true });
});

// start
client.once("ready", () => {
  console.log(`NovaHub bot online → ${client.user?.tag || "unknown"}`);
});
client.login(DISCORD_TOKEN);
