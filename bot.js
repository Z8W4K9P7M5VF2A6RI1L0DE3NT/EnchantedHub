// bot.js
// NovaHub Discord Bot — EXACTLY your structure, using your API only

require('dotenv').config();
const {
    Client,
    GatewayIntentBits,
    REST,
    Routes,
    SlashCommandBuilder,
    EmbedBuilder
} = require('discord.js');
const axios = require('axios');
const { Pool } = require('pg');

// ======================================================
// ENV + CONSTANTS
// ======================================================
const DISCORD_TOKEN = process.env.DISCORD_TOKEN;
const CLIENT_ID = process.env.CLIENT_ID;
const OWNER_ID = process.env.OWNER_ID;
const API_BASE = process.env.API_BASE || "https://novahub-zd14.onrender.com";

if (!DISCORD_TOKEN || !CLIENT_ID || !OWNER_ID) {
    console.error("❌ Missing DISCORD_TOKEN, CLIENT_ID, or OWNER_ID in .env");
    process.exit(1);
}

// Database
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Cost system
const TOKEN_COST = 5;

// Discord client
const client = new Client({
    intents: [GatewayIntentBits.Guilds]
});

// ======================================================
// Slash Commands
// ======================================================
const commands = [

    // ping
    new SlashCommandBuilder()
        .setName("ping")
        .setDescription("Check bot latency"),

    // verify
    new SlashCommandBuilder()
        .setName("verify")
        .setDescription("Accept rules & verify"),

    // view
    new SlashCommandBuilder()
        .setName("view")
        .setDescription("View your token balance"),

    // obf command
    new SlashCommandBuilder()
        .setName("obf")
        .setDescription("Obfuscate a .lua or .txt file (costs 5 tokens)")
        .addAttachmentOption(o =>
            o.setName("file")
             .setDescription("Upload .lua or .txt file")
             .setRequired(true)
        ),

    // api command
    new SlashCommandBuilder()
        .setName("api")
        .setDescription("Whitelist-only: obfuscate, store & return loader (costs 5 tokens)")
        .addAttachmentOption(o =>
            o.setName("file")
             .setDescription("Upload .lua or .txt file")
             .setRequired(true)
        ),

    // gift
    new SlashCommandBuilder()
        .setName("gift")
        .setDescription("Owner/whitelist: gift tokens to a user")
        .addUserOption(o =>
            o.setName("user")
             .setDescription("User to receive tokens")
             .setRequired(true)
        )
        .addIntegerOption(o =>
            o.setName("amount")
             .setDescription("Amount of tokens")
             .setRequired(true)
        ),

    // whitelist
    new SlashCommandBuilder()
        .setName("wl")
        .setDescription("Owner-only: whitelist a user")
        .addUserOption(o =>
            o.setName("user")
             .setDescription("User to whitelist")
             .setRequired(true)
        ),

    // blacklist
    new SlashCommandBuilder()
        .setName("bl")
        .setDescription("Owner-only: remove whitelist")
        .addUserOption(o =>
            o.setName("user")
             .setDescription("User to un-whitelist")
             .setRequired(true)
        )

].map(c => c.toJSON());

// Register commands
const rest = new REST({ version: '10' }).setToken(DISCORD_TOKEN);

(async () => {
    try {
        console.log("Registering slash commands...");
        await rest.put(
            Routes.applicationCommands(CLIENT_ID),
            { body: commands }
        );
        console.log("Slash commands registered.");
    } catch (err) {
        console.error("Error registering commands:", err);
    }
})();

// ======================================================
// Database helpers
// ======================================================
async function ensureUserRow(userId) {
    await pool.query(
        `INSERT INTO users(user_id) VALUES($1)
         ON CONFLICT (user_id) DO NOTHING`,
        [userId]
    );
}

async function getUser(userId) {
    await ensureUserRow(userId);
    const r = await pool.query(
        `SELECT user_id, tokens, whitelisted FROM users WHERE user_id=$1`,
        [userId]
    );
    return r.rows[0];
}

async function changeTokens(userId, amount) {
    await ensureUserRow(userId);
    await pool.query(
        `UPDATE users SET tokens = tokens + $1 WHERE user_id=$2`,
        [amount, userId]
    );
    const r = await pool.query(`SELECT tokens FROM users WHERE user_id=$1`, [userId]);
    return r.rows[0].tokens;
}

async function setWhitelist(userId, val) {
    await ensureUserRow(userId);
    await pool.query(`UPDATE users SET whitelisted=$1 WHERE user_id=$2`, [val, userId]);
}

async function chargeIfEnough(userId, cost) {
    const user = await getUser(userId);
    if ((user.tokens || 0) < cost) return false;
    await changeTokens(userId, -cost);
    return true;
}

// ======================================================
// Bot ready
// ======================================================
client.once("ready", () => {
    console.log(`NovaHub bot logged in as ${client.user.tag}`);
});

// ======================================================
// Slash command handler
// ======================================================
client.on("interactionCreate", async interaction => {
    if (!interaction.isChatInputCommand()) return;

    const cmd = interaction.commandName;
    const uid = interaction.user.id;

    try {

        // /ping ------------------------------------------
        if (cmd === "ping") {
            const sent = await interaction.reply({
                content: "Pinging...",
                fetchReply: true,
                ephemeral: true
            });

            const ms = Date.now() - sent.createdTimestamp;
            return interaction.editReply(`🏓 Pong! **${ms}ms**`);
        }

        // /verify ----------------------------------------
        if (cmd === "verify") {
            await ensureUserRow(uid);
            return interaction.reply({
                content: "✅ Verified successfully.",
                ephemeral: true
            });
        }

        // /view ------------------------------------------
        if (cmd === "view") {
            const u = await getUser(uid);
            return interaction.reply({
                content: `🔹 Tokens: ${u.tokens || 0}\n🔹 Whitelisted: ${u.whitelisted ? "Yes" : "No"}`,
                ephemeral: true
            });
        }

        // /obf -------------------------------------------
        if (cmd === "obf") {
            await interaction.deferReply({ ephemeral: true });

            const file = interaction.options.getAttachment("file");
            if (!file) return interaction.editReply("❌ No file provided.");

            const ext = file.name.split(".").pop().toLowerCase();
            if (!["lua", "txt"].includes(ext)) {
                return interaction.editReply("❌ Only .lua or .txt files allowed.");
            }

            const ok = await chargeIfEnough(uid, TOKEN_COST);
            if (!ok) return interaction.editReply(`❌ Need ${TOKEN_COST} tokens.`);

            try {
                const raw = await axios.get(file.url, { responseType: "text" });
                const script = raw.data;

                const api = await axios.post(
                    `${API_BASE}/obf`,
                    { script },
                    { timeout: 30000 }
                );

                const obf = api.data.obfuscatedCode || api.data.obfuscated || "";

                return interaction.editReply({
                    content: "✅ Obfuscation complete.",
                    files: [{
                        attachment: Buffer.from(obf, "utf8"),
                        name: "obfuscated.lua"
                    }]
                });

            } catch (err) {
                console.error("obf error:", err);
                await changeTokens(uid, TOKEN_COST); // refund
                return interaction.editReply("❌ Obfuscation failed. Tokens refunded.");
            }
        }

        // /api -------------------------------------------
        if (cmd === "api") {
            await interaction.deferReply({ ephemeral: true });

            const file = interaction.options.getAttachment("file");
            if (!file) return interaction.editReply("❌ No file provided.");

            const user = await getUser(uid);
            if (!user.whitelisted && uid !== OWNER_ID) {
                return interaction.editReply("❌ You are not whitelisted for /api.");
            }

            const ext = file.name.split(".").pop().toLowerCase();
            if (!["lua", "txt"].includes(ext)) {
                return interaction.editReply("❌ Only .lua or .txt files allowed.");
            }

            const ok = await chargeIfEnough(uid, TOKEN_COST);
            if (!ok) return interaction.editReply(`❌ Need ${TOKEN_COST} tokens.`);

            try {
                const raw = await axios.get(file.url, { responseType: "text" });
                const script = raw.data;

                const store = await axios.post(
                    `${API_BASE}/obfuscate-and-store`,
                    { script },
                    { timeout: 30000 }
                );

                const key = store.data.key;
                if (!key) {
                    await changeTokens(uid, TOKEN_COST);
                    return interaction.editReply("❌ Storage failed. Tokens refunded.");
                }

                const loader = `loadstring(game:HttpGet("${API_BASE}/retrieve/${key}"))()`;

                return interaction.editReply({
                    content: `✅ Stored successfully!\n🔑 Key: \`${key}\`\n\n📦 Loader:\n\`\`\`lua\n${loader}\n\`\`\``
                });

            } catch (err) {
                console.error("api error:", err);
                await changeTokens(uid, TOKEN_COST);
                return interaction.editReply("❌ API request failed. Tokens refunded.");
            }
        }

        // /gift -------------------------------------------
        if (cmd === "gift") {
            const target = interaction.options.getUser("user");
            const amount = interaction.options.getInteger("amount");

            if (!target || !amount || amount <= 0) {
                return interaction.reply({ content: "❌ Invalid arguments.", ephemeral: true });
            }

            const giver = await getUser(uid);
            if (uid !== OWNER_ID && !giver.whitelisted) {
                return interaction.reply({ content: "❌ Only owner or whitelisted may gift.", ephemeral: true });
            }

            await ensureUserRow(target.id);
            await changeTokens(target.id, amount);

            return interaction.reply({
                content: `✅ Gifted **${amount} tokens** to <@${target.id}>.`,
                ephemeral: true
            });
        }

        // /wl ---------------------------------------------
        if (cmd === "wl") {
            if (uid !== OWNER_ID) {
                return interaction.reply({ content: "❌ Owner-only.", ephemeral: true });
            }
            const target = interaction.options.getUser("user");
            await setWhitelist(target.id, true);
            return interaction.reply({ content: `✅ Whitelisted <@${target.id}>.`, ephemeral: true });
        }

        // /bl ---------------------------------------------
        if (cmd === "bl") {
            if (uid !== OWNER_ID) {
                return interaction.reply({ content: "❌ Owner-only.", ephemeral: true });
            }
            const target = interaction.options.getUser("user");
            await setWhitelist(target.id, false);
            return interaction.reply({ content: `✅ Removed whitelist for <@${target.id}>.`, ephemeral: true });
        }

    } catch (err) {
        console.error("Handler error:", err);
        try {
            await interaction.reply({ content: "❌ Internal error.", ephemeral: true });
        } catch {}
    }
});

// ======================================================
// Start bot
// ======================================================
client.login(DISCORD_TOKEN);
