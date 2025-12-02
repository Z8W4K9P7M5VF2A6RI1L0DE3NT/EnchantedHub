require("dotenv").config();
const {
    Client,
    GatewayIntentBits,
    SlashCommandBuilder,
    Routes,
    REST,
    EmbedBuilder
} = require("discord.js");
const axios = require("axios");

const API_BASE = "https://novahub-zd14.onrender.com";

const client = new Client({
    intents: [GatewayIntentBits.Guilds],
});

// ===================================================
// Slash Commands
// ===================================================
const commands = [
    new SlashCommandBuilder()
        .setName("obfuscate")
        .setDescription("Obfuscate Lua code instantly")
        .addStringOption(o =>
            o.setName("code")
             .setDescription("Paste your Lua script")
             .setRequired(true)
        ),

    new SlashCommandBuilder()
        .setName("store")
        .setDescription("Obfuscate and store a script → returns a key")
        .addStringOption(o =>
            o.setName("code")
             .setDescription("Paste your Lua code")
             .setRequired(true)
        ),

    new SlashCommandBuilder()
        .setName("retrieve")
        .setDescription("Retrieve a stored script by key")
        .addStringOption(o =>
            o.setName("key")
             .setDescription("The script key")
             .setRequired(true)
        ),

    new SlashCommandBuilder()
        .setName("ping")
        .setDescription("Check API response speed"),

    new SlashCommandBuilder()
        .setName("help")
        .setDescription("Shows all NovaHub commands")
];

// ===================================================
// Register Commands
// ===================================================
const rest = new REST({ version: "10" }).setToken(process.env.DISCORD_TOKEN);

(async () => {
    try {
        await rest.put(
            Routes.applicationCommands(process.env.CLIENT_ID),
            { body: commands }
        );
        console.log("Slash commands registered.");
    } catch (err) {
        console.error(err);
    }
})();

// ===================================================
// On Ready
// ===================================================
client.once("ready", () => {
    console.log(`NovaHub bot online → ${client.user.tag}`);
});

// ===================================================
// Interaction Handler
// ===================================================
client.on("interactionCreate", async (interaction) => {
    if (!interaction.isChatInputCommand()) return;

    const name = interaction.commandName;

    // ------------------------ /obfuscate ------------------------
    if (name === "obfuscate") {
        const code = interaction.options.getString("code");

        await interaction.reply({ content: "🔄 Obfuscating...", ephemeral: true });

        try {
            const res = await axios.post(`${API_BASE}/obfuscate`, { code });
            const obf = res.data.obfuscatedCode;

            await interaction.followUp({
                content: "✅ Obfuscation complete!",
                files: [{ attachment: Buffer.from(obf), name: "obfuscated.lua" }],
                ephemeral: true
            });
        } catch {
            await interaction.followUp({ content: "❌ API error.", ephemeral: true });
        }
    }

    // ------------------------ /store ------------------------
    if (name === "store") {
        const code = interaction.options.getString("code");

        await interaction.reply({ content: "🔄 Processing...", ephemeral: true });

        try {
            const res = await axios.post(`${API_BASE}/obfuscate-and-store`, { script: code });

            const key = res.data.key;

            await interaction.followUp({
                content: `✅ **Stored Successfully**\n🔑 Your key: \`${key}\`\nUse: \`/retrieve key:${key}\``,
                ephemeral: true
            });
        } catch {
            await interaction.followUp({ content: "❌ Storage failed.", ephemeral: true });
        }
    }

    // ------------------------ /retrieve ------------------------
    if (name === "retrieve") {
        const key = interaction.options.getString("key");

        await interaction.reply({ content: "🔎 Fetching script...", ephemeral: true });

        try {
            const res = await axios.get(`${API_BASE}/retrieve/${key}`, {
                headers: { "User-Agent": "Roblox" }
            });

            await interaction.followUp({
                content: "✅ Script retrieved!",
                files: [{ attachment: Buffer.from(res.data), name: "retrieved.lua" }],
                ephemeral: true
            });
        } catch {
            await interaction.followUp({ content: "❌ Key not found.", ephemeral: true });
        }
    }

    // ------------------------ /ping ------------------------
    if (name === "ping") {
        const start = Date.now();
        await axios.get(`${API_BASE}/`);
        const ms = Date.now() - start;

        await interaction.reply({
            content: `🏓 API Pong! **${ms}ms**`,
            ephemeral: true
        });
    }

    // ------------------------ /help ------------------------
    if (name === "help") {
        const embed = new EmbedBuilder()
            .setTitle("📘 NovaHub Command List")
            .setColor("Blue")
            .setDescription(`
**/obfuscate** — Obfuscate Lua  
**/store** — Obfuscate + Save  
**/retrieve** — Get stored script  
**/ping** — Check API speed  
**/help** — Show this menu
            `);

        await interaction.reply({ embeds: [embed], ephemeral: true });
    }
});

// ===================================================
// Start Bot
// ===================================================
client.login(process.env.DISCORD_TOKEN);
