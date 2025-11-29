require("dotenv").config();
const {
  Client,
  Intents,
  MessageEmbed,
  MessageActionRow,
  MessageSelectMenu,
  MessageAttachment,
} = require("discord.js");
const axios = require("axios");
const fs = require("fs");
const child_process = require("child_process");
const path = require("path");

// --- CONFIGURATION & UTILITIES ---

const log = (...e) => console.log("[PROMETHEUS]", ...e);
const error = (...e) => console.error("[PROMETHEUS]", ...e);

// IMPORTANT: This directory must be created manually in your project root.
const tempDir = path.join(__dirname, "Temp_files");
if (!fs.existsSync(tempDir)) {
  error("❌ Temp_files directory does not exist! Please create it manually.");
  process.exit(1);
}

// Environment variable for the CDN/Storage channel ID
const STORAGE_CHANNEL_ID = process.env.STORAGE_CHANNEL_ID || process.env.CDN_STORAGE_CHANNEL_ID;

/**
 * Fetches the storage channel object to upload files to.
 * @param {Client} client
 * @returns {Promise<import('discord.js').TextChannel>}
 */
async function ensureStorageChannel(client) {
  if (!STORAGE_CHANNEL_ID) throw new Error("STORAGE_CHANNEL_ID is not set in .env");
  let ch = client.channels.cache.get(STORAGE_CHANNEL_ID);
  if (!ch) ch = await client.channels.fetch(STORAGE_CHANNEL_ID).catch(() => null);
  
  if (!ch || !("send" in ch)) {
    throw new Error("STORAGE_CHANNEL_ID does not point to a text channel the bot can send to.");
  }
  return ch;
}

/**
 * Executes the external Nyx Obfuscator using LuaJIT.
 * WARNING: Relies on the external files: ./bin/luajit.exe and ./lua/cli.lua
 * @param {string} inputFile - Path to the raw Lua file.
 * @param {string} preset - The obfuscation preset (Weak, Medium, Strong).
 * @returns {Promise<string>} The path to the resulting obfuscated file.
 */
function obfuscate(inputFile, preset) {
  return new Promise((resolve, reject) => {
    // The Strong preset internally uses the Medium preset
    const presetToUse = preset === "Strong" ? "Medium" : preset;
    
    // Define the output file path in the temp directory
    const outputFile = path.join(tempDir, `obfuscated_${Date.now()}.lua`);
    
    // --- CRITICAL EXECUTION COMMAND ---
    // Ensure the path to luajit.exe and cli.lua are correct for your environment!
    const proc = child_process.spawn("./bin/luajit.exe", [
      "./lua/cli.lua",
      "--preset",
      presetToUse,
      inputFile,
      "--out",
      outputFile,
    ]);
    
    let stderr = "";
    proc.stderr.on("data", (d) => (stderr += d.toString()));
    
    proc.on("error", (err) => {
        error(`[OBF_ERR] Spawn failed for luajit.exe:`, err.message);
        reject(`Failed to execute obfuscator: Is './bin/luajit.exe' accessible? Details: ${err.message}`);
    });
    
    proc.on("close", (code) => {
      if (code !== 0) {
        error(`[OBF_ERR] LuaJIT exited with code ${code}. Stderr: ${stderr}`);
        return reject(stderr || `luajit exited with code ${code}. Check the server logs.`);
      }
      
      // Check if the output file was actually created and has content
      if (!fs.existsSync(outputFile) || fs.readFileSync(outputFile).length === 0) {
          return reject("Obfuscator finished but failed to produce a valid output file.");
      }
      
      resolve(outputFile);
    });
  });
}

// --- BOT INITIALIZATION ---

// Collect all tokens from env (e.g., DISCORD_TOKEN_1, DISCORD_TOKEN_2)
const tokens = Object.keys(process.env)
  .filter((key) => key.startsWith("DISCORD_TOKEN"))
  .map((key) => process.env[key]);

if (tokens.length === 0) {
  error("❌ No DISCORD_TOKEN found in .env! Please set at least DISCORD_TOKEN_1.");
  process.exit(1);
}

/**
 * Creates and launches a single Discord bot instance.
 * @param {string} token - The bot token.
 * @param {number} botNumber - The bot's index number.
 */
function createBot(token, botNumber) {
  // Use Intents.FLAGS.* as requested (compatible with discord.js v13)
  const client = new Client({
    intents: [Intents.FLAGS.GUILDS, Intents.FLAGS.GUILD_MESSAGES, Intents.FLAGS.DIRECT_MESSAGES],
    partials: ["CHANNEL"],
  });

  client.once("ready", () => {
    log(`✅ Bot #${botNumber} logged in as ${client.user?.tag || "Unknown"}`);

    // Set presence: DND + Playing Obfuscating Nyx Files
    client.user.setPresence({
      status: "dnd",
      activities: [
        {
          name: "Obfuscating Nyx Files",
          type: "PLAYING",
        },
      ],
    });
  });

  client.login(token);

  client.on("messageCreate", async (msg) => {
    // Ignore bots and empty content messages
    if (msg.author.bot || !msg.content) return;

    // --- .help COMMAND ---
    if (msg.content.toLowerCase() === ".help") {
      const helpText = `Here’s how to use the bot to obfuscate your scripts:
🔹 Command: \`.obf\` [attach your \`.lua\`/\`.txt\` file or paste inside a codeblock]
🔹 Supported Files: \`.lua\` and \`.txt\` only, or codeblocks
🔹 Obfuscation Levels: Weak 🪶, Medium 🛡️, Strong 💪 (chosen via dropdown)
🔒 Privacy: Use this bot in Direct Messages (DMs) for privacy.
🔹 Example: \`.obf\` → Attach file OR paste in codeblock → Choose obfuscation level → Get protected file ✅`;

      const helpEmbed = new MessageEmbed()
        .setColor("BLUE")
        .setTitle("📖 Obfuscator Bot Help")
        .setDescription(helpText)
        .setFooter({ text: "Made by Slayerson • Credits to Vyxonq • Powered by Nyx Obfuscator" });

      msg.channel.send({ embeds: [helpEmbed] }).catch((err) => error("Failed to send help message:", err));
      return;
    }

    // --- .obf COMMAND ---
    if (msg.content.toLowerCase().startsWith(".obf")) {
      let inputFile;
      let outputFile;
      let finalFile;
      let originalFileName;

      let cleanupFiles = []; // Array to track files for cleanup

      try {
          // --- 1. HANDLE INPUT (Attachment or Code Block) ---
          const attachment = msg.attachments.first();
          
          if (attachment) {
            // File attachment handler
            const ext = path.extname(attachment.name).toLowerCase();
            if (ext !== ".lua" && ext !== ".txt") {
              const errorEmbed = new MessageEmbed()
                .setColor("RED")
                .setTitle("❌ Obfuscation Failed")
                .setDescription("Only `.lua` and `.txt` file attachments are supported!");
              msg.reply({ embeds: [errorEmbed] });
              return;
            }

            inputFile = path.join(tempDir, `input_${Date.now()}${ext}`);
            cleanupFiles.push(inputFile);
            originalFileName = attachment.name;
            
            // Download the file stream and wait for it to finish writing
            const response = await axios({ method: "GET", url: attachment.url, responseType: "stream" });
            const writer = fs.createWriteStream(inputFile);
            response.data.pipe(writer);

            await new Promise((resolve, reject) => {
              writer.on("finish", resolve);
              writer.on("error", reject);
            });

          } else {
            // Code block handler
            const codeBlockMatch = msg.content.match(/
