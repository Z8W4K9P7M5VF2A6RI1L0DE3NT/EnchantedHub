// bot.js
require("dotenv").config();
const {
  Client,
  GatewayIntentBits,
  Partials,
  EmbedBuilder,
  ActionRowBuilder,
  StringSelectMenuBuilder,
  AttachmentBuilder
} = require("discord.js");

const axios = require("axios");
const fs = require("fs");
const path = require("path");

/* ----------------------- Logging ----------------------- */
const log = (...e) => console.log("[PROMETHEUS]", ...e);
const error = (...e) => console.error("[PROMETHEUS]", ...e);

/* ----------------------- Config ----------------------- */
// Remote obfuscation endpoint (server must accept { code: "<lua>" })
const API_URL = process.env.OBFUSCATE_API_URL || "https://novahub-zd14.onrender.com/obfuscate";

/* ----------------------- Temp Folder ----------------------- */
const tempDir = path.join(__dirname, "Temp_files");
if (!fs.existsSync(tempDir)) {
  error("❌ Temp_files directory does not exist! Please create it manually.");
  process.exit(1);
}

/* ----------------------- Storage Channel ----------------------- */
const STORAGE_CHANNEL_ID = process.env.STORAGE_CHANNEL_ID || process.env.CDN_STORAGE_CHANNEL_ID;
async function ensureStorageChannel(client) {
  if (!STORAGE_CHANNEL_ID) throw new Error("STORAGE_CHANNEL_ID not set in .env");
  let ch = client.channels.cache.get(STORAGE_CHANNEL_ID);
  if (!ch) ch = await client.channels.fetch(STORAGE_CHANNEL_ID).catch(() => null);
  if (!ch || !("send" in ch)) throw new Error("Invalid STORAGE_CHANNEL_ID or missing permissions.");
  return ch;
}

/* ----------------------- Remote Obfuscation ----------------------- */
/**
 * Sends the raw Lua code to the remote /obfuscate endpoint.
 * Returns the obfuscated code string or throws on error.
 */
async function obfuscateRemote(rawLua, preset = "Medium") {
  try {
    // Your server currently ignores preset param, but we'll send it anyway
    const resp = await axios.post(API_URL, { code: rawLua, preset }, {
      headers: { "Content-Type": "application/json" },
      timeout: 120000 // 2 minutes
    });

    if (resp?.data?.obfuscatedCode) {
      return resp.data.obfuscatedCode;
    } else {
      throw new Error("Invalid response from obfuscation server.");
    }
  } catch (err) {
    // Normalize axios errors
    if (err.response) {
      // server returned non-2xx
      throw new Error(`Obfuscation server error: ${err.response.status} ${err.response.statusText}`);
    } else if (err.request) {
      throw new Error("No response from obfuscation server.");
    } else {
      throw new Error(`Obfuscation request failed: ${err.message}`);
    }
  }
}

/* ----------------------- Tokens ----------------------- */
const tokens = Object.keys(process.env)
  .filter((key) => key.startsWith("DISCORD_TOKEN"))
  .map((key) => process.env[key])
  .filter(Boolean);

if (tokens.length === 0) {
  error("❌ No DISCORD_TOKEN found in .env");
  process.exit(1);
}

/* ----------------------- Bot Creator ----------------------- */
function createBot(token, botNumber) {
  const client = new Client({
    intents: [
      GatewayIntentBits.Guilds,
      GatewayIntentBits.GuildMessages,
      GatewayIntentBits.DirectMessages,
      GatewayIntentBits.MessageContent, // REQUIRED for reading messages
    ],
    partials: [Partials.Channel]
  });

  /* ----------------------- Bot Ready ----------------------- */
  client.once("ready", () => {
    log(`✅ Bot #${botNumber} logged in as ${client.user.tag}`);
    client.user.setPresence({
      status: "dnd",
      activities: [{ name: "Obfuscating Nyx Files", type: 0 }]
    });
  });

  client.login(token).catch(err => {
    error("Login failed for bot", botNumber, err);
  });

  /* ----------------------- Message Handler ----------------------- */
  client.on("messageCreate", async (msg) => {
    if (msg.author.bot) return;

    /* ------------ HELP COMMAND ------------ */
    if (msg.content.toLowerCase() === ".help") {
      const helpEmbed = new EmbedBuilder()
        .setColor("Blue")
        .setTitle("📖 Obfuscator Bot Help")
        .setDescription(
`Here’s how to use the bot:

🔹 **Command:** \`.obf\`  
Attach a **.lua**, **.txt** file or paste code inside a \`\`\`lua codeblock \`\`\`

🔹 **Levels:** Weak 🪶, Medium 🛡️, Strong 💪  
🔒 Use DM for privacy`
        )
        .setFooter({ text: "Made by Slayerson • Powered by Nyx Obfuscator" });

      return msg.reply({ embeds: [helpEmbed] });
    }

    /* ------------ OBFUSCATION COMMAND ------------ */
    if (msg.content.toLowerCase().startsWith(".obf")) {
      let inputFile;
      let originalFileName;
      let rawLua = "";

      const cleanup = () => {
        try { if (inputFile && fs.existsSync(inputFile)) fs.unlinkSync(inputFile); } catch {}
      };

      try {
        /* ---------- FILE ATTACHMENT ---------- */
        const attachment = msg.attachments.first();
        if (attachment) {
          const ext = path.extname(attachment.name).toLowerCase();
          if (![".lua", ".txt"].includes(ext)) {
            return msg.reply({
              embeds: [new EmbedBuilder()
                .setColor("Red")
                .setTitle("❌ Unsupported File")
                .setDescription("Only **.lua** and **.txt** files are supported.")]
            });
          }

          inputFile = path.join(tempDir, `input_${Date.now()}${ext}`);
          originalFileName = attachment.name;

          // download attachment
          const response = await axios({ url: attachment.url, method: "GET", responseType: "stream", timeout: 120000 });
          const writer = fs.createWriteStream(inputFile);
          response.data.pipe(writer);
          await new Promise((res, rej) => {
            writer.on("finish", res);
            writer.on("error", rej);
            response.data.on("error", rej);
          });

          rawLua = fs.readFileSync(inputFile, "utf8");
        }

        /* ---------- CODEBLOCK SUPPORT ---------- */
        else {
          const match = msg.content.match(/```(?:lua)?\n([\s\S]*?)```/i);
          if (!match) {
            return msg.reply({
              embeds: [new EmbedBuilder()
                .setColor("Red")
                .setTitle("❌ No Code Provided")
                .setDescription("Attach a file or provide code inside a ```lua codeblock ```")]
            });
          }

          rawLua = match[1];
          inputFile = path.join(tempDir, `input_${Date.now()}.lua`);
          originalFileName = `code_${Date.now()}.lua`;
          fs.writeFileSync(inputFile, rawLua, "utf8");
        }

        /* ---------- LEVEL SELECTOR ---------- */
        const chooseEmbed = new EmbedBuilder()
          .setColor("Purple")
          .setTitle("🔐 Choose Obfuscation Level")
          .setDescription("Select obfuscation strength below:");

        const row = new ActionRowBuilder().addComponents(
          new StringSelectMenuBuilder()
            .setCustomId(`obfuscation_level_${Date.now()}`)
            .setPlaceholder("Select Level")
            .addOptions([
              { label: "Weak", value: "Weak" },
              { label: "Medium", value: "Medium" },
              { label: "Strong", value: "Strong" },
            ])
        );

        const prompt = await msg.reply({ embeds: [chooseEmbed], components: [row] });

        const collector = prompt.createMessageComponentCollector({
          time: 60000,
          filter: (i) => i.user.id === msg.author.id
        });

        collector.on("collect", async (interaction) => {
          await interaction.deferUpdate();
          collector.stop();

          const level = interaction.values[0];
          // Your server's preset mapping; adjust if server expects something else
          const preset = level === "Strong" ? "Medium" : level;

          let obfuscatedCode;
          try {
            // Call remote obfuscation endpoint with raw code
            obfuscatedCode = await obfuscateRemote(rawLua, preset);
          } catch (err) {
            error("Remote obfuscation failed:", err);
            cleanup();
            return msg.reply({
              embeds: [new EmbedBuilder()
                .setColor("Red")
                .setTitle("❌ Failed to obfuscate")
                .setDescription("The obfuscation server returned an error. Try again later.")]
            });
          }

          // Prepare final file content and save
          const finalText = `--[[ Nyx Obfuscator ]]--\n\n${obfuscatedCode}`;
          const finalFilePath = path.join(tempDir, `final_${Date.now()}.lua`);
          fs.writeFileSync(finalFilePath, finalText, "utf8");

          /* ---------- UPLOAD TO STORAGE ---------- */
          let url;
          try {
            const channel = await ensureStorageChannel(client);
            const storageMsg = await channel.send({
              files: [new AttachmentBuilder(finalFilePath, { name: originalFileName })]
            });

            url = storageMsg.attachments.first().url;

          } catch (err) {
            error("Storage upload failed:", err);
            cleanup();
            return msg.reply({
              embeds: [new EmbedBuilder()
                .setColor("Red")
                .setTitle("❌ Storage upload failed")
                .setDescription("Storage channel not configured or missing permissions.")]
            });
          }

          /* ---------- SUCCESS EMBED ---------- */
          const resultEmbed = new EmbedBuilder()
            .setColor("Blue")
            .setTitle("Obfuscation Complete")
            .setDescription(
`**File:** ${originalFileName}  
[Click to Download](${url})`
            )
            .addFields({
              name: "Preview",
              value: "```lua\n" + finalText.slice(0, 500) + (finalText.length > 500 ? "...\n```" : "\n```")
            })
            .setFooter({ text: "Made by Slayerson • Powered by Nyx Obfuscator" });

          await msg.reply({ embeds: [resultEmbed] });

          // Cleanup
          try { fs.unlinkSync(finalFilePath); } catch {}
          cleanup();
          try { await prompt.delete(); } catch {}
        });

        collector.on("end", (collected) => {
          if (collected.size === 0) {
            try { msg.reply("⌛ Timed out — please run `.obf` again."); } catch {}
            cleanup();
          }
        });

      } catch (err) {
        error("Unexpected error in .obf handler:", err);
        cleanup();
        try {
          await msg.reply({
            embeds: [new EmbedBuilder()
              .setColor("Red")
              .setTitle("❌ An unexpected error occurred.")
              .setDescription("Check logs for details.")]
          });
        } catch {}
      }
    }
  });
}

/* ----------------------- Launch Bots ----------------------- */
tokens.forEach((token, i) => createBot(token, i + 1));
