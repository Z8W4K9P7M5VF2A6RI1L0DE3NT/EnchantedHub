

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
const child_process = require("child_process");
const path = require("path");

/* ----------------------- Logging ----------------------- */
const log = (...e) => console.log("[PROMETHEUS]", ...e);
const error = (...e) => console.error("[PROMETHEUS]", ...e);

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

/* ----------------------- Obfuscation Process ----------------------- */
function obfuscate(inputFile, preset) {
  return new Promise((resolve, reject) => {
    const outputFile = path.join(tempDir, `obfuscated_${Date.now()}.lua`);

    const proc = child_process.spawn("./bin/luajit.exe", [
      "./lua/cli.lua",
      "--preset",
      preset,
      inputFile,
      "--out",
      outputFile,
    ]);

    let stderr = "";
    proc.stderr.on("data", (d) => (stderr += d.toString()));

    proc.on("close", (code) => {
      if (code !== 0) return reject(stderr || `luajit exited with code ${code}`);
      resolve(outputFile);
    });

    proc.on("error", (err) => {
      reject(`Failed to start luajit.exe: ${err.message}`);
    });
  });
}

/* ----------------------- Tokens ----------------------- */
const tokens = Object.keys(process.env)
  .filter((key) => key.startsWith("DISCORD_TOKEN"))
  .map((key) => process.env[key]);

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

  client.login(token);

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

      const cleanup = () => {
        try { fs.unlinkSync(inputFile); } catch {}
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

          const response = await axios({ url: attachment.url, method: "GET", responseType: "stream" });
          response.data.pipe(fs.createWriteStream(inputFile));

          await new Promise((res, rej) => {
            response.data.on("end", res);
            response.data.on("error", rej);
          });
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

          const code = match[1];
          inputFile = path.join(tempDir, `input_${Date.now()}.lua`);
          originalFileName = `code_${Date.now()}.lua`;
          fs.writeFileSync(inputFile, code, "utf-8");
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
          const preset = level === "Strong" ? "Medium" : level;

          let outputFile;

          try {
            outputFile = await obfuscate(inputFile, preset);
          } catch (err) {
            error(err);
            cleanup();
            return msg.reply("❌ Failed to obfuscate the script.");
          }

          const obfuscated = fs.readFileSync(outputFile, "utf-8");
          const finalText = `--[[ Nyx Obfuscator ]]--\n\n${obfuscated}`;
          const finalFilePath = path.join(tempDir, `final_${Date.now()}.lua`);
          fs.writeFileSync(finalFilePath, finalText);

          /* ---------- UPLOAD TO STORAGE ---------- */
          let url;
          try {
            const channel = await ensureStorageChannel(client);
            const storageMsg = await channel.send({
              files: [new AttachmentBuilder(finalFilePath, { name: originalFileName })]
            });

            url = storageMsg.attachments.first().url;

          } catch (err) {
            error(err);
            cleanup();
            return msg.reply("❌ Storage channel not configured.");
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
              value: "```lua\n" + finalText.slice(0, 500) + "...\n```"
            })
            .setFooter({ text: "Made by Slayerson • Powered by Nyx Obfuscator" });

          await msg.reply({ embeds: [resultEmbed] });

          cleanup();
          try { await prompt.delete(); } catch {}
        });

        collector.on("end", (collected) => {
          if (collected.size === 0) {
            msg.reply("⌛ Timed out — please run `.obf` again.");
            cleanup();
          }
        });

      } catch (err) {
        error(err);
        cleanup();
        msg.reply("❌ An unexpected error occurred.");
      }
    }
  });
}

/* ----------------------- Launch Bots ----------------------- */
tokens.forEach((token, i) => createBot(token, i + 1));


