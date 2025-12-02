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
const error = (...e) => console.error("[PROMETHEUS:ERROR]", ...e);

/* ----------------------- Client Setup ----------------------- */
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent
  ],
  partials: [Partials.Channel]
});

/* ----------------------- Bot Online ----------------------- */
client.once("ready", () => {
  log(`Bot logged in as ${client.user.tag}`);
});

/* ----------------------- Example Command ----------------------- */
client.on("messageCreate", async (msg) => {
  if (msg.author.bot) return;

  if (msg.content === "!ping") {
    msg.reply("Pong!");
  }

  if (msg.content.startsWith("!get")) {
    try {
      const key = msg.content.split(" ")[1];

      if (!key) return msg.reply("❌ Provide key. Example: `!get abc123`");

      const url = `https://novahub-zd14.onrender.com/retrieve/${key}`;
      const res = await axios.get(url);

      const content = res.data.script;
      if (!content) return msg.reply("❌ Not found");

      msg.reply(`✅ Retrieved script:\n\`\`\`lua\n${content}\n\`\`\``);
    } catch (err) {
      msg.reply("❌ Error retrieving script.");
      error(err);
    }
  }
});

/* ----------------------- Login ----------------------- */
client.login(process.env.DISCORD_TOKEN);
