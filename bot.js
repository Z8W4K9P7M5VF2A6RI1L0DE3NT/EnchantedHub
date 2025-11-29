// bot.js
const { Client, GatewayIntentBits, AttachmentBuilder, SlashCommandBuilder } = require('discord.js');
const fetch = require('node-fetch'); // To download the file from Discord's CDN
const { runObfuscator } = require('./obfuscator'); // Import the shared logic
require('dotenv').config();

// --- Configuration ---
const MAX_FILE_SIZE_MB = 8;
const MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024;
const DEFAULT_PRESET = 'Medium';
const LUA_EXTENSION = '.lua';


// Initialize Discord Client (needs Guilds and MessageContent intents)
const client = new Client({ 
    intents: [
        GatewayIntentBits.Guilds, 
        GatewayIntentBits.GuildMessages, 
        GatewayIntentBits.MessageContent 
    ] 
});

// --- Bot Ready and Command Registration ---
client.on('ready', async () => {
    console.log(`[BOT] Logged in as ${client.user.tag}!`);
    
    // Define the /obf slash command
    const obfCommand = new SlashCommandBuilder()
        .setName('obf')
        .setDescription(`Obfuscates an attached Lua script using the ${DEFAULT_PRESET} preset.`)
        // Add an attachment option
        .addAttachmentOption(option => 
            option.setName('script')
                  .setDescription('The .lua file to obfuscate.')
                  .setRequired(true)
        );

    // Register the slash command (globally)
    try {
        await client.application.commands.create(obfCommand);
        console.log('[BOT] Registered /obf slash command.');
    } catch (error) {
        console.error('[BOT] Failed to register /obf command:', error);
    }
});


// --- Slash Command Interaction Handler (/obf) ---
client.on('interactionCreate', async (interaction) => {
    if (!interaction.isChatInputCommand()) return;

    if (interaction.commandName === 'obf') {
        // Defer the reply to give the obfuscation process time
        await interaction.deferReply({ ephemeral: false }); 

        // Get the attachment named 'script'
        const attachment = interaction.options.getAttachment('script'); 
        const preset = DEFAULT_PRESET; // Hardcoded to 'Medium'

        // 1. Validation
        if (!attachment.name.endsWith(LUA_EXTENSION) || attachment.size > MAX_FILE_SIZE_BYTES) {
            return interaction.editReply(`❌ Please attach a valid Lua file (must end with ${LUA_EXTENSION} and be under ${MAX_FILE_SIZE_MB}MB).`);
        }
        
        try {
            // 2. Download the attached file content
            const response = await fetch(attachment.url);
            // Check if the response is readable/successful
            if (!response.ok) {
                 return interaction.editReply('❌ Failed to download script from Discord. Please try again.');
            }
            const rawLuaCode = await response.text();
            
            // 3. Run the core obfuscation logic
            const obfuscatedCode = await runObfuscator(rawLuaCode, preset); 

            // 4. Send the result back as a file attachment
            const obfBuffer = Buffer.from(obfuscatedCode, 'utf8');
            const obfFile = new AttachmentBuilder(obfBuffer, { 
                name: `obfuscated_${attachment.name}` 
            });

            await interaction.editReply({ 
                content: `✅ **Obfuscation Complete** (Preset: ${preset})!`, 
                files: [obfFile] 
            });

        } catch (error) {
            console.error('[BOT] Slash Command Obfuscation Error:', error);
            await interaction.editReply('❌ An internal error occurred while processing your script. Check the host console for details.');
        }
    }
});


client.login(process.env.DISCORD_TOKEN);
