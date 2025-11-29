const { Client, GatewayIntentBits, AttachmentBuilder, SlashCommandBuilder } = require('discord.js');
const fetch = require('node-fetch');
const { runObfuscator } = require('./obfuscator');
require('dotenv').config();

// --- Configuration ---
const MAX_FILE_SIZE_MB = 8;
const MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024;
const DEFAULT_PRESET = 'Medium';
const LUA_EXTENSION = '.lua';
const TXT_EXTENSION = '.txt';

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
        .setDescription(`Obfuscates an attached .lua or .txt script (Output is .txt).`)
        .addAttachmentOption(option => 
            option.setName('script')
                  .setDescription('The .lua or .txt file containing the Lua code.')
                  .setRequired(true)
        );

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
        await interaction.deferReply({ ephemeral: false }); 

        const attachment = interaction.options.getAttachment('script'); 
        const preset = DEFAULT_PRESET; 
        
        const fileName = attachment.name;
        const lowerCaseFileName = fileName.toLowerCase();

        // 1. Validation: Accepts .lua OR .txt
        const isLuaOrTxt = lowerCaseFileName.endsWith(LUA_EXTENSION) || lowerCaseFileName.endsWith(TXT_EXTENSION);

        if (!isLuaOrTxt || attachment.size > MAX_FILE_SIZE_BYTES) { 
            return interaction.editReply(`❌ Please attach a valid Lua script file. We accept **.lua** or **.txt** inputs, but the size must be under **${MAX_FILE_SIZE_MB}MB**.`);
        }
        
        try {
            // 2. Download the attached file content
            const response = await fetch(attachment.url);
            if (!response.ok) {
                 return interaction.editReply('❌ Failed to download script from Discord. Please try again.');
            }
            const rawLuaCode = await response.text();
            
            // 3. Run the core obfuscation logic
            const obfuscatedCode = await runObfuscator(rawLuaCode, preset); 

            // 4. Determine the base file name and force .txt output
            let baseName = fileName;
            
            // Remove existing extension (case-insensitive)
            if (lowerCaseFileName.endsWith(LUA_EXTENSION)) {
                baseName = fileName.slice(0, -LUA_EXTENSION.length);
            } else if (lowerCaseFileName.endsWith(TXT_EXTENSION)) {
                baseName = fileName.slice(0, -TXT_EXTENSION.length);
            }
            
            // Append the desired .txt extension
            const outputFileName = `${baseName}${TXT_EXTENSION}`;
            
            const obfBuffer = Buffer.from(obfuscatedCode, 'utf8');
            const obfFile = new AttachmentBuilder(obfBuffer, { 
                name: `obfuscated_${outputFileName}` 
            });

            await interaction.editReply({ 
                content: `✅ **Obfuscation Complete** (Preset: ${preset})! Your output file is **.txt** format.`, 
                files: [obfFile] 
            });

        } catch (error) {
            console.error('[BOT] Slash Command Obfuscation Error:', error);
            await interaction.editReply('❌ An internal error occurred while processing your script. Check the host console for details.');
        }
    }
});


client.login(process.env.DISCORD_TOKEN);
