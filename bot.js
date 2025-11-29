const { Client, GatewayIntentBits, Partials, Collection, EmbedBuilder, REST, Routes, AttachmentBuilder } = require('discord.js');
const { spawn } = require('child_process'); // No longer used for obfuscation, but needed for the module structure
const fs = require('fs');
const path = require('path');

// Ensure Discord token is available from the environment variables set on Render
if (!process.env.DISCORD_TOKEN) {
    console.error("FATAL ERROR: DISCORD_TOKEN is not set in environment variables.");
    process.exit(1);
}

// --- CONFIGURATION ---
const TOKEN = process.env.DISCORD_TOKEN;
const CLIENT_ID = '1444160895872663615'; 
// The bot will now call the API endpoint running on the same server.
// RENDER_EXTERNAL_URL is available in the Node.js environment on Render.
const API_BASE_URL = process.env.RENDER_EXTERNAL_URL || 'http://localhost:3000'; 
const OBFUSCATE_ENDPOINT = `${API_BASE_URL}/obfuscate`; 


// --- CLIENT SETUP ---
const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.DirectMessages,
    ],
    partials: [Partials.Channel],
});

client.commands = new Collection();
client.once('clientReady', () => { 
    console.log(`[BOT] Logged in as ${client.user.tag}!`);
    registerSlashCommands();
});

// --- COMMAND HANDLER ---

client.on('interactionCreate', async interaction => {
    if (!interaction.isCommand()) return;

    // --- /obf COMMAND ---
    if (interaction.commandName === 'obf') {
        // Initial reply is private (ephemeral)
        await interaction.reply({ content: 'Processing file for obfuscation via API... This message is private.', ephemeral: true });

        const attachment = interaction.options.getAttachment('file'); 
        const fileName = attachment?.name.toLowerCase();

        // 1. VALIDATION: Accept both .lua and .txt
        if (
            !attachment || 
            (!fileName.endsWith('.lua') && !fileName.endsWith('.txt'))
        ) {
            return interaction.editReply({ 
                content: '❌ Error: Please upload a valid script file ending with either `.lua` or `.txt`.',
                ephemeral: true 
            });
        }
        
        try {
            // 2. Download the file content
            const response = await fetch(attachment.url);
            if (!response.ok) throw new Error(`Failed to download file: ${response.statusText}`);
            
            const rawLuaCode = await response.text();
            
            // 3. NEW: Call the local API endpoint for obfuscation
            const apiResponse = await fetch(OBFUSCATE_ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    code: rawLuaCode, 
                    fileName: attachment.name 
                }),
            });

            // Check API response status
            if (!apiResponse.ok) {
                const errorData = await apiResponse.json().catch(() => ({ message: 'API responded with an error status.' }));
                throw new Error(errorData.message || 'API responded with an error.');
            }

            const result = await apiResponse.json();
            const obfuscatedCode = result.obfuscatedCode;
            
            // 4. Determine the output file name, ensuring it always ends in .lua
            let outputFileName = attachment.name;
            if (outputFileName.toLowerCase().endsWith('.txt')) {
                outputFileName = outputFileName.slice(0, -4) + '.lua';
            }

            // 5. Send success reply with the obfuscated file (STILL PRIVATE)
            const obfBuffer = Buffer.from(obfuscatedCode, 'utf8');
            const attachmentToSend = new AttachmentBuilder(obfBuffer, { name: `obfuscated_${outputFileName}` });
            
            await interaction.editReply({
                content: '✅ Obfuscation successful! Your private obfuscated file is attached below.',
                files: [attachmentToSend],
                ephemeral: true
            });

        } catch (error) {
            console.error(`Obfuscation Error for ${interaction.id}:`, error.message);
            
            let errorMessage;
            
            // Check for API-reported syntax error (will be passed through error.message)
            if (error.message.includes('Invalid Lua syntax')) {
                 errorMessage = '❌ Error: Invalid Lua syntax. Please check your code.';
            } else {
                 errorMessage = `❌ Error: ${error.message}. Please try again.`;
            }

            // Send failure message (STILL PRIVATE)
            await interaction.editReply({ 
                content: errorMessage,
                ephemeral: true 
            });
        }
    }
});

// --- COMMAND REGISTRATION ---

// Define the slash command structure
const commands = [
    {
        name: 'obf',
        description: 'Uploads a Lua script for private obfuscation (accepts .lua and .txt).',
        options: [
            {
                name: 'file',
                description: 'The .lua or .txt file containing the script.',
                type: 11, // ApplicationCommandOptionType.Attachment
                required: true,
            },
        ],
    },
];

// Function to register the slash commands with Discord
async function registerSlashCommands() {
    try {
        const rest = new REST({ version: '10' }).setToken(TOKEN);
        
        // Registering commands globally using your specific CLIENT_ID
        await rest.put(
            Routes.applicationCommands(CLIENT_ID),
            { body: commands },
        );
        console.log('[BOT] Registered /obf slash command.');

    } catch (error) {
        console.error('[BOT] Failed to register commands:', error);
    }
}

client.login(TOKEN);
