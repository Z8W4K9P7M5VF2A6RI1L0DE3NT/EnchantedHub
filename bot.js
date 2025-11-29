const { Client, GatewayIntentBits, Partials, Collection, EmbedBuilder, REST, Routes, AttachmentBuilder } = require('discord.js');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

// Ensure Discord token is available from the environment variables set on Render
if (!process.env.DISCORD_TOKEN) {
    console.error("FATAL ERROR: DISCORD_TOKEN is not set in environment variables.");
    process.exit(1);
}

// --- CONFIGURATION ---
const TOKEN = process.env.DISCORD_TOKEN;
// Your specific Client ID has been inserted here:
const CLIENT_ID = '1444160895872663615'; 
const TEMP_DIR = path.join(__dirname, 'temp_files');

// Create temp directory if it doesn't exist
if (!fs.existsSync(TEMP_DIR)) {
    fs.mkdirSync(TEMP_DIR);
}

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
client.once('clientReady', () => { // Using clientReady to fix the deprecation warning
    console.log(`[BOT] Logged in as ${client.user.tag}!`);
    registerSlashCommands();
});

// --- COMMAND HANDLER ---

// Handle interaction created (slash commands)
client.on('interactionCreate', async interaction => {
    if (!interaction.isCommand()) return;

    // --- /obf COMMAND ---
    if (interaction.commandName === 'obf') {
        // Use ephemeral: true to make the initial reply private (only the user sees it)
        await interaction.reply({ content: 'Processing file for obfuscation... This message is private.', ephemeral: true });

        const attachment = interaction.options.getAttachment('file');

        if (!attachment || !attachment.name.endsWith('.lua')) {
            return interaction.editReply({ 
                content: '❌ Error: Please upload a valid `.lua` file.',
                ephemeral: true 
            });
        }

        const inputFilePath = path.join(TEMP_DIR, `input_${interaction.id}.lua`);
        const outputFilePath = path.join(TEMP_DIR, `output_${interaction.id}.lua`);

        try {
            // 1. Download the file content
            const response = await fetch(attachment.url);
            if (!response.ok) throw new Error(`Failed to download file: ${response.statusText}`);
            
            const fileBuffer = await response.buffer();
            fs.writeFileSync(inputFilePath, fileBuffer);

            // 2. Execute the Lua Obfuscator (assuming 'lua-obfuscator' is your executable)
            // The spawn command should reference your actual obfuscator tool.
            const obfuscatorProcess = spawn('lua', [
                'obfuscator/obfuscator.lua', // Replace with the actual path to your Lua obfuscator script/binary
                inputFilePath, 
                outputFilePath
            ]);

            let stderr = '';
            obfuscatorProcess.stderr.on('data', (data) => {
                stderr += data.toString();
            });

            await new Promise((resolve, reject) => {
                obfuscatorProcess.on('close', (code) => {
                    if (code === 0) {
                        resolve();
                    } else {
                        // Obfuscator returned a non-zero code, indicating failure (often syntax error)
                        reject(new Error(stderr || 'Obfuscation process failed with a non-zero exit code.'));
                    }
                });
                obfuscatorProcess.on('error', (err) => {
                    reject(err);
                });
            });

            // 3. Check for successful output file generation
            if (!fs.existsSync(outputFilePath)) {
                 throw new Error('Obfuscation failed to produce an output file. Check the obfuscator script/binary path.');
            }

            // 4. Send success reply with the obfuscated file (still ephemeral)
            const attachmentToSend = new AttachmentBuilder(outputFilePath, { name: `obfuscated_${attachment.name}` });
            
            // Success message with fixed grammar and requested emoji: "✅️ obfuscation sucsessfull" -> "✅ Obfuscation successful!"
            await interaction.editReply({
                content: '✅ Obfuscation successful! Your private obfuscated file is attached below.',
                files: [attachmentToSend],
                ephemeral: true // Ensures the final message and file remain private
            });

        } catch (error) {
            console.error(`Obfuscation Error for ${interaction.id}:`, error.message);
            
            let errorMessage;
            
            // Check if the error indicates a syntax issue (most common obfuscation failure)
            const syntaxErrorMatch = error.message.toLowerCase().includes('syntax') || error.message.toLowerCase().includes('failed');
            if (syntaxErrorMatch) {
                 // Requested failure message with fixed grammar: "Error in syan tax code" -> 
                 errorMessage = '❌ Error: Invalid Lua syntax. Please check your code.';
            } else {
                 errorMessage = '❌ Error: An unknown error occurred during obfuscation. Please try again.';
            }

            // Send failure message (still ephemeral)
            await interaction.editReply({ 
                content: errorMessage,
                ephemeral: true 
            });

        } finally {
            // 5. Cleanup temporary files
            try {
                if (fs.existsSync(inputFilePath)) fs.unlinkSync(inputFilePath);
                if (fs.existsSync(outputFilePath)) fs.unlinkSync(outputFilePath);
            } catch (cleanupError) {
                console.error("Error cleaning up temp files:", cleanupError);
            }
        }
    }
});

// --- COMMAND REGISTRATION ---

// Define the slash command structure
const commands = [
    {
        name: 'obf',
        description: 'Uploads a Lua file for private obfuscation.',
        options: [
            {
                name: 'file',
                description: 'The .lua file to obfuscate.',
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
        
        // Registering commands globally using your CLIENT_ID
        await rest.put(
            Routes.applicationCommands(CLIENT_ID),
            { body: commands },
        );
        console.log('[BOT] Registered /obf slash command.');

    } catch (error) {
        console.error('[BOT] Failed to register commands:', error);
        // Ensure CLIENT_ID is correctly set in the configuration section above.
    }
}

client.login(TOKEN);
