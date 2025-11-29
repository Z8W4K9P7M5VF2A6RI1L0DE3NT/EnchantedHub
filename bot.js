const { 
    Client, 
    GatewayIntentBits, 
    Partials, 
    AttachmentBuilder, 
    REST, 
    Routes,
    SlashCommandBuilder, 
} = require('discord.js');
const fetch = require('node-fetch'); // Still needed to download the file from Discord CDN
// --- IMPORTANT: Import the obfuscation function directly from obfuscator.js ---
const { runObfuscator } = require('./obfuscator'); 

// Ensure Discord token is available from the environment variables set on Render
if (!process.env.DISCORD_TOKEN) {
    console.error("FATAL ERROR: DISCORD_TOKEN is not set in environment variables.");
    process.exit(1);
}

// --- CONFIGURATION ---
const TOKEN = process.env.DISCORD_TOKEN;
const CLIENT_ID = '1444160895872663615'; 


// --- CLIENT SETUP ---
const client = new Client({
    intents: [
        // Only need Guilds for slash commands
        GatewayIntentIntentBits.Guilds,
    ],
    partials: [Partials.Channel],
});

client.once('clientReady', () => { 
    console.log(`[BOT] Logged in as ${client.user.tag}!`);
    registerSlashCommands();
});

// --- COMMAND HANDLER ---

client.on('interactionCreate', async interaction => {
    if (!interaction.isChatInputCommand()) return;

    // --- /obf COMMAND ---
    if (interaction.commandName === 'obf') {
        
        // 1. Initial Reply: PRIVATE confirmation (ephemeral: true)
        await interaction.reply({ 
            content: 'Processing file for obfuscation...', 
            ephemeral: true 
        });

        const attachment = interaction.options.getAttachment('file'); 
        const fileName = attachment?.name.toLowerCase();

        // 2. VALIDATION: Accept both .lua and .txt
        if (!fileName || (!fileName.endsWith('.lua') && !fileName.endsWith('.txt'))) {
            // If validation fails, edit the existing private reply with the error
            return interaction.editReply({ 
                content: '❌ Error: Please upload a valid script file ending with either `.lua` or `.txt`.',
                ephemeral: true 
            });
        }
        
        try {
            // 3. Download the file content
            const response = await fetch(attachment.url);
            if (!response.ok) throw new Error(`Failed to download file: ${response.statusText}`);
            
            const rawLuaCode = await response.text();
            
            // 4. --- RUN OBFUSCATOR DIRECTLY (from obfuscator.js) ---
            const obfuscatedCode = await runObfuscator(rawLuaCode, 'Medium');
            
            // 5. Determine the output file name, ensuring it always ends in .lua
            let outputFileName = attachment.name;
            if (outputFileName.toLowerCase().endsWith('.txt')) {
                outputFileName = outputFileName.slice(0, -4) + '.lua';
            }

            // 6. Create the public file attachment
            const obfBuffer = Buffer.from(obfuscatedCode, 'utf8');
            const attachmentToSend = new AttachmentBuilder(obfBuffer, { name: `obfuscated_${outputFileName}` });
            
            
            // --- STEP 7: Delete the initial PRIVATE reply ---
            await interaction.deleteReply().catch(err => console.error('Error deleting private reply:', err));

            // --- STEP 8: Send the final PUBLIC reply that targets the original command message ---
            const userPing = `<@${interaction.user.id}>`; 
            
            await interaction.channel.send({
                content: `${userPing} ✅ Obfuscation successful! The output file is attached below.`,
                files: [attachmentToSend],
                // Visually replies to the original command message
                messageReference: interaction.id, 
                failIfNotExists: false 
            });

        } catch (error) {
            console.error(`Obfuscation Error:`, error.message);
            
            let errorMessage;
            
            // Check for the specific syntax error thrown by obfuscator.js
            if (error.message.includes('Invalid Lua syntax')) {
                 errorMessage = '❌ Error: Invalid Lua syntax. Please check your code.';
            } else {
                 errorMessage = '❌ Error: An internal processing error occurred. Please try again or contact a bot administrator.';
            }

            // If we fail, we edit the existing private reply with the error message (keeping the error private)
            await interaction.editReply({ 
                content: errorMessage,
                ephemeral: true 
            }).catch(err => console.error('Error editing private reply during failure:', err));
        }
    }
});

// --- COMMAND REGISTRATION ---

// Define the slash command structure
const commands = [
    new SlashCommandBuilder()
        .setName('obf')
        .setDescription('Uploads a Lua script for obfuscation (accepts .lua and .txt).')
        .addAttachmentOption(option => 
            option.setName('file')
                  .setDescription('The .lua or .txt file containing the script.')
                  .setRequired(true)
        )
        .toJSON()
];

// Function to register the slash commands with Discord
async function registerSlashCommands() {
    try {
        const rest = new REST({ version: '10' }).setToken(TOKEN);
        
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
