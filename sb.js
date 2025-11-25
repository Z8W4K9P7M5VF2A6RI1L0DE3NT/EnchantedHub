// WARNING: Using self-bots is strictly against Discord's Terms of Service and can result in your account being permanently banned.
// Use this code at your own risk.

// --- Imports (Using CommonJS 'require' syntax) ---
// Note: We use raw numbers for intents and partials to bypass TypeErrors from the deprecated library's broken exports.
const { 
    Client, 
    MessageAttachment,
    Collection         
} = require('discord.js-selfbot-v13');
const axios = require('axios');
const fs = require('fs');
const path = require('path');

// --- Configuration ---
const PREFIX = '+';
const DELETE_COOLDOWN = 1.0; // Rate limit for self-deletion (1 second delay)
// *** IMPORTANT: This is your updated User Token. Ensure it is valid! ***
const TOKEN = 'MTI1NjIyMDU4NDM4NDEzOTI4NA.GOyhvz.kBk6m1GpG_1EUx8Cwy8wJGv5Z6BAmGFktfcJMA'; 

// --- Client Initialization ---
// FIX APPLIED: Using raw intent number (32767) to bypass broken GatewayIntentBits object.
// FIX APPLIED: Using raw partial number (1) for Partials.Channel to bypass broken Partials object.
const client = new Client({ 
    // 32767 grants all non-privileged intents
    intents: 32767,
    // 1 is the raw numerical value for Partials.Channel
    partials: [1] 
});

// --- State Management ---
const spamTasks = new Map();
const deletedMessages = new Map(); // Stores up to 10 deleted messages per channel
let lastDeleteTime = 0; // Tracks the time of the last successful deletion for rate limiting

// --- Helper Functions ---

/** * Custom message deletion with rate limit handling.
 * This is crucial for self-bots to avoid triggering Discord's internal abuse filters.
 */
async function selfDeleteMessage(message) {
    const currentTime = Date.now() / 1000;
    const timeSinceLastDelete = currentTime - lastDeleteTime;
    
    // Enforce a minimum delay between deletes
    if (timeSinceLastDelete < DELETE_COOLDOWN) {
        // Wait the remaining time
        await new Promise(resolve => setTimeout(resolve, (DELETE_COOLDOWN - timeSinceLastDelete) * 1000));
    }
    
    try {
        await message.delete();
        lastDeleteTime = Date.now() / 1000;
    } catch (error) {
        // Ignore "Unknown Message" error (10008) if message was already deleted
        if (error.code !== 10008) { 
             console.error("Error during message deletion:", error.message);
        }
    }
}

// --- Event Handlers ---

client.on('ready', () => {
    console.log(`Logged in as ${client.user.tag} (ID: ${client.user.id})`);
    console.log('------');
    // Set default presence
    client.user.setStatus('online').catch(console.error);
});

client.on('messageDelete', message => {
    // Check if the message object is complete and not a partial
    if (!message.partial) {
        const channelId = message.channel.id;
        if (!deletedMessages.has(channelId)) {
            deletedMessages.set(channelId, []);
        }
        
        const channelDeletes = deletedMessages.get(channelId);

        // Keep a maximum of 10 deleted messages per channel for the snipe command
        if (channelDeletes.length >= 10) {
            channelDeletes.shift(); 
        }

        channelDeletes.push({
            content: message.content,
            author: message.author,
            timestamp: new Date(),
            // Store URLs of attachments if they exist
            attachments: message.attachments.map(att => att.url)
        });
    }
});

client.on('messageCreate', async message => {
    // CRITICAL: A self-bot MUST only respond to its OWN messages to prevent conflicts and detection
    if (message.author.id !== client.user.id || !message.content.startsWith(PREFIX)) return;

    // Parse the command and arguments
    const args = message.content.slice(PREFIX.length).trim().split(/\s+/);
    const commandName = args.shift().toLowerCase();
    
    // --- Commands implementation starts here ---
    
    if (commandName === 'help') {
        const helpText = `
**MADE BY SLAYERSON NIGGA!**
\`${PREFIX}help\` 

**Messaging Commands:**
• \`${PREFIX}spam <message>\` - Rapidly sends a message (0.01s delay). **EXTREME RISK.**
• \`${PREFIX}stopspam\` - Stops the current spam task
• \`${PREFIX}an <message>\` - Sends an anonymous message (deletes command)
• \`${PREFIX}snipe <amount?>\` - Shows the last deleted message(s) in the channel (max 10 are stored)
• \`${PREFIX}delete <amount>\` - Deletes the bot's own recent messages (max 100)
• \`${PREFIX}cleanconv @user\` - Deletes up to 200 messages sent by the target user OR the bot
• \`${PREFIX}cn @user <amount?>\` - Deletes messages sent by the target user only (max 50, default)

**User Commands:**
• \`${PREFIX}userinfo @user\` - Gets information about a user
• \`${PREFIX}jtbz\` - Sends "Just Too Based!"

**Webhook Commands:**
• \`${PREFIX}checkwebhook <webhookURL>\` - Checks if a webhook URL is valid
• \`${PREFIX}spamwebhook <webhookURL> <webhookName> <message> <amount?>\` - Spams a webhook (max 10)

**Other Commands:**
• \`${PREFIX}account status <online|idle|dnd>\` - Sets the bot's presence status
• \`${PREFIX}serverinfo\` - Gets information about the current server
• \`${PREFIX}joke\` - Tells a random joke
• \`${PREFIX}choose <option1> <option2> ...\` - Chooses a random option (use comma separation for multi-word options)
`;
        // Use a 5-second self-delete on the help message to keep chat clean
        const helpMsg = await message.channel.send(helpText);
        setTimeout(() => selfDeleteMessage(helpMsg), 5000);
    }
    
    // --- Messaging Commands ---

    if (commandName === 'spam') {
        const spamMessage = args.join(' ');
        if (!spamMessage) return message.channel.send('Please provide a message to spam.');

        // Prevent multiple spam tasks in the same channel
        if (spamTasks.has(message.channel.id)) {
            return message.channel.send('A spam task is already running in this channel. Use `+stopspam` first.');
        }
        
        // Delete the command message immediately
        await selfDeleteMessage(message);

        const spamTask = setInterval(() => {
            // WARNING: A 10ms delay is extremely aggressive and WILL cause rate-limiting and potential bans.
            message.channel.send(spamMessage).catch(err => {
                // If a send fails, stop the spam to avoid continuous errors
                console.error("Spam send failed, stopping spam:", err.message);
                clearInterval(spamTasks.get(message.channel.id));
                spamTasks.delete(message.channel.id);
            }); 
        }, 10); 

        spamTasks.set(message.channel.id, spamTask);
    }

    if (commandName === 'stopspam') {
        await selfDeleteMessage(message); 
        if (spamTasks.has(message.channel.id)) {
            clearInterval(spamTasks.get(message.channel.id));
            spamTasks.delete(message.channel.id);
            const tempMsg = await message.channel.send('Spam stopped.');
            setTimeout(() => selfDeleteMessage(tempMsg), 5000);
        } else {
            const tempMsg = await message.channel.send('No spam task is currently running in this channel.');
            setTimeout(() => selfDeleteMessage(tempMsg), 5000);
        }
    }

    if (commandName === 'delete') {
        let amount = parseInt(args[0]) || 10;
        if (amount > 100) amount = 100; // Limit to 100 messages

        // Delete the command message first
        await selfDeleteMessage(message); 

        let deletedCount = 0;
        // Fetch up to 10 more messages than requested to ensure finding enough bot messages
        const messages = await message.channel.messages.fetch({ limit: amount + 10 }); 

        for (const msg of messages.values()) {
            if (deletedCount >= amount) break;
            
            // Only delete messages sent by the self-bot's user ID
            if (msg.author.id === client.user.id) {
                await selfDeleteMessage(msg);
                deletedCount++;
            }
        }
    }
    
    if (commandName === 'an') {
        const anonymousMessage = args.join(' ');
        if (!anonymousMessage) return message.channel.send('Please provide an anonymous message.');
        
        try {
            await selfDeleteMessage(message); // Delete the command
            await new Promise(resolve => setTimeout(resolve, 500)); // Small delay
            await message.channel.send(`Anonymous Message: **${anonymousMessage}**`);
        } catch (e) {
            console.error("Error during anonymous send:", e.message);
        }
    }
    
    if (commandName === 'snipe') {
        await selfDeleteMessage(message);
        let amount = parseInt(args[0]) || 1;
        if (amount < 1) amount = 1;
        
        const channelId = message.channel.id;
        const channelDeletes = deletedMessages.get(channelId);

        if (!channelDeletes || channelDeletes.length === 0) {
            const tempMsg = await message.channel.send("No message to snipe.");
            return setTimeout(() => selfDeleteMessage(tempMsg), 5000);
        }
        
        amount = Math.min(amount, channelDeletes.length);
        // Get the latest 'amount' messages and reverse to display from oldest sniped to newest sniped
        const messagesToSnipe = channelDeletes.slice(-amount).reverse(); 

        for (const [i, msgData] of messagesToSnipe.entries()) {
            const timeDiff = new Date() - msgData.timestamp;
            const secondsAgo = Math.floor(timeDiff / 1000);
            
            const attachments = msgData.attachments || [];
            const attachmentUrls = attachments.length > 0 ? `\n| Attachments: ${attachments.join(', ')}` : "";
            
            const snipeText = `
**SNIPE (${amount - i})**
| Author: ${msgData.author.tag}
| Time: ${secondsAgo} second${secondsAgo !== 1 ? 's' : ''} ago
| Message: ${msgData.content || '*[Content was empty or not captured]**'}
${attachmentUrls}
`;
            const snipeMsg = await message.channel.send(snipeText);
            // Delete snipe results after a delay
            setTimeout(() => selfDeleteMessage(snipeMsg), 10000); 
            await new Promise(resolve => setTimeout(resolve, 300)); // Small delay to avoid rate limit
        }
    }
    
    if (commandName === 'cleanconv' || commandName === 'cn') {
        await selfDeleteMessage(message);
        const user = message.mentions.users.first();
        if (!user) {
             const tempMsg = await message.channel.send("Please mention a user.");
             return setTimeout(() => selfDeleteMessage(tempMsg), 5000);
        }

        const limit = commandName === 'cn' ? parseInt(args[1]) || 50 : 200;
        let messagesToDelete = [];

        // Fetch up to 200 messages (Discord's max fetch limit)
        const messages = await message.channel.messages.fetch({ limit: 200 }); 
        
        for (const msg of messages.values()) {
            const isTarget = commandName === 'cleanconv' 
                ? (msg.author.id === user.id || msg.author.id === client.user.id)
                : (msg.author.id === user.id); 
            
            if (isTarget && msg.id !== message.id) {
                messagesToDelete.push(msg);
            }
        }
        
        messagesToDelete.splice(limit); // Enforce the limit
        let successCount = 0;

        // Deleting messages one by one to respect rate limits
        for (const msg of messagesToDelete) {
            try {
                await selfDeleteMessage(msg);
                successCount++;
                // Add a small delay between deletes to respect rate limit, even with selfDeleteMessage logic
                await new Promise(resolve => setTimeout(resolve, 300)); 
            } catch (e) {
                console.error("Error deleting message during cleanconv:", e.message);
            }
        }
        
        const tempMsg = await message.channel.send(`Successfully deleted ${successCount} message(s) for ${user.tag}.`);
        setTimeout(() => selfDeleteMessage(tempMsg), 5000);
    }


    // --- User Commands ---

    if (commandName === 'userinfo') {
        await selfDeleteMessage(message);
        const user = message.mentions.users.first() || message.author;
        
        const infoText = `
**User Info for ${user.tag}**
**ID:** ${user.id}
**Created:** ${user.createdAt.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}
**Bot:** ${user.bot ? 'Yes' : 'No'}
**Status:** ${user.presence?.status || 'Offline/Unknown'}
`;
        const tempMsg = await message.channel.send(infoText);
        setTimeout(() => selfDeleteMessage(tempMsg), 10000);
    }
    
    if (commandName === 'jtbz') {
        await selfDeleteMessage(message);
        await message.channel.send(" **Just Too Based!** ");
    }


    // --- Webhook Commands ---
    
    if (commandName === 'checkwebhook') {
        const webhookUrl = args[0];
        if (!webhookUrl) return message.channel.send("Please provide a webhook URL.");

        await selfDeleteMessage(message);

        try {
            // GET request to the webhook URL to fetch its data
            const response = await axios.get(webhookUrl);
            if (response.status === 200 && response.data.id) {
                const tempMsg = await message.channel.send(`Webhook Check: **Valid** | Name: ${response.data.name} (ID: ${response.data.id})`);
                setTimeout(() => selfDeleteMessage(tempMsg), 10000);
            } else {
                const tempMsg = await message.channel.send(`Webhook Check: **Invalid** | Status: ${response.status}`);
                setTimeout(() => selfDeleteMessage(tempMsg), 10000);
            }
        } catch (error) {
            const tempMsg = await message.channel.send("Webhook Check: **Error** (Invalid URL format or connection issue)");
            setTimeout(() => selfDeleteMessage(tempMsg), 10000);
        }
    }
    
    if (commandName === 'spamwebhook') {
        const [webhookUrl, webhookName, ...restArgs] = args;
        
        // Try to parse amount from the last argument
        let amount = 5;
        let spamMessage = restArgs.join(' ');
        
        const lastArg = restArgs[restArgs.length - 1];
        if (lastArg && !isNaN(parseInt(lastArg)) && restArgs.length > 0) {
            amount = parseInt(lastArg);
            spamMessage = restArgs.slice(0, restArgs.length - 1).join(' ');
        }
        
        if (!webhookUrl || !webhookName || !spamMessage) {
            await selfDeleteMessage(message);
            const tempMsg = await message.channel.send("Usage: `+spamwebhook <url> <name> <message> <amount?>`");
            return setTimeout(() => selfDeleteMessage(tempMsg), 7000);
        }
        
        await selfDeleteMessage(message); 

        if (amount > 10) {
            amount = 10;
            const tempMsg = await message.channel.send("Limiting spam amount to 10.");
            setTimeout(() => selfDeleteMessage(tempMsg), 5000);
        }
        
        let successCount = 0;
        for (let i = 0; i < amount; i++) {
            try {
                await axios.post(webhookUrl, {
                    content: spamMessage,
                    username: webhookName
                });
                successCount++;
                // IMPORTANT: Webhooks also have rate limits. A 1s delay is safer.
                await new Promise(resolve => setTimeout(resolve, 1000)); 
            } catch (error) {
                console.error(`Webhook spam failed on message ${i+1}: ${error.message}`);
                break; // Stop spamming on the first failure
            }
        }
        
        const tempMsg = await message.channel.send(`Successfully spammed ${successCount} message(s) to webhook.`);
        setTimeout(() => selfDeleteMessage(tempMsg), 5000);
    }


    // --- Other Commands ---

    if (commandName === 'serverinfo') {
        await selfDeleteMessage(message);
        if (!message.guild) return message.channel.send("This command only works in a server.");
        
        const guild = message.guild;
        // Count roles excluding @everyone
        const roles = guild.roles.cache.filter(role => role.name !== '@everyone').size;
        
        const infoText = `
**Server Info for ${guild.name}**
**Owner:** <@${guild.ownerId}>
**ID:** ${guild.id}
**Created:** ${guild.createdAt.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}
**Members:** ${guild.memberCount}
**Roles:** ${roles}
**Channels:** ${guild.channels.cache.size}
**Boost Level:** ${guild.premiumTier || 'None'}
`;
        const tempMsg = await message.channel.send(infoText);
        setTimeout(() => selfDeleteMessage(tempMsg), 10000);
    }
    
    if (commandName === 'joke') {
        await selfDeleteMessage(message);
        const jokes = [
            "Why don't scientists trust atoms? Because they make up everything!",
            "Why did the scarecrow win an award? Because he was outstanding in his field!",
            "What do you call a fake noodle? An impasta!",
            "How does a penguin build its house? Igloos it together!",
            "I told my wife she was drawing her eyebrows too high. She looked surprised."
        ];
        const joke = jokes[Math.floor(Math.random() * jokes.length)];
        const tempMsg = await message.channel.send(joke);
        setTimeout(() => selfDeleteMessage(tempMsg), 10000);
    }

    if (commandName === 'choose') {
        await selfDeleteMessage(message);
        if (args.length === 0) return message.channel.send("Provide options to choose from.");
        
        // Split options by comma and filter out empty strings
        const options = args.join(' ').split(',').map(o => o.trim()).filter(o => o.length > 0);
        
        if (options.length === 0) return message.channel.send("Provide options to choose from.");
        
        const choice = options[Math.floor(Math.random() * options.length)];
        const tempMsg = await message.channel.send(`🎲 I choose: **${choice}**`);
        setTimeout(() => selfDeleteMessage(tempMsg), 10000);
    }

    if (commandName === 'account') {
        await selfDeleteMessage(message);
        const subCommand = args[0]?.toLowerCase();
        
        if (subCommand === 'status') {
            const statusType = args[1]?.toLowerCase();
            const statusMapping = ['online', 'idle', 'dnd', 'invisible'];

            if (!statusType || !statusMapping.includes(statusType)) {
                const tempMsg = await message.channel.send("Invalid status. Use online, idle, or dnd.");
                return setTimeout(() => selfDeleteMessage(tempMsg), 5000);
            }
            
            try {
                await client.user.setStatus(statusType);
                const tempMsg = await message.channel.send(`Status set to **${statusType}**.`);
                setTimeout(() => selfDeleteMessage(tempMsg), 5000);
            } catch (e) {
                const tempMsg = await message.channel.send(`Failed to change status: ${e.message}`);
                setTimeout(() => selfDeleteMessage(tempMsg), 5000);
            }
        } 
        else if (subCommand === 'logout') {
            await message.channel.send("Logging out...").then(() => client.destroy());
        } else {
            const tempMsg = await message.channel.send("Use `+account status <online/idle/dnd>` to change your bot status.");
            setTimeout(() => selfDeleteMessage(tempMsg), 5000);
        }
    }
});


// --- Login ---

// This will attempt to log in using the User Token provided above.
client.login(TOKEN).catch(err => {
    console.error("Failed to log in. Ensure you are using a valid **User Token** and the self-bot library is correctly installed.");
    console.error(err);
});
