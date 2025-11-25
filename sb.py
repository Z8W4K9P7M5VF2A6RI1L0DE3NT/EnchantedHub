#
# Made By Slayerson
#


#
# V6 -All issues fixed 😭😭😭😭
#


import discord
from discord import Intents
from discord.ext import commands
import asyncio
import random
from datetime import datetime
import aiohttp
import json
import time


intents = Intents.default()
intents.message_content = True 
intents.members = True         
intents.presences = True 


bot = commands.Bot(
    command_prefix='+', 
    self_bot=True,   
    help_command=None,
    intents=intents 
)

spam_tasks = {}
an_tasks = {}
deleted_messages = {}
prefixes = {}
last_delete_time = 0
delete_cooldown = 1.0  

@bot.command(name='help')
async def custom_help(ctx):
    help_text = """
**MADE BY SLAYERSON NIGGA!**
`+help` 

**Messaging Commands:**
• `+spam <message>` 
• `+stopspam` 
• `+an <message>` 
• `+stopan` 
• `+snipe <amount?>` 
• `+delete <amount>` 
• `+cleanconv @user` 
• `+cn @user` 

**User Commands:**
• `+userinfo @user` 
• `+jtbz` 

**Webhook Commands:**
• `+checkwebhook <webhookURL>` 
• `+spamwebhook <webhookURL> <webhookName> <message> <amount?>`

**Other Commands:**
• `+account status|profile|logout` 
• `+serverinfo`
• `+joke` - Tell a random joke Look on google for sum Jokes LMFAO
• `+choose <option1> <option2> ...` 
• `+config prefix|settings` 
"""
    await ctx.send(help_text)

@bot.event
async def on_ready():
    
    print(f'Logged in as {bot.user} (ID: {bot.user.id})')
    print('------')

@bot.event
async def on_message_delete(message):
    if message.channel.id not in deleted_messages:
        deleted_messages[message.channel.id] = []
    
    if len(deleted_messages[message.channel.id]) >= 10:
        deleted_messages[message.channel.id].pop(0)
    
    deleted_messages[message.channel.id].append({
        'content': message.content,
        'author': message.author,
        'timestamp': datetime.now(),
        'attachments': [att.url for att in message.attachments]
    })

@bot.command(name='spam')
async def spam_cmd(ctx, *, message):
    if ctx.channel.id in spam_tasks:
        return
    
    async def spam_task():
        try:
            while ctx.channel.id in spam_tasks:
                await ctx.send(message)
                await asyncio.sleep(0.010)
        except Exception as e:
            print(f"Spam error: {e}")
        finally:
            if ctx.channel.id in spam_tasks:
                spam_tasks.pop(ctx.channel.id)
    
    spam_tasks[ctx.channel.id] = asyncio.create_task(spam_task())

@bot.command(name='stopspam')
async def stop_spam(ctx):
    if ctx.channel.id in spam_tasks:
        spam_tasks[ctx.channel.id].cancel()
        spam_tasks.pop(ctx.channel.id)

@bot.command(name='delete')
async def delete_cmd(ctx, amount: int = 10):
    if amount > 100:
        amount = 100
        
    def is_me(m):
        
        return m.author == ctx.author
    
    if isinstance(ctx.channel, discord.DMChannel):
        deleted_count = 0
        async for message in ctx.channel.history(limit=200):
            if deleted_count >= amount:
                break
            if is_me(message) and message.id != ctx.message.id:
                try:
                    await self_delete_message(message)
                    deleted_count += 1
                except:
                    continue
    else:
        
        deleted_count = 0
        async for message in ctx.channel.history(limit=200):
            if deleted_count >= amount:
                break
            if is_me(message) and message.id != ctx.message.id:
                try:
                    await self_delete_message(message)
                    deleted_count += 1
                except:
                    continue


async def self_delete_message(message):
    global last_delete_time
    
    current_time = time.time()
    time_since_last_delete = current_time - last_delete_time
    
    if time_since_last_delete < delete_cooldown:
        await asyncio.sleep(delete_cooldown - time_since_last_delete)
    
    try:
        await message.delete()
        last_delete_time = time.time()
    except discord.HTTPException as e:
        if e.status == 429:
            retry_after = e.retry_after if hasattr(e, 'retry_after') else 2.0
            await asyncio.sleep(retry_after)
            try:
                await message.delete()
                last_delete_time = time.time()
            except:
                pass
        else:
            pass

@bot.group(name='account', invoke_without_command=True)
async def account_group(ctx):
    await ctx.send("Use `+account status <online/idle/dnd>` to change your user status.")

@account_group.command(name='status')
async def set_status(ctx, status_type: str):
    
    status_mapping = {
        'online': 'online',
        'idle': 'idle', 
        'dnd': 'dnd',
        'invisible': 'invisible'
    }
    
    if status_type.lower() not in status_mapping:
        await ctx.send("Invalid status. Use online, idle, dnd, or invisible.")
        return
        
    try:
        
        await bot.change_presence(status=status_type.lower())
        await ctx.send(f"Status set to **{status_type}**.", delete_after=5)
    except Exception as e:
        await ctx.send(f"Failed to change status: {e}", delete_after=5)


@account_group.command(name='logout')
async def logout(ctx):
    await bot.close()

@bot.command(name='an')
async def an_cmd(ctx, *, message):
    try:
        await ctx.message.delete()
        await asyncio.sleep(0.5)
        await ctx.send(f" Anonymous Message: {message}")
    except:
        pass

@bot.command(name='stopan')
async def stop_an(ctx):
    if ctx.channel.id in an_tasks:
        an_tasks[ctx.channel.id].cancel()
        an_tasks.pop(ctx.channel.id)

@bot.command(name='snipe')
async def snipe_cmd(ctx, amount: int = 1):
    if ctx.channel.id not in deleted_messages or not deleted_messages[ctx.channel.id]:
        await ctx.send("No message to snipe.")
        return
    
    amount = min(amount, len(deleted_messages[ctx.channel.id]))
    messages_to_snipe = deleted_messages[ctx.channel.id][-amount:]
    
    for i, msg_data in enumerate(reversed(messages_to_snipe)):
        time_diff = datetime.now() - msg_data['timestamp']
        minutes_ago = int(time_diff.total_seconds() / 60)
        
        attachments = msg_data.get('attachments', [])
        image_install = attachments[0] if attachments else "None"
        
        snipe_text = f"""
**SNIPE**
| Auteur: {msg_data['author']}
| Message: {msg_data['content']}
| Image Install: {image_install}
| Date: {minutes_ago} minute{'s' if minutes_ago != 1 else ''} ago
"""
        await ctx.send(snipe_text)
        await asyncio.sleep(1)

@bot.command(name='cleanconv')
async def clean_conv_cmd(ctx, user: discord.User = None):
    if user is None:
        await ctx.send("Please mention a user.")
        return
        
    def is_conv_message(m):
        
        return m.author == user or m.author == ctx.author
    
    if isinstance(ctx.channel, discord.DMChannel):
        messages_to_delete = []
        async for message in ctx.channel.history(limit=200):
            if is_conv_message(message) and message.id != ctx.message.id:
                messages_to_delete.append(message)
        
        for message in messages_to_delete:
            try:
                await self_delete_message(message)
                await asyncio.sleep(0.3)
            except:
                continue
    else:
        
        messages_to_delete = []
        async for message in ctx.channel.history(limit=100):
            if is_conv_message(message) and message.id != ctx.message.id:
                messages_to_delete.append(message)

        for message in messages_to_delete:
            try:
                await self_delete_message(message)
                await asyncio.sleep(0.3)
            except:
                continue

@bot.command(name='cn')
async def clean_user_messages(ctx, user: discord.User = None, limit: int = 50):
    if user is None:
        await ctx.send("Please mention a user.")
        return
        
    def is_user_message(m):
        return m.author == user
    
    if isinstance(ctx.channel, discord.DMChannel):
        messages_to_delete = []
        async for message in ctx.channel.history(limit=200):
            if is_user_message(message) and message.id != ctx.message.id:
                messages_to_delete.append(message)
        
        for message in messages_to_delete:
            try:
                await self_delete_message(message)
                await asyncio.sleep(0.3)
            except:
                continue
    else:
        
        messages_to_delete = []
        async for message in ctx.channel.history(limit=limit):
            if is_user_message(message) and message.id != ctx.message.id:
                messages_to_delete.append(message)
        
        for message in messages_to_delete:
            try:
                await self_delete_message(message)
                await asyncio.sleep(0.3)
            except:
                continue


@bot.command(name='userinfo')
async def user_info_cmd(ctx, user: discord.User = None):
    user = user or ctx.author
    
    info_text = f"""
**User Info for {user}**
**ID:** {user.id}
**Created:** {user.created_at.strftime('%m/%d/%Y')}
**Bot:** {'Yes' if user.bot else 'No'}
"""
    await ctx.send(info_text)

@bot.command(name='jtbz')
async def jtbz_cmd(ctx):
    await ctx.send(" **Just Too Based!** ")

@bot.command(name='checkwebhook')
async def check_webhook_cmd(ctx, webhook_url: str):
    if isinstance(ctx.channel, discord.DMChannel):
        return
        
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(webhook_url) as response:
                if response.status == 200:
                    data = await response.json()
                    await ctx.send(f"Webhook Check: **Valid** | Name: {data.get('name')}", delete_after=10)
                else:
                    await ctx.send(f"Webhook Check: **Invalid** | Status: {response.status}", delete_after=10)
    except Exception:
        await ctx.send("Webhook Check: **Error** (Invalid URL format or connection issue)", delete_after=10)

@bot.command(name='spamwebhook')
async def spam_webhook_cmd(ctx, webhook_url: str, webhook_name: str, *, message: str, amount: int = 5):
    if isinstance(ctx.channel, discord.DMChannel):
        return
        
    if amount > 10:
        await ctx.send("Limit spam amount to 10.", delete_after=5)
        return
    
    try:
        for i in range(amount):
            async with aiohttp.ClientSession() as session:
                webhook = discord.Webhook.from_url(webhook_url, session=session)
                
                await webhook.send(content=message, username=webhook_name)
                await asyncio.sleep(1)
        await ctx.send(f"Spammed {amount} messages to webhook.", delete_after=5)
    except Exception:
        await ctx.send("Failed to send webhook spam. Check URL and permissions.", delete_after=5)

@bot.command(name='serverinfo')
async def server_info(ctx):
    if isinstance(ctx.channel, discord.DMChannel):
        await ctx.send("This command only works in a server.")
        return
        
    guild = ctx.guild
    roles = [role.name for role in guild.roles if role.name != "@everyone"]
    
    info_text = f"""
**Server Info for {guild.name}**
**Owner:** {guild.owner}
**ID:** {guild.id}
**Created:** {guild.created_at.strftime('%m/%d/%Y')}
**Members:** {guild.member_count}
**Roles:** {len(roles)}
**Channels:** {len(guild.channels)}
"""
    await ctx.send(info_text)

@bot.command(name='joke')
async def tell_joke(ctx):
    jokes = [
        "Why don't scientists trust atoms? Because they make up everything!",
        "Why did the scarecrow win an award? Because he was outstanding in his field!",
        "What do you call a fake noodle? An impasta!",
        "How does a penguin build its house? Igloos it together!",
    ]
    joke = random.choice(jokes)
    await ctx.send(joke)

@bot.command(name='choose')
async def choose_option(ctx, *options):
    if not options:
        await ctx.send("Provide options to choose from.")
        return
        
    choice = random.choice(options)
    await ctx.send(f" I choose: {choice}")

@bot.group(name='config', invoke_without_command=True)
async def config_group(ctx):
    if isinstance(ctx.channel, discord.DMChannel):
        await ctx.send("This command only works in a server.")
        return

@config_group.command(name='prefix')
async def set_prefix(ctx, new_prefix):
    if isinstance(ctx.channel, discord.DMChannel):
        return
        
    prefixes[ctx.guild.id] = new_prefix
    await ctx.send(f"Prefix set to `{new_prefix}` for this server.", delete_after=5)

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandOnCooldown):
        pass
    elif isinstance(error, discord.HTTPException) and error.status == 429:
        pass
    elif isinstance(error, commands.MissingRequiredArgument):
        pass
    

# DM SLAYERSON FPR HELP


bot.run("add ur shit hete mfs")


# DM SLAYERSON FOR HELP
