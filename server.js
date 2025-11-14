const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');
// require('dotenv').config(); // Uncomment if running locally and using .env file
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
const port = process.env.PORT || 10000;

// --- CRITICAL: INCREASED PAYLOAD LIMIT ---
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));

// --- Database Connection Pool ---
// Uses process.env.DATABASE_URL from Render/dotenv
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    // Required for cloud databases like Render
    ssl: { rejectUnauthorized: false }
});

// Define constants
const WATERMARK = "--[[ v0.1.0 NovaHub Lua Obfuscator ]] ";
const FALLBACK_WATERMARK = "--[[ OBFUSCATION FAILED: Returning raw script. Check your Lua syntax. ]] ";
const OBFUSCATOR_PRESET = 'Medium';
// Path to the external Lua obfuscator CLI
const SCRIPT_LUA_PATH = path.join(__dirname, 'src', 'cli.lua');

// Temporary token storage for secure access (in-memory, cleared on server restart)
const tempAccessTokens = {};

// Test connection and initialize table
pool.connect((err, client, done) => {
    if (err) {
        console.error('Database connection failed (Check DATABASE_URL):', err.stack);
        return;
    }
    console.log('Successfully connected to PostgreSQL.');

    // --- Database Schema (MUST MATCH CODE) ---
    const createTableQuery = `
        CREATE TABLE IF NOT EXISTS scripts (
            key VARCHAR(32) PRIMARY KEY,
            edit_password_hash VARCHAR(64) NOT NULL,
            access_password_hash VARCHAR(64), 
            raw_script TEXT NOT NULL,
            obfuscated_script TEXT, 
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
    `;
    client.query(createTableQuery, (err, res) => {
        done();
        if (err) {
            console.error('Error creating table:', err.stack);
        } else {
            console.log('Database table "scripts" initialized.');
        }
    });
});

// Middleware for static files and CORS
app.use(express.static('public'));
app.use(cors());

// --- Helper Functions ---
const generateUniqueId = () => {
    return crypto.randomBytes(16).toString('hex');
};

const hashPassword = (password) => {
    // Standard SHA-256 hash for password storage
    return crypto.createHash('sha256').update(password).digest('hex');
};

const applyFallback = (rawCode) => {
    return `${FALLBACK_WATERMARK}\n${rawCode}`;
};

// Reusable function to execute Prometheus Obfuscator
const runObfuscationStep = async (rawLuaCode) => {
    const timestamp = Date.now();
    const tempFile = path.join(__dirname, `temp_${timestamp}.lua`);
    const outputFile = path.join(__dirname, `obf_${timestamp}.lua`);
    
    // 1. Write raw code to temporary input file
    try {
        fs.writeFileSync(tempFile, rawLuaCode, 'utf8');
    } catch (e) {
        console.error('File Write Error:', e);
        return { code: applyFallback(rawLuaCode), success: false };
    }

    // 2. Execute obfuscator
    // NOTE: This assumes 'lua' is in the system path and 'src/cli.lua' exists.
    const command = `lua ${SCRIPT_LUA_PATH} --preset ${OBFUSCATOR_PRESET} --out ${outputFile} ${tempFile}`;
    
    return new Promise((resolve) => {
        // Set a timeout of 15 seconds for obfuscation
        exec(command, { timeout: 15000 }, (error, stdout, stderr) => { 
            // 3. Cleanup input file immediately
            try { fs.unlinkSync(tempFile); } catch (e) { /* silent fail */ } 
            
            if (error || stderr) {
                console.error(`Prometheus Execution Failed: ${error ? (error.killed ? 'Timeout or Kill' : error.message) : stderr}`);
                
                // 4. Cleanup output file if it exists, then fallback
                if (fs.existsSync(outputFile)) { try { fs.unlinkSync(outputFile); } catch (e) { /* silent fail */ } }
                
                resolve({ 
                    code: applyFallback(rawLuaCode), 
                    success: false 
                });
                return;
            }
            
            // 5. Success: Read output, apply watermark, cleanup output file
            let obfuscatedCode = '';
            try {
                obfuscatedCode = fs.readFileSync(outputFile, 'utf8');
                obfuscatedCode = WATERMARK + obfuscatedCode;
                fs.unlinkSync(outputFile);
            } catch (e) {
                 console.error('Obfuscator output file read/cleanup error:', e);
                 // Fallback if file ops fail after successful execution
                 resolve({ code: applyFallback(rawLuaCode), success: false });
                 return;
            }
            
            resolve({ 
                code: obfuscatedCode, 
                success: true 
            });
        });
    });
};


// =======================================================
// === 1. OBFUSCATE ROUTE (For Raw Output Preview) ======
// =======================================================
app.post('/obfuscate', async (req, res) => {
    const rawLuaCode = req.body.code;
    
    try {
        const result = await runObfuscationStep(rawLuaCode);
        
        res.status(200).json({ 
            obfuscatedCode: result.code,
            success: result.success
        });
        
    } catch (error) {
        console.error('Obfuscate route execution error:', error.stack);
        return res.status(500).json({ error: 'Internal execution error.' });
    }
});


// ==========================================================
// === 2. CREATE SECURE SCRIPT 
// ==========================================================
app.post('/create-secure-script', async (req, res) => {
    const rawLuaCode = req.body.script; 
    const editPassword = req.body.editPassword; 
    const accessPassword = req.body.accessPassword || null;

    if (!rawLuaCode || rawLuaCode.trim() === '' || !editPassword || editPassword.length < 4) {
        return res.status(400).json({ error: 'Script and a strong edit password (min 4 chars) are required.' });
    }
    
    // Step 1: Obfuscate the initial script
    const obfuscationResult = await runObfuscationStep(rawLuaCode);
    
    // Step 2: Store Raw, Obfuscated, and Password Hashes
    const scriptKey = generateUniqueId();
    const editPasswordHash = hashPassword(editPassword);
    const accessPasswordHash = accessPassword ? hashPassword(accessPassword) : null; 

    try {
        await pool.query(
            'INSERT INTO scripts(key, edit_password_hash, access_password_hash, raw_script, obfuscated_script) VALUES($1, $2, $3, $4, $5)',
            [scriptKey, editPasswordHash, accessPasswordHash, rawLuaCode, obfuscationResult.code]
        );

        console.log(`Script created successfully. Key: ${scriptKey}`);

        res.status(201).json({ 
            message: obfuscationResult.success ? 'Secure script created.' : 'Script created, but obfuscation failed (using fallback).',
            key: scriptKey,
            loaderUrl: `/retrieve/${scriptKey}`
        });

    } catch (error) {
        console.error('Database error during script creation:', error.stack); 
        res.status(500).json({ error: 'Internal server error during script storage.' });
    }
});


// ====================================================
// === 3. GET RAW FOR EDIT (Password Protected) =======
// ====================================================
app.post('/get-raw-for-edit', async (req, res) => {
    const scriptKey = req.body.key;
    const password = req.body.password;
    const passwordHash = hashPassword(password);

    try {
        const result = await pool.query(
            'SELECT raw_script, edit_password_hash FROM scripts WHERE key = $1', 
            [scriptKey]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Script not found.' });
        }
        
        const storedHash = result.rows[0].edit_password_hash;

        if (storedHash !== passwordHash) {
            return res.status(403).json({ error: 'Invalid password or key combination.' });
        }

        res.status(200).json({ 
            rawScript: result.rows[0].raw_script 
        });

    } catch (error) {
        console.error('Database error during raw script retrieval:', error.stack);
        res.status(500).json({ error: 'Internal server error.' });
    }
});


// ====================================================
// === 4. SAVE AND OBFUSCATE (Password Protected) =====
// ====================================================
app.post('/save-and-obfuscate', async (req, res) => {
    const scriptKey = req.body.key;
    const password = req.body.password;
    const newRawScript = req.body.newScript;
    const passwordHash = hashPassword(password);

    if (!newRawScript || newRawScript.trim() === '') {
        return res.status(400).json({ error: 'New script cannot be empty.' });
    }

    try {
        // Step 1: Verify Password Hash
        const checkResult = await pool.query(
            'SELECT edit_password_hash FROM scripts WHERE key = $1', 
            [scriptKey]
        );

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Script not found.' });
        }
        
        if (checkResult.rows[0].edit_password_hash !== passwordHash) {
            return res.status(403).json({ error: 'Invalid password or key combination.' });
        }

        // Step 2: Obfuscate the new script
        const obfuscationResult = await runObfuscationStep(newRawScript);
        
        // Step 3: Update the database
        await pool.query(
            'UPDATE scripts SET raw_script = $1, obfuscated_script = $2 WHERE key = $3',
            [newRawScript, obfuscationResult.code, scriptKey]
        );

        res.status(200).json({ 
            message: obfuscationResult.success ? 'Script saved and re-obfuscated successfully.' : 'Script saved, but re-obfuscation failed (using fallback).',
            success: obfuscationResult.success
        });

    } catch (error) {
        console.error('Database error during save and obfuscate:', error.stack);
        res.status(500).json({ error: 'Internal server error during script update.' });
    }
});


// ====================================================
// === 5. DELETE SCRIPT (Password Protected) ==========
// ====================================================
app.post('/delete-script', async (req, res) => {
    const scriptKey = req.body.key;
    const password = req.body.password;
    const passwordHash = hashPassword(password);

    try {
        // Step 1: Verify Password Hash
        const checkResult = await pool.query(
            'SELECT edit_password_hash FROM scripts WHERE key = $1', 
            [scriptKey]
        );

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Script not found.' });
        }
        
        if (checkResult.rows[0].edit_password_hash !== passwordHash) {
            return res.status(403).json({ error: 'Invalid password or key combination.' });
        }

        // Step 2: Delete from the database
        await pool.query('DELETE FROM scripts WHERE key = $1', [scriptKey]);

        res.status(200).json({ 
            message: 'Script deleted permanently.',
            success: true
        });

    } catch (error) {
        console.error('Database error during script deletion:', error.stack);
        res.status(500).json({ error: 'Internal server error during deletion.' });
    }
});


// ====================================================
// === 6. CHANGE EDIT PASSWORD (Password Protected) ===
// ====================================================
app.post('/change-edit-password', async (req, res) => {
    const scriptKey = req.body.key;
    const oldPassword = req.body.oldPassword;
    const newPassword = req.body.newPassword;
    const oldPasswordHash = hashPassword(oldPassword);
    const newPasswordHash = hashPassword(newPassword);

    if (!newPassword || newPassword.length < 4) {
        return res.status(400).json({ error: 'New password must be at least 4 characters.' });
    }

    try {
        // Step 1: Verify Old Password Hash
        const checkResult = await pool.query(
            'SELECT edit_password_hash FROM scripts WHERE key = $1', 
            [scriptKey]
        );

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Script not found.' });
        }
        
        if (checkResult.rows[0].edit_password_hash !== oldPasswordHash) {
            return res.status(403).json({ error: 'Invalid old password.' });
        }

        // Step 2: Update the password hash
        await pool.query(
            'UPDATE scripts SET edit_password_hash = $1 WHERE key = $2',
            [newPasswordHash, scriptKey]
        );

        res.status(200).json({ 
            message: 'Edit password changed successfully.',
            success: true
        });

    } catch (error) {
        console.error('Database error during password change:', error.stack);
        res.status(500).json({ error: 'Internal server error during password update.' });
    }
});


// ====================================================
// === 7. SECURE ACCESS / RETRIEVAL ENDPOINTS ===
// ====================================================

// GET /retrieve/:key: Conditional access point
app.get('/retrieve/:key', async (req, res) => {
    const scriptKey = req.params.key;
    const userAgent = req.headers['user-agent'];

    // 1. If request comes from Roblox, always serve the script directly
    if (userAgent && userAgent.includes('Roblox')) {
        try {
            const result = await pool.query(
                'SELECT obfuscated_script FROM scripts WHERE key = $1', 
                [scriptKey]
            );

            if (result.rows.length === 0) {
                res.setHeader('Content-Type', 'text/plain');
                return res.status(404).send('-- Error: Script not found or has expired.');
            }
            res.setHeader('Content-Type', 'text/plain');
            res.status(200).send(result.rows[0].obfuscated_script);
            
        } catch (error) {
            console.error('Database error during Roblox retrieval (Schema Check!):', error.stack);
            res.setHeader('Content-Type', 'text/plain');
            res.status(500).send('-- Error: Internal Server Failure.');
        }
        return;
    }

    // 2. If request is from a browser, serve the editor page
    // The editor page handles the access password check (if present) via client-side logic
    try {
        const result = await pool.query(
            'SELECT access_password_hash FROM scripts WHERE key = $1', 
            [scriptKey]
        );

        if (result.rows.length === 0) {
            // If script key is not found, redirect to a 404/home page
            return res.status(404).send('Script not found. Check the key.');
        }

        // Redirect to the editor page which will handle the edit password gate
        // We pass the key as a query parameter
        return res.redirect(`/editor.html?key=${scriptKey}`);

    } catch (error) {
        console.error('Database error during browser retrieval check (Schema Check!):', error.stack);
        res.status(500).send('Internal Server Error.');
    }
});

// Basic Health Check (Optional: Redirect to main UI)
app.get('/', (req, res) => {
    // Assuming your main creation UI is index.html in the public folder
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


// Start the server
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
    console.log(`Open in browser: http://localhost:${port}`);
});
