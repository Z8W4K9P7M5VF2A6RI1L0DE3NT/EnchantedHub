// obfuscator.js
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

// Constants from your original file
const WATERMARK = "\n-- </> v0.1.0 NovaHub Lua Obfuscator  "; 
const FALLBACK_WATERMARK = "--[[ OBFUSCATION FAILED: Returning raw script. Check your Lua syntax. ]] ";

const applyFallback = (rawCode) => {
    return `${FALLBACK_WATERMARK}\n${rawCode}`;
};

/**
 * Executes the external Lua obfuscator tool.
 * @param {string} rawLuaCode - The raw Lua code input.
 * @param {string} preset - The obfuscation preset (e.g., 'Medium').
 * @returns {Promise<string>} The obfuscated code, or fallback code on failure.
 */
async function runObfuscator(rawLuaCode, preset = 'Medium') {
    const timestamp = Date.now();
    
    // Use a temporary folder for files to keep the root clean
    const tempDir = path.join(__dirname, 'temp_files');
    if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir);
    }
    
    const tempFile = path.join(tempDir, `temp_${timestamp}.lua`);
    const outputFile = path.join(tempDir, `obf_${timestamp}.lua`);
    
    let obfuscatedCode = '';

    try {
        // 1. Write the raw code to a temporary file
        fs.writeFileSync(tempFile, rawLuaCode, 'utf8');

        // Note: The 'src/cli.lua' path must be correct relative to where the script runs!
        const command = `lua src/cli.lua --preset ${preset} --out ${outputFile} ${tempFile}`;
        
        // 2. Execute the Obfuscator
        await new Promise((resolve) => {
            exec(command, (error, stdout, stderr) => {
                
                // Clean up the temporary input file immediately
                if (fs.existsSync(tempFile)) fs.unlinkSync(tempFile); 
                
                if (error || stderr) {
                    console.error(`Prometheus Execution Failed: ${error ? error.message : stderr}`);
                    if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);
                    
                    // --- FALLBACK LOGIC ---
                    obfuscatedCode = applyFallback(rawLuaCode);
                    resolve();
                    return;
                }
                
                // Success path
                try {
                    if (fs.existsSync(outputFile)) {
                        obfuscatedCode = fs.readFileSync(outputFile, 'utf8');
                        obfuscatedCode = WATERMARK + obfuscatedCode;
                    } else {
                        obfuscatedCode = applyFallback(rawLuaCode);
                    }
                } catch (readError) {
                    console.error('File Read Error:', readError);
                    obfuscatedCode = applyFallback(rawLuaCode);
                } finally {
                    // Clean up the temporary output file
                    if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);
                }
                
                resolve();
            });
        });
        
    } catch (error) {
        console.error('Filesystem or Internal Execution Error:', error);
        obfuscatedCode = applyFallback(rawLuaCode);
    }

    return obfuscatedCode;
}

module.exports = {
    runObfuscator,
    // You can export constants here too if needed
};
