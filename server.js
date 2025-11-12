const express = require('express');
const bodyParser = require('body-parser');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
// Use the PORT environment variable provided by Render
const port = process.env.PORT || 3000; 

// Define the watermark constant
// MODIFIED: Adding a single space at the end to clearly separate it from the code payload.
const WATERMARK = "--[[ v0.1.0 NovaHub Lua Obfuscator ]] "; 

// Middleware to parse incoming JSON and serve static files
app.use(bodyParser.json());
app.use(express.static('public')); 

app.post('/obfuscate', (req, res) => {
    const luaCode = req.body.code;
    // Get the selected preset from the frontend (e.g., Medium)
    const preset = req.body.preset || 'Medium'; 
    const timestamp = Date.now();
    
    // Create temporary files in the root directory
    const tempFile = path.join(__dirname, `temp_${timestamp}.lua`);
    const outputFile = path.join(__dirname, `obf_${timestamp}.lua`);
    
    // 1. Write the user's code to a temporary file
    fs.writeFileSync(tempFile, luaCode, 'utf8');

    // 2. Define the command to run Prometheus
    const command = `lua src/cli.lua --preset ${preset} --out ${outputFile} ${tempFile}`;
    
    // 3. Execute the Prometheus CLI
    exec(command, (error, stdout, stderr) => {
        // 4. Clean up the temporary input file
        fs.unlinkSync(tempFile); 
        
        // 5. Check for errors
        if (error || stderr) {
            console.error(`Obfuscation failed: ${error ? error.message : stderr}`);
            // Check if the output file was created, and clean up if it was
            if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);
            
            // Return detailed error message to the client
            return res.status(500).json({ 
                error: 'Obfuscation failed.', 
                // Return stderr as the details for better debugging
                details: stderr || error.message 
            });
        }
        
        // 6. Read the obfuscated result
        try {
            let obfuscatedCode = fs.readFileSync(outputFile, 'utf8');
            
            // Prepend the watermark to the obfuscated code
            obfuscatedCode = WATERMARK + obfuscatedCode;
            
            // 7. Send the result back and clean up the output file
            res.json({ obfuscatedCode: obfuscatedCode });
            fs.unlinkSync(outputFile);
        } catch (readError) {
            // Handle case where output file might not exist or be readable
            return res.status(500).json({ error: 'Failed to read output file.' });
        }
    });
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
