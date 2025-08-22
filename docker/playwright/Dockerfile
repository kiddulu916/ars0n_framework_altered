FROM mcr.microsoft.com/playwright:v1.40.0-focal

WORKDIR /app

# Install Node.js and npm if not already present
RUN apt-get update && apt-get install -y \
    curl \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install Playwright and browsers
RUN npm install playwright@1.40.0 \
    && npx playwright install chromium \
    && npx playwright install firefox \
    && npx playwright install webkit

# Create scripts directory
RUN mkdir -p /app/scripts

# Create validation script
RUN cat > /app/scripts/validate.js << 'EOF'
const { chromium } = require('playwright');

async function validateXSS(url, payload) {
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    
    let dialogDetected = false;
    page.on('dialog', async dialog => {
        dialogDetected = true;
        await dialog.accept();
    });
    
    try {
        await page.goto(url, { timeout: 30000 });
        await page.waitForTimeout(2000);
        
        const content = await page.content();
        const screenshot = await page.screenshot({ fullPage: true });
        
        await browser.close();
        
        return {
            validated: dialogDetected || content.includes(payload),
            evidence: {
                screenshot: screenshot.toString('base64'),
                dom: content,
                dialogDetected
            }
        };
    } catch (error) {
        await browser.close();
        throw error;
    }
}

async function validateIDOR(baseUrl, authUrl, testPath) {
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    
    try {
        // Authenticate if needed
        if (authUrl) {
            await page.goto(authUrl);
            await page.waitForTimeout(1000);
        }
        
        // Test unauthorized access
        const response = await page.goto(`${baseUrl}${testPath}`);
        const content = await page.content();
        const screenshot = await page.screenshot({ fullPage: true });
        
        await browser.close();
        
        return {
            validated: response.status() === 200 && !content.includes('unauthorized'),
            evidence: {
                screenshot: screenshot.toString('base64'),
                statusCode: response.status(),
                content: content
            }
        };
    } catch (error) {
        await browser.close();
        throw error;
    }
}

// CLI interface
if (require.main === module) {
    const args = process.argv.slice(2);
    const action = args[0];
    
    if (action === 'validate-xss') {
        const url = args[1];
        const payload = args[2];
        validateXSS(url, payload).then(result => {
            console.log(JSON.stringify(result));
        }).catch(error => {
            console.error(JSON.stringify({ error: error.message }));
            process.exit(1);
        });
    } else if (action === 'validate-idor') {
        const baseUrl = args[1];
        const authUrl = args[2];
        const testPath = args[3];
        validateIDOR(baseUrl, authUrl, testPath).then(result => {
            console.log(JSON.stringify(result));
        }).catch(error => {
            console.error(JSON.stringify({ error: error.message }));
            process.exit(1);
        });
    }
}

module.exports = { validateXSS, validateIDOR };
EOF

# Make script executable
RUN chmod +x /app/scripts/validate.js

ENTRYPOINT ["node", "/app/scripts/validate.js"]
