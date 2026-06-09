#!/bin/bash
# Check Bugcrowd submission status
echo "=== Bugcrowd Submissions Check — $(date) ==="

cd /home/openclaw/.openclaw/workspace
NODE_PATH=./node_modules timeout 30 node -e "
const puppeteer = require('puppeteer-core');
(async () => {
    const browser = await puppeteer.connect({ browserURL: 'http://127.0.0.1:18801' });
    const pages = await browser.pages();
    const page = pages[0];
    
    await page.goto('https://bugcrowd.com/submissions', { waitUntil: 'networkidle2', timeout: 20000 });
    await new Promise(r => setTimeout(r, 3000));
    
    const text = await page.evaluate(() => document.body.innerText.substring(0, 1500));
    console.log(text);
    
    // Check for status changes
    const hasAccepted = text.includes('Accepted') && !text.includes('Accepted\\n0');
    const hasRejected = text.includes('Rejected') && !text.includes('Rejected\\n0');
    
    if (hasAccepted) console.log('\\n*** NEW ACCEPTED SUBMISSION! ***');
    if (hasRejected) console.log('\\n*** NEW REJECTED SUBMISSION! ***');
    
    browser.disconnect();
})().catch(e => console.error(e.message));
" 2>&1
