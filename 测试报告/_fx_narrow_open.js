/* 窄屏(1150)浮层打开态截图： inspector 浮在压暗遮罩之上 */
const { firefox } = require('playwright');
(async () => {
  const browser = await firefox.launch();
  const page = await browser.newPage({ viewport: { width: 1150, height: 900 } });
  await page.goto('http://127.0.0.1:8899/', { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.waitForFunction(() => { const b = document.getElementById('boot'); return b && b.classList.contains('out'); }, { timeout: 90000 });
  await page.evaluate(() => window.openDetail('CVE-2026-78357'));
  await page.waitForTimeout(1400);
  await page.screenshot({ path: '_fx_regress_1150_open.png' });
  await browser.close();
  console.log('shot ok');
})().catch(e => { console.error('FATAL', e); process.exit(2); });
