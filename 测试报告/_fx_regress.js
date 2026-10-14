/* _fx_regress.js —— 火狐「详情页整屏变暗」修复回归（2026-10-13）
 *
 * 判据（按优先级）：
 *  1. elementFromPoint：详情打开时，检查器中心点命中的元素必须位于 #inspector 内部
 *     （被遮罩盖住时会命中 #mask —— 这正是用户截图里的故障形态）。
 *  2. 计算样式：#mask.on 状态 + #inspector 的 z-index / position 与 CSS 媒体查询一致。
 *  3. 功能：窄屏(≤1200)点遮罩能关抽屉；宽屏(>1200)根本不出现遮罩。
 *  4. 旧浏览器提示 #legacy 在现代浏览器必须保持隐藏。
 * 用法： NODE_PATH=<node workspace>/node_modules node _fx_regress.js <base>
 */
const { firefox } = require('playwright');
const path = require('path');

const BASE = process.argv[2] || 'http://127.0.0.1:8899';
const OUT = __dirname;
const WIDTHS = [1600, 1250, 1150];
const DETAIL_ID = 'CVE-2026-78357';

(async () => {
  const browser = await firefox.launch();
  const rows = [];
  for (const w of WIDTHS) {
    const page = await browser.newPage({ viewport: { width: w, height: 900 } });
    const errors = [];
    page.on('pageerror', (e) => errors.push(String(e).slice(0, 120)));
    await page.goto(BASE + '/', { waitUntil: 'domcontentloaded', timeout: 60000 });
    await page.waitForFunction(
      () => { const b = document.getElementById('boot'); return b && b.classList.contains('out'); },
      { timeout: 90000 });
    await page.waitForTimeout(600);
    await page.evaluate((id) => window.openDetail(id), DETAIL_ID);
    await page.waitForTimeout(1400);           // 等 inspIn 动画播完
    const info = await page.evaluate(() => {
      const mask = document.getElementById('mask');
      const insp = document.getElementById('inspector');
      const ir = insp.getBoundingClientRect();
      const cx = Math.round(ir.x + ir.width / 2), cy = Math.round(ir.y + ir.height / 2);
      const hit = document.elementFromPoint(cx, cy);
      const inside = !!(hit && insp.contains(hit));
      const legacy = document.getElementById('legacy');
      return {
        maskOn: mask.classList.contains('on'),
        maskZ: getComputedStyle(mask).zIndex,
        inspZ: getComputedStyle(insp).zIndex,
        inspPos: getComputedStyle(insp).position,
        inspW: Math.round(ir.width), inspH: Math.round(ir.height),
        inspOnScreen: ir.right > 0 && ir.left < window.innerWidth && ir.width > 100,
        centerHit: hit ? (hit.id ? '#' + hit.id : hit.tagName + '.' + (hit.className || '').toString().slice(0, 30)) : 'null',
        hitInsideInspector: inside,
        detailTitle: ((document.querySelector('#dh h2') || {}).textContent || '').trim().slice(0, 40),
        legacyDisplay: legacy ? getComputedStyle(legacy).display : 'absent',
      };
    });
    // 窄屏功能：点遮罩应关闭抽屉；宽屏：遮罩不应在
    let closeWorks = null;
    if (info.maskOn) {
      await page.mouse.click(Math.round(w * 0.25), 450);
      await page.waitForTimeout(500);
      closeWorks = await page.evaluate(() =>
        !document.getElementById('mask').classList.contains('on') &&
        !document.querySelector('.stage')?.classList.contains('insp'));
    }
    const shot = path.join(OUT, `_fx_regress_${w}.png`);
    await page.screenshot({ path: shot });
    rows.push({ width: w, ...info, maskClickCloses: closeWorks, pageErrors: errors, shot: path.basename(shot) });
    await page.close();
  }
  await browser.close();
  console.log(JSON.stringify(rows, null, 2));
  const bad = rows.filter(r => !r.hitInsideInspector || r.pageErrors.length);
  console.log(bad.length ? `REGRESS FAIL: ${bad.length} 档位有问题` : 'ALL VIEWPORTS OK');
  process.exit(bad.length ? 1 : 0);
})().catch(e => { console.error('FATAL', e); process.exit(2); });
