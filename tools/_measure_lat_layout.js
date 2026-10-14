/* _measure_lat_layout.js —— 真实浏览器里量「实时监测 · 最新情报」左栏布局
 *
 * 为什么必须真浏览器：这次的 bug 是**布局** bug（标题被压成竖排、容器长出横向
 * 滚动条）。任何静态检查（正则/grep 断言）都只能证明"CSS 写了什么"，
 * 证明不了"浏览器算出来是什么"。这里用 Playwright 量三件事：
 *   ① #latestbody.scrollWidth 是否超过 clientWidth（横向滚动条的成因）
 *   ② .lat 每行的高度（竖排窄条会让行高暴涨）
 *   ③ .trl 是否还在参与 .lat 的横向排布（改成看它相对标题的 y 偏移）
 *
 * 用法： NODE_PATH=<workspace>/node_modules node tools/_measure_lat_layout.js
 */
const { chromium } = require('playwright');

const BASE = process.env.AISEC_BASE || 'http://127.0.0.1:8848';

/* 读页面里的实测数据 */
const PROBE = () => {
  const body = document.getElementById('latestbody');
  if (!body) return { err: 'no #latestbody' };
  const lats = Array.from(body.querySelectorAll('.lat'));
  const rows = lats.map((el) => {
    const r = el.getBoundingClientRect();
    const t = el.querySelector('.latt');
    const tr = el.querySelector('.trl');
    const trl = el.querySelector('.latmain');
    const trb = t ? t.getBoundingClientRect() : null;
    const trlb = trl ? trl.getBoundingClientRect() : null;
    return {
      rowW: Math.round(r.width),
      rowH: Math.round(r.height),
      /* 标题所在容器的宽度：被压成竖排时这个值会非常小（< 40px） */
      mainW: trlb ? Math.round(trlb.width) : null,
      titleW: trb ? Math.round(trb.width) : null,
      titleH: trb ? Math.round(trb.height) : null,
      /* 译文块在标题的下方（dy>0）还是在右侧（dy≈0 且 dx>0） */
      trDy: (tr && trb) ? Math.round(tr.getBoundingClientRect().top - trb.top) : null,
      trDx: (tr && trb) ? Math.round(tr.getBoundingClientRect().left - trb.left) : null,
      trW: tr ? Math.round(tr.getBoundingClientRect().width) : null,
    };
  });
  return {
    scrollW: body.scrollWidth,
    clientW: body.clientWidth,
    overflowX: body.scrollWidth - body.clientWidth,
    n: lats.length,
    nTrl: body.querySelectorAll('.trl').length,
    rows,
  };
};

(async () => {
  let browser = null;
  let bad = 0;
  try {
    browser = await chromium.launch();
    const page = await browser.newPage({ viewport: { width: 1600, height: 950 } });
    /* 无头环境下把译文块直接注入，等价于"翻译已开启并跑完"后的真实 DOM。
       翻译要真跑本机模型（几十秒），这里只验证**布局**——即块插进去之后的表现。 */
    await page.goto(BASE + '/', { waitUntil: 'load', timeout: 30000 });
    await page.waitForSelector('#latestbody .lat', { timeout: 25000 });

    /* 等侧栏渲染完 */
    await page.waitForTimeout(1200);

    const before = await page.evaluate(PROBE);
    console.log('=== 插入译文块之前（对照）===');
    console.log('  条目数:', before.n, ' 横向溢出:', before.overflowX, 'px');
    if (before.rows[0]) console.log('  首行:', JSON.stringify(before.rows[0]));

    /* 注入译文块：模拟 TR 用 el.after() 把 .trl 插在 .latt 后面。
       插在 .latmain 内部 —— 这正是修复后的结构。 */
    const injected = await page.evaluate(() => {
      const lats = Array.from(document.querySelectorAll('#latestbody .lat'));
      const zh = ['IBM Langflow OSS 1.0.0 至 1.12.2 可能导致远程代码执行',
                  'CVE-2026-97679 严重级别的身份验证绕过漏洞影响 Langflow 全部版本'];
      let n = 0;
      lats.forEach((el, i) => {
        const m = el.querySelector('.latmain');
        if (!m) return;
        const d = document.createElement('div');
        d.className = 'trl';
        d.textContent = zh[i % zh.length];
        m.appendChild(d);      /* 插进 .latmain —— 不是 .lat 的并列兄弟 */
        n++;
      });
      return n;
    });
    console.log('\n=== 注入译文块之后（译文在 .latmain 内）===');
    console.log('  已注入:', injected, '块');

    await page.waitForTimeout(400);
    const after = await page.evaluate(PROBE);
    console.log('  条目数:', after.n, ' 译文块数:', after.nTrl, ' 横向溢出:', after.overflowX, 'px');
    after.rows.slice(0, 3).forEach((r, i) => console.log('  行' + (i + 1) + ':', JSON.stringify(r)));

    console.log('\n=== 判定 ===');
    if (after.overflowX > 0) { console.log('  [FAIL] 仍有横向溢出 ' + after.overflowX + 'px'); bad++; }
    else console.log('  [PASS] 无横向溢出（scrollWidth == clientWidth，无横向滚动条）');

    const narrow = after.rows.filter((r) => r.mainW !== null && r.mainW < 60);
    if (narrow.length) {
      console.log('  [FAIL] ' + narrow.length + ' 行的标题容器被压到 <60px（竖排窄条）');
      bad++;
    } else console.log('  [PASS] 所有行标题容器宽度正常（无一被压成竖排窄条）');

    const side = after.rows.filter((r) => r.trDx !== null && r.trDx > 4);
    if (side.length) {
      console.log('  [FAIL] ' + side.length + ' 行的译文块还在标题右侧（仍在抢横向空间）');
      bad++;
    } else console.log('  [PASS] 译文块一律落在标题下方（dy>0），未参与横向排布');

    const tall = after.rows.filter((r) => r.rowH > 90);
    if (tall.length) {
      console.log('  [FAIL] ' + tall.length + ' 行高度异常（>90px，疑似逐字换行）');
      bad++;
    } else console.log('  [PASS] 行高正常（无逐字换行导致的高度暴涨）');

    await page.screenshot({ path: 'tools/_lat_after.png', fullPage: false });
    console.log('\n截图已存 tools/_lat_after.png');
  } catch (e) {
    console.log('测量失败：' + (e && e.message));
    bad++;
  } finally {
    if (browser) await browser.close();
  }
  process.exit(bad === 0 ? 0 : 1);
})();
