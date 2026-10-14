/* fmtFresh 边界测试：从 app.js 抽出原函数，注入假"现在"验证跨天/月末/跨年/时区 */
const fs = require('fs');
const src = fs.readFileSync('C:/Users/丁/Desktop/aisec-D_2.0/frontend/app.js', 'utf-8');
const m = src.match(/function fmtFresh\(iso\) \{[\s\S]*?\n\}/);
if (!m) { console.error('fmtFresh NOT FOUND'); process.exit(1); }

function makeFmtFresh(nowIso) {
  // 把 const now = new Date(); 换成固定时间
  const body = m[0].replace('const now = new Date();', `const now = new Date(${JSON.stringify(nowIso)});`);
  return new Function('iso', body.replace('function fmtFresh(iso) {', '').replace(/\}$/, ''));
}

const cases = [
  // [假"现在", 输入 iso, 期望文本包含, 期望 stale]
  ['2026-10-10T12:30:00+08:00', '2026-10-10T09:05:00+08:00', '09:05 同步', false],   // 当天
  ['2026-10-10T01:00:00+08:00', '2026-10-09T22:38:40+08:00', '昨天 22:38 同步', false], // 跨天（凌晨看昨晚）
  ['2026-10-01T00:30:00+08:00', '2026-09-30T23:50:00+08:00', '昨天 23:50 同步', false], // 月末→跨月昨天
  ['2026-10-01T12:00:00+08:00', '2026-09-24T16:52:20+08:00', '09-24 16:52 同步', true], // 同一年较早 + stale
  ['2027-01-01T00:10:00+08:00', '2026-12-31T23:55:00+08:00', '昨天 23:55 同步', false], // 跨年昨天
  ['2027-01-01T12:00:00+08:00', '2026-11-02T08:00:00+08:00', '2026-11-02 08:00 同步', true], // 跨年带年份
  ['2026-10-10T12:00:00+08:00', '2026-10-09T22:38:40Z', '06:38 同步', false],      // UTC(Z) → +08 已是当天 06:38
  ['2026-10-10T12:00:00+08:00', '', '—', true],                                       // 空输入
  ['2026-10-10T12:00:00+08:00', 'not-a-date', '—', true],                             // 非法输入
];

let pass = 0, fail = 0;
for (const [nowIso, iso, expect, expectStale] of cases) {
  const fmt = makeFmtFresh(nowIso);
  const r = fmt(iso);
  const okTxt = r.txt.includes(expect);
  const okStale = (expectStale === undefined) || (r.stale === expectStale);
  const ok = okTxt && okStale;
  ok ? pass++ : fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  now=${nowIso}  iso=${iso || '(空)'}\n      -> "${r.txt}"  stale=${r.stale}  (期望含 "${expect}"${expectStale !== undefined ? ', stale=' + expectStale : ''})`);
}
// 特别验证：UTC 输入的完整转换（2026-10-09T22:38:40Z 在 +08 是 10-10 06:38:40 → 当天）
const r = makeFmtFresh('2026-10-10T12:00:00+08:00')('2026-10-09T22:38:40Z');
console.log(`\n时区归一：UTC 22:38 -> 本机(+08) 显示 "${r.txt}"（应为当天 06:38）`);
console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
process.exit(fail ? 1 : 0);
