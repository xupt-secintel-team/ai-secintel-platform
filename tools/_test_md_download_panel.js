/* _test_md_download_panel.js —— 「下载七章制 Markdown」按钮必须**真的下载**
 *
 * 背景（真实用户截图 2026-10-07）：
 *   点「⬇ 下载七章制 Markdown」后浏览器**跳转**到了
 *   `127.0.0.1:8848/api/cmdb_scan?id=CMDB-...&md=1`，显示一整页 Markdown 源码，
 *   文件没落盘。
 *
 * 双重根因（本测试两边都钉）：
 *   ① 前端：`downloadFullMd()` 只写了 `a.href` + `target=_blank`，**没设 download**，
 *      把"下不下载"完全押在服务端响应头上了；
 *   ② 后端：`req.send(...)` 只有传 `filename=` 才会写
 *      `Content-Disposition: attachment`（core/server.py:_send），
 *      而两个 `?md=1` 导出分支只设了 `ctype="text/markdown"`、漏了 filename
 *      → 浏览器按 text/markdown **内联渲染**。
 *
 * ★ 这个坑的通用形态值得记：**`<a href>` 触发的是"导航"不是"下载"**，
 *   只有 `a.download` 或服务端 `Content-Disposition: attachment` 才是下载。
 *   少一个，用户就会离开当前页。
 *
 * 用法： node tools/_test_md_download_panel.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.dirname(__dirname);
const PANEL = fs.readFileSync(path.join(ROOT, 'modules', 'm2_enrich', 'web', 'panel.js'), 'utf8');
const BUILT = fs.readFileSync(path.join(ROOT, 'frontend', 'modules', 'm2_enrich', 'panel.js'), 'utf8');
const API = fs.readFileSync(path.join(ROOT, 'modules', 'm2_enrich', 'api.py'), 'utf8');

let PASS = 0, FAIL = 0;
function check(cond, label, extra) {
  if (cond) { PASS++; console.log('  [PASS] ' + label); }
  else { FAIL++; console.log('  [FAIL] ' + label + (extra !== undefined ? '  →  ' + extra : '')); }
}
function section(t) { console.log('\n=== ' + t + ' ==='); }

/* 切出函数源码段（indexOf + 花括号配平；★ 别用 split(sep,1)[1]，JS 的 limit 是截断） */
function fnSrc(src, name) {
  const i = src.indexOf('function ' + name + '(');
  if (i < 0) return '';
  const j = src.indexOf('{', i);
  let d = 0;
  for (let k = j; k < src.length; k++) {
    if (src[k] === '{') d++;
    else if (src[k] === '}') { d--; if (!d) return src.slice(i, k + 1); }
  }
  return '';
}

section('① 前端 downloadFullMd：走 blob 而不是裸 a.href');
const dl = fnSrc(PANEL, 'downloadFullMd');
check(dl.length > 0, '找到 downloadFullMd()');
check(/fetch\(/.test(dl), '用 fetch 取内容（不再靠浏览器导航）');
check(/\.blob\(\)/.test(dl), '取 blob');
check(/downloadBlob\(/.test(dl), '复用了已有的 downloadBlob 辅助');
check(!/target\s*=\s*'_blank'/.test(dl),
  'downloadFullMd 不再用 target=_blank（那会开新标签=导航，不是下载）');
check(/toast\(/.test(dl), '失败/成功有 toast 反馈');
/* ★ a.download 在 downloadBlob 里设置（downloadFullMd 只管取数据）。
   断言必须落在**真正设置它的那个函数**上 —— 落在 downloadFullMd 上会误判
   "没设 download"（第一版就踩了这个，把好的代码判成坏的）。 */
const dlb = fnSrc(PANEL, 'downloadBlob');
check(/a\.download\s*=/.test(dlb),
  'downloadBlob 里设了 a.download（下载的唯一前端开关）');

section('② 前端错误处理：后端出错要能读出原因');
check(/!r\.ok/.test(dl), '检查了 r.ok');
check(/j\.error|\.error/.test(dl), '尝试从 JSON 里取 error 文案（不是只报 HTTP 码）');
check(/请先完成一次 CMDB 分析|if \(!id\)/.test(dl), '没有报告 id 时明确提示，不发无意义请求');

section('③ 后端：md 导出必须走带 filename 的统一出口');
check(API.indexOf('def _md_response') >= 0, 'api.py 定义了 _md_response 单一出口');
check(API.indexOf('def _md_filename') >= 0, 'api.py 定义了 _md_filename 文件名规则');
check(/filename=/.test(API.slice(API.indexOf('def _md_response'),
                                API.indexOf('def _md_response') + 600)),
  '_md_response 里传了 filename（attachment 的唯一开关）');
/* 关键回归：不许再出现裸调 req.send(ctype="text/markdown") —— 那必然内联渲染。
   ★ 正则要**限定在单个 req.send(...) 调用内**：初版用 /req\.send\([^;]*?text\/markdown/g
   会从某处 req.send 一路吃到几十行外另一个 text/markdown，**误报 3 条**。
   改逐行扫描 + 向前回溯 3 行找配对的 req.send。
   ★ `_md_response` 自己的实现是**唯一合法**的裸调点（它就是要设 ctype），豁免。 */
const mdStart = API.indexOf('def _md_response');
const mdEnd = API.indexOf('\ndef ', mdStart + 10);
const lines = API.split('\n');
const nudeSites = [];
let off = 0;
for (let i = 0; i < lines.length; i++) {
  const lineStart = off;
  off += lines[i].length + 1;
  if (!/ctype="text\/markdown/.test(lines[i])) continue;
  if (lineStart >= mdStart && lineStart < mdEnd) continue;   // 豁免 _md_response 自身
  for (let k = i; k >= Math.max(0, i - 3); k--) {
    if (/req\.send\(/.test(lines[k])) {
      const chunk = lines.slice(k, i + 1).join('\n');
      if (!/filename\s*=/.test(chunk)) {
        nudeSites.push('L' + (k + 1) + ' ' + chunk.replace(/\s+/g, ' ').slice(0, 90));
      }
      break;
    }
  }
}
check(nudeSites.length === 0,
  '没有裸调 req.send(ctype="text/markdown") 的残留（会内联渲染不下载）', nudeSites);
const calls = API.match(/_md_response\(/g) || [];
check(calls.length >= 4, '_md_response 被调用 ≥3 处（+1 定义），实际 ' + calls.length);

section('④ 同步一致性：frontend/ 里也是修好的版本');
const builtDl = fnSrc(BUILT, 'downloadFullMd');
check(builtDl.length > 0, 'frontend/ 的 panel.js 里有 downloadFullMd（组装没漏文件）');
check(/fetch\(/.test(builtDl) && /downloadBlob\(/.test(builtDl),
  'frontend/ 的 downloadFullMd 也是 fetch + downloadBlob 版本（跑了 组装前端.py）');
check(!/target\s*=\s*'_blank'/.test(builtDl),
  'frontend/ 版本的 downloadFullMd 也不再用 target=_blank');

section('⑤ 对照组：tickets 出口一直是对的（别误伤）');
const tk = fnSrc(PANEL, 'downloadTickets');
check(tk.length > 0, '找到 downloadTickets()');
check(/cmdb_scan\/tickets/.test(tk), 'tickets 走自己的接口（服务端有 filename）');

console.log('\n结果：通过 ' + PASS + ' / 失败 ' + FAIL);
process.exit(FAIL === 0 ? 0 : 1);
