/* 临时预览脚本：把 ACMDB 的数据库面板单独导出成 HTML，用于人工核对布局 */
const fs = require('fs');
const vm = require('vm');
const path = require('path');

const ROOT = path.dirname(__dirname);
const CODE = fs.readFileSync(path.join(ROOT, 'modules', 'm2_enrich', 'web', 'panel.js'), 'utf8');
const CSS = fs.readFileSync(path.join(ROOT, 'modules', 'm2_enrich', 'web', 'panel.css'), 'utf8');

global.$ = () => null;
global.esc = (s) => String(s == null ? '' : s);
global.link = (u) => u;
global.openDetail = () => {};
global.toast = () => {};
global.location = { origin: 'http://127.0.0.1:8848' };
global.navigator = {};
global.AISEC = { register(m) { global.__m = m; } };
vm.runInThisContext(CODE);

const sec = global.__m.enrichSections().find((s) => s.id === 'enCmdb');
let h = sec.html;
// 只留数据库面板
h = h.replace(/id="cmPane-(rest|inline|file)"[^>]*>/g, 'id="hid" style="display:none">');
// 把数据库面板显示出来 + tab 高亮（真实运行时由 switchMode 做，这里预览要手动摆好）
h = h.replace('id="cmPane-sqlite" style="display:none"', 'id="cmPane-sqlite" style="display:block"');
h = h.replace('data-mode="sqlite">数据库文件', 'data-mode="sqlite" class="cm-tab on">数据库文件');
// 预置几个已选文件 + 高亮拖拽态，看看真实使用时的样子
h = h.replace('<div id="cmDbList" class="cm-files" style="display:none;flex:1 1 auto"></div>',
  '<div id="cmDbList" class="cm-files" style="flex:1 1 auto">'
  + '<div class="cm-file-i"><span class="n">01_ledger.db</span><span class="s">8.0 KB</span><button class="x">×</button></div>'
  + '<div class="cm-file-i"><span class="n">02_asset.db</span><span class="s">12.0 KB</span><button class="x">×</button></div>'
  + '<div class="cm-file-i"><span class="n">03_idc.db</span><span class="s">8.0 KB</span><button class="x">×</button></div>'
  + '<div class="meta-note" style="margin-top:4px">共 3 个数据库，分析时合并为一份报告</div></div>');
h = h.replace('class="cm-drop" id="cmDbDrop"', 'class="cm-drop drag" id="cmDbDrop"');
h = h.replace('id="cmDbClear" style="flex:none;display:none"', 'id="cmDbClear" style="flex:none"');

const base = '<!doctype html><meta charset="utf-8"><title>CMDB 数据库上传面板</title><style>'
  + CSS
  + 'body{background:#0e1116;padding:24px;font-family:"Microsoft YaHei",sans-serif;'
  + '--surface-1:rgba(255,255,255,.03);--surface-2:rgba(255,255,255,.07);'
  + '--line-1:rgba(255,255,255,.16);--line-2:rgba(255,255,255,.10);--line-3:rgba(255,255,255,.18);'
  + '--txt:#e8eaed;--txt-1:#e8eaed;--txt-2:#c2c6cc;--txt-3:#8a8f98;--txt-4:#6b7078;'
  + '--accent:#5b8def;--accent-2:#7aa2f7;--accent-soft:rgba(91,141,239,.10);--accent-line:rgba(91,141,239,.55)}'
  + '.panel{background:#151a21;border:1px solid rgba(255,255,255,.08);border-radius:12px;'
  + 'padding:14px;max-width:940px;margin:0 auto}'
  + '.en-scan-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:12px}'
  + '.en-scan-ttl{display:flex;flex-wrap:wrap;gap:8px;align-items:center;font-size:14px;color:var(--txt-1)}'
  + '.en-scan-ops{display:flex;gap:8px}'
  + '.chip{font-size:11px;padding:2px 8px;border-radius:999px;border:1px solid var(--line-2);color:var(--txt-3)}'
  + '.chip.trust{border-color:rgba(91,141,239,.4);color:#9dbaf5}'
  + '.btn{font-size:12px;padding:6px 14px;border-radius:8px;border:1px solid var(--line-2);'
  + 'background:var(--surface-2);color:var(--txt-1);cursor:pointer}'
  + '.btn.ghost{background:transparent}.btn.sm{padding:4px 11px;font-size:11.5px}'
  + '.as-in{width:100%;box-sizing:border-box;padding:9px 11px;border-radius:9px;'
  + 'border:1px solid var(--line-2);background:var(--surface-1);color:var(--txt-1);font-size:12.5px}'
  + '.asub-kevline{display:flex;gap:7px;align-items:center;font-size:12px;color:var(--txt-3);margin-top:10px}'
  + '.meta-note{font-size:11.5px;color:var(--txt-4);line-height:1.7}'
  + '</style>' + h;

fs.writeFileSync('C:/temp/cmdbpane.html', base, 'utf8');
console.log('written C:/temp/cmdbpane.html');
