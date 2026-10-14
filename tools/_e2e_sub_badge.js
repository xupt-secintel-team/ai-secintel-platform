/* 真实 HTTP 验证：角标判据（subs=0 不显示）在真后端上的表现

   验证顺序（每步都断言 /api/subscribe 的真实返回）：
     ① 现状快照
     ② 建一个临时订阅 → 确认 subs>=1
     ③ 删掉它 → 确认 subs 回到原值
   角标本身是前端逻辑（已由 _test_sub_badge.js 覆盖），这里只保证
   「subs 字段确实会随增删变」—— 那是前端判据的事实基础。
*/
const fs = require('fs');
const http = require('http');

let PASS = 0, FAIL = 0;
function ok(cond, label, extra) {
  if (cond) { PASS++; console.log('  [PASS] ' + label); }
  else { FAIL++; console.log('  [FAIL] ' + label + (extra !== undefined ? '  → ' + extra : '')); }
}

/* 本机有 HTTP_PROXY，Node 的 http 直连不受影响，但保险起见显式禁用代理 */
function req(method, path, body) {
  return new Promise((resolve) => {
    const data = body ? Buffer.from(JSON.stringify(body), 'utf8') : null;
    const r = http.request({ host: '127.0.0.1', port: 8848, path, method,
      headers: Object.assign({}, data ? { 'Content-Type': 'application/json',
        'Content-Length': data.length } : {}) }, (res) => {
      let b = '';
      res.on('data', (c) => { b += c; });
      res.on('end', () => { try { resolve({ code: res.statusCode, body: JSON.parse(b) }); }
                             catch (e) { resolve({ code: res.statusCode, body: { raw: b.slice(0, 200) } }); } });
    });
    r.on('error', (e) => resolve({ code: 0, body: { error: String(e) } }));
    if (data) r.write(data);
    r.end();
  });
}

(async () => {
  console.log('\n=== ① 现状快照 ===');
  const s0 = await req('GET', '/api/subscribe');
  ok(s0.code === 200 && s0.body.ok, 'GET /api/subscribe 可用', 'code=' + s0.code);
  const base = s0.body.status || {};
  console.log(`      subs=${base.subs} unread=${base.unread} alerts=${base.alerts}`);
  ok(typeof base.subs === 'number', 'status.subs 是数字（前端角标判据的事实基础）',
     JSON.stringify(base));

  console.log('\n=== ② 建临时订阅 → subs 应 +1 ===');
  const add = await req('POST', '/api/subscribe', { kind: 'product', value: '__badge_probe_zzz__' });
  ok(add.code === 200 && add.body.ok, 'POST /api/subscribe 成功', JSON.stringify(add.body).slice(0, 120));
  /* 注意：POST 返回的是 {ok, sub:{id,...}} —— sub 是对象，直接 || 会拿到整个对象
     （对象永远 truthy），必须显式取 .id。用探测子串兜底，避免再次静默拿错对象。 */
  let sid = (add.body.sub && add.body.sub.id) || add.body.id || '';
  if (!sid) {
    const all = (s1.body.subs || []).filter((x) => x && String(x.value || '').indexOf('__badge_probe_zzz__') >= 0);
    if (all.length === 1) sid = all[0].id;
  }
  ok(!!sid && typeof sid === 'string', '能取到新建订阅的 id（字符串）', JSON.stringify(sid));
  const s1 = await req('GET', '/api/subscribe');
  const n1 = (s1.body.status || {}).subs;
  ok(n1 === base.subs + 1, `"subs 从 ${base.subs} 变成 ${n1}"`, n1);

  console.log(`=== ③ 删掉临时订阅 → subs 回到 ${base.subs}（此时前端应移除角标） ===`);
  if (sid) {
    const del = await req('POST', '/api/subscribe/delete', { id: sid });
    ok(del.code === 200 && del.body.ok, 'POST /api/subscribe/delete 成功', JSON.stringify(del.body).slice(0, 120));
    ok(del.body.deleted === 1, 'deleted=1（确实删掉了 1 条，不是 0）', 'deleted=' + del.body.deleted);
  } else {
    ok(false, '能从新增响应里取到订阅 id', JSON.stringify(add.body).slice(0, 160));
  }
  const s2 = await req('GET', '/api/subscribe');
  const n2 = (s2.body.status || {}).subs;
  ok(n2 === base.subs, `subs 回到 ${base.subs}`, '实际=' + n2);

  console.log('\n=== ④ 删除历史告警未被误删（角标消失不等于数据丢失） ===');
  const a1 = (s1.body.status || {}).alerts;
  const a2 = (s2.body.status || {}).alerts;
  ok(a2 === a1, `删订阅前后 alerts 条数不变（${a1} → ${a2}，历史可复盘）`, a1, a2);

  console.log('\n=== ⑤ 静态资源已带新逻辑 ===');
  const app = await new Promise((resolve) => {
    http.get({ host: '127.0.0.1', port: 8848, path: '/app.js' }, (res) => {
      let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => resolve(b));
    });
  });
  ok(/AISEC\.refreshSubBadge\s*=\s*tick/.test(app), 'app.js 已暴露 AISEC.refreshSubBadge');
  ok(/paint\(st\.unread \|\| 0, st\.subs \|\| 0\)/.test(app), 'paint 收到了 subs 参数（subs=0 时不画）');

  console.log('\n' + '='.repeat(58));
  console.log(`合计 ${PASS + FAIL} 项，通过 ${PASS}，失败 ${FAIL}`);
  process.exit(FAIL ? 1 : 0);
})();