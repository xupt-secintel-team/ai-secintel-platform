/* ============================================================================
   fx.js —— v12 增量视觉层（纯加法，零业务侵入）· v2 性能修正版
   ① Three.js 3D 背景：粒子场 + 漂浮线框几何体 + 指针/滚动视差。
      three.min.js 是本地 vendor 副本（项目铁律：不引外部 CDN）。
   ② 滚动渐入：只补「本来就没有入场动画」的元素（.kpi）。
   ③ 微交互：主按钮涟漪（KPI/面板的指针跟随柔光已按用户要求删除，见文件内说明）。

   v2 修正（2026-10-10）：
   ★ 降级判据重写：旧版按「4 秒累计窗口 fps」判定，切视图的大块 innerHTML
     重绘属于主线程长任务，会把窗口 fps 拉穿阈值 → 误判「渲染太慢」→
     永久停循环（必须刷新才恢复）。现改为：
       - 逐帧 EMA（指数滑动平均）衡量稳态帧耗；
       - 单帧 >250ms 视为长任务/切页，丢弃不计；
       - 降级分级：0=全量 60fps → 1=半粒子 → 2=半粒子+隔帧(30fps 上限)；
       - 永不停止循环，且帧耗恢复后逐级回升 —— 降级是可逆的。
   ★ 渲染预算收紧：DPR ≤1.5（原 1.75）、antialias 关闭（点精灵+低透明线框
     对锯齿不敏感）、粒子上限 920→640。配合 styles.css 撤掉常驻大件的
     backdrop-filter，消除「毛玻璃每帧重采样动画画布」的合成风暴。
   ★ v3 性能收敛（2026-10-12 · 问题二「前端卡顿」，累计四轮）：
     一轮：粒子上限 640 → 320。
     二轮：DPR 1.5 → 1.25 → 1.0；渲染改为「每 2 帧一次」。
     三轮：指针跟随柔光整体删除；渲染节奏改为**按时间**节流（避免 120/144Hz
           屏白渲一倍）；新增 ?fx=off 诊断开关。
     四轮：DPR 1.0 → **0.9**；基线 30 → **24fps**（42ms），降级 16/12fps，
           滚动中仍为 ≈10fps（停滚 160ms 恢复）。
     合计把背景层每帧绘制成本压到最初的四分之一以下 —— 而它只是"氛围层"，
     粒子相位 0.12~0.42 rad/s（每帧位移约 1px），24fps 与 60fps 肉眼无从区分。
     EMA 降级/回升逻辑原样保留，并与新节奏叠加。
   ★ 浅色主题可见性：白底上亮色粒子会隐形 —— 浅色时切换为压暗色板
     （深金/深玉）、提高不透明度；线框透明度同步上调。
   不读写任何业务状态、不监听/修改任何接口数据流。
   ============================================================================ */
(function () {
  'use strict';
  if (window.__fxBooted) return;
  window.__fxBooted = true;
  document.documentElement.classList.add('fx-js');

  var RM = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ---------- ③ 微交互 ---------- */
  // 主按钮涟漪：pointerdown 在按下点扩散一圈暗金波纹（金底配墨纹，--accent-ink 同族）
  if (!RM) {
    document.addEventListener('pointerdown', function (e) {
      var b = e.target && e.target.closest ? e.target.closest('.btn.primary') : null;
      if (!b || b.disabled || b.classList.contains('loading')) return;
      var r = b.getBoundingClientRect();
      var s = document.createElement('span');
      s.className = 'fx-rip';
      s.setAttribute('aria-hidden', 'true');
      var d = Math.max(r.width, r.height) * 2.2;
      s.style.width = s.style.height = d + 'px';
      s.style.left = (e.clientX - r.left - d / 2) + 'px';
      s.style.top = (e.clientY - r.top - d / 2) + 'px';
      b.appendChild(s);
      setTimeout(function () { s.remove(); }, 660);
    }, { passive: true });
  }

  /* ---------- ③ 微交互 · 指针跟随柔光（★ v3 第三轮：整段删除） ----------
     原先在 document 上挂 pointermove，rAF 节流后对命中的 .kpi / .panel
     注入 <div class="fx-sheen">、每帧读一次 getBoundingClientRect 并写 --mx/--my。
     三笔开销：① 全局指针监听（页面任何移动都要进 closest 判定）；
     ② 每帧一次 getBoundingClientRect；③ 目标卡片每帧重绘一整块 320×240 渐变。
     这三笔换来的只是"鼠标下有一团光在跟"，视觉收益远小于成本，故删。
     （.res 上的同款柔光已在 styles.css 中一并删除。） */

  /* ---------- ② 滚动渐入（IntersectionObserver，入场后回收类名，归还 hover 过渡） ---------- */
  if (!RM && 'IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (ents) {
      ents.forEach(function (en) {
        if (!en.isIntersecting) return;
        var el = en.target;
        io.unobserve(el);
        el.classList.add('fx-in');
        // 过渡播完就摘掉 fx 类：原始 hover 过渡（如 .kpi 抬升）恢复生效
        setTimeout(function () {
          el.classList.remove('fx-pre', 'fx-in');
          el.style.removeProperty('--fxd');
        }, 950);
      });
    }, { threshold: .1, rootMargin: '0px 0px -4% 0px' });

    var seen = 0;
    function tag(el) {
      if (!el || el.nodeType !== 1 || el.__fxTagged) return;
      el.__fxTagged = 1;
      el.style.setProperty('--fxd', ((seen++ % 8) * 45) + 'ms');   // 阶梯错峰，一轮 8 拍
      el.classList.add('fx-pre');
      io.observe(el);
    }
    function scan(root) {
      if (root.matches && root.matches('.kpi')) tag(root);
      var list = root.querySelectorAll ? root.querySelectorAll('.kpi') : [];
      for (var i = 0; i < list.length; i++) tag(list[i]);
    }
    scan(document);
    // 监测台 / 富化台是数据到达后整板重绘 —— 盯住容器，给晚到的 .kpi 也补上渐入
    var mo = new MutationObserver(function (muts) {
      for (var i = 0; i < muts.length; i++) {
        var nodes = muts[i].addedNodes;
        for (var j = 0; j < nodes.length; j++) if (nodes[j].nodeType === 1) scan(nodes[j]);
      }
    });
    ['monboard', 'enrichboard'].forEach(function (id) {
      var el = document.getElementById(id);
      if (el) mo.observe(el, { childList: true, subtree: true });
    });
  }

  /* ---------- ① Three.js 3D 背景层 ---------- */
  function initGL() {
    if (RM || !window.THREE) return;
    // ★ 诊断/降级开关：网址加 ?fx=off 即可整体关闭 3D 背景层。
    // 放在创建 canvas 之前 —— 关闭时连 canvas 都不建，零残留、零开销。
    // 用途：判断"卡顿是否来自背景层"。若加上它立刻变流畅，说明瓶颈在 WebGL；
    // 若没变化，瓶颈在内容层（卡片绘制/DOM 数量），应往那个方向优化。
    if (/[?&]fx=off\b/.test(location.search)) return;

    var cv = document.createElement('canvas');
    cv.id = 'fxgl';
    cv.setAttribute('aria-hidden', 'true');
    // 插在 .backdrop 之后：网格/极光在下、粒子在上，.app 再压两者（DOM 顺序即层级）
    var bd = document.querySelector('.backdrop');
    if (bd && bd.parentNode) bd.parentNode.insertBefore(cv, bd.nextSibling);
    else document.body.appendChild(cv);

    var renderer;
    try {
      // antialias 关闭：点精灵 + 低透明线框对锯齿不敏感，省下的全屏 MSAA 很值钱
      renderer = new THREE.WebGLRenderer({ canvas: cv, alpha: true, antialias: false, powerPreference: 'low-power' });
    } catch (e) { cv.remove(); return; }
    renderer.setClearColor(0x000000, 0);

    var scene = new THREE.Scene();
    var cam = new THREE.PerspectiveCamera(58, 1, .1, 200);
    cam.position.set(0, 0, 30);

    // ★ v3 性能收敛（2026-10-12 · 二/四轮）：DPR 1.5 → 1.25 → 1.0 → **0.9**。
    // 全屏 WebGL 画布的每帧成本与像素数成正比：1920×1080 下 1.5=4.6M 像素、
    // 1.0=2.1M、0.9=1.7M。背景是"氛围层"——发光点精灵 + 低透明线框对分辨率
    // 本来就不敏感，0.9 下光点更柔和，也不会出现高 DPI 下细光点的硬边闪烁。
    var DPR = Math.min(window.devicePixelRatio || 1, 0.9);

    // —— 粒子场：金 / 玉两族，按屏幕面积定量，各自带呼吸相位 ——
    // ★ v3：上限 640 → 320（4K / 2K 屏的顶点更新量减半）。
    // 下限 200 与除数 13000 保持不变 —— 1080p 及以下的实际数量不变，视觉密度不受影响。
    var COUNT = Math.max(200, Math.min(320, Math.round(window.innerWidth * window.innerHeight / 13000)));
    if (window.innerWidth < 760) COUNT = Math.round(COUNT * .55);
    var pos = new Float32Array(COUNT * 3), col = new Float32Array(COUNT * 3),
        base = new Float32Array(COUNT * 3), ph = new Float32Array(COUNT * 2),
        tone = new Float32Array(COUNT);          // 每粒子的明暗系数，切主题时复用
    // 深色主题：亮金 / 亮玉（加法混合发光）；浅色主题：深金 / 深玉（普通混合压纸面）
    var GOLD_D = [.89, .69, .29], JADE_D = [.20, .76, .62],
        GOLD_L = [.55, .38, .10], JADE_L = [.06, .48, .38];
    var pick = new Uint8Array(COUNT);            // 0=金 1=玉
    for (var i = 0; i < COUNT; i++) {
      base[i*3]   = pos[i*3]   = (Math.random() - .5) * 96;
      base[i*3+1] = pos[i*3+1] = (Math.random() - .5) * 54;
      base[i*3+2] = pos[i*3+2] = -30 + Math.random() * 46;
      ph[i*2] = Math.random() * 6.283;
      ph[i*2+1] = .12 + Math.random() * .3;
      pick[i] = Math.random() < .68 ? 0 : 1;
      tone[i] = .45 + Math.random() * .55;
    }
    var geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    geo.setAttribute('color', new THREE.BufferAttribute(col, 3));
    var pmat = new THREE.PointsMaterial({
      size: .17, vertexColors: true, transparent: true, opacity: .5,
      depthWrite: false, blending: THREE.AdditiveBlending, sizeAttenuation: true
    });
    scene.add(new THREE.Points(geo, pmat));

    // —— 漂浮线框几何体：金（二十面体）/ 玉（八面体）/ 古铜（圆环），各一枚 ——
    function wire(g, color, opD, opL, x, y, z) {
      var m = new THREE.LineBasicMaterial({ color: color, transparent: true, opacity: opD });
      var l = new THREE.LineSegments(new THREE.EdgesGeometry(g), m);
      l.position.set(x, y, z);
      l.userData.opD = opD; l.userData.opL = opL;   // 深色/浅色两档透明度
      scene.add(l);
      return l;
    }
    var w1 = wire(new THREE.IcosahedronGeometry(6, 0), 0xe3b04b, .10, .30, -24, 9, -14);
    var w2 = wire(new THREE.OctahedronGeometry(4.4, 0), 0x2fbf9e, .09, .26, 22, -10, -10);
    var w3 = wire(new THREE.TorusGeometry(6.4, 1.7, 10, 42), 0xb8823a, .07, .22, 14, 12, -24);

    // —— 视差：指针 + 工作区滚动，全部缓动跟随（不跟手，跟"势"） ——
    var tx = 0, ty = 0, cx = 0, cy = 0, ts = 0, cs = 0;
    var lastScrollAt = -1e9;   // ★ v3：最近一次工作区滚动的时间戳，用于滚动中给渲染降频
    addEventListener('pointermove', function (e) {
      tx = (e.clientX / window.innerWidth - .5) * 2;
      ty = (e.clientY / window.innerHeight - .5) * 2;
    }, { passive: true });
    var ws = document.getElementById('workspace');
    if (ws) ws.addEventListener('scroll', function () {
      ts = Math.min(ws.scrollTop / 900, 1.6);
      lastScrollAt = performance.now();
    }, { passive: true });

    function size() {
      renderer.setPixelRatio(DPR);
      renderer.setSize(window.innerWidth, window.innerHeight, false);
      cam.aspect = window.innerWidth / window.innerHeight;
      cam.updateProjectionMatrix();
    }
    size();
    addEventListener('resize', size, { passive: true });

    // —— 主题跟随：浅色下粒子换压暗色板 + 普通混合（白底上加法混合会直接消失） ——
    function theme() {
      var light = document.documentElement.getAttribute('data-theme') === 'light';
      var G = light ? GOLD_L : GOLD_D, J = light ? JADE_L : JADE_D;
      for (var i = 0; i < COUNT; i++) {
        var c = pick[i] ? J : G, k = tone[i];
        col[i*3] = c[0] * k; col[i*3+1] = c[1] * k; col[i*3+2] = c[2] * k;
      }
      geo.attributes.color.needsUpdate = true;
      pmat.blending = light ? THREE.NormalBlending : THREE.AdditiveBlending;
      pmat.opacity = light ? .62 : .5;
      pmat.needsUpdate = true;
      [w1, w2, w3].forEach(function (w) {
        w.material.opacity = light ? w.userData.opL : w.userData.opD;
      });
    }
    theme();
    new MutationObserver(theme).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    // —— 主循环 + 可逆降级 ——
    // ema：稳态帧耗（指数滑动平均）；>250ms 的单帧是长任务/切页，丢弃不计，
    // 否则切视图的大块重绘会被误判为「渲染太慢」（v1 卡死的根因）。
    var running = true, t0 = performance.now(), lastT = 0, active = COUNT;
    var ema = 16.7, prevNow = 0, slowMs = 0, goodMs = 0, degraded = 0, frameNo = 0;
    var lastRenderAt = 0;   // ★ v3：最近一次真正渲染的时间戳（按时间节流，见主循环）

    // 探针：自动化点检读取（不暴露任何业务数据）。
    // 控制台输入 __fxStats 即可看到实际渲染帧数、降级等级、帧耗 EMA 与当前渲染间隔(ms)。
    window.__fxStats = { frames: 0, degraded: 0, ema: 16.7, iv: 42 };

    function applyLevel(lv) {
      degraded = lv;
      active = lv === 0 ? COUNT : Math.floor(COUNT / 2);
      geo.setDrawRange(0, active);
      window.__fxStats.degraded = lv;
    }

    document.addEventListener('visibilitychange', function () {
      running = !document.hidden;
      if (running) { t0 = performance.now() - lastT; prevNow = 0; requestAnimationFrame(tick); }
    });

    function tick(now) {
      if (!running) return;
      lastT = now - t0;
      var t = lastT / 1000;

      // —— 帧耗统计与分级 ——
      if (prevNow) {
        var dt = now - prevNow;
        if (dt < 250) {                          // 正常帧：并入 EMA
          ema = ema * .92 + dt * .08;
          if (ema > 21 && degraded < 2) {        // 稳态低于 ~48fps：持续 2.5s 才降级
            slowMs += dt; goodMs = 0;
            if (slowMs > 2500) { applyLevel(degraded + 1); slowMs = 0; }
          } else if (ema < 17.5 && degraded > 0) { // 稳态回到 ~57fps+：持续 4s 回升一级
            goodMs += dt; slowMs = 0;
            if (goodMs > 4000) { applyLevel(degraded - 1); goodMs = 0; }
          } else { slowMs = 0; goodMs = 0; }
        }
        // dt >= 250：主线程长任务（切视图/数据重绘）或后台切页，整帧丢弃
      }
      prevNow = now;
      frameNo++;

      // —— 渲染节奏（★ v3 三轮：改为**按时间**节流）——
      // 按帧数节流（frameNo % N）在 120/144Hz 屏上会白白多渲一倍；
      // 按时间节流则让任何刷新率的机器都锁定同一个渲染频率。
      // 背景粒子相位只有 0.12~0.42 rad/s（每帧位移约 1px），24fps 与 60fps 无从区分。
      // 滚动进行中再压到 ≈10fps —— 此时视线在内容上，把 GPU 让给滚动本身；
      // 停止滚动 160ms 后自动恢复。降级等级在此基线上继续降频。循环永不停止。
      var iv = degraded >= 2 ? 80 : (degraded >= 1 ? 60 : 42);   // 12 / 16 / 24 fps
      if (now - lastScrollAt < 160) iv = Math.max(iv, 100);      // 滚动中 ≈10fps
      window.__fxStats.iv = iv;
      if (now - lastRenderAt >= iv) {
        lastRenderAt = now;
        var p = geo.attributes.position.array;
        for (var i = 0; i < active; i++) {
          p[i*3]   = base[i*3]   + Math.sin(t * ph[i*2+1] + ph[i*2]) * 1.5;
          p[i*3+1] = base[i*3+1] + Math.cos(t * ph[i*2+1] * .8 + ph[i*2]) * 1.1;
        }
        geo.attributes.position.needsUpdate = true;

        w1.rotation.x = t * .07; w1.rotation.y = t * .10;
        w2.rotation.y = t * .12; w2.rotation.z = t * .05;
        w3.rotation.x = t * .05; w3.rotation.y = t * .08;
        w1.position.y = 9   + Math.sin(t * .40) * 1.6;
        w2.position.y = -10 + Math.cos(t * .33) * 1.4;
        w3.position.y = 12  + Math.sin(t * .27 + 2) * 1.8;

        cx += (tx - cx) * .03; cy += (ty - cy) * .03; cs += (ts - cs) * .04;
        cam.position.x = cx * 2.4;
        cam.position.y = -cy * 1.6 + cs * 2.2;
        cam.lookAt(0, cs * 1.4, -6);

        renderer.render(scene, cam);
        window.__fxStats.frames++;
        window.__fxStats.ema = Math.round(ema * 10) / 10;
      }
      requestAnimationFrame(tick);
    }
    // 先渲一帧再淡入（CSS 过渡 1.6s），避免粒子"凭空闪现"
    renderer.render(scene, cam);
    requestAnimationFrame(function () { cv.classList.add('on'); });
    requestAnimationFrame(tick);
  }

  if (document.readyState === 'loading') addEventListener('DOMContentLoaded', initGL);
  else initGL();
})();
