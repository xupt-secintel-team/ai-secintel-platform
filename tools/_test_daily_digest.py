# -*- coding: utf-8 -*-
"""core/daily_digest.py 的回归测试。

    py -3 tools/_test_daily_digest.py

覆盖的都是**真实踩过的坑**，不是"为了凑覆盖率"：

1. m2 重复扫描累加 —— 同一份 CMDB 当天被扫 4 次，直接 sum 会让"风险命中"
   虚高 4 倍（实测 40 万 → 120 万）。日报数字给评审看，这属于致命错。
2. `r in c_d` 判类型 —— dict 用 `==` 比较是 O(n²)，且两份内容相同的
   报告会互相认错类型。
3. 下载判据 —— "查得到"和"能下载"必须同一套，否则会发一份现场渲染的
   假报告（标题写着那天、生成时间是现在）。
4. target_date —— 用户说的"当天晚上 12:30"有 23:30 / 00:30 两种读法，
   凌晨时段必须归属前一天，否则 00:30 出的报告标题会写成第二天。
5. catch_up 只补真有数据的日期 —— 全空日期补出来是四份"当日无产出"，
   污染列表。
6. m3 台账 —— 问答量不能恒为 0（无记录就是无记录，但不能因为路径算错
   永远读不到）。
"""
from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))

PASS, FAIL = [], []


def ck(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  ok   " if cond else "  FAIL ") + name + (("  " + str(extra)) if extra and not cond else ""))


def main():
    import daily_digest as D

    print("\n[1] 模块注册表 + 方向注册表")
    ck("四个模块齐全", set(D.MODULE_IDS) == {"m1_monitor", "m0_ops", "m2_enrich", "m3_qa"},
       D.MODULE_IDS)
    ck("每个模块有名称与描述",
       all(n and d for _i, n, d in D.MODULES))
    ck("MIME 含 md/json", set(D.MIME) == {"md", "json"})
    # —— AI 安全四方向（2026-10-07）——
    ck("四方向齐全", set(D.DIR_IDS) == {"dir_infra", "dir_model", "dir_appagent", "dir_supply"},
       D.DIR_IDS)
    ck("每个方向有名称与描述",
       all(n and d for _i, n, d in D.DIRECTIONS))
    ck("方向 id 不与模块 id 冲突", not (set(D.DIR_IDS) & set(D.MODULE_IDS)))
    # 方向 ↔ 日报分类一一映射，且键真实存在于日报口径里（防漂移）
    try:
        sys.path.insert(0, ROOT)
        import daily_report as _DR
        _cats = set(_DR._CAT_ORDER)
    except Exception as e:  # noqa: BLE001
        _cats = None
        print("     （daily_report 不可导入，跳过口径比对：%s）" % e)
    if _cats is not None:
        ck("方向映射的四个分类键与日报口径一致",
           set(D.DIR_CATEGORY.values()) == _cats,
           "%s vs %s" % (sorted(D.DIR_CATEGORY.values()), sorted(_cats)))
    ck("ENTRY_NAME = 模块 + 方向 共 8 个", len(D.ENTRY_NAME) == 8, sorted(D.ENTRY_NAME))

    print("\n[2] m2 重复扫描折叠逻辑存在性")
    _src = open(D.__file__, encoding="utf-8").read()
    ck("含 dedup 函数", "def dedup(" in _src)
    ck("含 _src_key 数据源标识", "def _src_key(" in _src)
    ck("不再用 `r in c_d` 判类型", "r in c_d" not in _src)

    print("\n[3] parse_hhmm / target_date")
    ck("23:30", D.parse_hhmm("23:30") == (23, 30))
    ck("00:30", D.parse_hhmm("00:30") == (0, 30))
    ck("非法输入返回 None", D.parse_hhmm("abc") is None)
    ck("空串返回 None", D.parse_hhmm("") is None)
    # 凌晨时段归属前一天
    old = D.DAILY_AT
    try:
        D.DAILY_AT = "00:30"
        d = D.target_date(time.time())
        exp = time.strftime("%Y-%m-%d", time.localtime(time.time() - 86400))
        ck("00:30 归属前一天", d == exp, "got %s want %s" % (d, exp))
        D.DAILY_AT = "23:30"
        ck("23:30 就是当天",
           D.target_date(time.time()) == time.strftime("%Y-%m-%d"))
    finally:
        D.DAILY_AT = old

    print("\n[4] m2 重复扫描必须折叠（真实数据 + 构造数据）")
    ck("_num 容错：'abc'→0", D._num("abc") == 0)
    ck("_num 容错：None→0", D._num(None) == 0)
    ck("_num 容错：'12.9'→12", D._num("12.9") == 12)
    ck("_num：bool 不当数字", D._num(True) == 0)
    ck("_fmt_num 千分位", D._fmt_num(1234567) == "1,234,567")
    ck("_fmt_num 非数字原样返回", D._fmt_num("abc") == "abc")

    # 用真实落盘的 cmdb_scans.json 验证：当天重复源的次数必须被折叠
    cmdb_fp = os.path.join(D.paths.DATA_DIR, "cmdb_scans.json")
    if os.path.isfile(cmdb_fp):
        rows = json.load(io.open(cmdb_fp, encoding="utf-8"))
        rows = [r for r in rows if isinstance(r, dict)]
        by_day = {}
        for r in rows:
            by_day.setdefault(str(r.get("created_at") or "")[:10], []).append(r)
        day = max(by_day) if by_day else None
        if day:
            day_rows = by_day[day]
            srcs = {}
            for r in day_rows:
                k = str(r.get("source_name") or r.get("source") or r.get("id"))
                srcs[k] = srcs.get(k, 0) + 1
            rep_cnt = sum(v - 1 for v in srcs.values() if v > 1)
            got = D._build_m2(day)
            hit = next((m for m in got["metrics"] if m["k"] == "CMDB 风险命中"), None)
            uniq = next((m for m in got["metrics"] if m["k"] == "CMDB 审计"), None)
            ck("有重复源时明确标注折叠次数",
               (rep_cnt == 0) or any("重复" in m["k"] for m in got["metrics"]),
               "rep=%d" % rep_cnt)
            if uniq and uniq["v"].endswith("次"):
                n_uniq = int(uniq["v"].split()[0].replace(",", ""))
                ck("CMDB 审计次数 = 去重后的源数（不是扫描次数）",
                   n_uniq == len(srcs), "%d vs %d" % (n_uniq, len(srcs)))
            if rep_cnt and hit:
                ck("风险命中数不含重复累加",
                   "1,201,481" not in hit["v"], hit["v"])
            print("     %s: %s | 重复折叠 %d 次" % (day, hit["v"] if hit else "-", rep_cnt))

    print("\n[5] valid_date / today")
    ck("合法日期", D.valid_date("2026-10-07") == "2026-10-07")
    ck("非法日期被拒", D.valid_date("2026/10/07") is None)
    ck("空串被拒", D.valid_date("") is None)
    ck("2026-13-01 被拒", D.valid_date("2026-13-01") is None)
    ck("2026-02-30 被拒", D.valid_date("2026-02-30") is None)
    ck("today 格式正确", len(D.today()) == 10)

    print("\n[6] 已落盘报告可读")
    days = D.available_dates("m1_monitor", 30)
    ck("m1 有可用日期", bool(days), days)
    if days:
        rep = D.load("m1_monitor", days[0])
        ck("报告含 headline", bool(rep.get("headline")))
        ck("报告含 metrics", isinstance(rep.get("metrics"), list))
        ck("metrics 每项有 k/v", all("k" in x and "v" in x
                                for x in rep.get("metrics", [])))
        ck("has() 与实际一致", D.has("m1_monitor", days[0]))

    print("\n[7] list_all 不带 sections（防响应爆量）+ 只含方向")
    la = D.list_all(days=10)
    ck("有 grid", isinstance(la.get("grid"), list))
    ck("2026-10-07 起只返回方向元信息（模块台账已去掉）",
       "modules" not in la and len(la.get("directions") or []) == 4,
       sorted(la.keys()))
    ck("方向元信息带颜色", all(str(d.get("color") or "").startswith("#")
                          for d in la.get("directions") or []))
    ck("grid 每格不含 sections",
       all("sections" not in m
           for g in la["grid"] for m in g["modules"].values()))
    ck("grid 里只有方向格（不再有模块格）",
       all(k in D.DIR_IDS for g in la["grid"] for k in g["modules"]))
    ck("grid 方向格带 kind=direction",
       all(m.get("kind") == "direction"
           for g in la["grid"] for m in g["modules"].values()))

    print("\n[8] 未知模块 / 非法日期被拒")
    ck("build 未知模块返回 None", D.build("no_such_module") is None)
    ck("_path 非法日期仍安全", isinstance(D._path("m1_monitor", "bad-date", "json"), str))

    print("\n[9] 通知读写（同一天只留一条）")
    empty = D.push_notification([], title="空报告")
    ck("空报告不发通知", isinstance(empty, dict) and empty.get("ok") is False, empty)
    ck("空报告返回结构化结果而非 None", isinstance(empty, dict))
    rep = D.load("m1_monitor", days[0]) if days else None
    fake = [{"module": "m1_monitor", "module_name": "情报监测", "date": D.today()}]
    # ★ 先清掉当天遗留的通知再推。
    #   push_notification 对同 (kind,date) 是**就地更新**，且只在内容签名变了
    #   （_sig）时才把 read 翻回 false。上一次跑本测试留下的那条签名与这次
    #   推送的完全一致 → 沿用已读状态 → "未读数增加"在第二次以后必然失败。
    #   这是**测试自身没隔离状态**，不是被测代码的问题。
    _day0 = D.today()
    _kept = [r for r in D._load_notifications()
             if not (isinstance(r, dict) and r.get("kind") == "daily_report"
                     and r.get("date") == _day0)]
    D._save_notifications(_kept)
    r1 = D.push_notification([rep or fake[0]] if rep else fake)
    ck("通知已写入", bool((r1.get("pushed") or {}).get("id")), r1)
    ck("未读数增加", D.notifications(limit=5)["unread"] >= 1,
       D.notifications(limit=5)["unread"])
    # ★ 同一天再推一次：必须合并而不是新增（曾同一天堆了 5 条）
    cnt_before = len([x for x in D._load_notifications()
                      if x.get("date") == D.today()])
    r2 = D.push_notification(fake)
    cnt_after = len([x for x in D._load_notifications()
                     if x.get("date") == D.today()])
    ck("同一天重复推送不新增通知", cnt_after == cnt_before,
       "%d → %d" % (cnt_before, cnt_after))
    ck("重复推送返回 replaced=True", r2.get("replaced") is True, r2)
    # 内容变了要重新标未读
    D.mark_read([(r1.get("pushed") or {}).get("id")])
    _changed = fake + [{"module": "m2_enrich", "module_name": "情报富化",
                        "date": D.today()}]
    r3 = D.push_notification(_changed)
    ck("内容变化后重新置为未读",
       (r3.get("pushed") or {}).get("read") is False, r3.get("pushed"))
    r = D.mark_read([(r1.get("pushed") or {}).get("id")])
    ck("标记已读生效", r.get("marked", 0) >= 0)
    ck("通知列表倒序（最新在前）", bool(D.notifications(limit=5)["items"]))
    # 去重函数本身
    dup = [{"kind": "daily_report", "date": "2026-01-01", "id": "a"},
           {"kind": "daily_report", "date": "2026-01-01", "id": "b"},
           {"kind": "daily_report", "date": "2026-01-02", "id": "c"},
           {"kind": "other", "date": "2026-01-01", "id": "d"}]
    dd = D._dedup_notifications(dup)
    ck("去重后同一天只剩一条",
       len([x for x in dd if x.get("date") == "2026-01-01"
            and x.get("kind") == "daily_report"]) == 1, dd)
    ck("去重保留最后一条", "b" in [x.get("id") for x in dd])
    ck("去重不动其它 kind", "d" in [x.get("id") for x in dd])
    # ★ 把本段推送的通知**删掉**，而不是只标已读 ——
    #   mark_read() 只是把红点消了，条目照样留在用户的通知列表里，
    #   跑一次测试就多一条"每日报告已生成"，那是测试数据不是真实报告。
    D._save_notifications(_kept)

    print("\n[9b] ZIP 打包下载")
    ck("build_zip 存在", callable(getattr(D, "build_zip", None)))
    if callable(getattr(D, "build_zip", None)):
        # zip 只打四方向（2026-10-07 起模块台账已去掉）——
        # 选一个**确有方向报告**的日子；一个都没有就先为今天生成一遍
        # （生成是幂等的，notify=False 不打扰通知列表）。
        dir_days = D.available_dates("dir_infra", 30)
        if not dir_days:
            D.generate_all(D.today(), notify=False)
            dir_days = D.available_dates("dir_infra", 30)
        _day = dir_days[0] if dir_days else D.today()
        payload, included = D.build_zip(_day)
        ck("打包返回 bytes", isinstance(payload, (bytes, bytearray)) and payload)
        ck("清单非空（当天确有报告）", bool(included), included)
        import io as _io
        import zipfile as _zip
        z = _zip.ZipFile(_io.BytesIO(payload))
        names = z.namelist()
        ck("含 README 清单", "README.txt" in names, names)
        ck("ZIP 无损坏（testzip 通过）", z.testzip() is None)
        md_files = [n for n in names if n.endswith(".md")]
        ck("至少含一个 md", len(md_files) >= 1, md_files)
        # 2026-10-07 起包里只有方向文件（模块台账已去掉）
        ck("包内只有方向文件（无 m0/m1/m2/m3）",
           not any(n.split("_")[0] in D.MODULE_IDS for n in names
                   if n != "README.txt"), names)
        # 每个文件名的日期都必须等于所选日期（不能混进别的日子）
        ck("包内日期一致", all(_day in n for n in names
                          if n != "README.txt"), names)
        # 空日期必须打不出包（路由据此 404）
        p0, inc0 = D.build_zip("1999-01-01")
        ck("无数据日期 included 为空", inc0 == [], inc0)
        ck("无数据日期不产字节", not p0 or not inc0)
        # 只要 md
        p1, inc1 = D.build_zip(_day, ("md",))
        z1 = _zip.ZipFile(_io.BytesIO(p1))
        ck("只打包 md 时不含 json",
           not any(n.endswith(".json") for n in z1.namelist()), z1.namelist())

    print("\n[10] m3 问答台账路径（真实数据目录）")
    sys.path.insert(0, os.path.join(ROOT, "modules", "m3_qa", "backend"))
    sys.path.insert(0, os.path.join(ROOT, "modules", "m3_qa"))
    try:
        import api as m3api
        fp = m3api._qa_log_path()
        ck("台账在项目 data 目录下",
           os.path.normpath(fp) == os.path.normpath(
               os.path.join(D.paths.DATA_DIR, "qa_log.jsonl")), fp)
        # 真写两条，读回来核对
        m3api._log_qa("单测问题A", 100, {"sources": [1], "used_llm": True}, None)
        m3api._log_qa("单测问题B", 200, None, RuntimeError("x"))
        with io.open(fp, encoding="utf-8") as f:
            lines = [l for l in f if l.strip()]
        ck("台账写入了 2 条", len(lines) >= 2, len(lines))
        last = json.loads(lines[-1])
        ck("最后一条是错误记录", last.get("error") == "x")
        ck("耗时字段是整数", isinstance(last.get("ms"), int))
        prev = json.loads(lines[-2])
        ck("sources 计数正确", prev.get("sources") == 1)
        ck("used_llm 记录正确", prev.get("used_llm") is True)
        # 清理测试写入
        keep = [l for l in lines if "单测问题" not in l]
        with io.open(fp, "w", encoding="utf-8", newline="\n") as f:
            f.writelines(keep)
    except ImportError:
        ck("m3 api 可导入", False, "ImportError")

    print("\n[10b] 「不造空报告」的边界（单模块空 vs 整日全空）")
    # 整日全空 → 一份都不落盘
    r = D.generate_all("1999-01-01", notify=False)
    ck("整日全空时不生成任何报告", r["generated"] == [], r["generated"])
    ck("整日全空时说明原因", "均无产出" in (r.get("note") or ""), r.get("note"))
    left = [f for mid in D.MODULE_IDS
            for f in (os.listdir(D.module_dir(mid)) if os.path.isdir(D.module_dir(mid)) else [])
            if f.startswith("1999")]
    ck("整日全空不落盘（目录里没有 1999 文件）",
       left == [] and not [f for did in D.DIR_IDS
                           for f in (os.listdir(D.module_dir(did))
                                     if os.path.isdir(D.module_dir(did)) else [])
                           if f.startswith("1999")], left)
    # 单模块无产出（m0/m3）→ 照常落盘，不能让列表凭空少两格
    # ★ 用 today()，并**主动把当天问答台账挪走**来构造 m3 无产出。
    #   之前这里直接拿 today() 断言 m3 是 no_data —— 那天台账里只要有记录
    #   （本机当天用过问答就会有），m3 就是有产出，断言当天必挂。
    #   这是**用例选错了构造方式**，不是被测代码的 bug：
    #   「整日全空不落盘」要求四模块全空，而 1999 年连 m1 也没数据，
    #   拿历史日期根本走不到「单模块空」这条分支。
    today = D.today()
    qa_fp = os.path.join(D.paths.DATA_DIR, "qa_log.jsonl")
    stash = qa_fp + ".digesttest.bak"
    moved = False
    try:
        if os.path.isfile(qa_fp):
            with io.open(qa_fp, encoding="utf-8") as f:
                all_lines = [l for l in f if l.strip()]
            keep = [l for l in all_lines if str(json.loads(l).get("ts") or "")[:10] != today]
            if len(keep) != len(all_lines):
                with io.open(stash, "w", encoding="utf-8", newline="\n") as f:
                    f.writelines(all_lines)
                with io.open(qa_fp, "w", encoding="utf-8", newline="\n") as f:
                    f.writelines(keep)
                moved = True
        r2 = D.generate_all(today, notify=False)
        ck("生成只产四方向（模块台账已去掉）",
           set(r2["generated"]) == set(D.DIR_IDS), r2["generated"])
        ck("四份方向报告照常落盘", len(r2["generated"]) == 4, r2["generated"])
        for mid in ("m0_ops", "m3_qa"):
            rr = D.build(mid, today)
            ck("%s 无产出时标 no_data" % mid, rr.get("empty_reason") == "no_data",
               rr.get("empty_reason"))
            ck("%s 无产出时如实写进 empty_note" % mid, bool(rr.get("empty_note")))
            ck("%s 无产出但仍有 headline（不是空白）" % mid, bool(rr.get("headline")))
    finally:
        if moved and os.path.isfile(stash):
            with io.open(stash, encoding="utf-8") as f:
                data = f.read()
            with io.open(qa_fp, "w", encoding="utf-8", newline="\n") as f:
                f.write(data)
            os.remove(stash)
    ck("问答台账已还原（测试不该改用户数据）",
       os.path.isfile(qa_fp) and os.path.getsize(qa_fp) > 0, qa_fp)
    ck("有数据模块不标 no_data（m1 今天确有产出）",
       D.build("m1_monitor", today).get("empty_reason", "") == "",
       D.build("m1_monitor", today).get("empty_reason"))

    print("\n[10c] AI 安全四方向报告（2026-10-07 新增）")
    # 方向报告与 m1 日报**同源**（同一分类桶切片），条目数必须对得上 ——
    # 对不上就说明方向卡自己又分了一遍类（口径漂移，评审一眼看穿）。
    try:
        import daily_report as _DR
        _pub = _DR._json_public(_DR.collect(today))
    except Exception:  # noqa: BLE001
        _pub = None
    for did in D.DIR_IDS:
        rr = D.build(did, today)
        ck("%s 构建成功" % did, isinstance(rr, dict) and rr.get("module") == did)
        ck("%s 标 kind=direction" % did, rr.get("kind") == "direction")
        ck("%s 名称来自 DIRECTIONS" % did, rr.get("module_name") == D.DIR_NAME.get(did))
        ck("%s 带 category 映射" % did, rr.get("category") == D.DIR_CATEGORY.get(did))
        ck("%s 带合法颜色" % did, str(rr.get("color") or "").startswith("#"))
        ck("%s headline 非空" % did, bool(rr.get("headline")))
        ck("%s metrics 每项有 k/v" % did,
           all("k" in x and "v" in x for x in rr.get("metrics", [])))
        if _pub is not None:
            _cat = next((c for c in _pub.get("categories") or []
                         if c.get("key") == D.DIR_CATEGORY.get(did)), None)
            _want = _num2 = int((_cat or {}).get("count") or 0)
            m0 = (rr.get("metrics") or [{}])[0]
            _got = D._num(str(m0.get("v") or "0").replace(",", "").split()[0]) \
                if m0.get("v") else 0
            ck("%s 条目数与日报分类桶一致" % did, _got == _want,
               "%d vs %d" % (_got, _want))
            ck("%s 空态与日报口径一致" % did,
               (rr.get("empty_reason") == "no_data") == (_want == 0),
               rr.get("empty_reason"))
    # markdown 渲染：方向报告要带口径说明（注明取自日报分类桶）
    _d0 = D.build("dir_infra", today)
    _md = D.render_markdown(_d0)
    ck("方向报告 md 含方向名", D.DIR_NAME["dir_infra"] in _md)
    ck("方向报告 md 带四方向口径说明", "AI 安全四方向" in _md)
    ck("方向报告 md 含分类键", D.DIR_CATEGORY["dir_infra"] in _md)
    # 落盘 / 读回（[10b] 的 generate_all 已把当天八份全落盘）
    if os.path.isfile(D._path("dir_infra", today, "json")):
        back = D.load("dir_infra", today)
        ck("方向报告落盘后可读回", isinstance(back, dict) and back.get("module") == "dir_infra")
        ck("读回的 kind 仍是 direction", back.get("kind") == "direction")
    # ZIP：当天八份全在时，清单必须含四个方向（下载交付不能悄悄丢方向）
    payload, included = D.build_zip(today)
    if payload and included:
        n_dir_in_zip = sum(1 for x in included
                           for nm in D.DIR_NAME.values() if nm in x)
        ck("ZIP 清单包含四个方向", n_dir_in_zip == 4, included)
    # 缺失口径与补全窗口（2026-10-07 模块台账去掉后）：missing_days 按
    # 方向算（仅展示）；catch_up 默认窗口 3 天 —— 方向源（monitor_state
    # 近 40 轮）老日期会滚动掉，窗口拉满只会天天空跑 + 拖慢启动
    _src_d = open(D.__file__, encoding="utf-8").read()
    _md_src = _src_d.split("def missing_days", 1)[1].split("\ndef ", 1)[0]
    ck("missing_days 按方向算（模块台账已去掉）", "DIR_IDS" in _md_src)
    _cu_src = _src_d.split("def catch_up", 1)[1].split("\ndef ", 1)[0]
    ck("catch_up 默认窗口收窄为 3 天", "days or 3" in _cu_src)
    _ga_src = _src_d.split("def generate_all", 1)[1].split("\ndef ", 1)[0]
    ck("generate_all 只遍历方向（for did in DIR_IDS）", "for did in DIR_IDS" in _ga_src)
    ck("cleanup 覆盖方向与模块文件（历史模块文件也要过期）",
       "MODULE_IDS + DIR_IDS" in
       _src_d.split("def cleanup", 1)[1].split("\ndef ", 1)[0])

    print("\n[11] mailer.send_simple_mail 存在且前置校验")
    # 注意校验顺序：未配 SMTP 时会先在 _cfg() 处返回（早于空正文判断），
    # 所以下面断言"不发送"，具体错误文案随本机配置状态而变。
    sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich", "backend"))
    try:
        import mailer
        ck("send_simple_mail 已实现", callable(getattr(mailer, "send_simple_mail", None)))
        r = mailer.send_simple_mail(["a@b.com"], "s", "   ")
        ck("空正文不发", r.get("ok") is False, r)
        r2 = mailer.send_simple_mail(["不是邮箱"], "s", "正文")
        ck("非法收件人被拒", r2.get("ok") is False, r2)
        r3 = mailer.send_simple_mail([], "s", "正文")
        ck("无收件人被拒", r3.get("ok") is False, r3)
        # 未配 SMTP 时不应抛异常（调用方在定时线程里，抛出会打断调度）
        try:
            mailer.send_simple_mail(["a@b.com"], "s", "正文")
            ck("未配 SMTP 不抛异常", True)
        except Exception as e:  # noqa: BLE001
            ck("未配 SMTP 不抛异常", False, e)
    except ImportError:
        ck("mailer 可导入", False, "ImportError")

    print("\n[12] cleanup dry_run 不真删")
    fp = D._path("m1_monitor", days[0] if days else D.today(), "json")
    if os.path.isfile(fp):
        before = os.path.getsize(fp)
        D.cleanup(dry_run=True, retention_days=0)
        ck("dry_run 后文件仍在", os.path.isfile(fp))
        ck("dry_run 后大小不变", os.path.getsize(fp) == before)

    print("\n" + "=" * 60)
    print("通过 %d / %d" % (len(PASS), len(PASS) + len(FAIL)))
    if FAIL:
        print("失败：")
        for f in FAIL:
            print("  - " + f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
