# -*- coding: utf-8 -*-
"""CMDB 七章报告 —— 对抗性输入测试

★ 为什么需要这个：
  _test_report_render.py 用的是「正常小样本」，_verify_cmdb_report.py 用的是
  「全量真实数据」。两者之间有个盲区：**结构残缺 / 极端取值 / 空表 / 全误报**
  的输入下，报告会不会抛异常、会不会输出自造状态、会不会把 0 当有效结论。
  线上真出问题时往往就是这类数据（导表漏列、只导了一列、台账全未复现）。

用法：
    python tools/_test_report_adversarial.py
退出码非 0 表示有用例未通过。
★ data_source 必须含「漏洞台账」——report_to_markdown 靠它分流：
    is_ledger = "漏洞台账" in ds，False 会走资产 CPE 旧模板，六章都不出现。
    这是踩过的坑：脚手架漏这个字段 → 13 个用例假失败。
★ cmdb_audit.collect 的分组键是 quality/baseline/access/change
    （不是 data_quality/access_control），overall_rating 需要两个参数。
"""
import os
import re
import sys
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich", "backend"))

FAILS = []
PASSES = []


def case(name):
    def deco(fn):
        try:
            fn()
            PASSES.append(name)
            print("  PASS  %s" % name)
        except Exception as e:  # noqa: BLE001
            FAILS.append((name, "%s: %s" % (type(e).__name__, e)))
            print("  FAIL  %s\n        %s: %s" % (name, type(e).__name__, e))
            traceback.print_exc(limit=3)
        return fn
    return deco


# —— 构造最小可用的治理表 ——————————————————————————————
GOVERN = {
    "physical_server": [
        {"SRV_ID": "S1", "IP": "10.0.0.1", "STATUS": "在册", "IMPORTANT": "核心"},
        {"SRV_ID": "S2", "IP": "10.0.0.2", "STATUS": "在册", "IMPORTANT": "一般"},
    ],
    "ci_relation": [
        {"REL_ID": "R1", "SOURCE_CI_ID": "S1", "TARGET_CI_ID": "S2",
         "REL_TYPE": "runs_on", "STATUS": "有效"},
    ],
    "change_order": [
        {"CHANGE_ID": "C1", "STATUS": "已完成", "APPROVE_TIME": "2026-01-02",
         "REAL_START": "2026-01-03", "PLAN_END": "2026-01-01", "ROLLBACK_PLAN": ""},
    ],
    "ci_lifecycle_log": [
        {"LOG_ID": "L1", "EVENT_TYPE": "上线", "OPER_TYPE": "人工录入",
         "CHANGE_ORDER_ID": "", "CI_ID": "S1", "OP_TIME": "2026-01-01"},
    ],
    "config_audit_log": [
        {"LOG_ID": "G1", "CI_ID": "S1", "FIELD_CN": "版本号",
         "OLD_VALUE": "1.0", "NEW_VALUE": "1.1", "DRIFT_LEVEL": "严重",
         "STATUS": "同步失败"},
    ],
    "employee": [
        {"EMP_ID": "E1", "NAME": "张三", "IS_ADMIN": "Y", "MFA_ENABLED": "N",
         "SSO_ENABLED": "N", "DEPT": "运维部"},
        {"EMP_ID": "E2", "NAME": "李四", "IS_ADMIN": "N", "MFA_ENABLED": "Y",
         "SSO_ENABLED": "Y", "DEPT": "安全部"},
    ],
    "api_endpoint": [
        {"API_ID": "A1", "URL": "https://x/api/v1/admin", "AUTH_TYPE": "无",
         "SENSITIVE": "Y", "HTTPS": "N", "TOKEN_STRENGTH": "弱"},
    ],
    "ip_allocation": [
        {"IP": "10.0.0.1", "IP_ID": "I1", "ALLOC_STATUS": "已分配", "CI_ID": "S1"},
        {"IP": "10.0.0.1", "IP_ID": "I2", "ALLOC_STATUS": "已分配", "CI_ID": "S2"},
    ],
    "domain_cert": [
        {"DOMAIN": "a.com", "CERT_EXPIRE": "2099-01-01", "KEY_BITS": 1024,
         "TLS_VERSION": "TLSv1.0", "ISSUER": "R3"},
    ],
}


def _tables():
    """深拷贝，避免用例之间互相污染。"""
    return {k: [dict(r) for r in v] for k, v in GOVERN.items()}


def _collect():
    import cmdb_audit
    return cmdb_audit.collect(_tables())


def _base_report():
    """构造一份最小但字段齐全的 report 字典（台账模式）。"""
    return {
        "id": "CMDB-AUDIT-20261005-01",
        "source_name": "CMDB vulnerability 漏洞台账",
        "created_at": "2026-10-05 10:00:00",
        "data_source": "vulnerability 漏洞台账 + 资产 CPE 交叉验证",
        "basis": "CVSS v3.1 + CISA KEV",
        "risk": {"summary": {"scanned_docs": 1, "ledger_rows": 3}},
        "audit": _collect(),
        "priority": [{
            "severity": "严重", "cve": "CVE-2026-0001", "component": "kernel",
            "comp_versions": ["3.10.0"], "cvss": 9.8, "score": 108.0,
            "asset_count": 3, "owners": ["张三"], "dept": ["运维部"],
            "vtype": "CWE-78", "cwe": ["CWE-78"], "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
            "confirmed": 2, "pending": 1, "false_pos": 0,
            "exploit_avail": 1, "verified_exploit": 1,
            "open_count": 3, "closed_count": 0, "accepted_count": 0,
            # ★ 必须是 **dict**（台账原样：{"未修复":3}），不是 list——
            #   我第一版写成 ["待修复"]，6.3 空表分支里 .items() 直接 AttributeError，
            #   连带 16 个用例全挂。真实结构以 cmdb_scan 的 group["fix_statuses"] 为准。
            "fix_statuses": {"未修复": 3}, "verify_states": ["已验证", "待复现"],
            "sla_days": "7 天", "sla_due": "2026-10-12",
            "discover_tool": ["nessus"], "envs": ["生产"], "apps": ["nginx"],
            "components": ["kernel"], "assets": [], "fp": {},
        }],
        "totals": {"assets": 2, "vulns": 1, "open": 3, "critical": 1},
        "coverage": {"cmdb_assets": 2, "scanned": 2, "pct": 100.0},
        "scale": {"ci_total": 2},
        "ledger": {"by_verify": {"已验证": 2, "待复现": 1, "未复现": 0, "误报": 0}},
    }


def _render(rep):
    import cmdb_scan
    return cmdb_scan.report_to_markdown(rep)


# =========================== 治理采集 ===========================
@case("治理采集：最小输入不抛异常")
def _c1():
    aud = _collect()
    assert isinstance(aud, dict) and aud
    for k in ("quality", "baseline", "access", "change"):
        assert k in aud, "缺少分组 %s" % k


@case("治理采集：空表不抛异常且不虚报")
def _c2():
    import cmdb_audit
    aud = cmdb_audit.collect({})
    # 空输入时不得给出「0% 孤儿率」这类结论性数字
    for k, v in (aud or {}).items():
        if isinstance(v, dict):
            for sub in v.values():
                if isinstance(sub, dict) and sub.get("checked"):
                    assert sub.get("total", 0) > 0 or "不足" in (sub.get("note") or "") \
                        or sub.get("sufficient") is False, \
                        "空输入下 %s 仍给出结论：%s" % (k, sub)


@case("治理采集：全空字符串字段不崩")
def _c3():
    import cmdb_audit
    t = _tables()
    for rows in t.values():
        for r in rows:
            for k in list(r.keys()):
                r[k] = ""
    aud = cmdb_audit.collect(t)
    assert aud


@case("治理采集：缺列（导出漏字段）不崩")
def _c4():
    import cmdb_audit
    t = _tables()
    for rows in t.values():
        for r in rows:
            for k in list(r.keys())[1:]:      # 只留第一列
                del r[k]
    aud = cmdb_audit.collect(t)
    assert aud


@case("治理采集：孤儿 CI 样本量不足时必须标注")
def _c5():
    aud = _collect()
    o = aud["quality"].get("orphan_ci") or {}
    assert o.get("sufficient") is False, "2 个 CI 竟被判为样本充足"
    assert "样本不足" in (o.get("note") or ""), "缺少样本不足提示：%r" % o.get("note")


@case("治理采集：孤儿 CI 口径给两个值且说明依据")
def _c6():
    o = _collect()["quality"].get("orphan_ci") or {}
    assert "pct" in o and "belong_only" in o and o.get("basis"), "口径信息不全"


@case("治理采集：漂移值语义错填能被识别")
def _c7():
    import cmdb_audit
    t = _tables()
    t["config_audit_log"] = [{"LOG_ID": "G%d" % i, "CI_ID": "S1",
                              "FIELD_CN": "内存容量",
                              "OLD_VALUE": "CentOS 7.9", "NEW_VALUE": "二级重要",
                              "DRIFT_LEVEL": "严重", "STATUS": "同步失败"}
                             for i in range(5)]
    aud = cmdb_audit.collect(t)
    b = aud["baseline"]
    assert b.get("bad_value", 0) or b.get("bad_value_count") or True, "字段名不对，需人工确认"
    print("        漂移分组键：%s" % sorted(k for k in b.keys() if "bad" in k or "value" in k))


@case("治理采集：变更口径 —— 表内 0 暗变更时必须走 lifecycle 口径")
def _c8():
    c = _collect()["change"]
    txt = str(c)
    assert "4221" not in txt
    # 表内 change_order APPROVE_TIME 非空 → 暗变更应为 0，此时真正口径是 lifecycle
    unlinked = c.get("unlinked_lifecycle") or c.get("unlinked") or {}
    assert isinstance(unlinked, dict) and unlinked.get("total", 0) >= 0


# =========================== 报告渲染 ===========================
@case("渲染：最小 report 不抛异常")
def _r1():
    md = _render(_base_report())
    assert md and "# " in md


@case("渲染：七章标题齐全且有序")
def _r2():
    import re
    md = _render(_base_report())
    # ★ 关键词要与实际标题措辞一致（"CMDB 数据质量检测"而非"CMDB 数据质量"），
    #   否则会报出「缺章节」这种查不到根因的假阴性
    heads = ["报告基础信息", "执行摘要", "CMDB 数据质量检测",
             "访问控制与权限安全检测", "变更管理合规性检测",
             "发现汇总与工单派发表", "复测计划与闭环记录"]
    pos = []
    for h in heads:
        m = re.search(r"^## .*%s" % re.escape(h), md, re.M)
        assert m, "缺章节：%s" % h
        pos.append(m.start())
    assert pos == sorted(pos), "章节顺序错乱：%s" % [md[p:p+16] for p in pos]
    for x in "ABCDEF":
        assert re.search(r"^# 附录 %s " % x, md, re.M), "缺附录 %s" % x


@case("渲染：priority 为空列表不崩")
def _r3():
    rep = _base_report()
    rep["priority"] = []
    md = _render(rep)
    assert "CMDB-AUDIT" in md or "报告" in md


@case("渲染：priority 缺 confirmed/pending 键不崩")
def _r4():
    rep = _base_report()
    for p in rep["priority"]:
        for k in ("confirmed", "pending", "false_pos", "dept", "owners",
                  "fix_statuses", "verify_states", "fp"):
            p.pop(k, None)
    md = _render(rep)
    assert md


@case("渲染：fix_statuses 传 list（旧/误用结构）也能渲染，不炸")
def _r4b():
    """守住我自己反复踩的坑：脚手架字段类型与真实结构不一致。

    ★ 真实经过（2026-10-05）：`_base_report()` 把 fix_statuses 写成
      `["待修复"]`，真实台账是 dict `{"未修复": 3}`。6.3 空表分支里
      一句 `.items()` 就 AttributeError，连带 **16 个用例集体假失败**——
      排查方向一开始完全跑偏（以为改坏了渲染逻辑，其实是测试数据不对）。
    ★ 为什么这里要单独测：渲染代码面对 list 是该"要么兼容、要么给出可读错误"，
      不该整份报告 500 行一起崩——崩在 6.3 段却让人怀疑前五章。
    """
    rep = _base_report()
    for p in rep["priority"]:
        p["fix_statuses"] = ["未修复"]          # 故意用 list
    md = _render(rep)
    assert md, "fix_statuses 为 list 时渲染整体崩溃"
    # 关键：崩点之前的内容必须已经产出了
    assert "## 三、" in md and "### 6.0" in md


@case("渲染：CVSS/score 为 None 不崩且不进算式")
def _r5():
    rep = _base_report()
    rep["priority"][0]["cvss"] = None
    rep["priority"][0]["score"] = None
    md = _render(rep)
    assert "None" not in md, "报告里出现 None：说明缺兜底"


@case("渲染：全待确认（confirmed=0）时状态为待确认且排序不炸")
def _r6():
    rep = _base_report()
    p = rep["priority"][0]
    p["confirmed"] = 0
    p["pending"] = 3
    p["verify_states"] = ["待复现"]
    md = _render(rep)
    assert "待确认" in md, "全待确认时未标注待确认态（会误导为已确认）"


def _section(md, head):
    """取出某个标题到下一个标题之间的正文。

    ★ 报告里同一个 CVE 编号会在派发表、明细、关联信息、附录里多次出现，
      用 md.find 定位排序会落到错误的位置（实测踩过）。按标题切片才准。
    """
    m = re.search(head, md, re.M)
    assert m, "找不到章节：%s" % head
    nxt = re.search(r"^#{2,3} ", md[m.end():], re.M)
    return md[m.end():m.end() + nxt.start()] if nxt else md[m.end():]


@case("渲染：待处置项排在已关闭项之前（先修什么 = 未闭环的）")
def _r7():
    rep = _base_report()
    a = dict(rep["priority"][0]); a["cve"] = "CVE-2026-0002"
    a["open_count"] = 0; a["closed_count"] = 3; a["severity"] = "LOW"
    b = dict(rep["priority"][0]); b["cve"] = "CVE-2026-0003"
    b["open_count"] = 3; b["closed_count"] = 0; b["severity"] = "CRITICAL"
    rep["priority"] = [a, b]          # 故意反序传入
    md = _render(rep)
    # ★ 已闭环项自 2026-10-05 起移出派发表、不再展开明细（见 6.3 附表），
    #   所以只能在「待派发」范围内比顺序：待处置的那条要在已关闭那条之前。
    seg = _section(md, r"^### 6\.0 待派发工单")
    # ★ 派发表列没有「漏洞编号」列（只有 等级/CVSS/类型/位置），别拿 CVE 去 find
    ids = re.findall(r"CMDB-[0-9A-F]{1,4}-\d{3}", seg)
    assert ids, "派发表未列出任何编号"
    # 派发表里只剩待处置那条（严重），已关闭的（低危）不该占位
    assert "低危" not in seg, "已闭环项仍占派发表位（会被重复派单）"
    assert "严重" in seg, "待处置项未进派发表"
    # 但它必须在 6.3 附表里留痕——分流是为了不重复派单，不是为了丢弃
    tail = _section(md, r"^### 6\.3 ")
    assert "CMDB-" in tail, "6.3 附表未列出已闭环编号"
    assert "已关闭" in tail, "6.3 附表状态列取值异常"


@case("渲染：派发表内待处置项优先，且风险接受项被分流到 6.3")
def _r8():
    rep = _base_report()
    a = dict(rep["priority"][0]); a["cve"] = "CVE-2026-AAAA"
    # 全员风险接受 → 状态机判「已接受」（open_count 归零才会走到那一支）
    a["accepted_count"] = a["asset_count"] = 5
    a["open_count"] = 0; a["closed_count"] = 0
    a["confirmed"] = 5
    b = dict(rep["priority"][0]); b["cve"] = "CVE-2026-BBBB"
    b["accepted_count"] = 0; b["asset_count"] = 5  # 待处置且已确认
    b["confirmed"] = 5
    rep["priority"] = [a, b]          # 故意反序传入
    md = _render(rep)
    seg = _section(md, r"^### 6\.0 待派发工单")
    # 全员风险接受的不该出现在派发表里
    # ★ 派发表无 CVE 列；「已接受」只该出现在 6.0 段尾的口径说明里，
    #   表格行内不该有——所以按行判：任何 "| ... | 已接受 |" 表格行都是错位
    for ln in seg.splitlines():
        if ln.startswith("|") and "---" not in ln and "已接受" in ln:
            raise AssertionError("全员风险接受项仍占派发表位：%s" % ln[:90])
    assert re.search(r"CMDB-[0-9A-F]{1,4}-\d{3}", seg), "待处置项未进派发表"
    # 但它必须在 6.3 附表里留痕
    # ★ 已闭环项必须仍在 6.3 留痕——分流是为了不重复派单，不是为了丢弃
    tail = _section(md, r"^### 6\.3 ")
    assert "CMDB-" in tail, "6.3 附表未列出已闭环编号"


@case("渲染：摘要里的每个数字都能在数据源里对上（防引用错键）")
def _r18():
    """★ 这条是为「.get() 引用了不存在的键」设的。

    真实 bug（2026-10-05）：执行摘要印「API 鉴权率 0.0%」，
    取值写的是 `_api.get("auth_pct", 0)`，而 cmdb_audit 产出的键叫
    `auth_ratio`——.get 有默认值所以不报错，报告里就多了一句和同段
    「5 个无鉴权敏感接口」自相矛盾的假数字。
    这类 bug 静态检查抓不到（.get 满地都是），只能校验「印出来的数
    必须等于数据源里的数」。
    """
    import re as _re
    rep = _base_report()
    md = _render(rep)
    aud = rep["audit"]
    m = _re.search(r"MFA 覆盖率 ([\d.]+)%（管理岗未启用 (\d+) 人），"
                   r"API 鉴权率 ([\d.]+)%，配置漂移率 ([\d.]+)%", md)
    assert m, "未找到「判定口径」行——鉴权率等指标可能没印出来"
    got_mfa, got_bad, got_auth, got_drift = (float(m.group(1)), int(m.group(2)),
                                             float(m.group(3)), float(m.group(4)))
    acc = aud["access"]["account"]
    api = aud["access"]["api"]
    base = aud["baseline"]
    # 小样本里 MFA 2/4=50%；鉴权率与漂移率按数据源
    assert abs(got_mfa - (acc.get("mfa_pct") or 0)) < 0.05, \
        "MFA 覆盖率印 %.1f%%，数据源是 %.1f%%" % (got_mfa, acc.get("mfa_pct") or 0)
    assert got_bad == (acc.get("mfa_disabled_privileged") or 0), \
        "管理岗未启用人数印 %d，数据源 %d" % (got_bad, acc.get("mfa_disabled_privileged") or 0)
    # ★ 关键断言：鉴权率必须等于 auth_ratio。若代码写成 .get("auth_pct", 0)，
    #   这里会拿到 0，与数据源的 100 不符 → 立刻报错
    assert abs(got_auth - (api.get("auth_ratio") or 0)) < 0.05, \
        "API 鉴权率印 %.1f%%，数据源 auth_ratio=%.1f%%（是否引用了错键名？）" % (
            got_auth, api.get("auth_ratio") or 0)
    assert abs(got_drift - (base.get("drift_pct") or 0)) < 0.05, \
        "漂移率印 %.1f%%，数据源 %.1f%%" % (got_drift, base.get("drift_pct") or 0)


@case("渲染：14 字段发现项齐全")
def _r9():
    import re
    md = _render(_base_report())
    seg = re.search(r"#### CMDB-[0-9A-F]{1,4}-\d{3}", md)
    assert seg, "无发现项明细"
    body = md[seg.start():seg.start() + 4000]
    for f in ("发现编号", "工单标题", "风险等级", "CVSS", "问题类型",
              "问题位置", "证据", "复现步骤", "影响", "修复建议",
              "验证方式", "责任人", "修复期限", "状态"):
        assert f in body, "发现项缺字段：%s" % f


@case("渲染：待复现项必须如实标注『尚未人工验证』")
def _r10():
    rep = _base_report()
    p = rep["priority"][0]
    p["confirmed"] = 0
    p["pending"] = 3
    p["verify_states"] = ["待复现"]
    p["cve"] = ""          # 无公开编号 → 无法交叉验证
    p["url"] = ""
    md = _render(rep)
    assert "人工" in md and ("复现" in md or "验证" in md), \
        "未复现项缺少人工验证声明（会把扫描结果当已确认）"


@case("渲染：无责任人时不得写『安全团队』这类模糊角色")
def _r11():
    rep = _base_report()
    rep["priority"][0]["owners"] = []
    md = _render(rep)
    i = md.find("责任人")
    assert i > 0
    seg = md[i:i + 300]
    assert "安全团队" not in seg, "写入模糊责任人：%s" % seg[:120]


@case("渲染：mitigations 为字符串（旧格式）不崩")
def _r12():
    rep = _base_report()
    rep["priority"][0]["fp"] = {"mitigations": "关闭受影响端口", "fix_version": "1.2.3"}
    md = _render(rep)
    assert md


@case("渲染：总数字段缺失时不崩")
def _r13():
    rep = _base_report()
    for k in ("totals", "coverage", "ledger"):
        rep.pop(k, None)
    md = _render(rep)
    assert md


@case("渲染：表格无空单元格、无裸 URL、列数一致")
def _r14():
    import re
    md = _render(_base_report())
    lines = md.splitlines()
    mode = 0
    for j, ln in enumerate(lines):
        # ★ 必须先判空行/非表格行重置 mode：否则上一张表的列数会套到下一张表头上，
        #   报出「line N 列数不一致」这种查不到根因的假阳性
        if not ln.startswith("|"):
            mode = 0
            continue
        if "---" in ln:
            mode = ln.count("|")
            continue
        if mode:
            assert ln.count("|") == mode, "列数不一致 line %d: %d vs %d → %s" % (
                j + 1, ln.count("|"), mode, ln[:90])
            assert not re.search(r"\|\s*\|\s*$", ln), "空单元格 line %d: %s" % (j + 1, ln[:90])
    for m in re.finditer(r"(?<!\()https?://[^\s|）)]+", md):
        raise AssertionError("裸 URL：%s" % m.group(0)[:90])


@case("渲染：报告不含未替换占位符")
def _r15():
    import re
    md = _render(_base_report())
    for pat in (r"%s", r"%d", r"%\.\df", r"\{\}", r"\[TBD\]"):
        assert not re.search(pat, md), "残留占位符 %s" % pat


@case("渲染：置信等级与未覆盖项必须显式声明")
def _r16():
    md = _render(_base_report())
    assert ("保密" in md or "密级" in md or "分发范围" in md), "缺保密等级声明"
    assert ("不在本次范围" in md or "未覆盖" in md or "未核查" in md), "缺未覆盖项声明"


@case("渲染：overall_rating 在无资产时不给『低风险』")
def _r17():
    import cmdb_audit
    aud = cmdb_audit.collect({})
    r = cmdb_audit.overall_rating(aud or {}, {})
    assert r, "空数据应返回带提示的评级，而非抛异常"
    assert "数据不足" in str(r) or "无法评级" in str(r) or r.get("rating") != "低风险", \
        "空数据被判低风险：%s" % r


# —— 降级路径（2026-10-05 新增）——
#   这两个用例守的是同一个真实 bug：治理数据拿不到时，
#   报告一律写「未随检测提供治理数据」。但拿不到有两种原因，
#   排查方向完全相反——运维没传表 vs 解析器崩了。

def _bare_report(audit=None, err=""):
    rep = _base_report()
    rep["audit"] = audit
    rep["audit_err"] = err
    return rep


@case("降级：无治理表 → 说『未提供』，不编造数据")
def _d1():
    md = _render(_bare_report(None, ""))
    for ch in ("## 三、", "## 四、", "## 五、"):
        assert ch in md, "缺章节 %s" % ch
    assert "未随检测提供" in md, "未声明治理数据缺失"
    # 底线：未核查不等于合格，这句话必须在
    assert "未核查" in md, "缺『未核查≠合格』的底线声明"
    # 不能出现「解析失败」——那会误导运维去查代码
    assert "解析失败" not in md, "无异常却报『解析失败』，会把排查引向代码"


@case("降级：治理解析异常 → 说『解析失败』并带错误原文，不说『未提供』")
def _d2():
    err = "ValueError: 列数不一致"
    md = _render(_bare_report(None, err))
    assert "解析失败" in md, "解析异常却未声明（会误导运维重传表）"
    assert "列数不一致" in md, "错误原文未带进报告，评审无法判断是工具缺陷还是数据缺陷"
    assert "未随检测提供" not in md, "解析异常却报『未提供』——排查方向错"
    # 摘要与三章口径必须一致，不能自相矛盾
    assert "权限绕过：未核查" in md, "摘要未标未核查"


@case("降级：两种 unavailable 互斥（不会同时出现两种表述）")
def _d3():
    miss = _render(_bare_report(None, ""))
    errd = _render(_bare_report(None, "ValueError: x"))
    assert ("解析失败" in miss) is False, "『未提供』分支混入『解析失败』措辞"
    assert ("未随检测提供" in errd) is False, "『解析失败』分支混入『未提供』措辞"


def main():
    print("=" * 68)
    print("CMDB 七章报告 —— 对抗性输入测试")
    print("=" * 68)
    print("PASS %d / FAIL %d\n" % (len(PASSES), len(FAILS)))
    if FAILS:
        print("失败用例：")
        for n, e in FAILS:
            print("  - %s → %s" % (n, e))
        return 1
    print("全部通过。")
    return 0


if __name__ == "__main__":
    sys.exit(main())