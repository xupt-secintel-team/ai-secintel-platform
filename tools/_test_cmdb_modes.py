# -*- coding: utf-8 -*-
"""CMDB 四种接入模式的冒烟测试（inline / sqlite / file / rest-error）。

为什么需要（2026-10-05 实际踩坑）：给 _load_assets 增加返回值时，只测了 file
模式（全量离线验证），inline 模式的 return 漏改 → 只有粘贴数据时才报
`not enough values to unpack`。四种模式都跑一遍，漏网路径立刻暴露。
"""
import json
import os
import sqlite3
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich", "backend"))

import cmdb_scan as CS  # noqa: E402

LEDGER_CSV = (
    "VULN_ID,VULN_NO,AFFECTED_COMPONENT,COMPONENT_VERSION,FIX_VERSION,SEVERITY,"
    "CVSS_SCORE,CI_ID,CI_TYPE,CI_NAME,CI_IP,OWNER,PLAN_FIX_DATE,FIX_STATUS,"
    "RELATED_PATCH,IS_INTERNET_FACING,IS_REGULATORY,BUSINESS_BG,ENV_TYPE,CWE_ID,"
    "VULN_TYPE,VULN_NAME,APP_NAME,EMP_ID,DEPT_ID\n"
    "VUL-00000001,CVE-2026-11111,Apache Tomcat,9.0.80,9.0.83,高危 High,9.8,"
    "SRV-000001,SRV,web01,10.1.1.1,张三,2026-10-20,未修复,PAT-0001,Y,Y,FIN,"
    "生产环境 PROD,CWE-20,远程代码执行,远程代码执行漏洞,统一支付网关,EMP1,D001\n"
    "VUL-00000002,CNVD-2026-22222,MySQL,5.7.30,8.0.33,中危 Medium,6.5,"
    "SRV-000002,SRV,db01,10.1.1.2,李四,2026-11-20,修复中,PAT-0002,N,N,ECOM,"
    "测试环境 TEST,CWE-89,SQL注入,SQL注入漏洞,商品中心,EMP2,D002\n"
    "VUL-00000003,,Redis,6.0.16,7.2.4,低危 Low,3.3,SRV-000003,SRV,cache01,"
    "10.1.1.3,王五,2026-12-01,未修复,PAT-0003,N,N,AI,预发布环境 STAGE,"
    "CWE-120,缓冲区溢出,缓冲区溢出漏洞,推荐算法,EMP3,D003\n"
)
# 资产表（验证位置索引 / 资产清单）
ASSET_CSV = (
    "SRV_ID,HOSTNAME,INNER_IP,IDC_ID,CAB_ID,OS_NAME,OWNER,IMPORTANCE,ENV_TYPE\n"
    "SRV-000001,web01,10.1.1.1,IDC-0001,CAB-000001,CentOS 7.9,张三,核心,生产环境 PROD\n"
    "SRV-000002,db01,10.1.1.2,IDC-0002,CAB-000002,Ubuntu 22.04,李四,重要,测试环境 TEST\n"
    "SRV-000003,cache01,10.1.1.3,IDC-0001,CAB-000001,CentOS 7.9,王五,一般,预发布环境 STAGE\n"
)
IDC_CSV = (
    "IDC_ID,IDC_NAME,CITY,REGION,TIER_LEVEL\n"
    "IDC-0001,银川数据中心,银川,西北,T4\n"
    "IDC-0002,北京滨江数据中心,北京,华北,T3+\n"
)
CAB_CSV = (
    "CAB_ID,CAB_CODE,IDC_ID,FLOOR,ROOM_NO\n"
    "CAB-000001,AZ-银川-01-A-01,IDC-0001,6F,M11模块\n"
    "CAB-000002,AZ-北京-02-B-02,IDC-0002,5F,M9模块\n"
)

_fails = []


def ok(name, cond, detail=""):
    print("  %s %-46s %s" % ("PASS" if cond else "FAIL", name, detail))
    if not cond:
        _fails.append(name)


def _assert_report(rep, tag):
    s = rep["risk"]["summary"]
    ok("%s：识别为台账数据源" % tag, "漏洞台账" in (rep.get("data_source") or ""))
    ok("%s：台账行读进来了" % tag, s.get("ledger_rows", 0) >= 3,
       "%d 行" % s.get("ledger_rows", 0))
    pr = rep["priority"]
    ok("%s：产出处置工单" % tag, len(pr) >= 1, "%d 条" % len(pr))
    ok("%s：工单有责任人" % tag, all(p.get("owners") for p in pr))
    ok("%s：工单有 SLA" % tag, all(p.get("sla_days") for p in pr))
    ok("%s：工单有修复方案" % tag, all(p.get("fix_plan") for p in pr))
    cve = [p for p in pr if str(p.get("cve", "")).startswith("CVE-")]
    ok("%s：CVE 工单带 NVD 链接" % tag, bool(cve) and bool(cve[0].get("official_url")),
       cve[0].get("official_url", "") if cve else "无 CVE 工单")
    ok("%s：编号覆盖率已统计" % tag, bool(s.get("id_coverage")))
    md = CS.report_to_markdown(rep)
    # ★ 报告有两套模板（2026-10-05 七章制改造后）：
    #     台账模式 → 七章 + 附录 A~F（有漏洞台账才有派单依据）
    #     资产匹配模式 → 五章（无台账，退回资产 CPE 视角）
    #   原来这里写死「六节齐全」（六节模板早已不存在），四种模式全 FAIL ——
    #   断言长期红着没人看，等于没有断言。改成按 is_ledger 分别校验。
    if s.get("ledger_rows"):
        chapters = ("## 一、报告基础信息", "## 二、执行摘要", "## 三、CMDB 数据质量检测",
                    "## 四、CMDB 访问控制与权限安全检测", "## 五、变更管理合规性检测",
                    "## 六、发现汇总与工单派发表", "## 七、复测计划与闭环记录")
        label = "报告七章齐全"
    else:
        chapters = ("## 一、总体结论", "## 二、优先处置清单", "## 三、资产风险清单",
                    "## 四、软件组件命中明细", "## 五、说明")
        label = "报告五章齐全"
    missing = [c for c in chapters if c not in md]
    ok("%s：%s" % (tag, label), not missing, "缺：%s" % missing)
    if s.get("ledger_rows"):
        ok("%s：附录 A~F 齐全" % tag,
           all(("附录 %s" % L) in md for L in "ABCDEF"),
           [L for L in "ABCDEF" if ("附录 %s" % L) not in md])
    ok("%s：资产有机房位置" % tag, any(h.get("location") for h in rep["risk"]["hosts"]),
       rep["risk"]["hosts"][0].get("location", "") if rep["risk"]["hosts"] else "无资产")


def test_inline():
    print("\n[1/4] inline 模式（粘贴 CSV：台账+机房+机柜多表，空行分隔）")
    # 真实运维场景：从 CMDB 一次性复制四张表粘进来（表块之间空一行）
    pasted = "\n".join((LEDGER_CSV.strip(), ASSET_CSV.strip(),
                        IDC_CSV.strip(), CAB_CSV.strip()))
    r = CS.analyze(None, {"mode": "inline", "text": pasted})
    ok("inline：返回 ok", r.get("ok"), r.get("error", ""))
    if r.get("ok"):
        _assert_report(r["report"], "inline")
        hosts = r["report"]["risk"]["hosts"]
        ok("inline：位置回溯到机房+机柜", any(
            "银川" in (h.get("location") or "") for h in hosts),
            hosts[0].get("location", "") if hosts else "无")
    # 单表（只粘台账）也必须能出报告——位置列显示「未登记」而不是整体失败
    r1 = CS.analyze(None, {"mode": "inline", "text": LEDGER_CSV})
    ok("inline：单表台账仍可出报告", r1.get("ok"), r1.get("error", ""))
    if r1.get("ok"):
        ok("inline：单表台账责任人齐全",
           all(p.get("owners") for p in r1["report"]["priority"]))


def test_file():
    print("\n[2/4] file 模式（上传 CSV，含机房/机柜表）")
    files = [{"filename": "vulnerability.csv", "data": LEDGER_CSV.encode()},
             {"filename": "physical_server.csv", "data": ASSET_CSV.encode()},
             {"filename": "idc_room.csv", "data": IDC_CSV.encode()},
             {"filename": "cabinet.csv", "data": CAB_CSV.encode()}]
    r = CS.analyze(None, {"mode": "file", "files": files, "name": "冒烟"})
    ok("file：返回 ok", r.get("ok"), r.get("error", ""))
    if r.get("ok"):
        _assert_report(r["report"], "file")
        hosts = r["report"]["risk"]["hosts"]
        ok("file：位置回溯到机房+机柜", any(
            "银川" in (h.get("location") or "") for h in hosts),
            hosts[0].get("location", "") if hosts else "无")


def test_sqlite():
    print("\n[3/4] sqlite 模式（直读本地库，含机房/机柜/物理机表）")
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    try:
        conn = sqlite3.connect(tmp.name)
        conn.execute("""CREATE TABLE vulnerability (
            VULN_ID TEXT, VULN_NO TEXT, AFFECTED_COMPONENT TEXT,
            COMPONENT_VERSION TEXT, FIX_VERSION TEXT, SEVERITY TEXT,
            CVSS_SCORE TEXT, CI_ID TEXT, CI_TYPE TEXT, CI_NAME TEXT, CI_IP TEXT,
            OWNER TEXT, PLAN_FIX_DATE TEXT, FIX_STATUS TEXT, RELATED_PATCH TEXT,
            IS_INTERNET_FACING TEXT, IS_REGULATORY TEXT, BUSINESS_BG TEXT,
            ENV_TYPE TEXT, CWE_ID TEXT, VULN_TYPE TEXT, VULN_NAME TEXT,
            APP_NAME TEXT, EMP_ID TEXT, DEPT_ID TEXT)""")
        # 位置链路要能从 CI 反查机房/机柜，所以物理机/机房/机柜三张表都得建
        conn.execute("""CREATE TABLE physical_server (
            SRV_ID TEXT, HOSTNAME TEXT, INNER_IP TEXT, IDC_ID TEXT, CAB_ID TEXT,
            OS_NAME TEXT, OWNER TEXT, IMPORTANCE TEXT, ENV_TYPE TEXT)""")
        conn.execute("""CREATE TABLE idc_room (
            IDC_ID TEXT, IDC_NAME TEXT, CITY TEXT, REGION TEXT, TIER_LEVEL TEXT)""")
        conn.execute("""CREATE TABLE cabinet (
            CAB_ID TEXT, CAB_CODE TEXT, IDC_ID TEXT, FLOOR TEXT, ROOM_NO TEXT)""")
        import csv as _csv
        import io as _io
        for table, text in (("vulnerability", LEDGER_CSV),
                            ("physical_server", ASSET_CSV),
                            ("idc_room", IDC_CSV),
                            ("cabinet", CAB_CSV)):
            rows = list(_csv.reader(_io.StringIO(text)))
            cols = rows[0]
            q = 'INSERT INTO "%s" VALUES (%s)' % (table, ",".join(["?"] * len(cols)))
            for row in rows[1:]:
                conn.execute(q, [c if c else None for c in row])
        conn.commit()
        conn.close()
        r = CS.analyze(None, {"mode": "sqlite", "path": tmp.name})
        ok("sqlite：返回 ok", r.get("ok"), r.get("error", ""))
        if r.get("ok"):
            _assert_report(r["report"], "sqlite")
            hosts = r["report"]["risk"]["hosts"]
            ok("sqlite：位置回溯到机房+机柜", any(
                "银川" in (h.get("location") or "") for h in hosts),
                hosts[0].get("location", "") if hosts else "无")
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def _make_db(path, tables):
    """按 {表名: CSV 文本} 建一个 SQLite 库。"""
    import csv as _csv
    import io as _io
    conn = sqlite3.connect(path)
    for table, text in tables.items():
        rows = list(_csv.reader(_io.StringIO(text)))
        if not rows:
            continue
        cols = rows[0]
        conn.execute('CREATE TABLE "%s" (%s)' % (
            table, ",".join('"%s" TEXT' % c for c in cols)))
        q = 'INSERT INTO "%s" VALUES (%s)' % (table, ",".join(["?"] * len(cols)))
        for row in rows[1:]:
            conn.execute(q, [c if c else None for c in row])
    conn.commit()
    conn.close()


def test_sqlite_multi_db():
    """分库上传（2026-10-06 新增）：台账库 / 资产库 / 机房库拆成三个 .db 一起传。

    为什么必须测：真实 CMDB 常按业务域分库，浏览器上传又是「多文件」入口。
    如果后端只认 paths[0]，台账库排在第二个时报告会静默退化成
    「资产 CPE 匹配」，责任人/期限/SLA 全空 —— 这种失败不报错、只出废报告。
    """
    print("\n[3b/4] sqlite 多库合并（分库上传）")
    import csv as _csv
    import io as _io
    d = tempfile.mkdtemp(prefix="cmdb_multi_")
    p_led = os.path.join(d, "01_ledger.db")
    p_ast = os.path.join(d, "02_asset.db")
    p_idc = os.path.join(d, "03_idc.db")
    try:
        # 三个库各放一部分：台账 / 物理机+机柜 / 机房
        _make_db(p_led, {"vulnerability": LEDGER_CSV})
        _make_db(p_ast, {"physical_server": ASSET_CSV, "cabinet": CAB_CSV})
        _make_db(p_idc, {"idc_room": IDC_CSV})

        r = CS.analyze(None, {"mode": "sqlite", "paths": [p_led, p_ast, p_idc]})
        ok("多库：返回 ok", r.get("ok"), r.get("error", ""))
        if not r.get("ok"):
            return
        rep = r["report"]
        _assert_report(rep, "sqlite-multi")

        # ① 台账来自第 1 个库 → 报告主数据源必须是台账（有 priority 处置项）
        ok("多库：台账被识别为主数据源（三个库合起来才完整）",
           bool(rep.get("priority")), "priority 为空说明台账没读到")

        # ② 位置链路跨库：资产库给 CI→机柜，机房库给机柜→机房名
        hosts = rep.get("risk", {}).get("hosts") or []
        loc = " ".join((h.get("location") or "") for h in hosts)
        ok("多库：位置跨库回溯（资产库+机房库合并）", "银川" in loc, loc[:60] or "无位置")

        # ③ 数据来源标签要体现多库，不能只报第一个
        src = json.dumps(rep, ensure_ascii=False)
        ok("多库：数据来源体现多库", "个库" in src, "未找到多库标识")

        # ④ 库顺序颠倒也要成立（不能依赖「第一个是台账」）
        r2 = CS.analyze(None, {"mode": "sqlite", "paths": [p_idc, p_ast, p_led]})
        ok("多库：乱序也能读出台账", bool(r2.get("ok")) and bool(r2["report"].get("priority")),
           r2.get("error", ""))

        # ⑤ paths + path 混传时两者都要生效（前端两个入口不会同时用，但后端要稳）
        r3 = CS.analyze(None, {"mode": "sqlite", "paths": [p_led], "path": p_ast})
        ok("多库：paths 与 path 混传不报错", bool(r3.get("ok")), r3.get("error", ""))

        # ⑥ 坏库不能拖垮整次分析：混入一个非 SQLite 文件
        p_bad = os.path.join(d, "99_broken.db")
        with open(p_bad, "wb") as f:
            f.write(b"this is not a sqlite database at all")
        r4 = CS.analyze(None, {"mode": "sqlite", "paths": [p_led, p_bad, p_ast]})
        ok("多库：坏库被跳过，好库仍出报告",
           bool(r4.get("ok")) and bool(r4["report"].get("priority")),
           r4.get("error", ""))

        # ⑦ 全部是坏库时要给明确错误，不能崩也不能假装成功
        r5 = CS.analyze(None, {"mode": "sqlite", "paths": [p_bad]})
        ok("多库：全坏时返回明确错误", (not r5.get("ok")) and bool(r5.get("error")),
           r5.get("error", "")[:80])

        # ⑧ ★ 句柄必须归还（2026-10-06 e2e 抓到的真实泄漏）
        #   原来三处 conn.close() 都写在 try 末尾，上传非 SQLite 文件时中途抛异常
        #   → 句柄不还 → Windows 上 os.remove 删不掉被占用的文件 → 用户的 CMDB 库
        #   永久残留在 data/tmp_cmdb。Linux 能删，所以这个 bug 只在 Windows 显形。
        #   这里直接验「读完之后文件能删掉」，删不掉就是句柄还挂着。
        leaked = []
        for p in (p_led, p_bad, p_ast, p_idc):
            CS.analyze(None, {"mode": "sqlite", "paths": [p]})
            try:
                os.unlink(p)          # 删不掉 = 还有句柄占着
            except OSError as e:
                leaked.append("%s(%s)" % (os.path.basename(p), e.errno))
                # 补救，否则后面的 finally 会因为文件已不在而误判
                pass
        ok("多库：读完后文件可删（无句柄泄漏）", not leaked, "删不掉：%s" % leaked)
    finally:
        for p in (p_led, p_ast, p_idc):
            try:
                os.unlink(p)
            except OSError:
                pass
        try:
            os.rmdir(d)
        except OSError:
            pass


def test_rest_and_errors():
    print("\n[4/4] rest 模式与错误分支")
    # rest 无 url → 应给出明确错误而不是抛异常（_fetch_rest 曾被误删）
    try:
        r = CS.analyze(None, {"mode": "rest", "url": ""})
        ok("rest：无地址时返回明确错误", (not r.get("ok")) and bool(r.get("error")),
           r.get("error", "")[:60])
    except Exception as e:  # noqa: BLE001
        ok("rest：无地址时返回明确错误", False, "抛异常 %s" % e)
    # _fetch_rest 必须真实存在（曾被 _vuln_ledger_rows 的 return 吞掉）
    ok("_fetch_rest 函数存在", callable(getattr(CS, "_fetch_rest", None)))
    r = CS.analyze(None, {"mode": "inline", "text": ""})
    ok("inline：空输入返回明确错误", (not r.get("ok")) and bool(r.get("error")))


def main():
    test_inline()
    test_file()
    test_sqlite()
    test_sqlite_multi_db()
    test_rest_and_errors()
    print("\n" + "=" * 66)
    if _fails:
        print("失败 %d 项：%s" % (len(_fails), _fails))
        return 1
    print("四种接入模式全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
