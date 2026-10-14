# -*- coding: utf-8 -*-
"""
邮件自检.py —— 一条命令确认「分析报告发邮箱」这条链路真的通
============================================================
在项目根目录跑：

    py -3 tools/邮件自检.py                        # 发到发件邮箱自己
    py -3 tools/邮件自检.py --to a@qq.com          # 发到指定地址
    py -3 tools/邮件自检.py --xlsx --md            # 连 xlsx / md 附件一起验

它做的事：
  1. 按「启动服务.bat」完全相同的方式读 secrets.env（只取值，绝不打印密码）；
  2. 打印当前 SMTP 配置（host/port/SSL/发件人；密码只报长度）；
  3. 真连一次 SMTP、真发一封自检邮件，把服务端原话带回来；
  4. 失败时直接告诉你是哪一类问题（认证/网络/被拒），以及怎么改。

为什么单独写一个脚本：发信失败的原因（授权码错、端口封了、进了垃圾箱）
在网页上只表现为一句 "发送失败"，没法定位。这里把对话框摊开给你看。
"""
from __future__ import annotations

import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# ---- 输出编码兜底（Windows 控制台默认 GBK，中文/符号会炸） ----
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")   # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass

# ---- 按启动脚本的方式注入 secrets.env（只进 os.environ，不落盘） ----
_secrets = os.path.join(ROOT, "secrets.env")
_loaded = []
if os.path.exists(_secrets):
    with open(_secrets, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip().lstrip("\ufeff")
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())
            _loaded.append(k.strip())

os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost")
os.environ.setdefault("no_proxy", "127.0.0.1,localhost")

sys.path.insert(0, ROOT)

from modules.m2_enrich.backend import mailer  # noqa: E402


def _demo_report() -> dict:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    return {
        "id": "MAILTEST-%s" % time.strftime("%Y%m%d%H%M%S"),
        "name": "SMTP 配置自检",
        "generated_at": now,
        "ts": now,
        "summary": {"ci_total": 3, "vuln_total": 5, "critical": 1},
        # 供 xlsx 附件试算的最小样例（字段不全时 build_xlsx 有自己的兜底）
        "tickets": [
            {"cve": "CVE-2024-0001", "component": "openssl", "severity": "Critical",
             "hosts": ["10.0.0.11", "10.0.0.12"], "owners": ["zhangsan"]},
            {"cve": "CVE-2024-0002", "component": "nginx", "severity": "High",
             "hosts": ["10.0.0.13"], "owners": ["lisi"]},
        ],
        "meta": {"hosts": {"10.0.0.11": {"owner": "zhangsan"}}},
    }


_DEMO_MD = """# SMTP 自检邮件

这是一封由 **AI-SecIntel 2.0** 发出的自检邮件，用来确认「分析报告发邮箱」能正常工作。
收到它就说明：**授权码有效、SMTP 连得通、邮件能投递**。

## 检查项

| 项目 | 结果 |
| --- | --- |
| SMTP 登录 | 通过 |
| 报告正文（HTML 渲染） | 本表格就是渲染结果 |
| 附件（如选择） | 见邮件附件区 |

## 说明

- 报告正文默认按 **basic 脱敏**（内网 IP、责任人邮箱会被替换），
  避免把资产信息原样发到外部邮箱；
- 这封信是自检用的，可直接删除。
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="SMTP 发信自检")
    ap.add_argument("--to", default="", help="收件人（默认发到发件邮箱自己）")
    ap.add_argument("--mask", default="basic", choices=["basic", "strict"],
                    help="脱敏级别，默认 basic")
    ap.add_argument("--md", action="store_true", help="附带 .md 附件")
    ap.add_argument("--xlsx", action="store_true", help="附带简略台账 .xlsx 附件")
    ap.add_argument("--timeout", type=int, default=30, help="SMTP 超时秒数")
    args = ap.parse_args()

    print("=" * 62)
    print("  AI-SecIntel 2.0 · 邮件发信自检")
    print("=" * 62)
    print("  secrets.env 变量名：%s（值不打印）" % (_loaded or "（文件不存在）"))
    print()

    st = mailer.config_status()
    if not st.get("configured"):
        print("  [×] SMTP 未配置，无法自检。")
        print("      提示：%s" % st.get("hint", ""))
        print()
        print("  修法：双击「设置密钥.bat」，或在 secrets.env 里填：")
        print("        AISEC_SMTP_HOST=smtp.qq.com")
        print("        AISEC_SMTP_PORT=465")
        print("        AISEC_SMTP_USER=你的邮箱@qq.com")
        print("        AISEC_SMTP_PASS=授权码（不是登录密码）")
        return 2

    print("  服务器 ：%s:%s" % (st["host"], st["port"]))
    print("  加密   ：%s" % ("SSL/TLS 直连" if st["ssl"] else "明文/STARTTLS"))
    print("  发件人 ：%s" % st["from"])
    print("  密码   ：已配置（%d 位，不显示）" % len(os.environ.get("AISEC_SMTP_PASS", "")))
    print()

    to = (args.to or st["from"]).strip()
    good, bad = mailer.parse_recipients(to) if to else ([], [])
    if not good:
        print("  [×] 收件人地址不合法：%r" % to)
        return 2
    if bad:
        print("  [!] 以下地址被忽略（格式不对）：%s" % "、".join(bad))

    xb = None
    if args.xlsx:
        try:
            from modules.m2_enrich.backend import cmdb_ticket_xlsx
            xb = cmdb_ticket_xlsx.build_xlsx(_demo_report(), mask=args.mask)
            print("  附件   ：简略台账 xlsx（%.1f KB，附件通道一并验证）" % (len(xb) / 1024.0))
        except Exception as e:  # noqa: BLE001
            print("  [!] 生成 xlsx 样例失败（%s），本次只发正文" % type(e).__name__)
            xb = None
    if args.md:
        print("  附件   ：报告 .md")

    print()
    print("  正在连接 SMTP 并发送到 %s ..." % "、".join(good))
    t0 = time.time()
    res = mailer.send_report_mail(
        good, _demo_report(), _DEMO_MD,
        mask=args.mask, attach_md=args.md, host_tag="自检",
        timeout=args.timeout, xlsx_bytes=xb)
    dt = time.time() - t0

    print()
    if res.get("ok"):
        print("  [√] 发送成功（耗时 %.1fs）" % dt)
        print("      收件人：%s" % "、".join(res.get("to", good)))
        print("      脱敏级：%s" % res.get("mask"))
        print()
        print("  如果没看到邮件，按顺序查：")
        print("    1) 垃圾邮件 / 广告邮件箱（QQ 常把程序发的信丢这里）")
        print("    2) 订阅邮件箱、或在搜索框搜「CMDB 资产风险分析报告」")
        print("    3) 发件箱「已发送」里有没有这封 —— 有=已投出，问题在收件侧")
        return 0

    print("  [×] 发送失败（耗时 %.1fs）" % dt)
    print("      原因：%s" % res.get("error", "未知"))
    print()
    err = str(res.get("error", ""))
    print("  对照修法：")
    if "认证" in err or "auth" in err.lower() or "535" in err:
        print("    · 授权码不对/已失效 —— 回 QQ 邮箱设置里重新生成一个，填进 AISEC_SMTP_PASS")
        print("    · 注意 AISEC_SMTP_USER 必须是完整邮箱地址，不是昵称")
        print("    · QQ 邮箱 POP3/SMTP 服务要处于「已开启」状态")
    elif "超时" in err or "timeout" in err.lower():
        print("    · 端口被网络/防火墙拦了：企业网常封 25 和 465")
        print("    · 换 587 试：AISEC_SMTP_PORT=587（STARTTLS）")
        print("    · 或改走自己的手机热点/其他网络验证")
    elif "未配置" in err:
        print("    · 回看上面的配置项，secrets.env 里四个必填项要齐")
    else:
        print("    · 把上面这句「原因」原样发出来，按它给的服务端原话定位")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[已取消]")
        sys.exit(1)
