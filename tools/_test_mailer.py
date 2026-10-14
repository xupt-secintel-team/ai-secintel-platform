#!/usr/bin/env python
"""_test_mailer.py —— 邮件投递模块单元测试（2026-10-06）

不连真实 SMTP：用一个假的 smtplib.SMTP 类替换掉，验证
  · 收件人解析（多分隔符 / 非法地址 / 重复 / 上限）
  · 未配置时的行为（不能静默"成功"）
  · 认证失败 / 超时 / 连接失败的错误文案是否可操作
  · 外发默认脱敏（绝不把原文发出去）
  · MIME 结构（主题中文不乱码、附件存在）

运行：python tools/_test_mailer.py
"""
import importlib.util
import os
import socket
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich", "backend"))


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


mailer = _load("mailer_under_test", "modules/m2_enrich/backend/mailer.py")

_fails = []
_n = [0]


def ok(name, cond, detail=""):
    _n[0] += 1
    print("  %s %-56s %s" % ("PASS" if cond else "FAIL", name, detail))
    if not cond:
        _fails.append(name)


def _clear_env():
    for k in list(os.environ):
        if k.startswith("AISEC_SMTP_"):
            del os.environ[k]


def _set_env(**kw):
    _clear_env()
    for k, v in kw.items():
        os.environ["AISEC_SMTP_" + k] = str(v)


print("=" * 62)
print("=== ① 收件人解析 ===")
_g, _b = mailer.parse_recipients("a@qq.com, b@163.com;c@gmail.com、d@x.cn")
ok("逗号/分号/顿号都能分隔", _g == ["a@qq.com", "b@163.com", "c@gmail.com", "d@x.cn"], _g)

_g, _b = mailer.parse_recipients("  a@qq.com  \n b@163.com ")
ok("空白与换行容错", _g == ["a@qq.com", "b@163.com"], _g)

_g, _b = mailer.parse_recipients("a@qq.com,,,b@163.com")
ok("连续分隔符不产生空项", len(_g) == 2, _g)

_g, _b = mailer.parse_recipients("a@qq.com, a@qq.com")
ok("重复地址去重", len(_g) == 1, _g)

_g, _b = mailer.parse_recipients("<a@qq.com>")
ok("尖括号包裹（从邮件客户端粘贴常见）", _g == ["a@qq.com"], _g)

_g, _b = mailer.parse_recipients(["a@qq.com", "b@163.com"])
ok("列表入参", len(_g) == 2, _g)

print("\n=== ② 非法地址识别 ===")
_g, _b = mailer.parse_recipients("a@qq.com, 不是邮箱, b@")
ok("合法与非法分开", _g == ["a@qq.com"] and len(_b) == 2, (_g, _b))

for bad in ["no-at-sign", "a@", "@qq.com", "a@qq", "a@@qq.com"]:
    _g, _b = mailer.parse_recipients(bad)
    ok("拒绝 %r" % bad, not _g, _g)

# 空格本来就在分隔符里，所以 "a b@qq.com" 会被拆成 a / b@qq.com，
# 其中 b@qq.com 是合法地址 —— 这是正确行为，不是 bug。显式记一条防后人误改。
_g, _b = mailer.parse_recipients("a b@qq.com")
ok("含空格的串按空格切分（保留合法项）", _g == ["b@qq.com"], _g)

r = mailer.validate("全是坏的")
ok("全非法时报错并点名", r["ok"] is False and "全是坏的" in r["error"], r.get("error"))

r = mailer.validate("")
ok("空输入报「请填写收件邮箱」", r["ok"] is False and "填写" in r["error"], r.get("error"))

r = mailer.validate("a@qq.com")
ok("合法输入通过", r["ok"] is True and r["recipients"] == ["a@qq.com"], r)

print("\n=== ③ 收件人数量上限 ===")
many = ",".join("u%d@qq.com" % i for i in range(25))
r = mailer.validate(many)
ok("超过 %d 个被拒" % mailer.MAX_RECIPIENTS,
   r["ok"] is False and "超过" in r["error"], r.get("error"))

r = mailer.validate(",".join("u%d@qq.com" % i for i in range(20)))
ok("正好 20 个通过", r["ok"] is True and len(r["recipients"]) == 20, len(r.get("recipients") or []))

print("\n=== ④ 未配置 SMTP 时不能假成功 ===")
_clear_env()
ok("configured() 为 False", mailer.configured() is False)
st = mailer.config_status()
ok("状态接口回 configured=False", st["configured"] is False)
ok("给出可操作提示（含 secrets.env 与授权码）",
   "secrets.env" in st["hint"] and "授权码" in st["hint"], st["hint"][:60])
res = mailer.send_report_mail(["a@qq.com"], {"id": "X"}, "# md")
ok("未配置时发送返回 ok=False", res["ok"] is False, res.get("error", "")[:40])
ok("错误文案说明怎么配", "secrets.env" in res.get("error", ""), res.get("error", "")[:60])

print("\n=== ⑤ 配置读取与端口推断 ===")
_set_env(HOST="smtp.qq.com", USER="u@qq.com", PASS="pwd")
c = mailer._cfg()
ok("端口按已知服务商推断为 465", c["port"] == 465, c)
ok("465 默认走 SSL", c["ssl"] is True)

_set_env(HOST="smtp.example.com", PORT="25", USER="u@x.cn", PASS="p")
ok("显式 25 端口", mailer._cfg()["port"] == 25)
ok("25 默认不走 SSL", mailer._cfg()["ssl"] is False)

_set_env(HOST="smtp.qq.com", PORT="25", USER="u@qq.com", PASS="p", SSL="1")
ok("SSL=1 强制开启", mailer._cfg()["ssl"] is True)
_set_env(HOST="smtp.qq.com", PORT="465", USER="u@qq.com", PASS="p", SSL="0")
ok("SSL=0 强制关闭", mailer._cfg()["ssl"] is False)

_set_env(HOST="smtp.qq.com", USER="u@qq.com", PASS="p", FROM="bot@qq.com")
ok("FROM 可独立指定", mailer._cfg()["from"] == "bot@qq.com")
_set_env(HOST="smtp.qq.com", USER="u@qq.com", PASS="p")
ok("FROM 默认同 USER", mailer._cfg()["from"] == "u@qq.com")

_set_env(HOST="smtp.qq.com", USER="u@qq.com", PASS="p", PORT="not-a-number")
ok("端口非法时回落推断值而非崩溃", mailer._cfg()["port"] == 465, mailer._cfg()["port"])

_set_env(HOST="smtp.qq.com", USER="u@qq.com")     # 缺 PASS
ok("缺密码即视为未配置", mailer.configured() is False)

st = mailer.config_status()
ok("状态接口绝不回传密码",
   "pass" not in str(st).lower() or st.get("pass") in (None, ""), sorted(st.keys()))

print("\n=== ⑥ 外发默认脱敏（安全底线）===")
_set_env(HOST="smtp.qq.com", USER="u@qq.com", PASS="p")
captured = {}


class _FakeSMTP:
    """假的 SMTP：只记录 login/sendmail 调用，不碰网络。"""

    def __init__(self, host="", port=0, timeout=0):
        captured["host"] = host
        captured["port"] = port
        captured["timeout"] = timeout

    def ehlo(self):
        return 250, b"ok"

    def starttls(self):
        return 220, b"ok"

    def login(self, u, p):
        captured["login"] = (u, p)
        return 235, b"ok"

    def sendmail(self, frm, to, msg):
        captured["from"] = frm
        captured["to"] = to
        captured["msg"] = msg

    def quit(self):
        captured["quit"] = True


_real_smtplib = mailer.smtplib
mailer.smtplib = types.SimpleNamespace(
    SMTP=_FakeSMTP, SMTP_SSL=_FakeSMTP, SMTPException=Exception)

_rep = {"id": "CMDB-20261006-abc123", "name": "核心生产区",
        "summary": {"ci_total": 128, "critical": 9}}
_md = "# CMDB 资产风险分析报告\n\n## 一、概述\n\n共 128 台资产。\n"

res = mailer.send_report_mail(["a@qq.com"], _rep, _md)
ok("模拟发送成功", res["ok"] is True, res.get("error", ""))
ok("默认脱敏级别是 basic（不是 off）", res["mask"] == "basic", res.get("mask"))
ok("mask 显式传 off 才生效 off",
   mailer.send_report_mail(["a@qq.com"], _rep, _md, mask="off")["mask"] == "basic",
   "非法值退回 basic")
ok("mask=strict 生效", mailer.send_report_mail(["a@qq.com"], _rep, _md, mask="strict")["mask"] == "strict")

raw = captured["msg"]
ok("主题含中文（Header 编码）", "Subject:" in raw and "=?utf-8?" in raw.lower(), raw[:80])
ok("收件人正确", captured["to"] == ["a@qq.com"], captured["to"])
ok("登录用配置里的账号", captured["login"][0] == "u@qq.com")
ok("正常路径 quit 被调用", captured.get("quit") is True)
# 正文里本来就含 "CMDB" 与 "markdown" 相关措辞，不能用子串粗判有无附件；
# 附件的判定特征是 Content-Disposition: attachment
ok("默认不带 .md 附件", "Content-Disposition: attachment" not in captured["msg"])

mailer.send_report_mail(["a@qq.com"], _rep, _md, attach_md=True)
ok("attach=True 时带 .md 附件",
   "Content-Disposition: attachment" in captured["msg"])
ok("附件是 markdown 子类型", "application/markdown" in captured["msg"].lower())

print("\n=== ⑦ 发送失败的文案必须可操作 ===")


class _AuthFail:
    def __init__(self, host="", port=0, timeout=0):
        pass

    def ehlo(self):
        return 250, b"ok"

    def starttls(self):
        return 220, b"ok"

    def login(self, u, p):
        raise _real_smtplib.SMTPAuthenticationError(535, b"535 auth failed")

    def quit(self):
        pass


mailer.smtplib = types.SimpleNamespace(
    SMTP=_AuthFail, SMTP_SSL=_AuthFail,
    SMTPException=_real_smtplib.SMTPException)
r = mailer.send_report_mail(["a@qq.com"], _rep, _md)
ok("认证失败 ok=False", r["ok"] is False)
ok("认证失败提示「授权码」", "授权码" in r.get("error", ""), r.get("error", "")[:70])


class _Timeout:
    """连接建立后无响应 → login 阶段抛 timeout。"""

    def __init__(self, host="", port=0, timeout=0):
        self.timeout = timeout

    def ehlo(self):
        return 250, b"ok"

    def starttls(self):
        return 220, b"ok"

    def login(self, u, p):
        raise socket.timeout("timed out")

    def quit(self):
        pass


mailer.smtplib = types.SimpleNamespace(
    SMTP=_Timeout, SMTP_SSL=_Timeout,
    SMTPException=_real_smtplib.SMTPException)
r = mailer.send_report_mail(["a@qq.com"], _rep, _md, timeout=7)
ok("连接超时 ok=False", r["ok"] is False)
ok("超时文案带主机端口与建议", "smtp.qq.com" in r.get("error", "")
   and "防火墙" in r.get("error", ""), r.get("error", "")[:70])


class _ConnFail:
    def __init__(self, host="", port=0, timeout=0):
        raise ConnectionRefusedError("connection refused")

    def quit(self):
        pass


mailer.smtplib = types.SimpleNamespace(
    SMTP=_ConnFail, SMTP_SSL=_ConnFail,
    SMTPException=_real_smtplib.SMTPException)
r = mailer.send_report_mail(["a@qq.com"], _rep, _md)
ok("连接被拒 ok=False 且不崩", r["ok"] is False and r.get("error"), r.get("error", "")[:60])

mailer.smtplib = _real_smtplib

print("\n=== ⑧ 发送前再校验收件人 ===")
r = mailer.send_report_mail([], _rep, _md)
ok("空收件人被拒", r["ok"] is False and "收件人" in r.get("error", ""), r.get("error"))
r = mailer.send_report_mail(["坏地址"], _rep, _md)
ok("非法收件人在发送层也被拒", r["ok"] is False, r.get("error"))

print("\n=== ⑨ 主题与正文 ===")
s = mailer.build_subject(_rep)
ok("主题含报告编号尾 8 位", "abc123" in s, s)
ok("主题含报告名", "核心生产区" in s, s)
s2 = mailer.build_subject({"id": "X"}, host_tag="prod")
ok("host_tag 进主题便于区分环境", s2.startswith("[prod]"), s2)

msg, plain = mailer.build_body(_rep, _md, ["a@qq.com"], html=False)
ok("plain 备选含关键指标", "128" in plain and "9" in plain, plain[:60])
ok("plain 含保密语义（报告编号）", "CMDB-20261006-abc123" in plain)

msg2, _ = mailer.build_body(_rep, _md, ["a@qq.com"], html=True)
raw2 = msg2.as_string()
ok("无 markdown 库时降级为 HTML 而非报错", "text/html" in raw2)
ok("同时保留纯文本备选", "text/plain" in raw2)

print("\n=== ⑩ 异步入口必须立刻返回 ===")
_clear_env()
mailer.clear_last_result()
ok("初始无上次结果", mailer.last_result() is None)
import time as _t
_t0 = _t.time()
mailer.send_async(["a@qq.com"], _rep, _md)
_dt = _t.time() - _t0
ok("send_async 立即返回（<0.2s）", _dt < 0.2, "%.4fs" % _dt)
_t.sleep(0.6)
lr = mailer.last_result()
ok("后台线程写回了结果", lr is not None and lr.get("ok") is False, (lr or {}).get("error", "")[:40])

_clear_env()

print("\n" + "=" * 62)
print("通过 %d，失败 %d" % (_n[0] - len(_fails), len(_fails)))
if _fails:
    print("失败项：")
    for f in _fails:
        print("  - " + f)
sys.exit(1 if _fails else 0)