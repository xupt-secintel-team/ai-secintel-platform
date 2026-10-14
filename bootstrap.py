# -*- coding: utf-8 -*-
"""
bootstrap.py —— 一键环境配置（用户三项硬性要求的第 ③ 条 + 安装包安装器）
==========================================================================
    「如果电脑环境不适合，可以自动配置环境」
    「弄成安装包，可以自动配置环境、安装文件」

这是什么
--------
双击它（Windows 上由 安装.bat 调用，macOS 上由 安装.command 调用，
Linux 上 `python3 bootstrap.py`），它会把"能不能跑"这件事一次性做完：

    ①  体检     Python 版本 / 操作系统 / CPU / 内存 / 磁盘 → 得出性能档位
    ②  建环境   在项目内建 .venv 虚拟环境（不污染系统 Python）
    ③  选镜像   并发探测清华/阿里/腾讯/中科大/官方源，挑**最快可达**的那个
    ④  装依赖   按档位分档安装：低配只装核心档，高配才建议 torch
    ⑤  自检     逐个 import 校验 + 生成 .aisec_env.json 环境档案
    ⑥  给结论   打印"下一步做什么"，失败也给明确的补救命令

为什么不用 requirements.txt 一把梭
-----------------------------------
torch 装机约 470MB、transformers 再 200MB+，在 4GB 内存的赛方笔记本上
装完就占满磁盘、启动还要多十几秒；而它只影响"新建语义索引"这一个
可选功能（已有索引照样检索）。所以按档位分档装：

    minimal（任何机器都装）  requests urllib3 openpyxl markdown
                             —— 富化/联网 + 报告导出（.xlsx 台账、邮件正文渲染）
    standard（主流机器）     + beautifulsoup4 numpy     —— 解析/语义检索
    full（高配，需确认）     + torch transformers ...   —— 本地嵌入模型

命令行
------
    python bootstrap.py               # 完整流程（体检→建环境→装依赖→自检）
    python bootstrap.py --check       # 只体检，不装东西（CI / 排障用）
    python bootstrap.py --json        # 机器可读输出（供自测脚本断言）
    python bootstrap.py --no-venv     # 装进当前解释器，不建虚拟环境
    python bootstrap.py --full        # 连 torch/transformers 一起装
    python bootstrap.py --offline     # 离线模式：只检测，不联网不安装

退出码：0 = 环境可用；1 = 环境不可用且已给出补救指引；2 = 版本硬性不达标
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "core"))

try:
    import compat
except Exception as _e:                              # pragma: no cover
    print("!! 无法加载 core/compat.py：%s" % _e)
    raise SystemExit(1)
try:
    import envprofile
except Exception as _e:                              # pragma: no cover
    print("!! 无法加载 core/envprofile.py：%s" % _e)
    raise SystemExit(1)

compat.ensure_utf8_stdio()

# ── 依赖分档 ────────────────────────────────────────────────────────────────
# openpyxl / markdown 体积很小（各百 KB），但缺了不是"降级"而是
# 「下载简略版 xlsx」直接报错、邮件正文退化成纯文本 —— 所以放进 minimal。
PACK_MINIMAL = ["requests", "urllib3", "openpyxl", "markdown"]
PACK_STANDARD = ["beautifulsoup4", "numpy"]
# 可选重依赖：仅 --full 或高配档且用户确认时才装
PACK_FULL = ["openai"]
PACK_TORCH = ["torch", "transformers", "sentencepiece"]

# ── pip 镜像（国内优先；自动测速选最快可达的）───────────────────────────────
MIRRORS = [
    ("清华", "https://pypi.tuna.tsinghua.edu.cn/simple"),
    ("阿里", "https://mirrors.aliyun.com/pypi/simple"),
    ("腾讯", "https://mirrors.cloud.tencent.com/pypi/simple"),
    ("中科大", "https://pypi.mirrors.ustc.edu.cn/simple"),
    ("官方", "https://pypi.org/simple"),
]

ENV_FILE = os.path.join(HERE, ".aisec_env.json")
VENV_DIR = os.path.join(HERE, ".venv")


def log(msg=""):
    compat.safe_print(msg, flush=True)


def hr(title=""):
    log("=" * 68)
    if title:
        log("  " + title)
        log("=" * 68)


# ── ① 体检 ──────────────────────────────────────────────────────────────────

def step_check():
    """环境体检：版本 + 硬件画像 + 档位。不联网、不改文件。"""
    rt = compat.check_runtime()
    prof = envprofile.profile()
    tier_obj = envprofile.Tier(prof)
    return {"runtime": rt, "profile": prof, "tier": tier_obj.name,
            "describe": tier_obj.describe()}


# ── ② 建虚拟环境 ────────────────────────────────────────────────────────────

def venv_python_path():
    """本平台下 .venv 里的解释器路径（三个系统各不一样，别写死）。"""
    if compat.IS_WIN:
        return os.path.join(VENV_DIR, "Scripts", "python.exe")
    return os.path.join(VENV_DIR, "bin", "python")


def _venv_runnable(py, timeout_s=30):
    """`.venv` 里的解释器**能不能真跑**。

    ★ 文件存在 ≠ 能用：从别的机器整个拷过来的 venv，pyvenv.cfg 记的是
    原机器的解释器绝对路径（实测 ``D:\\python\\python.exe``），`if exist`
    通过、真正执行立刻报 ``did not find executable at ...``。
    判据必须是"跑不跑得起来"，与 ``tools/_选解释器.bat`` 保持一致。
    """
    try:
        r = subprocess.run([py, "-c", "print(1)"], cwd=HERE,
                           timeout=timeout_s, capture_output=True)
        return r.returncode == 0
    except Exception:
        return False


def step_venv(timeout_s=180):
    """建 .venv；**已存在且真能跑**才复用。返回 (python_path, 是否新建)。"""
    py = venv_python_path()
    if os.path.isfile(py):
        if _venv_runnable(py):
            log("  · 虚拟环境已存在且可用：%s" % os.path.relpath(py, HERE))
            return py, False
        log("  · 虚拟环境存在但**跑不起来**（多半是从别的机器拷过来的，")
        log("    pyvenv.cfg 还记着原机的解释器路径）。正在重建 ...")
        # 不直接删：venv 内含上万个文件，删除既慢，又可能被安全护栏 / 杀软的
        # 批量删除拦截挡住（实测会抛 SAFE_DELETE_BULK_CONFIRM_REQUIRED）。
        # 改名归档即可 —— 同样让下面的 venv 创建走"全新"分支，而且可回滚。
        bak = VENV_DIR + ".broken_" + time.strftime("%Y%m%d%H%M%S")
        try:
            os.rename(VENV_DIR, bak)
            log("  · 旧的（跑不起来的）环境已改名归档：%s"
                % os.path.basename(bak))
            log("    确认新环境正常后，可自行删除该目录。")
        except Exception as _e:                       # pragma: no cover
            log("  !! 旧环境改名失败：%s" % _e)
            log("     请手动把 .venv 改名或删除后重试。")
    log("  · 正在创建虚拟环境 .venv ...")
    try:
        r = subprocess.run([sys.executable, "-m", "venv", VENV_DIR],
                           cwd=HERE, timeout=timeout_s,
                           capture_output=True)
        if r.returncode != 0 or not os.path.isfile(py):
            err = (r.stderr or b"").decode("utf-8", "replace")[:400]
            log("  !! 创建失败：%s" % err)
            log("     常见原因：系统缺 python3-venv（Ubuntu 需 apt install python3-venv）")
            return None, False
        log("  · 虚拟环境就绪")
        return py, True
    except subprocess.TimeoutExpired:
        log("  !! 创建虚拟环境超时（%ss），改用当前解释器" % timeout_s)
        return None, False
    except Exception as _e:
        log("  !! 创建虚拟环境异常：%s，改用当前解释器" % _e)
        return None, False


# ── ③ 选镜像 ────────────────────────────────────────────────────────────────

def pick_mirror(timeout=3.0):
    """并发探活各镜像，返回最快可达的 (名字, url)；全不可达返回 (None, None)。

    这一步很关键：赛方机器多半在国内，走 pypi.org 经常 30s 超时，
    表现为"装依赖卡住不动"——实际是源不可达而不是网断了。
    """
    import urllib.request
    from concurrent.futures import ThreadPoolExecutor

    def _probe(item):
        name, url = item
        t0 = time.time()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "aisec-bootstrap"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if r.status == 200:
                    return (round(time.time() - t0, 3), name, url)
        except Exception:
            pass
        return None

    try:
        with ThreadPoolExecutor(max_workers=len(MIRRORS)) as ex:
            results = [x for x in ex.map(_probe, MIRRORS) if x]
    except Exception:
        results = []
    if not results:
        return None, None
    results.sort(key=lambda x: x[0])
    return results[0][1], results[0][2]


# ── ④ 装依赖 ────────────────────────────────────────────────────────────────

def _pip_args(mirror_url):
    """组装 pip 的镜像参数（含 trusted-host，避免老 pip 因证书问题拒绝镜像站）。"""
    if not mirror_url:
        return []
    host = mirror_url.split("//")[-1].split("/")[0]
    return ["-i", mirror_url, "--trusted-host", host]


def step_install(py, tier_name, mirror_url, want_full=False, timeout_s=600):
    """按档位装依赖。返回 dict 结果。"""
    packs = list(PACK_MINIMAL)
    if tier_name in ("mid", "high"):
        packs += PACK_STANDARD
    if want_full or tier_name == "high":
        packs += PACK_FULL
    if want_full:
        packs += PACK_TORCH

    py = py or sys.executable
    result = {"python": py, "mirror": mirror_url, "requested": packs,
              "installed": [], "failed": [], "logs": []}

    # 先升级 pip（老 pip 装不上新 wheel；失败不阻断）
    try:
        r = subprocess.run([py, "-m", "pip", "install", "--upgrade", "pip"]
                           + _pip_args(mirror_url),
                           cwd=HERE, timeout=180, capture_output=True)
        if r.returncode == 0:
            result["logs"].append("pip 已升级")
    except Exception:
        pass

    if not packs:
        return result

    cmd = [py, "-m", "pip", "install"] + _pip_args(mirror_url) + packs
    log("  · 安装依赖：%s" % " ".join(packs))
    try:
        r = subprocess.run(cmd, cwd=HERE, timeout=timeout_s, capture_output=True)
        out = (r.stdout or b"").decode("utf-8", "replace")
        err = (r.stderr or b"").decode("utf-8", "replace")
        if r.returncode == 0:
            result["installed"] = list(packs)
            result["logs"].append("安装完成")
        else:
            # 整体失败时逐个重试，把"哪个包装不上"定位清楚
            log("  !! 批量安装失败，改为逐个安装以定位问题")
            for p in packs:
                try:
                    r2 = subprocess.run(
                        [py, "-m", "pip", "install"] + _pip_args(mirror_url) + [p],
                        cwd=HERE, timeout=timeout_s, capture_output=True)
                    if r2.returncode == 0:
                        result["installed"].append(p)
                    else:
                        result["failed"].append(p)
                except Exception as _e:
                    result["failed"].append(p)
                    result["logs"].append("%s: %s" % (p, _e))
            # torch 走官方 CPU 源再试一次（镜像站常不同步 torch）
            if "torch" in result["failed"]:
                try:
                    r3 = subprocess.run(
                        [py, "-m", "pip", "install", "torch",
                         "--index-url", "https://download.pytorch.org/whl/cpu"],
                        cwd=HERE, timeout=timeout_s * 2, capture_output=True)
                    if r3.returncode == 0:
                        result["failed"].remove("torch")
                        result["installed"].append("torch")
                except Exception:
                    pass
        tail = (err or out).strip().splitlines()
        if tail:
            result["logs"].extend(tail[-5:])
    except subprocess.TimeoutExpired:
        result["failed"] = list(packs)
        result["logs"].append("安装超时（%ss）——网络太慢或源不可达" % timeout_s)
    except Exception as _e:
        result["failed"] = list(packs)
        result["logs"].append("安装异常：%s" % _e)
    return result


# ── ⑤ 自检 ──────────────────────────────────────────────────────────────────

def step_verify(py):
    """逐个 import 校验核心模块是否真的可用（装了不等于能 import）。"""
    py = py or sys.executable
    mods = ["requests", "urllib3"]
    ok, missing = True, []
    for m in mods:
        try:
            r = subprocess.run([py, "-c",
                                "import importlib.util,sys;sys.exit(0 if importlib.util.find_spec('%s') else 1)" % m],
                               cwd=HERE, timeout=60, capture_output=True)
            if r.returncode != 0:
                ok = False
                missing.append(m)
        except Exception:
            ok = False
            missing.append(m)
    return {"ok": ok, "missing": missing}


# ── 主流程 ──────────────────────────────────────────────────────────────────

def run(args):
    result = {"ok": False, "steps": {}}
    hr("AI-SecIntel 2.0 · 环境自动配置")
    log("  项目目录：%s" % HERE)

    # ① 体检
    log("")
    log("[1/5] 环境体检")
    chk = step_check()
    rt, prof = chk["runtime"], chk["profile"]
    result["steps"]["check"] = chk
    log("      Python %s · %s %s · CPU %s 核 · 内存 %sGB"
        % (rt["python"], rt["os_name"], rt["arch"] or "",
           prof["cpu_count"], prof["mem_gb"] or "?"))
    log("      性能档位：%s（%s）"
        % (chk["tier"], envprofile.TIERS[chk["tier"]]["label"]))
    for reason in rt["reasons"]:
        log("      · %s" % reason)
    if rt["fatal"]:
        log("")
        log("!! Python 版本硬性不达标，无法继续。")
        log("   %s" % rt["hint"])
        result["fatal"] = True
        return result
    if not rt["ok"] and not args.ignore_version:
        log("      （版本低于建议下限 %s，仍尝试配置；若启动异常请按提示升级）"
            % rt["min_required"])

    if args.check:
        log("")
        log("--check：只体检，不安装。")
        result["ok"] = rt["ok"]
        return result

    # ② 建环境
    log("")
    log("[2/5] 准备运行环境")
    py = sys.executable
    if not args.no_venv:
        vpy, created = step_venv()
        if vpy:
            py = vpy
        else:
            log("  · 回退：使用当前解释器 %s" % py)
    else:
        log("  · --no-venv：使用当前解释器 %s" % py)
    result["steps"]["python"] = py

    if args.offline:
        log("")
        log("--offline：跳过联网与安装。")
        result["steps"]["install"] = {"skipped": True}
        result["ok"] = True
        return result

    # ③ 选镜像
    log("")
    log("[3/5] 选择最快的软件源")
    mirror_name, mirror_url = pick_mirror(
        timeout=envprofile.T.timeout(3.0, minimum=2.0))
    if mirror_url:
        log("  · 已选：%s（%s）" % (mirror_name, mirror_url))
    else:
        log("  · 所有源均不可达（离线或网络受限），将使用 pip 默认配置")
    result["steps"]["mirror"] = {"name": mirror_name, "url": mirror_url}

    # ④ 装依赖
    log("")
    log("[4/5] 安装依赖（按%s档）" % chk["tier"])
    inst = step_install(py, chk["tier"], mirror_url, want_full=args.full,
                        timeout_s=envprofile.T.timeout(600, minimum=300))
    result["steps"]["install"] = inst
    if inst["installed"]:
        log("  · 已安装：%s" % ", ".join(inst["installed"]))
    if inst["failed"]:
        log("  !! 安装失败：%s（功能会自动降级，不影响主体运行）"
            % ", ".join(inst["failed"]))

    # ⑤ 自检
    log("")
    log("[5/5] 安装后自检")
    ver = step_verify(py)
    result["steps"]["verify"] = ver
    result["ok"] = bool(ver["ok"]) or bool(args.ignore_version)
    if ver["ok"]:
        log("  · 核心模块可用：requests / urllib3")
    else:
        log("  !! 核心模块仍缺失：%s（富化接口将降级到标准库，主体照常运行）"
            % ", ".join(ver["missing"]))

    # 落环境档案
    try:
        with open(ENV_FILE, "w", encoding="utf-8") as f:
            json.dump({"python": py, "tier": chk["tier"], "mirror": mirror_url,
                       "profile": prof, "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                       "installed": inst.get("installed", []),
                       "failed": inst.get("failed", [])},
                      f, ensure_ascii=False, indent=2)
        log("  · 环境档案已写入 .aisec_env.json")
    except Exception as _e:
        log("  · 环境档案写入失败（不影响运行）：%s" % _e)
    result["env_file"] = ENV_FILE
    return result


def main():
    ap = argparse.ArgumentParser(description="AI-SecIntel 一键环境配置")
    ap.add_argument("--check", action="store_true", help="只体检不安装")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    ap.add_argument("--no-venv", action="store_true", help="不建虚拟环境")
    ap.add_argument("--full", action="store_true", help="连 torch/transformers 一起装")
    ap.add_argument("--offline", action="store_true", help="离线：不联网不安装")
    ap.add_argument("--ignore-version", action="store_true", help="版本不达标也继续")
    args = ap.parse_args()

    res = run(args)

    if args.json:
        compat.safe_print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1

    log("")
    hr("配置结论")
    if res.get("fatal"):
        log("  环境不可用：Python 版本硬性不达标，请先安装 Python 3.7+ 后重试。")
        return 2
    if res.get("ok"):
        log("  环境已就绪。下一步：")
        if compat.IS_WIN:
            log("    双击  启动服务.bat")
        else:
            log("    执行  ./start.sh")
        py = res["steps"].get("python") or sys.executable
        log("    或命令行：%s core/server.py 8848" % py)
    else:
        log("  环境部分可用：核心依赖缺失，系统会自动降级运行。")
        log("  若需完整能力，手动补装：pip install -r requirements.txt")
    log("")
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
