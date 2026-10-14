"""tools/_test_circuit.py —— 源熔断 / 镜像回退 / 自愈事件回填 的回归测试

为什么必须是"真打"而不是静态断言：
  熔断的全部价值在于**时间维度上的状态迁移**（失败累积 → 熔断 → 冷却 → 半开 →
  恢复）。静态扫源码永远证明不了"第 3 次失败真的会熔断""冷却到期真的会半开"。
  所以这里直接驱动 CircuitBreaker，走完整状态机，并对**副作用**
  （circuit_events.jsonl / dispositions.json）做真实文件断言。

跑法： py tools/_test_circuit.py
"""
import json
import os
import sys
import tempfile
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "core"))
sys.path.insert(0, _ROOT)          # modules.* 需要项目根在 path 里

PASS, FAIL = [], []


def ck(cond, name, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  [OK]   " if cond else "  [FAIL] ") + name + (
        ("  → " + str(extra)) if extra and not cond else ""))


def main():
    # 全部读写都指向临时目录，绝不碰生产 data/ 与真实处置库
    tmp = tempfile.mkdtemp(prefix="aisec_circuit_")
    import circuit
    circuit.paths.DATA_DIR = tmp
    circuit.STATE_FP = os.path.join(tmp, "circuit_state.json")
    circuit.EVENT_FP = os.path.join(tmp, "circuit_events.jsonl")
    # 事件回填指向临时处置库
    import modules.m0_ops.backend.disposition as disp_mod  # noqa
    _orig_init = disp_mod.DispositionStore.__init__

    def _patched_init(self, data_dir):
        self.fp = os.path.join(tmp, "dispositions.json")
        import threading
        self._lock = threading.Lock()
    disp_mod.DispositionStore.__init__ = _patched_init

    # ── A. 失败累积到阈值才熔断（不是第 1 次就熔断）────────────────
    print("\nA. 熔断阈值")
    b = circuit.CircuitBreaker()
    ev1 = b.record("nvd", False, "timeout")
    ev2 = b.record("nvd", False, "timeout")
    ck(ev1 == "-" and ev2 == "-", "前 2 次失败不熔断", f"got {ev1},{ev2}")
    ck(b.allow("nvd") is True, "未达阈值仍允许抓取")
    ev3 = b.record("nvd", False, "timeout")
    ck(ev3 == "trip", "第 3 次失败熔断", f"got {ev3}")
    ck(b.allow("nvd") is False, "熔断后跳过该源（不再白等超时）")

    # ── B. 熔断状态落盘 + snapshot 可观测 ──────────────────────
    print("\nB. 状态可观测")
    b.flush()
    ck(os.path.isfile(circuit.STATE_FP), "熔断状态已落盘")
    snap = b.snapshot()
    ck("nvd" in snap and snap["nvd"]["state"] == "tripped", "snapshot 显示 tripped")
    ck(snap["nvd"]["cooldown_left_sec"] > 0, "冷却剩余秒数 > 0",
       snap["nvd"].get("cooldown_left_sec"))
    ck(snap["nvd"]["mirror_available"] is True, "nvd 有镜像可用")
    ck(snap["nvd"]["last_err"] == "timeout", "失败原因被保留")

    # ── C. 冷却到期自动半开（把冷却调成 0 来验证，不真的等 5 分钟）──
    print("\nC. 半开与恢复")
    old_cd = circuit.COOLDOWN_SEC
    circuit.COOLDOWN_SEC = 0
    ck(b.allow("nvd") is True, "冷却到期后半开，允许重试")
    ck(b.snapshot()["nvd"]["state"] == "half_open", "状态变为 half_open")
    b.record("nvd", True)                      # 成功 1 次，还不够
    ck(b.snapshot()["nvd"]["state"] == "half_open", "仅 1 次成功不解除（防抖）")
    r = b.record("nvd", True)                  # 连续第 2 次成功
    ck(r == "recover", "连续 2 次成功 → 恢复", f"got {r}")
    # 恢复后源是健康的，snapshot 有意不再列出（避免面板噪音）——
    # 所以断言的是"已从故障列表消失"而不是"state==ok"
    ck("nvd" not in b.snapshot(),
       "恢复后不再出现在故障面板（健康源不占版面）", b.snapshot())
    circuit.COOLDOWN_SEC = old_cd

    # ── D. 镜像：无镜像的源如实返回 None（不编造）──────────────
    print("\nD. 镜像回退")
    ck(bool(circuit.MIRRORS.get("nvd")), "nvd 配了镜像")
    ck(circuit.MIRRORS.get("kev") == [], "kev 无镜像如实为空数组")
    b2 = circuit.CircuitBreaker()
    for _ in range(3):
        b2.record("kev", False, "down")
    ck(b2.snapshot()["kev"]["mirror_available"] is False, "kev 熔断后标注无镜像")
    ck(b2.mirror_of("kev") is None, "kev 熔断期 mirror_of 返回 None")

    # ── E. 「本轮无新条目」不等于源挂了（这是最容易被写错的一条）──
    print("\nE. 空结果不误熔断")
    b3 = circuit.CircuitBreaker()
    # 快源 15s 轮询：连续 5 轮空（每次间隔很小）不应触发任何失败累计
    for _ in range(5):
        b3.record("csdn", True, empty=True, min_gap_sec=180)
    ck(b3.snapshot().get("csdn", {}).get("fails", 0) == 0,
       "短时间连续空结果不计失败", b3.snapshot().get("csdn"))
    # 持续空超过阈值 → 升级为失败。
    # 用 min_gap_sec=0.05（50ms）而不是 0，这样走的是「调用方显式给阈值」分支，
    # 不用真等 180s；先 sleep 60ms 让持续时长越过阈值。
    time.sleep(0.06)
    b3.record("csdn", True, empty=True, min_gap_sec=0.05)
    s3 = b3.snapshot().get("csdn", {})
    ck(s3.get("fails", 0) >= 1, "持续空超阈值后升级为失败", s3)
    ck("持续" in (s3.get("last_err") or ""), "失败原因写明是持续无数据", s3.get("last_err"))

    # ── F. 自愈事件真的落盘（熔断/恢复各有记录 + 回填处置库）────
    print("\nF. 自愈事件落盘")
    ck(os.path.isfile(circuit.EVENT_FP), "circuit_events.jsonl 已生成")
    evs = [json.loads(l) for l in open(circuit.EVENT_FP, encoding="utf-8") if l.strip()]
    kinds = [e["kind"] for e in evs]
    ck("trip" in kinds, "有 trip 事件", kinds)
    ck("recover" in kinds, "有 recover 事件", kinds)
    ck("half_open" in kinds, "有 half_open 事件", kinds)
    ck(any(e.get("detail") for e in evs), "事件带可读 detail")
    d_fp = os.path.join(tmp, "dispositions.json")
    ck(os.path.isfile(d_fp), "处置记忆库被自动回填")
    recs = json.load(open(d_fp, encoding="utf-8"))
    ck(len(recs) >= 2, "处置库至少 2 条（trip+recover）", len(recs))
    ck(all(r.get("actor") == "auto:circuit" for r in recs),
       "回填来源标记为自动（actor=auto:circuit）")
    ck(all(r.get("cve") for r in recs), "每条都有 cve 字段（库结构一致，未被拒）")
    ck(any("src:nvd" == r.get("component") for r in recs),
       "component 标记为 src:<源名>，可按源筛选")

    # ── G. 跨进程重启不直接触发熔断（fails 折半）──────────────
    print("\nG. 重启不误熔断")
    b4 = circuit.CircuitBreaker()
    b4.record("xz", False, "e1")
    b4.record("xz", False, "e1")
    b4.flush()
    b5 = circuit.CircuitBreaker()          # 模拟进程重启后重新加载
    ck(b5.snapshot().get("xz", {}).get("fails", 0) == 1,
       "重启后 fails 折半（2→1），不会一启动就熔断",
       b5.snapshot().get("xz"))

    # ── H. 损坏的状态文件不阻断（首跑/被截断都当空状态）────────
    print("\nH. 容错")
    with open(circuit.STATE_FP, "w", encoding="utf-8") as f:
        f.write("{坏掉的 JSON")
    b6 = circuit.CircuitBreaker()
    ck(b6.snapshot() == {}, "状态文件损坏时退化为空状态，不抛异常")
    ck(b6.allow("nvd") is True, "损坏后仍允许全部源抓取（宁多抓不漏抓）")

    disp_mod.DispositionStore.__init__ = _orig_init
    print("\n" + "=" * 58)
    print("通过 %d / 失败 %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项：")
        for f in FAIL:
            print("  · " + f)
    print("=" * 58)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
