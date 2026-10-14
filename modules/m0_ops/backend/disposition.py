# -*- coding: utf-8 -*-
"""处置闭环回填记忆库 —— 把「静态决策」变成「越用越聪明的系统」。

机制创新点：决策智能体产出处置卡后并非终点。运营人员/下游系统处置完
（打补丁、验证、误报），把结果回填进来；下次遇到**同类漏洞**（同 CVE、
或同组件）决策时，直接复用历史处置经验：
  - 同 CVE 再出现 → 秒判「已处置/已验证」，不再重复研判
  - 同组件（component）新漏洞 → 自动带出「该组件上次怎么处置的」作为参照

落盘 data/dispositions.json，结构为处置记录列表，每条约：
  { cve, component, status, note, actor, ts }

status 取值：resolved(已修复) / verified(已验证) / false_positive(误报) / ignored(已接受风险)
"""
import json
import os
import threading
import time

DISPOSITION_CAP = 500

STATUS_LABELS = {
    "resolved": "已修复",
    "verified": "已验证",
    "false_positive": "误报",
    "ignored": "已接受风险",
}


class DispositionStore:
    """处置回填记忆库（确定性、无外部依赖，落盘 JSON）。"""

    def __init__(self, data_dir):
        self.fp = os.path.join(data_dir, "dispositions.json")
        # 读-改-写需串行：POST /api/ops/disposition 与编排守护线程可能并发回填
        self._lock = threading.Lock()

    def _load(self):
        try:
            if os.path.isfile(self.fp):
                with open(self.fp, encoding="utf-8") as f:
                    data = json.load(f)
                # 文件损坏/被外部改坏时可能不是列表；下面都按列表用，非列表一律当空库
                return data if isinstance(data, list) else []
        except Exception:  # noqa: BLE001
            pass
        return []

    def _save(self, data):
        """原子写。返回 True=落盘成功。失败必须上报——否则 record() 会
        返回 ok=True 骗前端「已回填」，实际磁盘上什么都没有（处置经验静默丢失）。"""
        tmp = "%s.%d.%d.tmp" % (self.fp, os.getpid(), threading.get_ident())
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data[-DISPOSITION_CAP:], f, ensure_ascii=False, indent=1)
            os.replace(tmp, self.fp)
            return True
        except Exception:  # noqa: BLE001
            try:
                if os.path.isfile(tmp):
                    os.remove(tmp)
            except OSError:
                pass
            return False

    def record(self, cve, status, component="", note="", actor=""):
        """回填一条处置结果。返回规范化后的记录。"""
        cve = (cve or "").strip().upper()
        if not cve:
            return {"ok": False, "error": "缺少 CVE"}
        if status not in STATUS_LABELS:
            return {"ok": False, "error": f"status 必须是 {list(STATUS_LABELS)} 之一"}
        rec = {
            "cve": cve,
            "component": (component or "").strip()[:80],
            "status": status,
            "status_label": STATUS_LABELS[status],
            "note": (note or "").strip()[:200],
            "actor": (actor or "").strip()[:40],
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        with self._lock:
            data = self._load()
            data.append(rec)
            if not self._save(data):
                return {"ok": False, "error": "处置记录落盘失败（磁盘/权限问题），本次回填未保存"}
        return {"ok": True, "record": rec}

    def for_cve(self, cve):
        """某 CVE 的历史处置（最新在前）。"""
        cve = (cve or "").strip().upper()
        data = self._load()
        return [r for r in data if r.get("cve") == cve][::-1]

    def _norm(self, s):
        """组件名归一化：去括号版本区间、去比较符+版本号，小写。"""
        import re
        s = (s or "").strip()
        s = re.sub(r"[（(][^)）]*[)）]", "", s)
        s = re.sub(r"[≤≥<>]=?\s*[\d.]+", "", s)
        s = re.sub(r"[≤≥<>]\s*[\d.]+", "", s)
        return s.strip().strip("-_ .").lower()

    def for_component(self, component):
        """同组件的所有处置（用于「同类组件自动关联」）。归一化后匹配。"""
        comp = self._norm(component)
        if not comp:
            return []
        data = self._load()
        out = []
        for r in data:
            rc = self._norm(r.get("component") or "")
            if not rc:
                continue
            # 双向子串：任一方向包含即视为同组件（覆盖「ollama」vs「ollama/ollama」这类前缀差异）
            if comp and (comp in rc or rc in comp):
                out.append(r)
        return out[::-1]

    def all(self, limit=50):
        data = self._load()
        return data[::-1][:limit]

    def boost(self, cve, components):
        """决策时的「历史经验加速」：返回同 CVE / 同组件的处置提示。

        返回 dict：
          same_cve: 该 CVE 是否已有处置（有则秒判，无需重复研判）
          related:  同组件的处置记录（作参照）
          hint:     一句可读的加速提示
        """
        cve = (cve or "").strip().upper()
        sc = self.for_cve(cve)
        comps = [c for c in (components or []) if c]
        rel = []
        seen = set()
        for c in comps:
            for r in self.for_component(c):
                if r.get("cve") == cve:
                    continue
                k = r.get("cve")
                if k not in seen:
                    seen.add(k)
                    rel.append(r)
        hint = ""
        if sc:
            latest = sc[0]
            hint = (f"该漏洞已有处置记录（{latest.get('status_label')}"
                    f"，{latest.get('ts', '')[:10]}），可跳过重复研判直接复用结论")
        elif rel:
            hint = (f"发现 {len(rel)} 个同组件({comps[0] if comps else ''})漏洞的处置参照，"
                    f"可沿用既有处置路径")
        return {"same_cve": bool(sc), "same_cve_records": sc[:3],
                "related": rel[:5], "hint": hint}
