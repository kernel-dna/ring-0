"""Alert windows: cut what the SIEM and the ML flagged out of the normal dataset.

``train_markov_from_dataset`` learns every line of a recorded day as normal,
a scanner burst included, and so does replay when it measures alerts per day.
The worker's quarantine only protects the live profile. This module turns
alerts into windows, drops the events inside them from training and replay,
and writes them out as labelled traces in the attack-trace format: raw
KernelEventV1 lines plus a ``.cgroups.json`` sidecar, scorable by
``replay --attacks``.

A window has a scope, because web rules fire in bursts: 12 478 "dotfile
probing" alerts fell in 355 distinct minutes over 30 days, 6 297 of them on
2026-11-20. A host-wide window per alert would discard hours of every process.
A web alert removes only the web stack's units instead. A shell spawned by
gunicorn stays in kernel-ai.service, so an exploit that worked is cut whole.
An ML alert carries a pid and removes that process alone.

Alerts are read on PROD (Elastic key from elastic.env, DSN from ml.env, both
read-only); the dataset is replayed wherever it was copied::

    ssh prod 'cd /opt/ring0/kernel-ai && sudo bash -c "set -a; . /etc/kernel-ai/ml.env; \\
        set +a; PYTHONPATH=. venv/bin/python - fetch --since 2026-11-18"' \\
        < kernel_ai/ml/exclusions.py > alerts.json
    python -m kernel_ai.ml.exclusions cut --data ~/kernel-ai-eval/prod-normal \\
        --alerts alerts.json --out ~/kernel-ai-eval/alert-windows
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from bisect import bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from itertools import accumulate
from pathlib import Path
from typing import Iterable

# The worker's poisoning guard keeps the same margin around a high anomaly.
PAD_SEC = 120.0
WEB_UNITS = ("unit:nginx.service", "unit:kernel-ai.service")
SSH_UNITS = ("unit:ssh.service", "unit:ssh@.service")
# Stage 1/2 judge host-wide magnitudes and carry no pid. Stage 2 wrote a row a
# minute (1 867 a day) until its emit flag went off on 2026-11-21; a host-wide
# window per row would cut the whole day.
ML_SKIP = ("stage1_baseline", "stage2_isoforest")
ML_WEB = ("stage9_http", "stage9_success")
SEVERITY = ("low", "medium", "high", "critical")
_SIEM_SOURCE = [
    "@timestamp",
    "kibana.alert.original_time",
    "kibana.alert.threshold_result",
    "kibana.alert.rule.rule_id",
    "kibana.alert.rule.name",
    "kibana.alert.severity",
]


def _epoch(value) -> float | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, datetime):
        try:
            value = datetime.fromisoformat(str(value).strip().replace(" ", "T").replace("Z", "+00:00"))
        except ValueError:
            return None
    # A bare date on the command line means UTC, like the dataset's day directories.
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).timestamp()


def _severity(value) -> str:
    return value if value in SEVERITY else "medium"


@dataclass(frozen=True)
class Window:
    start: float
    end: float
    # Unit context keys (see ``unit_context``); empty means any unit.
    units: tuple[str, ...] = ()
    pid: int | None = None
    labels: tuple[str, ...] = ()
    severity: str = "medium"
    alerts: int = 1

    def covers(self, ts: float, pid: int, unit: str | None) -> bool:
        if not self.start <= ts <= self.end:
            return False
        if self.pid is not None and pid != self.pid:
            return False
        return not self.units or unit in self.units

    @property
    def scope(self) -> str:
        if self.pid is not None:
            return f"pid{self.pid}"
        if self.units == WEB_UNITS:
            return "web"
        if self.units == SSH_UNITS:
            return "ssh"
        return self.units[0].removeprefix("unit:") if self.units else "host"


def siem_scope(rule_id: str) -> tuple[str, ...] | None:
    """Units a rule's window covers: ``()`` is the whole host, None skips the rule."""
    if rule_id.endswith("-feed-stopped"):
        return None  # our own telemetry going quiet, not an attack
    if rule_id.startswith(("kernelai-web-", "kernelai-nginx-", "kernelai-flood-")):
        return WEB_UNITS
    if rule_id.startswith("kernelai-ssh-"):
        return SSH_UNITS
    return ()


def siem_windows(records: Iterable[dict], pad: float = PAD_SEC) -> list[Window]:
    out = []
    for r in records:
        rule = str(r.get("rule_id") or "")
        units = siem_scope(rule)
        end = _epoch(r.get("ts"))
        if units is None or end is None:
            continue
        # A threshold alert stands for every request counted since ``from``.
        start = min(_epoch(r.get("from")) or end, end)
        out.append(Window(start - pad, end + pad, units=units, labels=(f"siem:{rule}",),
                          severity=_severity(r.get("severity"))))
    return out


def ml_windows(records: Iterable[dict], pad: float = PAD_SEC) -> list[Window]:
    out = []
    for r in records:
        source = str(r.get("source") or "")
        ts = _epoch(r.get("ts"))
        if source in ML_SKIP or ts is None:
            continue
        label = f"ml:{source}" + (f":{r['kind']}" if r.get("kind") else "")
        base = Window(ts - pad, ts + pad, labels=(label,), severity=_severity(r.get("severity")))
        if source in ML_WEB:
            out.append(replace(base, units=WEB_UNITS))
        elif r.get("pid"):
            out.append(replace(base, pid=int(r["pid"])))
        else:
            out.append(base)  # a verdict on the global window: no process to pin it to
    return out


def merge(windows: Iterable[Window]) -> list[Window]:
    """Union overlapping windows of one scope, so a burst of alerts is one window."""
    groups: dict[tuple, list[Window]] = defaultdict(list)
    for w in windows:
        groups[(w.pid, w.units)].append(w)
    out = []
    for group in groups.values():
        group.sort(key=lambda w: w.start)
        cur = group[0]
        for w in group[1:]:
            if w.start > cur.end:
                out.append(cur)
                cur = w
                continue
            cur = replace(
                cur,
                end=max(cur.end, w.end),
                labels=tuple(sorted(set(cur.labels) | set(w.labels))),
                severity=max(cur.severity, w.severity, key=SEVERITY.index),
                alerts=cur.alerts + w.alerts,
            )
        out.append(cur)
    return sorted(out, key=lambda w: (w.start, w.scope))


class WindowIndex:
    """Find the window covering an event; there are few windows and millions of events."""

    def __init__(self, windows: Iterable[Window]) -> None:
        self.windows = sorted(windows, key=lambda w: w.start)
        self._starts = [w.start for w in self.windows]
        # Running max of the ends: a lookup scans back only while an earlier
        # window can still be open.
        self._reach = list(accumulate((w.end for w in self.windows), max))

    def __len__(self) -> int:
        return len(self.windows)

    def match(self, ts: float, pid: int, unit: str | None) -> Window | None:
        i = bisect_right(self._starts, ts) - 1
        while i >= 0 and self._reach[i] >= ts:
            w = self.windows[i]
            if w.covers(ts, pid, unit):
                return w
            i -= 1
        return None

    @classmethod
    def from_alerts(cls, path: str, *, pad: float = PAD_SEC) -> "WindowIndex":
        data = json.loads(Path(path).expanduser().read_text())
        return cls(merge(siem_windows(data.get("siem") or [], pad) + ml_windows(data.get("ml") or [], pad)))


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


class _CutWriter:
    """Append each excluded line to its window's trace; few windows are open at once."""

    MAX_OPEN = 32

    def __init__(self, out_dir: str) -> None:
        self.out = Path(out_dir).expanduser()
        self.out.mkdir(parents=True, exist_ok=True)
        self.traces: dict[Window, dict] = {}
        self._open: dict[Window, object] = {}
        self._cgroups: dict[str, dict[int, str]] = {}

    def _fh(self, w: Window, rec: dict):
        fh = self._open.get(w)
        if fh is None:
            if len(self._open) >= self.MAX_OPEN:
                self._open.pop(next(iter(self._open))).close()
            fh = self._open[w] = open(self.out / f"{rec['name']}.jsonl", "ab" if rec["events"] else "wb")
        return fh

    def add(self, w: Window, obj: dict, line: bytes, day: str) -> None:
        from kernel_ai.ml.normal_dataset import load_cgroups

        rec = self.traces.get(w)
        if rec is None:
            slug = re.sub(r"[^a-z0-9]+", "-", w.labels[0].lower()).strip("-")[:48] if w.labels else "alert"
            name = f"{time.strftime('%Y%m%dT%H%M%S', time.gmtime(w.start))}-{w.scope}-{slug}"
            rec = self.traces[w] = {"name": name, "events": 0, "by_syscall": Counter(), "cgroups": {}}
        self._fh(w, rec).write(line + b"\n")
        rec["events"] += 1
        rec["by_syscall"][str((obj.get("syscall") or {}).get("name"))] += 1
        if day not in self._cgroups:
            self._cgroups[day] = load_cgroups(day)
        try:
            path = self._cgroups[day].get(int(obj.get("cgroup_id") or 0))
        except (TypeError, ValueError):
            path = None
        if path is not None:
            rec["cgroups"][str(obj["cgroup_id"])] = path

    def close(self) -> list[dict]:
        for fh in self._open.values():
            fh.close()
        self._open = {}
        index = []
        for w, rec in self.traces.items():
            (self.out / f"{rec['name']}.cgroups.json").write_text(
                json.dumps(rec["cgroups"], indent=0, sort_keys=True))
            index.append({
                "file": f"{rec['name']}.jsonl",
                "start": _iso(w.start),
                "end": _iso(w.end),
                "scope": w.scope,
                "units": list(w.units),
                "pid": w.pid,
                "labels": list(w.labels),
                "severity": w.severity,
                "alerts": w.alerts,
                "events": rec["events"],
                "by_syscall": dict(rec["by_syscall"].most_common()),
            })
        index.sort(key=lambda r: (r["start"], r["scope"]))
        (self.out / "index.json").write_text(json.dumps(index, indent=1, ensure_ascii=False))
        return index


def cut(root: str, days: list[str] | None, index: WindowIndex, out_dir: str) -> dict:
    """Write every excluded event to its window's trace; return what was cut."""
    from kernel_ai.ml.replay import iter_dataset_events

    writer = _CutWriter(out_dir)
    kept = 0
    for _ in iter_dataset_events(root, days, exclude=index, on_excluded=writer.add):
        kept += 1
    traces = writer.close()
    excluded = sum(t["events"] for t in traces)
    by_label: Counter = Counter()
    for t in traces:
        by_label[t["labels"][0] if t["labels"] else "?"] += t["events"]
    return {
        "windows": len(index),
        "windows_with_events": len(traces),
        "kept": kept,
        "excluded": excluded,
        "excluded_share": round(excluded / max(1, kept + excluded), 4),
        "excluded_by_label": dict(by_label.most_common()),
        "out": str(writer.out),
    }


# -- fetch, run on PROD -------------------------------------------------------


def fetch_siem(since: float, until: float | None) -> list[dict]:
    from kernel_ai.services.siem import _es_search, _load_config

    cfg = _load_config()
    if not cfg.get("url") or not cfg.get("api_key"):
        raise SystemExit("Elastic is not configured (KERNEL_AI_ES_URL / KERNEL_AI_ES_API_KEY)")
    span = {"gte": int(since * 1000), "format": "epoch_millis"}
    if until is not None:
        span["lt"] = int(until * 1000)
    body = {
        "size": 1000,
        "query": {"range": {"kibana.alert.original_time": span}},
        "sort": [{"@timestamp": "asc"}, {"kibana.alert.uuid": "asc"}],
        "_source": _SIEM_SOURCE,
    }
    out = []
    while True:
        hits = (_es_search(cfg, body, timeout=30.0).get("hits") or {}).get("hits") or []
        for hit in hits:
            src = hit.get("_source") or {}
            out.append({
                "ts": _epoch(src.get("kibana.alert.original_time") or src.get("@timestamp")),
                "from": _epoch((src.get("kibana.alert.threshold_result") or {}).get("from")),
                "rule_id": src.get("kibana.alert.rule.rule_id"),
                "rule": src.get("kibana.alert.rule.name"),
                "severity": src.get("kibana.alert.severity"),
            })
        if len(hits) < body["size"]:
            return out
        body["search_after"] = hits[-1]["sort"]


def fetch_ml(since: float, until: float | None) -> list[dict]:
    from kernel_ai.ml.config import MLConfig
    from kernel_ai.ml.store import connect

    with connect(MLConfig().dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT ts, source, severity, meta->>'pid', meta->>'kind'
            FROM ml_anomalies
            WHERE ts >= to_timestamp(%s) AND ts < to_timestamp(%s) AND NOT (source = ANY(%s))
            ORDER BY ts
            """,
            (since, until if until is not None else time.time() + 60, list(ML_SKIP)),
        )
        return [
            {"ts": ts.timestamp(), "source": source, "severity": severity,
             "pid": int(pid) if pid and pid.isdigit() else None, "kind": kind}
            for ts, source, severity, pid, kind in cur.fetchall()
        ]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch", help="read SIEM alerts and ML anomalies as JSON (run on PROD)")
    f.add_argument("--since", required=True, help="UTC date or ISO time")
    f.add_argument("--until", help="UTC date or ISO time (default: now)")
    c = sub.add_parser("cut", help="write alert windows out of a normal dataset")
    c.add_argument("--data", required=True, help="kernel-ai-normal root")
    c.add_argument("--days", nargs="*", help="UTC days (default: all)")
    c.add_argument("--alerts", required=True, help="output of fetch")
    c.add_argument("--out", required=True, help="directory for the labelled traces")
    c.add_argument("--pad", type=float, default=PAD_SEC, help="seconds around each alert")
    args = ap.parse_args()

    if args.cmd == "fetch":
        since, until = _epoch(args.since), _epoch(args.until)
        if since is None:
            raise SystemExit(f"--since: not a date: {args.since}")
        json.dump({"since": since, "until": until, "siem": fetch_siem(since, until),
                   "ml": fetch_ml(since, until)}, sys.stdout)
        return
    index = WindowIndex.from_alerts(args.alerts, pad=args.pad)
    print(json.dumps(cut(str(Path(args.data).expanduser()), args.days, index, args.out), indent=1))


if __name__ == "__main__":
    main()
