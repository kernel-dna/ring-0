import gzip
import json
import random
import time

from kernel_ai.ml.exclusions import (
    PAD_SEC,
    WEB_UNITS,
    Window,
    WindowIndex,
    cut,
    merge,
    ml_windows,
    siem_windows,
)
from kernel_ai.ml.replay import iter_dataset_events

T0 = 1795219200.0  # 2026-11-21T00:00:00Z


def test_web_alert_cuts_the_web_stack_only():
    [w] = siem_windows([{"ts": T0 + 600, "rule_id": "kernelai-web-traversal", "severity": "high"}])
    idx = WindowIndex([w])
    assert idx.match(T0 + 600 - PAD_SEC, 7, "unit:nginx.service") is w
    assert idx.match(T0 + 650, 8, "unit:kernel-ai.service") is w
    assert idx.match(T0 + 650, 9, "unit:cron.service") is None
    assert idx.match(T0 + 600 + PAD_SEC + 1, 7, "unit:nginx.service") is None
    assert w.severity == "high" and w.labels == ("siem:kernelai-web-traversal",)


def test_threshold_alert_covers_everything_it_counted():
    [w] = siem_windows([{"ts": T0 + 600, "from": T0 + 300, "rule_id": "kernelai-web-scanner-404"}])
    assert (w.start, w.end) == (T0 + 300 - PAD_SEC, T0 + 600 + PAD_SEC)


def test_telemetry_rules_and_host_magnitude_stages_cut_nothing():
    assert siem_windows([{"ts": T0, "rule_id": "kernel-ai-ml-feed-stopped"}]) == []
    assert ml_windows([{"ts": T0, "source": "stage2_isoforest"},
                       {"ts": T0, "source": "stage1_baseline"}]) == []


def test_ml_alert_cuts_its_process_and_stage9_the_web_stack():
    w8, w9, w4 = ml_windows([
        {"ts": T0, "source": "stage8_sequence", "pid": 42},
        {"ts": T0, "source": "stage9_http", "kind": "attempt"},
        {"ts": T0, "source": "stage4_sequence"},
    ])
    assert w8.pid == 42 and w8.units == ()
    assert w9.units == WEB_UNITS and w9.labels == ("ml:stage9_http:attempt",)
    assert w4.pid is None and w4.units == ()
    idx = WindowIndex([w8])
    assert idx.match(T0, 42, "unit:cron.service") is w8
    assert idx.match(T0, 43, "unit:cron.service") is None


def test_a_burst_of_alerts_is_one_window():
    burst = [{"ts": T0 + i, "rule_id": "kernelai-web-sensitive-files"} for i in range(0, 300, 3)]
    burst.append({"ts": T0 + 100, "rule_id": "kernelai-web-traversal", "severity": "high"})
    ssh = {"ts": T0 + 100, "rule_id": "kernelai-ssh-bruteforce"}
    merged = merge(siem_windows(burst + [ssh]))
    [web] = [w for w in merged if w.scope == "web"]
    assert len(merged) == 2
    assert web.alerts == 101 and web.severity == "high"
    assert (web.start, web.end) == (T0 - PAD_SEC, T0 + 297 + PAD_SEC)
    assert set(web.labels) == {"siem:kernelai-web-sensitive-files", "siem:kernelai-web-traversal"}


def test_index_agrees_with_a_linear_scan():
    rnd = random.Random(7)
    # A long window ahead of many short ones forces lookups to scan back past it.
    windows = [Window(T0, T0 + 4000, pid=3)]
    for _ in range(200):
        start = T0 + rnd.uniform(-500, 9000)
        windows.append(Window(start, start + rnd.uniform(1, 300), pid=rnd.choice([None, 1, 2]),
                              units=rnd.choice([(), WEB_UNITS])))
    idx = WindowIndex(windows)
    for _ in range(3000):
        ts = T0 + rnd.uniform(-600, 9500)
        pid = rnd.choice([1, 2, 3])
        unit = rnd.choice(["unit:nginx.service", "unit:cron.service", None])
        hit = idx.match(ts, pid, unit)
        assert (hit is not None) == any(w.covers(ts, pid, unit) for w in windows)
        assert hit is None or hit.covers(ts, pid, unit)


def _line(ts, pid, cgroup, name):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + ".000000000Z"
    return json.dumps({"schema": "kernel.event/v1", "kind": "syscall_span", "timestamp": stamp,
                       "pid": pid, "uid": 33, "comm": "nginx" if cgroup == 5 else "cron",
                       "cgroup_id": cgroup, "syscall": {"name": name}}).encode()


def _dataset(root):
    day = root / "2026-11-21"
    day.mkdir(parents=True)
    (day / "cgroups.json").write_text(json.dumps(
        {"5": "system.slice/nginx.service", "6": "system.slice/cron.service"}))
    lines = []
    for i in range(600):
        lines.append(_line(T0 + i, 100, 5, "accept4" if i % 2 else "connect"))
        lines.append(_line(T0 + i, 200, 6, "clone" if i % 2 else "execve"))
    with gzip.open(day / "00.jsonl.gz", "wb") as fh:
        fh.write(b"\n".join(lines) + b"\n")
    return lines


def test_training_skips_exactly_what_cut_writes_out(tmp_path):
    from kernel_ai.ml.sequence_deep.train_markov import train_markov_from_dataset

    root = tmp_path / "normal"
    lines = _dataset(root)
    alerts = tmp_path / "alerts.json"
    alerts.write_text(json.dumps({
        "siem": [{"ts": T0 + 300, "rule_id": "kernelai-web-traversal", "severity": "high"}],
        "ml": [{"ts": T0 + 60, "source": "stage8_sequence", "pid": 200}],
    }))
    idx = WindowIndex.from_alerts(str(alerts))
    # nginx for 300±120 s, inclusive: 241 events; pid 200 from the start to 60+120 s: 181.
    kept = list(iter_dataset_events(str(root), None, exclude=idx))
    assert len(kept) == 1200 - 241 - 181
    assert not any(e.pid == 100 and T0 + 180 <= e.ts <= T0 + 420 for e in kept)

    summary = cut(str(root), None, idx, str(tmp_path / "cut"))
    assert summary["excluded"] == 241 + 181 and summary["kept"] == len(kept)
    index = json.loads((tmp_path / "cut" / "index.json").read_text())
    [web] = [r for r in index if r["scope"] == "web"]
    assert web["events"] == 241 and web["labels"] == ["siem:kernelai-web-traversal"]
    trace = tmp_path / "cut" / web["file"]
    written = trace.read_bytes().splitlines()
    assert len(written) == 241 and set(written) <= set(lines)
    sidecar = json.loads((tmp_path / "cut" / web["file"].replace(".jsonl", ".cgroups.json")).read_text())
    assert sidecar == {"5": "system.slice/nginx.service"}

    metrics = train_markov_from_dataset(str(root), None, str(tmp_path / "m.joblib"),
                                        context="unit", exclude=str(alerts))
    assert metrics["events"] == len(kept) and metrics["excluded_events"] == 241 + 181
