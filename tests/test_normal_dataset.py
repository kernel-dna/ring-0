"""Tests for the frozen normal dataset recorder and its replay reader."""

import gzip
import json

from kernel_ai.ml.normal_dataset import (
    HourlyRecorder,
    enforce_budget,
    iter_events,
    iter_lines,
)

# 2026-11-17T14:59:58Z
T0 = 1794927598.0


class Clock:
    def __init__(self, t: float) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def _line(seq: int, name: str = "connect") -> bytes:
    return json.dumps(
        {"schema": "kernel.event/v1", "seq": seq, "kind": "syscall_span", "pid": 7,
         "syscall": {"nr": 42, "name": name, "args": [3, 0, 16, 0, 0, 0]}},
        separators=(",", ":"),
    ).encode()


def _rec(tmp_path, clock, **kw):
    return HourlyRecorder(
        tmp_path / "normal",
        sensor_socket="/nonexistent.sock",
        sensor_binary="/nonexistent-bin",
        min_free_bytes=0,
        clock=clock,
        **kw,
    )


def test_rotates_by_utc_hour_and_writes_meta(tmp_path):
    clock = Clock(T0)
    rec = _rec(tmp_path, clock)
    rec.connected()
    rec.write(_line(1))
    rec.write(_line(2, "execve"))
    clock.t = T0 + 5  # 15:00:03
    rec.write(_line(3))
    rec.close()

    day = tmp_path / "normal" / "2026-11-17"
    assert sorted(p.name for p in day.iterdir()) == [
        "14.jsonl.gz", "14.meta.json", "15.jsonl.gz", "15.meta.json", "manifest.json",
    ]
    meta14 = json.loads((day / "14.meta.json").read_text())
    assert meta14["events"] == 2
    assert meta14["by_syscall"] == {"connect": 1, "execve": 1}
    assert json.loads((day / "manifest.json").read_text())["format"].startswith("kernel-ai.")
    assert [e["seq"] for e in iter_events(tmp_path / "normal")] == [1, 2, 3]


def test_lines_are_stored_verbatim(tmp_path):
    rec = _rec(tmp_path, Clock(T0))
    raw = _line(9)
    rec.write(raw + b"\n")
    rec.close()
    path = tmp_path / "normal" / "2026-11-17" / "14.jsonl.gz"
    assert list(iter_lines(path)) == [raw]


def test_seq_reset_counts_sensor_restart_not_forward_gap(tmp_path):
    rec = _rec(tmp_path, Clock(T0))
    for seq in (10, 50, 51, 3, 4):
        rec.write(_line(seq))
    assert rec.stats.seq_resets == 1


def test_restart_within_hour_appends_and_merges_meta(tmp_path):
    clock = Clock(T0 - 60)
    first = _rec(tmp_path, clock)
    first.write(_line(1))
    first.close()
    second = _rec(tmp_path, clock)
    second.write(_line(2))
    second.write(_line(3))
    second.close()

    day = tmp_path / "normal" / "2026-11-17"
    assert json.loads((day / "14.meta.json").read_text())["events"] == 3
    assert [e["seq"] for e in iter_events(tmp_path / "normal")] == [1, 2, 3]


def test_truncated_tail_reads_up_to_last_flush(tmp_path):
    clock = Clock(T0 - 100)
    rec = _rec(tmp_path, clock, flush_sec=0.0)
    for seq in range(1, 6):
        rec.write(_line(seq))
    # Recorder never closed, as after kill -9: no gzip trailer on disk.
    path = tmp_path / "normal" / "2026-11-17" / "14.jsonl.gz"
    assert [json.loads(l)["seq"] for l in iter_lines(path)] == [1, 2, 3, 4, 5]


def test_disconnect_time_is_accounted(tmp_path):
    clock = Clock(T0 - 100)
    rec = _rec(tmp_path, clock)
    rec.connected()
    rec.write(_line(1))
    rec.disconnected()
    clock.t += 12
    rec.connected()
    assert rec.stats.reconnects == 1
    assert rec.stats.disconnected_sec == 12


def test_low_disk_skips_and_counts(tmp_path):
    rec = HourlyRecorder(
        tmp_path / "normal",
        sensor_socket="/x",
        sensor_binary="/x",
        min_free_bytes=1 << 62,
        clock=Clock(T0),
    )
    rec.write(_line(1))
    rec.write(_line(2))
    assert rec.stats.events == 0
    assert rec.stats.skipped_low_disk == 2


def test_budget_drops_oldest_whole_days_but_never_today(tmp_path):
    root = tmp_path / "normal"
    for day in ("2026-11-14", "2026-11-15", "2026-11-16"):
        (root / day).mkdir(parents=True)
        (root / day / "00.jsonl.gz").write_bytes(b"x" * 1000)
    removed = enforce_budget(root, 1500, keep=root / "2026-11-14")
    assert [p.name for p in removed] == ["2026-11-15", "2026-11-16"]
    assert [p.name for p in root.iterdir()] == ["2026-11-14"]


def test_iter_lines_on_garbage_file_is_empty(tmp_path):
    path = tmp_path / "bad.jsonl.gz"
    path.write_bytes(b"not gzip at all")
    assert list(iter_lines(path)) == []
    path2 = tmp_path / "ok.jsonl.gz"
    with gzip.open(path2, "wb") as fh:
        fh.write(b'{"a":1}\n{"b":')
    assert list(iter_lines(path2)) == [b'{"a":1}']


def _cg_line(seq: int, cgroup_id: int) -> bytes:
    return json.dumps(
        {"schema": "kernel.event/v1", "seq": seq, "kind": "syscall_span", "pid": 7,
         "cgroup_id": cgroup_id, "syscall": {"name": "connect"}},
        separators=(",", ":"),
    ).encode()


def _fake_cgroupfs(tmp_path):
    root = tmp_path / "cgroup"
    (root / "system.slice" / "nginx.service").mkdir(parents=True)
    (root / "user.slice" / "user-1000.slice" / "session-4.scope").mkdir(parents=True)
    ino = lambda p: (root / p).stat().st_ino  # noqa: E731
    return root, ino


def test_cgroup_map_records_ids_seen_and_survives_the_unit_going_away(tmp_path):
    from kernel_ai.ml.normal_dataset import CgroupMap, load_cgroups

    root, ino = _fake_cgroupfs(tmp_path)
    nginx, session = ino("system.slice/nginx.service"), ino("user.slice/user-1000.slice/session-4.scope")
    clock = Clock(T0 - 100)
    cg = CgroupMap(str(root), clock=clock, proc_root=str(tmp_path / "no-proc"))
    rec = _rec(tmp_path, clock, cgroups=cg)
    rec.write(_cg_line(1, nginx))
    # The session ends; its id was resolved while it existed and stays known.
    (root / "user.slice" / "user-1000.slice" / "session-4.scope").rmdir()
    rec.write(_cg_line(2, session))
    rec.write(_cg_line(3, nginx))
    rec.close()
    day = tmp_path / "normal" / "2026-11-17"
    assert load_cgroups(day) == {
        nginx: "system.slice/nginx.service",
        session: "user.slice/user-1000.slice/session-4.scope",
    }
    assert cg.scans == 1


def test_cgroup_map_rescans_for_a_new_id_but_not_per_event(tmp_path):
    from kernel_ai.ml.normal_dataset import CgroupMap, load_cgroups

    root, ino = _fake_cgroupfs(tmp_path)
    clock = Clock(T0 - 100)
    cg = CgroupMap(str(root), min_rescan_sec=10, clock=clock, proc_root=str(tmp_path / "no-proc"))
    rec = _rec(tmp_path, clock, cgroups=cg)
    rec.write(_cg_line(1, ino("system.slice/nginx.service")))
    (root / "system.slice" / "kernel-ai.service").mkdir()
    new = ino("system.slice/kernel-ai.service")
    for i in range(50):
        rec.write(_cg_line(2 + i, new))
    assert cg.scans == 1
    clock.t += 11
    rec.write(_cg_line(99, new))
    assert cg.scans == 2
    rec.write(_cg_line(100, 424242))  # never resolvable: one rescan, then remembered
    clock.t += 11
    rec.write(_cg_line(101, 424242))
    rec.write(_cg_line(102, 424242))
    rec.close()
    assert cg.scans == 3
    got = load_cgroups(tmp_path / "normal" / "2026-11-17")
    assert got[new] == "system.slice/kernel-ai.service" and 424242 not in got


def test_cgroup_map_names_a_short_job_from_proc_between_rescans(tmp_path):
    from kernel_ai.ml.normal_dataset import CgroupMap, load_cgroups

    root, ino = _fake_cgroupfs(tmp_path)
    proc = tmp_path / "proc"
    clock = Clock(T0 - 100)
    cg = CgroupMap(str(root), min_rescan_sec=10, clock=clock, proc_root=str(proc))
    rec = _rec(tmp_path, clock, cgroups=cg)
    rec.write(_cg_line(1, ino("system.slice/nginx.service")))
    # A timer's job starts right after the scan and is gone within seconds.
    (root / "system.slice" / "metrics.service").mkdir()
    job = ino("system.slice/metrics.service")
    (proc / "7").mkdir(parents=True)
    (proc / "7" / "cgroup").write_text("0::/system.slice/metrics.service\n")
    rec.write(_cg_line(2, job))
    (root / "system.slice" / "backup.service").mkdir()
    moved = ino("system.slice/backup.service")
    (root / "system.slice" / "metrics.service").rmdir()
    # pid 7 has since moved on: its cgroup now is not the event's, so it names nothing.
    (proc / "7" / "cgroup").write_text("0::/system.slice/nginx.service\n")
    rec.write(_cg_line(3, moved))
    rec.close()
    assert cg.scans == 1
    got = load_cgroups(tmp_path / "normal" / "2026-11-17")
    assert got[job] == "system.slice/metrics.service" and moved not in got
