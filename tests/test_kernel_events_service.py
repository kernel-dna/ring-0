"""Tests for ``kernel_ai.services.kernel_events``."""

import json
import os
import time

import pytest

from kernel_ai.services import kernel_events as svc


def _snapshot(tmp_path, monkeypatch, payload):
    path = tmp_path / "kernel-events.json"
    path.write_text(json.dumps(payload))
    monkeypatch.setattr(svc, "SNAPSHOT", str(path))
    return path


def _payload():
    return {
        "seq": 4,
        "dropped": 2,
        "min_duration_us": 100000,
        "traced_syscalls": ["read", "futex"],
        "sources": {"syscalls": "bpftrace", "wakeup": "sched_wakeup correlation"},
        "events": [
            {"seq": 1, "pid": 10, "tid": 10, "syscall": "read"},
            {"seq": 2, "pid": 20, "tid": 21, "syscall": "futex"},
            {"seq": 3, "pid": 10, "tid": 11, "syscall": "read"},
            {"seq": 4, "pid": 30, "tid": 30, "syscall": "read"},
        ],
    }


def test_filters_by_process_and_cursor(tmp_path, monkeypatch):
    _snapshot(tmp_path, monkeypatch, _payload())

    out = svc.get_kernel_events(pids=[10], since_seq=1)

    assert out["available"] is True
    assert [event["seq"] for event in out["events"]] == [3]
    assert out["seq"] == 4
    assert out["source"]["kind"] == "ebpf"
    assert out["source"]["dropped"] == 2


def test_limit_keeps_newest_events(tmp_path, monkeypatch):
    _snapshot(tmp_path, monkeypatch, _payload())

    out = svc.get_kernel_events(limit=2)

    assert [event["seq"] for event in out["events"]] == [3, 4]


def test_missing_or_stale_snapshot_is_honest(tmp_path, monkeypatch):
    monkeypatch.setattr(svc, "SNAPSHOT", str(tmp_path / "missing.json"))
    assert svc.get_kernel_events()["source"]["reason"] == "no-collector"

    path = _snapshot(tmp_path, monkeypatch, _payload())
    old = time.time() - 120
    os.utime(path, (old, old))
    assert svc.get_kernel_events()["source"]["reason"] == "stale"


def test_reports_when_client_cursor_fell_out_of_ring(tmp_path, monkeypatch):
    payload = _payload()
    payload["events"] = payload["events"][2:]
    _snapshot(tmp_path, monkeypatch, payload)

    assert svc.get_kernel_events(since_seq=1)["cursor_lost"] is True


def _security_snapshot(tmp_path, monkeypatch, events):
    path = tmp_path / "security-names.json"
    path.write_text(json.dumps({"seq": len(events), "dropped": 0, "events": events}))
    monkeypatch.setattr(svc, "SECURITY_SNAPSHOT", str(path))
    return path


def test_security_stream_publishes_names_only(tmp_path, monkeypatch):
    _security_snapshot(
        tmp_path,
        monkeypatch,
        [
            {
                "seq": 1,
                "syscall": "connect",
                "pid": 10,
                "comm": "curl",
                "args": [3, 0, 16],
                "sockaddr": "10.0.0.5:443",
            },
            {"seq": 2, "syscall": "execve", "ppid": 1, "path": "/usr/bin/id", "uid": 0,
             "unit": "nginx.service"},
            {"seq": 3, "syscall": "/usr/bin/id"},
            {"seq": 4, "syscall": "bind", "unit": "x/../../etc/passwd"},
        ],
    )

    out = svc.get_kernel_events(stream="security")

    assert out["events"] == [
        {"seq": 1, "syscall": "connect"},
        {"seq": 2, "syscall": "execve", "unit": "nginx.service"},
        {"seq": 4, "syscall": "bind"},
    ]
    assert out["source"]["stream"] == "security"
    assert out["source"]["fields"] == "names, units"
    assert "traced_syscalls" not in out["source"]


def test_security_stream_passes_a_mutation_only_with_a_clean_ngram(tmp_path, monkeypatch):
    path = _security_snapshot(
        tmp_path,
        monkeypatch,
        [
            {"seq": 1, "syscall": "execve", "pid": 7, "novel": True, "ngram": ["connect", "clone", "execve"]},
            {"seq": 2, "syscall": "execve", "novel": True, "ngram": ["connect", "/bin/sh", "execve"]},
            {"seq": 3, "syscall": "execve", "novel": "yes", "ngram": ["bind", "clone", "execve"]},
            {"seq": 4, "syscall": "execve", "novel": True},
            {"seq": 5, "syscall": "execve", "novel": True, "ngram": ["bind"] * 9},
        ],
    )

    out = svc.get_kernel_events(stream="security")

    assert out["events"] == [
        {"seq": 1, "syscall": "execve", "novel": True, "ngram": ["connect", "clone", "execve"]},
        {"seq": 2, "syscall": "execve"},
        {"seq": 3, "syscall": "execve"},
        {"seq": 4, "syscall": "execve"},
        {"seq": 5, "syscall": "execve"},
    ]
    assert out["source"]["fields"] == "names, units"

    payload = json.loads(path.read_text())
    payload["sources"] = {"fields": "names, units, mutations"}
    path.write_text(json.dumps(payload))
    assert svc.get_kernel_events(stream="security")["source"]["fields"] == "names, units, mutations"


def test_security_stream_passes_only_a_small_integer_lane(tmp_path, monkeypatch):
    path = _security_snapshot(
        tmp_path,
        monkeypatch,
        [{"seq": i + 1, "syscall": "accept4", "lane": lane}
         for i, lane in enumerate([0, 999, 1000, -1, True, "3", 2.0])],
    )
    payload = json.loads(path.read_text())
    payload["sources"] = {"fields": "names, units, lanes, mutations, pids"}
    path.write_text(json.dumps(payload))

    out = svc.get_kernel_events(stream="security")

    assert [e.get("lane") for e in out["events"]] == [0, 999, None, None, None, None, None]
    assert out["source"]["fields"] == "names, units, lanes, mutations"


def test_security_stream_marks_the_requesters_hops_and_never_passes_a_port(tmp_path, monkeypatch):
    path = _security_snapshot(
        tmp_path,
        monkeypatch,
        [
            {"seq": 1, "syscall": "connect", "unit": "nginx.service", "hop": 51234},
            {"seq": 2, "syscall": "accept4", "unit": "kernel-ai.service", "hop": 51234},
            {"seq": 3, "syscall": "accept4", "unit": "kernel-ai.service", "hop": 51236},
            {"seq": 4, "syscall": "accept4", "hop": "51234"},
            {"seq": 5, "syscall": "accept4", "hop": True},
        ],
    )

    out = svc.get_kernel_events(stream="security", mine=[51234, 1])

    assert [e.get("mine") for e in out["events"]] == ["request", "request", None, None, None]
    assert all("hop" not in e for e in out["events"])
    assert "51234" not in json.dumps(out)
    assert all("mine" not in e for e in svc.get_kernel_events(stream="security")["events"])
    assert out["source"]["fields"] == "names, units"

    payload = json.loads(path.read_text())
    payload["sources"] = {"fields": "names, units, hops, lanes"}
    path.write_text(json.dumps(payload))
    assert svc.get_kernel_events(stream="security")["source"]["fields"] == "names, units, lanes, mine"


def test_security_stream_marks_nginxs_accept_of_the_requesters_connection(tmp_path, monkeypatch):
    _security_snapshot(
        tmp_path,
        monkeypatch,
        [
            {"seq": 1, "syscall": "accept4", "unit": "nginx.service", "client": 40000},
            {"seq": 2, "syscall": "accept4", "unit": "nginx.service", "hop": 40000},
            {"seq": 3, "syscall": "connect", "unit": "user.slice", "hop": 40000},
            {"seq": 4, "syscall": "accept4", "unit": "nginx.service", "client": 40002},
            {"seq": 5, "syscall": "connect", "unit": "nginx.service", "hop": 51234},
            {"seq": 6, "syscall": "accept4", "unit": "kernel-ai.service", "hop": 51234},
            {"seq": 7, "syscall": "accept4", "client": "40000"},
        ],
    )

    out = svc.get_kernel_events(stream="security", mine=[51234], conns=[40000])

    assert [e.get("mine") for e in out["events"]] == ["connection", "connection", None, None, "request", "request", None]
    assert all("client" not in e and "hop" not in e for e in out["events"])
    assert "40000" not in json.dumps(out)


def test_conn_seqs_name_the_requesters_accepts_and_a_first_poll_reaches_back(tmp_path, monkeypatch):
    events = [{"seq": 1, "syscall": "accept4", "unit": "nginx.service", "client": 40000}]
    events += [{"seq": n, "syscall": "connect", "unit": "nginx.service"} for n in range(2, 12)]
    events += [{"seq": 12, "syscall": "accept4", "unit": "nginx.service", "client": 40002}]
    _security_snapshot(tmp_path, monkeypatch, events)

    first = svc.get_kernel_events(stream="security", limit=3, conns=[40000])
    assert [e["seq"] for e in first["events"]] == list(range(1, 13))
    assert first["conn_seqs"] == [1]
    later = svc.get_kernel_events(stream="security", since_seq=5, limit=3, conns=[40000, 40002])
    assert [e["seq"] for e in later["events"]] == [10, 11, 12]
    assert later["conn_seqs"] == [1, 12]
    assert len(svc.get_kernel_events(stream="security", limit=3)["events"]) == 3
    assert "conn_seqs" not in svc.get_kernel_events(stream="security", conns=[40004])


def test_only_the_security_stream_takes_mine(tmp_path, monkeypatch):
    with pytest.raises(ValueError):
        svc.get_kernel_events(stream="latency", mine=[51234])
    with pytest.raises(ValueError):
        svc.get_kernel_events(stream="latency", conns=[40000])


def test_security_stream_refuses_pid_filters_and_unknown_streams(tmp_path, monkeypatch):
    _security_snapshot(tmp_path, monkeypatch, [{"seq": 1, "syscall": "bind"}])

    with pytest.raises(ValueError):
        svc.get_kernel_events(stream="security", pids=[10])
    with pytest.raises(ValueError):
        svc.get_kernel_events(stream="raw")


def _immune_store(tmp_path, monkeypatch, alerts):
    path = tmp_path / "security-immune.json"
    path.write_text(json.dumps({"ts": 1.0, "alerts": alerts}))
    monkeypatch.setattr(svc, "IMMUNE_SNAPSHOT", str(path))
    monkeypatch.setattr(svc, "_immune", {"mtime": None, "alerts": {}})
    return path


def test_alert_fragment_passes_the_names_only_filter(tmp_path, monkeypatch):
    _immune_store(tmp_path, monkeypatch, {"a-1": {
        "rule": "Web: sensitive file / dotfile probing", "t": 2000.0,
        "units": ["nginx.service", "kernel-ai.service", "bad unit!"],
        "calls": [
            [2, "accept4", 0, 0],
            [3, "connect", 0, 4096],
            [4, "Exec ve", 1, 0],
            [5, "accept4", 2, 0],
            [6, "accept4", 9, 0],
            [7, "execve", 1, 1, ["accept4", "/bin/sh", "execve"]],
            [8, "execve", 1, 1, ["accept4", "clone", "execve"]],
            [9, "accept4", 1, 0, ["a", "b"], "203.0.113.9"],
            ["10", "accept4", 1, 0],
        ],
        "at": 3,
    }})

    out = svc.get_alert_fragment("a-1")

    assert out["available"] is True
    assert out["at_seq"] == 3
    assert out["units"] == ["nginx.service", "kernel-ai.service"]
    assert out["events"] == [
        {"seq": 2, "syscall": "accept4", "unit": "nginx.service", "lane": 0},
        {"seq": 3, "syscall": "connect", "unit": "nginx.service"},
        {"seq": 5, "syscall": "accept4", "lane": 0},
        {"seq": 7, "syscall": "execve", "unit": "kernel-ai.service", "lane": 1},
        {"seq": 8, "syscall": "execve", "unit": "kernel-ai.service", "lane": 1,
         "novel": True, "ngram": ["accept4", "clone", "execve"]},
    ]
    assert "t" not in out and "rule" not in out


def test_alert_fragment_reports_an_alert_it_never_captured(tmp_path, monkeypatch):
    _immune_store(tmp_path, monkeypatch, {})

    assert svc.get_alert_fragment("b-2")["available"] is False
    assert svc.get_alert_fragment("b-2")["source"]["reason"] == "not-captured"
    with pytest.raises(ValueError):
        svc.get_alert_fragment("../security-names")


def test_fragment_sizes_follow_the_store_when_it_changes(tmp_path, monkeypatch):
    path = _immune_store(tmp_path, monkeypatch, {"a": {"units": [], "calls": [[1, "bind", 0, 0]] * 3}})

    assert svc.fragment_sizes() == {"a": 3}
    path.write_text(json.dumps({"alerts": {"a": {"calls": []}, "b": {"calls": [[1, "bind", 0, 0]] * 200}}}))
    os.utime(path, (time.time() + 5, time.time() + 5))
    assert svc.fragment_sizes() == {"a": 0, "b": 96}
    path.unlink()
    assert svc.fragment_sizes() == {}
