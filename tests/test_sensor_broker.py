"""Tests for the KernelEvent v1 unprivileged broker."""

from collections import Counter, deque
from datetime import datetime, timezone
import importlib.util
import json
import os
import pickle
import sys
import time
from pathlib import Path

import pytest


PATH = Path(__file__).parents[1] / "deploy" / "ebpf" / "sensor_broker.py"
SPEC = importlib.util.spec_from_file_location("sensor_broker", PATH)
broker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(broker)


def test_adapt_event_preserves_inspector_fields():
    payload = {
        "schema": "kernel.event/v1",
        "seq": 9,
        "kind": "syscall_span",
        "timestamp": "2026-09-01T10:00:00Z",
        "pid": 42,
        "tid": 43,
        "uid": 1000,
        "cpu": 2,
        "cgroup_id": 88,
        "comm": "worker",
        "subsystem": "fs",
        "syscall": {
            "nr": 63,
            "name": "read",
            "args": [5, 4096, 16, 0, 0, 0],
            "return": 8,
            "duration_us": 250_000,
            "fd": 5,
            "fd_target": "pipe:[8123]",
        },
        "wakeup": {
            "waker_pid": 10,
            "waker_tid": 11,
            "waker_comm": "producer",
            "wakee_tid": 43,
            "target_cpu": 2,
        },
    }

    event = broker.adapt_event(payload)

    assert event["schema"] == "kernel.event/v1"
    assert event["syscall"] == "read"
    assert event["duration_us"] == 250_000
    assert event["fd_target"] == "pipe:[8123]"
    assert event["wakeup"]["waker_comm"] == "producer"
    assert event["exit_ts"] - event["enter_ts"] == 0.25


def test_adapt_event_rejects_unknown_contract_or_kind():
    assert broker.adapt_event({"schema": "kernel.event/v0"}) is None
    assert broker.adapt_event(
        {"schema": "kernel.event/v1", "kind": "network_packet"}
    ) is None


def test_names_view_keeps_only_the_syscall_name():
    payload = {
        "schema": "kernel.event/v1",
        "seq": 9,
        "kind": "syscall_span",
        "timestamp": "2026-09-01T10:00:00Z",
        "pid": 42,
        "tid": 43,
        "ppid": 1,
        "uid": 0,
        "cpu": 2,
        "cgroup_id": 88,
        "comm": "sshd",
        "syscall": {
            "nr": 59,
            "name": "execve",
            "args": [1, 2, 3, 0, 0, 0],
            "return": 0,
            "duration_us": 900,
            "path": "/usr/bin/id",
            "sockaddr": {"family": "AF_INET", "addr": "10.0.0.5", "port": 22},
        },
    }

    assert broker.names_view(payload) == {"syscall": "execve"}
    units = {88: "ssh.service"}
    asked = []

    def unit_of(cgroup_id, pid):
        asked.append((cgroup_id, pid))
        return units.get(cgroup_id)

    assert broker.names_view(payload, unit_of) == {"syscall": "execve", "unit": "ssh.service"}
    assert broker.names_view({**payload, "cgroup_id": 89}, unit_of) == {"syscall": "execve"}
    assert asked == [(88, 42), (89, 42)]


def test_public_unit_folds_like_the_ml_context_and_hides_sessions():
    spec = importlib.util.spec_from_file_location(
        "markov_for_broker_test", Path(__file__).parents[1] / "kernel_ai" / "ml" / "sequence_deep" / "markov.py"
    )
    markov = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = markov
    spec.loader.exec_module(markov)
    for path in ("system.slice/nginx.service", "system.slice/system-ssh.slice/ssh@12-10.0.0.5:22-1.2.3.4:5.service",
                 "init.scope", "system.slice/kernel-ai-crypto-exerciser.service", "", "system.slice/cron.service"):
        assert broker.public_unit(path) == markov.unit_context(path).removeprefix("unit:")
    assert broker.public_unit("user.slice/user-1000.slice/session-41.scope") == "user.slice"
    assert broker.public_unit("user.slice/user-1000.slice/user@1000.service/app.slice/app-cursor-2505.scope") == "user.slice"
    assert broker.public_unit(None) is None


def test_names_view_rejects_anything_but_a_syscall_identifier():
    base = {"schema": "kernel.event/v1", "kind": "syscall_span"}
    for name in ("", "exec ve", "/usr/bin/id", "x" * 33, None, 59):
        assert broker.names_view({**base, "syscall": {"name": name}}) is None
    assert broker.names_view({"schema": "kernel.event/v1", "kind": "network_packet"}) is None


def _profile(tmp_path, ngrams, n=3):
    path = tmp_path / "stide_latest.joblib"
    with open(path, "wb") as handle:
        pickle.dump({"ngrams": set(ngrams), "n": n, "meta": {"stage": 4}}, handle, protocol=4)
    return path


def test_load_profile_reads_what_joblib_writes_without_joblib(tmp_path):
    joblib = pytest.importorskip("joblib")
    path = tmp_path / "stide_latest.joblib"
    joblib.dump({"ngrams": {"bind|accept|clone"}, "n": 3, "meta": {"stage": 4, "min_count": 3}}, path)

    assert broker.load_profile(path) == (frozenset({"bind|accept|clone"}), 3)


def test_load_profile_refuses_anything_that_names_a_class(tmp_path):
    path = tmp_path / "stide_latest.joblib"
    path.write_bytes(pickle.dumps({"ngrams": Counter({"a|b|c": 1}), "n": 3}))

    assert broker.load_profile(path) is None
    assert broker.load_profile(tmp_path / "missing.joblib") is None


def test_mutations_mark_an_ngram_the_profile_lacks_per_process(tmp_path):
    marks = broker.Mutations(str(_profile(tmp_path, {"bind|accept|clone", "accept|clone|execve"})))
    calls = [(7, "bind"), (8, "execve"), (7, "accept"), (7, "clone"), (8, "execve"), (7, "execve"), (7, "setuid")]

    assert [marks.observe(pid, name) for pid, name in calls] == [None] * 6 + [["clone", "execve", "setuid"]]
    assert marks.observe(0, "execve") is None


def test_mutations_forget_the_least_recent_process_beyond_the_bound(tmp_path):
    marks = broker.Mutations(str(_profile(tmp_path, set())), max_strands=2)
    for pid in (1, 2, 1, 3):
        marks.observe(pid, "bind")

    assert list(marks.strands) == [1, 3]


def test_mutations_follow_a_rebuilt_profile_and_mark_nothing_without_one(tmp_path):
    path = _profile(tmp_path, set())
    marks = broker.Mutations(str(path))
    _profile(tmp_path, {"a|b|c"})
    os.utime(path, (1, 1))
    marks.refresh()
    assert [marks.observe(1, name) for name in ("a", "b", "c")] == [None, None, None]

    path.unlink()
    marks.refresh()
    assert [marks.observe(1, name) for name in ("x", "y", "z")] == [None, None, None]


def test_names_view_marks_a_mutation_with_names_and_no_pid(tmp_path):
    marks = broker.Mutations(str(_profile(tmp_path, set())))
    base = {"schema": "kernel.event/v1", "kind": "syscall_span", "pid": 42, "cgroup_id": 88}

    out = [broker.names_view({**base, "syscall": {"name": name}}, mutations=marks)
           for name in ("connect", "clone", "execve")]

    assert out == [
        {"syscall": "connect"},
        {"syscall": "clone"},
        {"syscall": "execve", "novel": True, "ngram": ["connect", "clone", "execve"]},
    ]


def test_lanes_keep_a_process_on_one_number_within_its_unit():
    lanes = broker.Lanes(max_pids=3)

    assert [lanes.lane(pid, unit) for pid, unit in
            [(10, "nginx.service"), (11, "nginx.service"), (10, "nginx.service"), (12, "ssh.service")]] == [0, 1, 0, 0]
    assert lanes.lane(10, "cron.service") == 0
    lanes.lane(13, "nginx.service")
    assert 11 not in lanes.of_pid
    assert lanes.lane(11, "nginx.service") == 3


def test_lanes_wrap_per_unit(monkeypatch):
    monkeypatch.setattr(broker, "LANES_PER_UNIT", 2)
    lanes = broker.Lanes()

    assert [lanes.lane(pid, "user.slice") for pid in (1, 2, 3)] == [0, 1, 0]


def test_names_view_gives_a_lane_and_no_pid(tmp_path):
    lanes = broker.Lanes()
    base = {"schema": "kernel.event/v1", "kind": "syscall_span", "cgroup_id": 88, "syscall": {"name": "accept4"}}

    def unit_of(cgroup_id, pid):
        return "nginx.service"

    out = [broker.names_view({**base, "pid": pid}, unit_of, lanes=lanes) for pid in (900, 901, 900)]
    assert out == [{"syscall": "accept4", "unit": "nginx.service", "lane": lane} for lane in (0, 1, 0)]
    assert broker.names_view({**base, "pid": 0}, unit_of, lanes=lanes) == {"syscall": "accept4", "unit": "nginx.service"}


def test_names_view_pairs_a_loopback_hop_by_its_port():
    base = {"schema": "kernel.event/v1", "kind": "syscall_span"}
    sent = {"name": "connect", "local_port": 51234, "sockaddr": {"family": "inet", "addr": "127.0.0.1", "port": 8000}}
    took = {"name": "accept4", "sockaddr": {"family": "inet", "addr": "127.0.0.1", "port": 51234}}
    assert broker.names_view({**base, "syscall": sent}) == {"syscall": "connect", "hop": 51234}
    assert broker.names_view({**base, "syscall": took}) == {"syscall": "accept4", "hop": 51234}
    mapped = {**took, "sockaddr": {"family": "inet6", "addr": "::ffff:127.0.0.1", "port": 51234}}
    assert broker.names_view({**base, "syscall": mapped})["hop"] == 51234
    outside = [
        {**sent, "sockaddr": {"family": "inet", "addr": "10.0.0.5", "port": 5432}},
        {**took, "sockaddr": {"family": "inet"}},
        {**sent, "local_port": 0},
        {**sent, "local_port": "51234"},
        {**took, "sockaddr": {"family": "inet", "addr": "127.0.0.1", "port": 70000}},
        {**took, "name": "bind"},
        {"name": "connect", "local_port": 51234, "sockaddr": {"family": "unix", "path": "/run/x.sock"}},
    ]
    for span in outside:
        assert "hop" not in broker.names_view({**base, "syscall": span}), span


def test_names_view_keeps_the_port_an_outside_peer_connected_from():
    base = {"schema": "kernel.event/v1", "kind": "syscall_span"}
    took = {"name": "accept4", "sockaddr": {"family": "inet", "port": 40000}}
    assert broker.names_view({**base, "syscall": took}) == {"syscall": "accept4", "client": 40000}
    six = {**took, "sockaddr": {"family": "inet6", "port": 40000}}
    assert broker.names_view({**base, "syscall": six})["client"] == 40000
    for span in (
        {**took, "sockaddr": {"family": "inet", "addr": "127.0.0.1", "port": 40000}},
        {**took, "sockaddr": {"family": "inet"}},
        {**took, "sockaddr": {"family": "unix", "port": 40000}},
        {**took, "sockaddr": {"family": "inet", "port": "40000"}},
        {**took, "sockaddr": {"family": "inet", "port": 0}},
        {**took, "name": "connect", "local_port": 40000},
        {**took, "name": "bind"},
    ):
        assert "client" not in broker.names_view({**base, "syscall": span}), span


def test_names_only_snapshot_lists_lanes_and_mutations(tmp_path, monkeypatch):
    output = tmp_path / "security-names.json"
    monkeypatch.setattr(broker, "OUT_PATH", str(output))
    monkeypatch.setattr(broker, "NAMES_ONLY", True)
    marks = broker.Mutations(str(_profile(tmp_path, {"a|b|c"})))

    broker.write_snapshot(deque(), seq=0, dropped=0, started_at=1.0, mutations=marks, lanes=broker.Lanes())

    assert json.loads(output.read_text())["sources"]["fields"] == "names, units, hops, clients, lanes, mutations"


def test_names_only_snapshot_names_the_profile_it_marks_with(tmp_path, monkeypatch):
    output = tmp_path / "security-names.json"
    monkeypatch.setattr(broker, "OUT_PATH", str(output))
    monkeypatch.setattr(broker, "NAMES_ONLY", True)
    marks = broker.Mutations(str(_profile(tmp_path, {"a|b|c", "b|c|d"})))

    broker.write_snapshot(deque(), seq=0, dropped=0, started_at=1.0, mutations=marks)

    sources = json.loads(output.read_text())["sources"]
    assert sources["fields"] == "names, units, hops, clients, mutations"
    assert sources["mutations"] == "stide n=3, 2 n-grams"


def test_names_only_snapshot_does_not_claim_wakeup_correlation(tmp_path, monkeypatch):
    output = tmp_path / "security-names.json"
    monkeypatch.setattr(broker, "OUT_PATH", str(output))
    monkeypatch.setattr(broker, "NAMES_ONLY", True)

    broker.write_snapshot(
        deque([{"syscall": "bind", "seq": 1}]), seq=1, dropped=0, started_at=1.0
    )

    payload = json.loads(output.read_text())
    assert payload["sources"]["fields"] == "names, units, hops, clients"
    assert "wakeup" not in payload["sources"]
    assert payload["events"] == [{"syscall": "bind", "seq": 1}]


def test_write_snapshot_skips_fsync_by_default(tmp_path, monkeypatch):
    output = tmp_path / "kernel-events.json"
    monkeypatch.setattr(broker, "OUT_PATH", str(output))
    monkeypatch.setattr(broker, "FSYNC_SNAPSHOT", False)

    def unexpected_fsync(_fd):
        raise AssertionError("volatile snapshots must not fsync by default")

    monkeypatch.setattr(broker.os, "fsync", unexpected_fsync)

    broker.write_snapshot(deque(), seq=4, dropped=2, started_at=1.0)

    payload = json.loads(output.read_text())
    assert payload["seq"] == 4
    assert payload["dropped"] == 2
    assert payload["events"] == []


WEB = "Web: sensitive file / dotfile probing"


def _iso(at):
    return datetime.fromtimestamp(at, timezone.utc).isoformat().replace("+00:00", "Z")


def _alert(key, at, rule=WEB):
    return {"id": key, "rule": rule, "time": _iso(at + 40), "event_time": _iso(at),
            "source_ip": "203.0.113.9", "url_path": "/.env", "severity": "medium"}


def _feed(immune, calls):
    for at, seq, unit, name, *rest in calls:
        event = {"seq": seq, "syscall": name, "unit": unit}
        if rest:
            event["lane"] = rest[0]
        if len(rest) > 1:
            event.update(novel=True, ngram=rest[1])
        immune.keep(event, at)


def test_immune_captures_the_attacked_units_calls_around_the_attack(tmp_path):
    immune = broker.Immune(str(tmp_path / "security-immune.json"), started=1000.0)
    _feed(immune, [
        (1930.0, 1, "kernel-ai.service", "accept4", 0),
        (1950.0, 2, "nginx.service", "accept4", 0),
        (1999.0, 3, "nginx.service", "connect", 0),
        (2000.0, 4, "cron.service", "execve", 0),
        (2000.2, 5, "ssh.service", "accept4", 0),
        (2000.5, 6, "nginx.service", "accept4", 1),
        (2001.0, 7, "kernel-ai.service", "accept4", 0, ["accept4", "accept4", "execve"]),
        (2070.0, 8, "nginx.service", "accept4", 1),
    ])

    assert immune.capture([_alert("a1", 2000.0)], now=2061.0) == 1

    assert immune.alerts == {"a1": {
        "rule": WEB, "t": 2000.0, "units": ["nginx.service", "kernel-ai.service"],
        "calls": [[2, "accept4", 0, 0], [3, "connect", 0, 0], [6, "accept4", 0, 1],
                  [7, "accept4", 1, 0, ["accept4", "accept4", "execve"]]],
        "at": 6,
    }}


def test_immune_keeps_the_nearest_calls_on_each_side(tmp_path, monkeypatch):
    monkeypatch.setattr(broker, "FRAGMENT_SIDE", 2)
    immune = broker.Immune(str(tmp_path / "security-immune.json"), started=1000.0)
    _feed(immune, [(1990.0 + i * 4, i, "ssh.service", "clone", 7) for i in range(6)])

    immune.capture([_alert("s1", 2000.0, rule="SSH: multiple failed logins (possible brute force)")], now=2100.0)

    assert [call[0] for call in immune.alerts["s1"]["calls"]] == [1, 2, 3, 4]
    assert immune.alerts["s1"]["at"] == 3


def test_immune_waits_for_the_reach_and_skips_what_it_cannot_cut(tmp_path):
    immune = broker.Immune(str(tmp_path / "security-immune.json"), started=1000.0)
    _feed(immune, [(2000.0, 1, "nginx.service", "accept4", 0)])
    alerts = [
        _alert("early", 2000.0),
        _alert("before-start", 1030.0),
        _alert("host", 2000.0, rule="Host telemetry: ML syscall feed stopped"),
        {**_alert("no-attack-time", 2000.0), "event_time": None},
        "not an alert",
    ]

    assert immune.capture(alerts, now=2030.0) == 0
    assert immune.capture(alerts, now=2060.0) == 1
    assert set(immune.alerts) == {"early"}
    _feed(immune, [(2061.0, 2, "nginx.service", "connect", 0)])
    assert immune.capture([_alert("early", 2000.0)], now=2100.0) == 0
    assert [call[0] for call in immune.alerts["early"]["calls"]] == [1]


def test_immune_skips_an_attack_older_than_a_history_that_overflowed(tmp_path, monkeypatch):
    monkeypatch.setattr(broker, "HISTORY_MAX", 3)
    immune = broker.Immune(str(tmp_path / "security-immune.json"), started=1000.0)
    _feed(immune, [(1990.0 + i, i, "nginx.service", "accept4", 0) for i in range(5)])

    assert immune.capture([_alert("a1", 2000.0)], now=2070.0) == 0
    assert immune.capture([_alert("a2", 2060.0)], now=2130.0) == 1
    assert immune.alerts["a2"]["calls"] == [] and immune.alerts["a2"]["at"] is None


def test_immune_history_forgets_a_call_after_a_quarter_hour(tmp_path):
    immune = broker.Immune(str(tmp_path / "security-immune.json"), started=0.0)
    _feed(immune, [(1000.0, 1, "nginx.service", "accept4", 0), (1901.0, 2, "nginx.service", "accept4", 0)])

    assert [entry[1] for entry in immune.history["nginx.service"]] == [2]


def test_immune_alerts_of_one_attack_share_one_cut(tmp_path):
    immune = broker.Immune(str(tmp_path / "security-immune.json"), started=1000.0)
    _feed(immune, [(2000.0, 1, "nginx.service", "accept4", 0)])

    assert immune.capture([_alert("a1", 2000.0), _alert("a2", 2000.0)], now=2100.0) == 2
    assert immune.alerts["a1"]["calls"] == immune.alerts["a2"]["calls"] == [[1, "accept4", 0, 0]]


def test_immune_store_survives_a_restart_and_keeps_a_day(tmp_path, monkeypatch):
    monkeypatch.setattr(broker, "IMMUNE_MAX", 2)
    path = tmp_path / "security-immune.json"
    path.write_text(json.dumps({"alerts": {
        "old": {"rule": WEB, "t": 100.0, "units": [], "calls": [], "at": None},
        "kept": {"rule": WEB, "t": 90000.0, "units": [], "calls": [], "at": None},
        "broken": {"rule": WEB, "t": "yesterday"},
    }}))
    immune = broker.Immune(str(path), started=90000.0)
    _feed(immune, [(90100.0, 1, "nginx.service", "accept4", 0), (90110.0, 2, "nginx.service", "accept4", 0)])

    assert immune.capture([_alert("new", 90100.0)], now=90200.0) == 1
    assert set(immune.alerts) == {"kept", "new"}
    assert immune.capture([_alert("newer", 90110.0)], now=90200.0) == 1
    immune.write()

    assert set(broker.Immune(str(path), started=0.0).alerts) == {"new", "newer"}
    assert oct(os.stat(path).st_mode & 0o777) == "0o644"


def test_poll_alerts_hands_over_the_list_the_app_serves(tmp_path, monkeypatch):
    import http.server
    import threading

    body = json.dumps({"available": True, "alerts": [_alert("a1", 2000.0)]}).encode()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200 if self.path == "/api/siem-alerts?hours=1" else 404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setattr(broker, "ALERTS_POLL_S", 0.05)
    immune = broker.Immune(str(tmp_path / "security-immune.json"), started=0.0)
    stop = threading.Event()
    try:
        poller = threading.Thread(target=broker.poll_alerts, daemon=True, args=(
            immune, f"http://127.0.0.1:{server.server_port}/api/siem-alerts?hours=1", stop))
        poller.start()
        for _ in range(100):
            if immune.inbox is not None:
                break
            time.sleep(0.02)
    finally:
        stop.set()
        poller.join(timeout=2)
        server.shutdown()
        server.server_close()
    assert not poller.is_alive()
    assert immune.take() == [_alert("a1", 2000.0)]
    assert immune.inbox is None


def test_poll_alerts_delivers_nothing_when_the_app_is_down(tmp_path, monkeypatch):
    import socket as socket_module
    import threading

    probe = socket_module.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    immune = broker.Immune(str(tmp_path / "security-immune.json"), started=0.0)
    stop = threading.Event()
    monkeypatch.setattr(stop, "wait", lambda timeout: stop.set())

    broker.poll_alerts(immune, f"http://127.0.0.1:{port}/api/siem-alerts", stop)

    assert immune.inbox is None
