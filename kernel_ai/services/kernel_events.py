"""Read the bounded eBPF stream used by Kernel Event Inspector."""

from __future__ import annotations

import json
import os
import re
import time

SNAPSHOT = os.environ.get("KERNEL_EVENTS_SNAPSHOT", "/run/kernel-ai/kernel-events.json")
# Names-only view of the sensor's security stream. Whatever the file holds, only
# the syscall name, its systemd unit, its order, the broker's lane number for its
# process, for a call the broker marked as a mutation the names of the n-gram it
# completed, and whether the call carried one of the requester's own requests
# leave this module. The loopback port that decides the last one does not.
SECURITY_SNAPSHOT = os.environ.get(
    "KERNEL_SECURITY_NAMES_SNAPSHOT", "/run/kernel-ai/security-names.json"
)
# The same stream's calls around each SIEM alert's attack, as the broker captured them.
IMMUNE_SNAPSHOT = os.environ.get(
    "KERNEL_SECURITY_IMMUNE_SNAPSHOT", "/run/kernel-ai/security-immune.json"
)
STREAMS = ("latency", "security")
MAX_AGE_S = float(os.environ.get("KERNEL_EVENTS_MAX_AGE_S", "5"))
MAX_LIMIT = 200
_SYSCALL_NAME = re.compile(r"[a-z0-9_]{1,32}")
_UNIT_NAME = re.compile(r"[A-Za-z0-9_.@:-]{1,64}")
_ALERT_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
_NGRAM_MAX = 8
_LANES = 1000
_FRAGMENT_MAX = 96
_OPTIONAL_FIELDS = ("lanes", "mutations")
_immune = {"mtime": None, "alerts": {}}


def _unavailable(reason, *, age=None, stream="latency"):
    return {
        "available": False,
        "seq": 0,
        "events": [],
        "source": {
            "kind": "ebpf",
            "scope": "machine",
            "stream": stream,
            "reason": reason,
            "age": age,
        },
    }


def _snapshot(path, stream):
    try:
        stat = os.stat(path)
    except OSError:
        return None, _unavailable("no-collector", stream=stream)
    age = max(0.0, time.time() - stat.st_mtime)
    if age > MAX_AGE_S:
        return None, _unavailable("stale", age=round(age, 3), stream=stream)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError, TypeError):
        return None, _unavailable("invalid-snapshot", age=round(age, 3), stream=stream)
    if not isinstance(payload, dict) or not isinstance(payload.get("events"), list):
        return None, _unavailable("invalid-snapshot", age=round(age, 3), stream=stream)
    return payload, None


def _mine(event, mine, conns):
    """A hop of one of the requester's requests, or nginx's accept of one of its connections."""
    hop = event.get("hop")
    if type(hop) is int and hop in mine:
        return "request"
    # nginx's accept of a browser on the same host comes from loopback, so its peer is a hop
    peer = event.get("client", hop)
    if event.get("syscall") in ("accept", "accept4") and type(peer) is int and peer in conns:
        return "connection"
    return None


def _name_only(event, mine=frozenset(), conns=frozenset()):
    name = event.get("syscall")
    if not isinstance(name, str) or not _SYSCALL_NAME.fullmatch(name):
        return None
    out = {"seq": int(event.get("seq", 0)), "syscall": name}
    kind = _mine(event, mine, conns)
    if kind:
        out["mine"] = kind
    unit = event.get("unit")
    if isinstance(unit, str) and _UNIT_NAME.fullmatch(unit):
        out["unit"] = unit
    lane = event.get("lane")
    if type(lane) is int and 0 <= lane < _LANES:
        out["lane"] = lane
    ngram = event.get("ngram")
    if (
        event.get("novel") is True
        and isinstance(ngram, list)
        and 2 <= len(ngram) <= _NGRAM_MAX
        and all(isinstance(n, str) and _SYSCALL_NAME.fullmatch(n) for n in ngram)
    ):
        out["novel"] = True
        out["ngram"] = list(ngram)
    return out


def _immune_alerts():
    try:
        mtime = os.stat(IMMUNE_SNAPSHOT).st_mtime
    except OSError:
        return {}
    if mtime != _immune["mtime"]:
        try:
            with open(IMMUNE_SNAPSHOT, "r", encoding="utf-8") as handle:
                alerts = json.load(handle).get("alerts")
        except (OSError, ValueError, AttributeError):
            alerts = None
        _immune["alerts"] = alerts if isinstance(alerts, dict) else {}
        _immune["mtime"] = mtime
    return _immune["alerts"]


def _fragment_events(entry):
    units = entry.get("units")
    calls = entry.get("calls")
    if not isinstance(units, list) or not isinstance(calls, list):
        return []
    events = []
    for call in calls[:_FRAGMENT_MAX]:
        if not isinstance(call, list) or len(call) not in (4, 5):
            continue
        seq, name, k, lane = call[:4]
        if type(seq) is not int or type(k) is not int or not 0 <= k < len(units):
            continue
        raw = {"seq": seq, "syscall": name, "unit": units[k], "lane": lane}
        if len(call) == 5:
            raw.update(novel=True, ngram=call[4])
        event = _name_only(raw)
        if event is not None:
            events.append(event)
    return events


def fragment_sizes():
    """Alert id → how many calls the broker captured around its attack."""
    return {
        key: min(_FRAGMENT_MAX, len(entry["calls"]))
        for key, entry in _immune_alerts().items()
        if isinstance(entry, dict) and isinstance(entry.get("calls"), list)
    }


def get_alert_fragment(alert):
    """The security stream's calls around one alert's attack, in the stream's own shape."""
    if not isinstance(alert, str) or not _ALERT_ID.fullmatch(alert):
        raise ValueError("alert must be a SIEM alert id")
    entry = _immune_alerts().get(alert)
    source = {"kind": "ebpf", "scope": "machine", "stream": "security", "fields": "names, units, lanes, mutations"}
    if not isinstance(entry, dict):
        return {"available": False, "alert": alert, "events": [], "source": {**source, "reason": "not-captured"}}
    events = _fragment_events(entry)
    at = entry.get("at")
    return {
        "available": True,
        "alert": alert,
        "events": events,
        # the first call at or after the attack; the calls before it led up to it
        "at_seq": at if type(at) is int else None,
        "units": [u for u in entry.get("units") or [] if isinstance(u, str) and _UNIT_NAME.fullmatch(u)],
        "source": source,
    }


def get_kernel_events(*, pids=None, since_seq=0, limit=80, stream="latency", mine=None, conns=None):
    """mine: the ports the requester's earlier requests reached the app from; the
    security stream marks the calls of the loopback hops that carried them.
    conns: the ports the requester's connections reached nginx from; the security
    stream marks nginx's accept of each, and conn_seqs names those accepts wherever
    they stand in the snapshot."""
    if stream not in STREAMS:
        raise ValueError(f"stream must be one of: {', '.join(STREAMS)}")
    security = stream == "security"
    if security and pids:
        raise ValueError("the security stream carries no pids to filter by")
    if (mine or conns) and not security:
        raise ValueError("only the security stream marks the requester's own calls")
    ports = frozenset(mine or ())
    conn_ports = frozenset(conns or ())
    path = SECURITY_SNAPSHOT if security else SNAPSHOT
    payload, error = _snapshot(path, stream)
    if error:
        return error
    wanted = set()
    for pid in pids or []:
        try:
            value = int(pid)
        except (TypeError, ValueError):
            continue
        if value > 0:
            wanted.add(value)
    since = max(0, int(since_seq or 0))
    bounded_limit = max(1, min(MAX_LIMIT, int(limit or 80)))
    all_events = [event for event in payload["events"] if isinstance(event, dict)]
    oldest_seq = min((int(event.get("seq", 0)) for event in all_events), default=0)
    cursor_lost = bool(since and oldest_seq and since < oldest_seq - 1)
    events = []
    for event in all_events:
        try:
            seq = int(event.get("seq", 0))
            pid = int(event.get("pid", 0))
        except (TypeError, ValueError):
            continue
        if seq <= since:
            continue
        if wanted and pid not in wanted:
            continue
        if security:
            event = _name_only(event, ports, conn_ports)
            if event is None:
                continue
        events.append(event)
    # Over HTTP/1.1 a page polls on several connections, and nginx accepted each one before
    # the page knew its port, so an earlier reply may already have carried that accept
    own = sorted(
        event["seq"]
        for event in all_events
        if security and type(event.get("seq")) is int and _mine(event, ports, conn_ports) == "connection"
    )
    if own and not since:
        # a first poll reaches back to the accept of its connection, made as the page loaded
        bounded_limit = max(bounded_limit, sum(1 for event in events if event["seq"] >= own[0]))
    events = events[-bounded_limit:]
    age = max(0.0, time.time() - os.path.getmtime(path))
    source = {
        "kind": "ebpf",
        "scope": "machine",
        "stream": stream,
        "age": round(age, 3),
        "dropped": int(payload.get("dropped", 0)),
    }
    if security:
        declared = {f.strip() for f in str((payload.get("sources") or {}).get("fields") or "").split(",")}
        fields = ["names", "units"] + [f for f in _OPTIONAL_FIELDS if f in declared]
        source["fields"] = ", ".join(fields + (["mine"] if "hops" in declared else []))
    else:
        source.update(
            {
                "min_duration_us": int(payload.get("min_duration_us", 0)),
                "traced_syscalls": payload.get("traced_syscalls", []),
                "syscalls": (payload.get("sources") or {}).get("syscalls"),
                "wakeup": (payload.get("sources") or {}).get("wakeup"),
            }
        )
    result = {
        "available": True,
        "seq": int(payload.get("seq", 0)),
        "events": events,
        "cursor_lost": cursor_lost,
        "source": source,
    }
    if own:
        result["conn_seqs"] = own[-16:]
    return result
