"""A unit's seccomp karyotype: the calls it makes, against the groups systemd filters by.

The sensor counts every syscall of every cgroup (``--syscall-sets-snapshot``). This module
names the numbers as libseccomp does, which is how systemd turns a ``SystemCallFilter=``
line into a filter; folds cgroups into the unit names the security stream uses, so a
SEQUENCER track and its karyotype share one; and reads whether the unit runs under a filter.

What leaves here: syscall names and counts per unit, how long ago each count last grew, a
filter's kind and size, and the kernel's ``Seccomp:`` mode of the unit's main process. Never
a pid, a cgroup path, an instance name, or the calls a unit's real filter lists.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import re
import subprocess
import time

SETS_SNAPSHOT = os.environ.get("KERNEL_SYSCALL_SETS", "/run/kernel-ai/syscall-sets.json")
# The sensor republishes every five seconds.
MAX_AGE_S = 30.0
# A count that grew within the immune history's quarter hour is a call in use now.
RECENT_S = 900
FILTER_TTL_S = 30.0
MAX_NR = 512
OTHER = "other"
# every call systemd knows, not a group of them
_NOT_A_GROUP = ("@known",)
_UNIT_SUFFIXES = (".service", ".scope", ".socket", ".mount", ".swap", ".slice")
_UNFILTERED_SUFFIXES = (".slice", ".scope")
_DIGITS = re.compile(r"\d+")
_UNIT_NAME = re.compile(r"[A-Za-z0-9_.@:-]{1,64}")
_SCMP_ARCH_NATIVE = 0
_SECCOMP_MODES = {"0": "none", "1": "strict", "2": "filter"}

_cache = {"names": None, "chromosomes": None, "snapshot": (None, None), "filters": {}}


def public_unit(cgroup_path):
    """The unit a cgroup path is published as: the security stream's folding (``public_unit``
    in deploy/ebpf/sensor_broker.py), so the strip's tracks and the karyotypes match."""
    if cgroup_path is None:
        return None
    parts = [p for p in str(cgroup_path).split("/") if p]
    if parts and parts[0] == "user.slice":
        return "user.slice"
    for name in reversed(parts):
        if name.endswith(_UNIT_SUFFIXES):
            if "@" in name:
                name = name.split("@", 1)[0] + "@" + name[name.rindex("."):]
            return _DIGITS.sub("", name)
    return _DIGITS.sub("", parts[-1]) if parts else "-.slice"


def syscall_names():
    """Number → name on this machine's architecture, as libseccomp resolves them."""
    if _cache["names"] is None:
        names = {}
        try:
            lib = ctypes.CDLL(ctypes.util.find_library("seccomp") or "libseccomp.so.2")
            libc = ctypes.CDLL(None)
            lib.seccomp_syscall_resolve_num_arch.restype = ctypes.c_void_p
            lib.seccomp_syscall_resolve_num_arch.argtypes = [ctypes.c_uint32, ctypes.c_int]
            libc.free.argtypes = [ctypes.c_void_p]
            for nr in range(MAX_NR):
                pointer = lib.seccomp_syscall_resolve_num_arch(_SCMP_ARCH_NATIVE, nr)
                if pointer:
                    names[nr] = ctypes.string_at(pointer).decode("ascii", "replace")
                    libc.free(pointer)
        except (OSError, AttributeError):
            names = {}
        _cache["names"] = names
    return _cache["names"]


def parse_groups(text):
    """``systemd-analyze syscall-filter`` → {"@group": {"desc", "groups", "calls"}}."""
    groups, current = {}, None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if line.startswith("@"):
            current = groups.setdefault(stripped, {"desc": "", "groups": [], "calls": []})
        elif current is None:
            continue
        elif stripped.startswith("#"):
            current["desc"] = current["desc"] or stripped.lstrip("#").strip()
        elif stripped.startswith("@"):
            current["groups"].append(stripped)
        else:
            current["calls"].append(stripped)
    return groups


def build_chromosomes(groups, native):
    """One chromosome per group, made of the group's own calls that exist on this
    architecture, largest first as in a karyogram; calls in no group make the last one.
    A composite group (@system-service, @privileged) is its own calls; its subgroups are
    chromosomes of their own."""
    chromosomes, placed = [], set()
    for name, group in groups.items():
        if name in _NOT_A_GROUP:
            continue
        calls = sorted({call for call in group["calls"] if call in native})
        if not calls:
            continue
        placed.update(calls)
        chromosomes.append({"id": name, "desc": group["desc"], "groups": list(group["groups"]), "calls": calls})
    chromosomes.sort(key=lambda c: (-len(c["calls"]), c["id"]))
    rest = sorted(native - placed)
    if rest:
        chromosomes.append({"id": OTHER, "desc": "In no group: a filter can only name them one by one",
                            "groups": [], "calls": rest})
    return chromosomes


def chromosomes():
    if _cache["chromosomes"] is None:
        try:
            text = subprocess.run(
                ["systemd-analyze", "syscall-filter", "--no-pager"],
                capture_output=True, text=True, timeout=10, check=False,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            text = ""
        _cache["chromosomes"] = build_chromosomes(parse_groups(text), set(syscall_names().values()))
    return _cache["chromosomes"]


def fold_units(payload):
    """Public unit → {"real": its busiest unit's own name, "calls": {nr: [count, last grew]}}.
    The real name stays here: it is what systemctl is asked about."""
    units = {}
    for cgroup in payload.get("cgroups") or ():
        if not isinstance(cgroup, dict):
            continue
        path, calls = cgroup.get("path"), cgroup.get("calls")
        if not isinstance(path, str) or not path or not isinstance(calls, list):
            continue
        unit = public_unit(path)
        if not unit or not _UNIT_NAME.fullmatch(unit):
            continue
        entry = units.setdefault(unit, {"real": None, "busiest": -1, "calls": {}})
        total = 0
        for call in calls:
            if not (isinstance(call, list) and len(call) == 3 and all(type(v) is int for v in call)):
                continue
            nr, count, moved = call
            if not 0 <= nr < MAX_NR or count <= 0:
                continue
            total += count
            have = entry["calls"].get(nr)
            entry["calls"][nr] = [count + have[0], max(moved, have[1])] if have else [count, moved]
        leaf = path.rsplit("/", 1)[-1]
        if total > entry["busiest"] and leaf.endswith(_UNIT_SUFFIXES):
            entry["real"], entry["busiest"] = leaf, total
    return units


def _snapshot():
    try:
        stat = os.stat(SETS_SNAPSHOT)
    except OSError:
        return None, "no-collector"
    if time.time() - stat.st_mtime > MAX_AGE_S:
        return None, "stale"
    mtime, document = _cache["snapshot"]
    if mtime == stat.st_mtime and document is not None:
        return document, None
    try:
        with open(SETS_SNAPSHOT, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return None, "invalid-snapshot"
    if not isinstance(payload, dict) or not isinstance(payload.get("cgroups"), list):
        return None, "invalid-snapshot"
    document = {
        "since": payload.get("since") if isinstance(payload.get("since"), str) else None,
        "generated_at": payload.get("generated_at") if isinstance(payload.get("generated_at"), str) else None,
        "arch": payload.get("arch") if isinstance(payload.get("arch"), str) else None,
        "units": fold_units(payload),
    }
    _cache["snapshot"] = (stat.st_mtime, document)
    return document, None


def parse_filter(properties):
    """systemctl's SystemCallFilter, NoNewPrivileges → kind and size only. An empty deny
    list prints as a bare ``~``."""
    raw = (properties.get("SystemCallFilter") or "").strip()
    names = raw.lstrip("~").split()
    kind = "none" if not names else ("deny" if raw.startswith("~") else "allow")
    return {"kind": kind, "size": len(names), "no_new_privs": properties.get("NoNewPrivileges") == "yes"}


def kernel_seccomp(status_text):
    """/proc/<pid>/status → the kernel's own view: seccomp mode, filters stacked, no_new_privs."""
    fields = dict(line.split(":", 1) for line in status_text.splitlines() if ":" in line)
    mode = _SECCOMP_MODES.get(fields.get("Seccomp", "").strip())
    if mode is None:
        return None
    out = {"mode": mode, "no_new_privs": fields.get("NoNewPrivs", "").strip() == "1"}
    filters = fields.get("Seccomp_filters", "").strip()
    if filters.isdigit():
        out["filters"] = int(filters)
    return out


def _unit_filter(real):
    now = time.monotonic()
    cached = _cache["filters"].get(real)
    if cached and now - cached[0] < FILTER_TTL_S:
        return cached[1]
    state = None
    try:
        out = subprocess.run(
            ["systemctl", "show", real, "-p", "LoadState", "-p", "SystemCallFilter",
             "-p", "NoNewPrivileges", "-p", "MainPID"],
            capture_output=True, text=True, timeout=5, check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        out = ""
    properties = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    if properties.get("LoadState") == "loaded":
        state = parse_filter(properties)
        pid = properties.get("MainPID", "0")
        if pid.isdigit() and int(pid) > 0:
            try:
                with open(f"/proc/{int(pid)}/status", "r", encoding="ascii", errors="replace") as handle:
                    kernel = kernel_seccomp(handle.read())
            except OSError:
                kernel = None
            if kernel:
                state["kernel"] = kernel
    _cache["filters"][real] = (now, state)
    return state


def _unavailable(reason):
    return {"available": False, "units": [], "source": {"kind": "ebpf", "reason": reason}}


def get_units():
    """Every unit seen, busiest first, with the chromosomes their calls fall into."""
    document, reason = _snapshot()
    if document is None:
        return {**_unavailable(reason), "chromosomes": chromosomes()}
    now = time.time()
    rows = []
    for unit, entry in document["units"].items():
        calls = entry["calls"].values()
        rows.append({
            "unit": unit,
            "distinct": len(entry["calls"]),
            "calls": sum(count for count, _ in calls),
            "recent": sum(1 for _, moved in calls if now - moved <= RECENT_S),
        })
    rows.sort(key=lambda row: -row["calls"])
    return {
        "available": True,
        "since": document["since"],
        "arch": document["arch"],
        "recent_s": RECENT_S,
        "units": rows,
        "chromosomes": chromosomes(),
        "source": {"kind": "ebpf", "scope": "machine", "fields": "units, syscall names, counts"},
    }


def get_unit(unit):
    """One unit's calls, busiest first, as [name, calls, seconds since the count last grew],
    and the filter it runs under."""
    if not isinstance(unit, str) or not _UNIT_NAME.fullmatch(unit):
        raise ValueError("unit must be a systemd unit name")
    document, reason = _snapshot()
    if document is None:
        return {**_unavailable(reason), "unit": unit}
    entry = document["units"].get(unit)
    if entry is None:
        return {**_unavailable("unit-not-seen"), "unit": unit}
    names = syscall_names()
    now = time.time()
    calls = [
        [names.get(nr, f"syscall_{nr}"), count, max(0, round(now - moved))]
        for nr, (count, moved) in sorted(entry["calls"].items(), key=lambda item: -item[1][0])
    ]
    real = entry["real"]
    unit_filter = _unit_filter(real) if real and not real.endswith(_UNFILTERED_SUFFIXES) else None
    return {
        "available": True,
        "unit": unit,
        "since": document["since"],
        "arch": document["arch"],
        "recent_s": RECENT_S,
        "calls": calls,
        "filter": unit_filter,
        "source": {"kind": "ebpf", "scope": "machine", "fields": "syscall names, counts, filter kind and size"},
    }
