"""New genes: a unit making a call it has never been seen to make.

The sensor counts every call of every cgroup since it started (``syscall-sets.json``),
folded into units as the karyotype folds them. A unit's genome here is every call it has
been seen to make, by name, since numbers differ between architectures; it lives on disk,
so neither a sensor restart, which zeroes the counts, nor a reboot forgets it.

A call outside the genome is a mutation, and joins the genome at once: a call mutates a
unit only the first time. What a unit does before it has a genome of its own is learnt
silently, never reported:
- for WARMUP_S after the watch first runs, every unit;
- for WARMUP_S after a unit is first seen, that unit: all a service does in its first hour,
  or a timer on its first run, is its own;
- for START_S after a unit gets a new cgroup, which is what a restart is: the sensor never
  saw the start of a unit that was up before it, so a first restart would otherwise mutate
  in every call a start makes. An attack in a restart's first START_S is missed with them.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import time

from kernel_ai.services import syscall_genome

logger = logging.getLogger("kernel_ai.ml.genes")

SCHEMA = "kernel.syscall-genes/v1"
GENES_OUT = os.environ.get("KERNEL_SYSCALL_GENES", "/run/kernel-ai/syscall-genes.json")
# The sensor republishes every five seconds; every other snapshot is enough.
CHECK_S = 10.0
WARMUP_S = 3600.0
START_S = 120.0
KEEP_S = 7 * 86400.0
KEEP_MAX = 500


def _write_json(path, payload, mode):
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".syscall-genes-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"))
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def cgroups_of(payload):
    """Public unit → the ids of the cgroups folded into it."""
    ids = {}
    for cgroup in payload.get("cgroups") or ():
        if isinstance(cgroup, dict) and type(cgroup.get("id")) is int and isinstance(cgroup.get("path"), str):
            unit = syscall_genome.public_unit(cgroup["path"])
            if unit:
                ids.setdefault(unit, set()).add(cgroup["id"])
    return ids


class GeneWatch:
    def __init__(self, state_path, sets_path=None, out_path=GENES_OUT):
        self.state_path = str(state_path)
        self.sets_path = sets_path or syscall_genome.SETS_SNAPSHOT
        self.out_path = out_path
        self.state = self._load()
        self._seen_mtime = None
        self._checked = 0.0

    def _load(self):
        try:
            with open(self.state_path, "r", encoding="utf-8") as handle:
                state = json.load(handle)
        except (OSError, ValueError):
            return None
        if not isinstance(state, dict) or state.get("schema") != SCHEMA or not isinstance(state.get("units"), dict):
            return None
        if not isinstance(state.get("events"), list):
            state["events"] = []
        return state

    def tick(self, now=None):
        """Read the sensor's snapshot if a new one is out; returns the mutations it held."""
        now = time.time() if now is None else now
        if now - self._checked < CHECK_S:
            return 0
        self._checked = now
        try:
            mtime = os.stat(self.sets_path).st_mtime
        except OSError:
            return 0
        if mtime == self._seen_mtime or now - mtime > syscall_genome.MAX_AGE_S:
            return 0
        try:
            with open(self.sets_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, ValueError):
            return 0
        if not isinstance(payload, dict) or not isinstance(payload.get("cgroups"), list):
            return 0
        names = syscall_genome.syscall_names()
        # without libseccomp every call would be learnt as a number and mutate once named
        if not names:
            return 0
        self._seen_mtime = mtime
        found = self.observe(syscall_genome.fold_units(payload), names, now,
                             arch=payload.get("arch"), cgroups=cgroups_of(payload))
        _write_json(self.out_path, self.public(now), 0o644)
        return found

    def observe(self, units, names, now, arch=None, cgroups=None):
        """Fold one snapshot's units into the genomes; returns how many calls mutated."""
        state = self.state
        if state is not None and arch and state.get("arch") and state["arch"] != arch:
            logger.warning("syscall genes: architecture %s, genomes learnt on %s; learning again",
                           arch, state["arch"])
            state = None
        if state is None:
            state = self.state = {"schema": SCHEMA, "arch": arch, "since": round(now, 3), "units": {}, "events": []}
        cgroups = cgroups or {}
        learnt = found = 0
        for unit, entry in units.items():
            genome = state["units"].get(unit)
            if genome is None:
                genome = state["units"][unit] = {"first": round(now), "calls": {}}
            # kept on disk only with a call learnt: a worker restarted on stale ids just
            # gives the units whose ids moved a start they did not have
            ids = sorted(cgroups.get(unit, ()))
            if ids and ids != genome.get("cgroups"):
                if "cgroups" in genome and set(ids) - set(genome["cgroups"]):
                    genome["started"] = round(now)
                genome["cgroups"] = ids
            learning = (now - state["since"] < WARMUP_S or now - genome["first"] < WARMUP_S
                        or now - genome.get("started", 0) < START_S)
            for nr, (count, moved) in entry["calls"].items():
                name = names.get(nr, f"syscall_{nr}")
                if name in genome["calls"]:
                    continue
                # a call counted once was first made when its count last grew
                at = moved if count == 1 and moved <= now else now
                genome["calls"][name] = round(at)
                if learning:
                    learnt += 1
                    continue
                state["events"].append({"unit": unit, "call": name, "t": round(at, 3)})
                found += 1
        if found:
            kept = [e for e in state["events"] if e["t"] >= now - KEEP_S]
            state["events"] = kept[-KEEP_MAX:]
            logger.info("syscall genes: %d new calls (%s)", found, ", ".join(
                f"{e['unit']} {e['call']}" for e in state["events"][-found:][:8]))
        if learnt or found:
            _write_json(self.state_path, state, 0o640)
        return found

    def public(self, now):
        state = self.state or {}
        units = state.get("units") or {}
        since = state.get("since") or now
        return {
            "schema": SCHEMA,
            "generated_at": now,
            "since": state.get("since"),
            "warmup_s": WARMUP_S,
            "learning_until": since + WARMUP_S if now - since < WARMUP_S else None,
            "units": len(units),
            "events": [e for e in state.get("events") or () if e["t"] >= now - KEEP_S],
        }
