"""Tests for ``kernel_ai.services.syscall_genome``."""

import json
import time

import pytest

from kernel_ai.services import syscall_genome as svc

GROUPS = """\
# Not showing unlisted system calls, couldn't retrieve kernel system call list: Permission denied
@default
    # System calls that are always permitted
    brk
    exit_group
@network-io
    # Network or Unix socket IO, should not be needed if not network facing
    accept4
    connect
    recvfrom
@system-service
    # General system service operations
    @default
    @network-io
    ioctl
    open
@known
    # All known syscalls declared in the kernel
    accept4
    brk
"""
NAMES = {0: "brk", 1: "exit_group", 2: "accept4", 3: "connect", 4: "recvfrom", 5: "ioctl", 6: "ptrace"}


@pytest.fixture(autouse=True)
def fresh_cache(monkeypatch):
    monkeypatch.setattr(svc, "_cache", {"names": dict(NAMES), "chromosomes": None,
                                        "snapshot": (None, None), "filters": {}})


def _snapshot(tmp_path, monkeypatch, cgroups):
    path = tmp_path / "syscall-sets.json"
    path.write_text(json.dumps({"schema": "kernel.syscall-sets/v1", "since": "2026-11-23T20:00:00Z",
                                "arch": "arm64", "cgroups": cgroups}))
    monkeypatch.setattr(svc, "SETS_SNAPSHOT", str(path))
    return path


def test_chromosomes_are_own_calls_on_this_arch_largest_first():
    chromosomes = svc.build_chromosomes(svc.parse_groups(GROUPS), set(NAMES.values()))
    assert [c["id"] for c in chromosomes] == ["@network-io", "@default", "@system-service", "other"]
    service = chromosomes[2]
    # open is not on this architecture; the subgroups stay named, not merged in
    assert service["calls"] == ["ioctl"] and service["groups"] == ["@default", "@network-io"]
    assert chromosomes[-1]["calls"] == ["ptrace"]
    assert all(c["id"] != "@known" for c in chromosomes)


def test_units_fold_like_the_security_stream(tmp_path, monkeypatch):
    now = int(time.time())
    _snapshot(tmp_path, monkeypatch, [
        {"id": 1, "path": "/system.slice/nginx.service", "calls": [[2, 50, now], [0, 3, now - 2000]]},
        {"id": 2, "path": "/user.slice/user-1000.slice/session-4.scope", "calls": [[6, 1, now]]},
        {"id": 3, "path": "/user.slice/user-1000.slice/user@1000.service/app.slice/x-12.scope", "calls": [[6, 2, now]]},
        {"id": 4, "path": "", "calls": [[2, 9, now]]},
    ])
    out = svc.get_units()
    assert out["available"] is True
    assert [(u["unit"], u["distinct"], u["calls"], u["recent"]) for u in out["units"]] == [
        ("nginx.service", 2, 53, 1),
        ("user.slice", 1, 3, 1),
    ]


def test_unit_calls_are_named_and_carry_no_path_or_pid(tmp_path, monkeypatch):
    now = int(time.time())
    _snapshot(tmp_path, monkeypatch, [
        {"id": 1, "path": "/system.slice/postgresql@14-main.service", "calls": [[3, 5, now - 60], [449, 1, now]]},
    ])
    asked = []
    monkeypatch.setattr(svc, "_unit_filter", lambda real: asked.append(real) or {"kind": "none", "size": 0})
    out = svc.get_unit("postgresql@.service")
    assert out["unit"] == "postgresql@.service"
    assert out["calls"][0][:2] == ["connect", 5] and 55 <= out["calls"][0][2] <= 65
    assert out["calls"][1][:2] == ["syscall_449", 1]
    # systemctl is asked about the real instance; the reply names only the public unit
    assert asked == ["postgresql@14-main.service"]
    assert "14" not in json.dumps(out)


def test_slices_and_scopes_have_no_filter_to_read(tmp_path, monkeypatch):
    _snapshot(tmp_path, monkeypatch, [{"id": 2, "path": "/user.slice/user-1000.slice/session-4.scope",
                                       "calls": [[6, 1, int(time.time())]]}])
    monkeypatch.setattr(svc, "_unit_filter", lambda real: pytest.fail("a scope was asked about"))
    assert svc.get_unit("user.slice")["filter"] is None


def test_unknown_or_malformed_unit():
    with pytest.raises(ValueError):
        svc.get_unit("../etc/passwd")


def test_stale_snapshot_is_unavailable(tmp_path, monkeypatch):
    path = _snapshot(tmp_path, monkeypatch, [])
    old = time.time() - 120
    import os
    os.utime(path, (old, old))
    assert svc.get_units()["source"]["reason"] == "stale"


def test_filter_kind_and_size_only():
    assert svc.parse_filter({"SystemCallFilter": "~", "NoNewPrivileges": "no"}) == \
        {"kind": "none", "size": 0, "no_new_privs": False}
    assert svc.parse_filter({"SystemCallFilter": "read write brk", "NoNewPrivileges": "yes"}) == \
        {"kind": "allow", "size": 3, "no_new_privs": True}
    assert svc.parse_filter({"SystemCallFilter": "~ptrace bpf"})["kind"] == "deny"


def test_kernel_view_from_proc_status():
    status = "Name:\tfilebeat\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n"
    assert svc.kernel_seccomp(status) == {"mode": "filter", "no_new_privs": True, "filters": 1}
    assert svc.kernel_seccomp("Name:\tx\n") is None
