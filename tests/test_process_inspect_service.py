"""Tests for ``kernel_ai.services.process_inspect``."""

from kernel_ai.services import process_inspect as svc


def test_only_real_shared_memory_counts_as_an_ipc_channel():
    assert svc._is_ipc_shared_mapping("/dev/shm/pulse-shm-1")
    assert svc._is_ipc_shared_mapping("/memfd:wayland-cursor")
    assert svc._is_ipc_shared_mapping("/SYSV00000000")
    assert not svc._is_ipc_shared_mapping("/dev/dri/card0")
    assert not svc._is_ipc_shared_mapping("/usr/share/fonts/truetype/x")
    assert not svc._is_ipc_shared_mapping("/var/cache/fontconfig/abc")


def test_get_ipc_links_summary_empty_proc(monkeypatch):
    monkeypatch.setattr(svc.os, "listdir", lambda path: [] if path == "/proc" else [])
    monkeypatch.setattr(svc.psutil, "net_connections", lambda kind: [])
    out = svc.get_ipc_links_summary(max_pairs=20, max_nodes=8)
    assert out["process_nodes"] == []
    assert out["pair_links"] == []
    assert out["stats"]["pair_count"] == 0
    assert out["stats"]["shared_unix_socket_inodes"] == 0
    assert out["stats"]["shared_tcp_socket_inodes"] == 0


def test_family_label_and_peer_split():
    assert svc._family_label("AddressFamily.AF_UNIX", "SOCK_STREAM") == "unix"
    assert svc._family_label("AddressFamily.AF_INET", "SocketKind.SOCK_STREAM") == "tcp"
    assert svc._family_label("AddressFamily.AF_INET6", "SOCK_DGRAM") == "udp6"
    assert svc._split_ip_port("127.0.0.1:8000") == ("127.0.0.1", 8000)
    assert svc._split_ip_port("/run/foo.sock") is None
    assert svc._hex_ipv4("0100007F") == "127.0.0.1"


def test_annotate_connection_peers_pairs_loopback(monkeypatch):
    class _Addr:
        def __init__(self, ip, port):
            self.ip = ip
            self.port = port

    class _Conn:
        def __init__(self, pid, lip, lport, rip, rport):
            self.pid = pid
            self.laddr = _Addr(lip, lport)
            self.raddr = _Addr(rip, rport)

    class _Proc:
        def __init__(self, pid, name):
            self.info = {"pid": pid, "name": name}

    monkeypatch.setattr(
        svc.psutil,
        "process_iter",
        lambda attrs: [_Proc(10, "gunicorn"), _Proc(20, "sshd")],
    )
    monkeypatch.setattr(
        svc.psutil,
        "net_connections",
        lambda kind: [
            _Conn(10, "127.0.0.1", 8000, "127.0.0.1", 44312),
            _Conn(20, "127.0.0.1", 44312, "127.0.0.1", 8000),
        ],
    )
    rows = svc._annotate_connection_peers(
        [
            {
                "local_address": "127.0.0.1:8000",
                "remote_address": "127.0.0.1:44312",
                "peer_pid": None,
                "peer_name": None,
            }
        ]
    )
    assert rows[0]["peer_pid"] == 20
    assert rows[0]["peer_name"] == "sshd"


def test_get_process_fds_info_basic(monkeypatch):
    class _FakeProc:
        def num_fds(self):
            return 3

        def open_files(self):
            return []

        def connections(self):
            return []

    monkeypatch.setattr(svc.psutil, "Process", lambda _pid: _FakeProc())
    out = svc.get_process_fds_info(123)
    assert out["pid"] == 123
    assert out["num_fds"] == 3


def test_get_process_fds_info_descriptors(monkeypatch):
    class _FakeProc:
        def num_fds(self):
            return 5

        def open_files(self):
            return []

        def connections(self):
            return []

    targets = {
        "/proc/123/fd/0": "/dev/null",
        "/proc/123/fd/1": "pipe:[10]",
        "/proc/123/fd/2": "pipe:[11]",
        "/proc/123/fd/7": "socket:[12]",
        "/proc/123/fd/19": "pipe:[13]",
    }

    monkeypatch.setattr(svc.psutil, "Process", lambda _pid: _FakeProc())
    monkeypatch.setattr(svc.os.path, "exists", lambda path: path == "/proc/123/fd")
    monkeypatch.setattr(svc.os, "listdir", lambda path: ["19", "0", "7", "2", "1"] if path == "/proc/123/fd" else [])
    monkeypatch.setattr(svc.os, "readlink", lambda path: targets[path])
    # Isolate the unrelated namespace probe: this test is about fd descriptor
    # parsing, and the real fingerprint reads /proc/<pid>/ns/* (not mocked here).
    monkeypatch.setattr(svc, "get_process_namespace_fingerprint", lambda _pid: {})

    out = svc.get_process_fds_info(123)
    descriptors = out["descriptors"]
    assert [item["fd"] for item in descriptors] == [0, 1, 2, 7, 19]
    assert [item["type"] for item in descriptors] == ["stdin", "stdout", "stderr", "socket", "pipe"]


def test_enrich_descriptor_metadata_reads_epoll_members_and_vfs(monkeypatch):
    descriptors = [
        {"fd": 4, "type": "anon_inode", "target": "anon_inode:[eventpoll]"},
        {"fd": 7, "type": "pipe", "target": "pipe:[12]"},
        {"fd": 9, "type": "file", "target": "/srv/data.log"},
    ]

    monkeypatch.setattr(
        svc,
        "_read_fdinfo",
        lambda _pid, fd: {
            "readable": True,
            "mount_id": 31 if fd == 9 else None,
            "registrations": (
                [{"fd": 7, "events": "19", "data": "7"}] if fd == 4 else []
            ),
        },
    )
    monkeypatch.setattr(
        svc.os,
        "stat",
        lambda _path: type("Stat", (), {"st_ino": 812, "st_dev": 2049})(),
    )
    monkeypatch.setattr(svc.os, "major", lambda _device: 8)
    monkeypatch.setattr(svc.os, "minor", lambda _device: 1)

    epoll_sets = svc._enrich_descriptor_metadata(123, descriptors)

    assert epoll_sets == [
        {
            "epfd": 4,
            "target": "anon_inode:[eventpoll]",
            "observable": True,
            "registrations": [
                {
                    "fd": 7,
                    "events": "19",
                    "data": "7",
                    "type": "pipe",
                    "target": "pipe:[12]",
                    "local_address": None,
                    "remote_address": None,
                }
            ],
        }
    ]
    assert descriptors[2]["vfs"] == {
        "mount_id": 31,
        "inode": 812,
        "device": "8:1",
    }


class _FakeAncestor:
    """Minimal psutil.Process stand-in for lineage walking."""

    def __init__(self, pid, name, create_time, parent=None):
        self.pid = pid
        self._name = name
        self._create_time = create_time
        self._parent = parent

    def as_dict(self, _fields):
        return {
            "pid": self.pid,
            "name": self._name,
            "create_time": self._create_time,
            "status": "sleeping",
            "username": "alex",
        }

    def cmdline(self):
        return ["/usr/bin/" + self._name]

    def name(self):
        return self._name

    def parent(self):
        return self._parent

    def children(self):
        return []


def test_get_process_lineage_orders_oldest_first(monkeypatch):
    init = _FakeAncestor(1, "systemd", 1000.0)
    shell = _FakeAncestor(50, "bash", 2000.0, parent=init)
    leaf = _FakeAncestor(900, "python3", 3000.0, parent=shell)

    monkeypatch.setattr(svc.psutil, "Process", lambda _pid: leaf)
    monkeypatch.setattr(svc.psutil, "boot_time", lambda: 999.0)

    out = svc.get_process_lineage_info(900)
    assert [row["pid"] for row in out["chain"]] == [1, 50, 900]
    assert [row["name"] for row in out["chain"]] == ["systemd", "bash", "python3"]
    assert out["depth"] == 3
    assert out["truncated"] is False
    assert out["chain"][0]["create_time"] == 1000.0


def test_get_process_lineage_breaks_parent_cycle(monkeypatch):
    a = _FakeAncestor(10, "a", 1000.0)
    b = _FakeAncestor(11, "b", 1100.0, parent=a)
    a._parent = b  # pathological /proc race: parent chain loops back

    monkeypatch.setattr(svc.psutil, "Process", lambda _pid: b)
    monkeypatch.setattr(svc.psutil, "boot_time", lambda: 999.0)

    out = svc.get_process_lineage_info(11)
    assert [row["pid"] for row in out["chain"]] == [10, 11]


_ALL_CAPS = (1 << 41) - 1
_HOST_MOUNTS = "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
_HOST_USERS = "         0          0 4294967295\n"
_USERS = {0: "root", 33: "www-data", 101: "systemd-resolve", 1000: "alex"}


def _fake_lineage(tmp_path, monkeypatch, procs):
    """Ancestors oldest first, each with its /proc status, mount table, interfaces, uid map and cgroup.

    Returns the youngest; open() reads the fake /proc and getpwuid the users above.
    """
    root = tmp_path / "proc"
    parent = None
    for spec in procs:
        pid = spec["pid"]
        folder = root / str(pid)
        (folder / "net").mkdir(parents=True)
        euid = spec.get("euid", spec.get("uid", 0))
        filters = spec.get("filters", 0)
        (folder / "status").write_text(
            f"Name:\t{spec['name']}\n"
            f"Uid:\t{spec.get('uid', 0)}\t{euid}\t{euid}\t{euid}\n"
            f"CapEff:\t{spec.get('caps', _ALL_CAPS):016x}\n"
            f"CapBnd:\t{spec.get('bound', _ALL_CAPS):016x}\n"
            f"NoNewPrivs:\t{spec.get('nnp', 0)}\n"
            f"Seccomp:\t{2 if filters else 0}\n"
            f"Seccomp_filters:\t{filters}\n"
            f"NSpid:\t{pid}\n"
        )
        (folder / "mountinfo").write_text(spec.get("mounts", _HOST_MOUNTS))
        (folder / "net" / "dev").write_text("Inter-|   Receive\n face |bytes\n    lo: 0 0\n  eth0: 0 0\n")
        (folder / "uid_map").write_text(spec.get("uid_map", _HOST_USERS))
        (folder / "cgroup").write_text(f"0::{spec.get('cgroup', '/init.scope')}\n")
        parent = _FakeAncestor(pid, spec["name"], 1000.0 + pid, parent=parent)
    (root / "sys" / "kernel").mkdir(parents=True)
    (root / "sys" / "kernel" / "cap_last_cap").write_text("40\n")

    real_open = open

    def fake_open(path, *args, **kwargs):
        if isinstance(path, str) and path.startswith("/proc/"):
            return real_open(root / path[len("/proc/"):], *args, **kwargs)
        return real_open(path, *args, **kwargs)

    def getpwuid(uid):
        if uid not in _USERS:
            raise KeyError(uid)
        return type("pw", (), {"pw_name": _USERS[uid]})()

    monkeypatch.setattr("builtins.open", fake_open)
    monkeypatch.setattr(svc.pwd, "getpwuid", getpwuid)
    monkeypatch.setattr(svc.psutil, "Process", lambda _pid: parent)
    monkeypatch.setattr(svc.psutil, "boot_time", lambda: 999.0)
    return parent


def test_lineage_traits_mark_where_a_trait_changes(monkeypatch, tmp_path):
    _fake_lineage(tmp_path, monkeypatch, [
        {"pid": 1, "name": "systemd"},
        {"pid": 949, "name": "nginx", "cgroup": "/system.slice/nginx.service"},
        {"pid": 950, "name": "nginx", "uid": 33, "caps": 0, "cgroup": "/system.slice/nginx.service"},
    ])

    out = svc.get_process_lineage_info(950, traits=True)

    assert out["caps_full"] == 41
    systemd, master, worker = out["chain"]
    assert systemd["traits"] == {"user": "root", "real_user": None, "caps": 41, "bound": 41, "nnp": False,
                                 "seccomp": 0, "filters": 0, "ns": [], "unit": "init.scope"}
    assert systemd["changes"] == [] and master["changes"] == []
    assert master["traits"]["unit"] == "nginx.service"
    assert worker["changes"] == [
        {"trait": "user", "from": "root", "to": "www-data", "kind": "drop"},
        {"trait": "caps", "from": 41, "to": 0, "kind": "drop"},
    ]
    assert [row["adopted"] for row in out["chain"]] == [False, False, False]
    assert [row["privesc"] for row in out["chain"]] == [None, None, None]


def test_lineage_traits_tell_a_namespace_by_what_it_shows(monkeypatch, tmp_path):
    _fake_lineage(tmp_path, monkeypatch, [
        {"pid": 1, "name": "systemd"},
        {"pid": 725, "name": "systemd-resolve", "uid": 101, "caps": 1 << 10, "bound": 1 << 10, "nnp": 1,
         "filters": 22, "mounts": "640 590 8:1 / / ro - ext4 /dev/sda1 rw\n",
         "cgroup": "/system.slice/systemd-resolved.service"},
        {"pid": 726, "name": "resolve-child", "uid": 101, "caps": 1 << 10, "bound": 1 << 10, "nnp": 1,
         "filters": 22, "mounts": "640 590 8:1 / / ro - ext4 /dev/sda1 rw\n",
         "cgroup": "/system.slice/systemd-resolved.service"},
    ])

    _, resolved, child = svc.get_process_lineage_info(726, traits=True)["chain"]

    assert resolved["traits"]["ns"] == ["mnt"]
    assert {change["trait"]: change["kind"] for change in resolved["changes"]} == {
        "user": "drop", "caps": "drop", "bound": "drop", "nnp": "drop", "seccomp": "drop", "ns": "new"}
    assert [c for c in resolved["changes"] if c["trait"] == "seccomp"] == [
        {"trait": "seccomp", "from": 0, "to": 22, "kind": "drop"}]
    # the same mount table is the same namespace: inherited, not new again
    assert child["traits"]["ns"] == ["mnt"] and child["changes"] == []


def test_lineage_privesc_follows_stage5s_rule(monkeypatch, tmp_path):
    _fake_lineage(tmp_path, monkeypatch, [
        {"pid": 1, "name": "systemd"},
        {"pid": 40, "name": "bash", "uid": 1000, "caps": 0},
        {"pid": 41, "name": "sudo", "uid": 1000, "euid": 0},
    ])
    helper = svc.get_process_lineage_info(41, traits=True)["chain"][-1]
    assert helper["privesc"] == "helper"
    assert helper["traits"]["user"] == "root" and helper["traits"]["real_user"] == "alex"
    assert helper["changes"][0] == {"trait": "user", "from": "alex", "to": "root", "kind": "gain"}

    _fake_lineage(tmp_path / "again", monkeypatch, [
        {"pid": 1, "name": "systemd"},
        {"pid": 40, "name": "bash", "uid": 1000, "caps": 0},
        {"pid": 42, "name": "python3", "uid": 1000, "euid": 0},
    ])
    assert svc.get_process_lineage_info(42, traits=True)["chain"][-1]["privesc"] == "flagged"


def test_lineage_tells_an_adopted_child_and_namespaced_capabilities(monkeypatch, tmp_path):
    _fake_lineage(tmp_path, monkeypatch, [
        {"pid": 1, "name": "systemd"},
        {"pid": 60, "name": "sandboxed", "uid": 1000, "caps": 0, "nnp": 1, "filters": 1},
        # no_new_privs and the filter gone: its own parent exited and this one adopted it
        {"pid": 61, "name": "orphan", "uid": 1000, "caps": 0},
    ])
    orphan = svc.get_process_lineage_info(61, traits=True)["chain"][-1]
    assert orphan["adopted"] is True and orphan["changes"] == []

    _fake_lineage(tmp_path / "again", monkeypatch, [
        {"pid": 1, "name": "systemd"},
        {"pid": 70, "name": "chrome", "uid": 1000, "caps": 0},
        {"pid": 71, "name": "chrome", "uid": 1000, "caps": 1 << 21, "uid_map": "         0       1000          1\n"},
    ])
    sandbox = svc.get_process_lineage_info(71, traits=True)["chain"][-1]
    assert sandbox["traits"]["ns"] == ["user"]
    assert {"trait": "caps", "from": 0, "to": 1, "kind": "gain", "userns": True} in sandbox["changes"]


def test_plain_lineage_reads_no_traits(monkeypatch, tmp_path):
    _fake_lineage(tmp_path, monkeypatch, [{"pid": 1, "name": "systemd"}, {"pid": 5, "name": "bash", "uid": 1000}])
    out = svc.get_process_lineage_info(5)
    assert "caps_full" not in out
    assert all("traits" not in row and "changes" not in row for row in out["chain"])


def test_activity_counters_expose_deltas_source(monkeypatch, tmp_path):
    class _Times:
        user = 1.25
        system = 0.5

    class _FakeProc:
        def cpu_times(self):
            return _Times()

    status = tmp_path / "status"
    status.write_text(
        "Name:\tnginx\nThreads:\t4\n"
        "voluntary_ctxt_switches:\t120\n"
        "nonvoluntary_ctxt_switches:\t7\n"
    )
    io_file = tmp_path / "io"
    io_file.write_text("read_bytes: 4096\nwrite_bytes: 8192\n")
    stat_file = tmp_path / "stat"
    stat_file.write_text(
        "77 (nginx worker) S 1 2 3 4 5 6 1200 8 3 1 0 0 0\n"
    )

    real_open = open

    def fake_open(path, *args, **kwargs):
        if path == "/proc/77/status":
            return real_open(status, *args, **kwargs)
        if path == "/proc/77/io":
            return real_open(io_file, *args, **kwargs)
        if path == "/proc/77/stat":
            return real_open(stat_file, *args, **kwargs)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(svc.psutil, "Process", lambda _pid: _FakeProc())
    monkeypatch.setattr("builtins.open", fake_open)

    out = svc.get_process_activity_counters(77)
    assert out["ctx_voluntary"] == 120
    assert out["ctx_nonvoluntary"] == 7
    assert out["num_threads"] == 4
    assert out["cpu_user"] == 1.25
    assert out["minflt"] == 1200
    assert out["cminflt"] == 8
    assert out["majflt"] == 3
    assert out["cmajflt"] == 1
    assert out["read_bytes"] == 4096
    assert out["io_readable"] is True
    assert out["ts"] > 0


def test_activity_counters_survive_unreadable_io(monkeypatch):
    class _FakeProc:
        def cpu_times(self):
            raise svc.psutil.AccessDenied(77)

    def fake_open(path, *args, **kwargs):
        raise PermissionError(path)

    monkeypatch.setattr(svc.psutil, "Process", lambda _pid: _FakeProc())
    monkeypatch.setattr("builtins.open", fake_open)

    out = svc.get_process_activity_counters(77)
    assert out["io_readable"] is False
    assert out["read_bytes"] is None
    assert out["cpu_user"] is None
    assert out["ctx_voluntary"] is None
