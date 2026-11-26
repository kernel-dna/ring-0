import importlib.util
import json
import math
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("kdna", ROOT / "tools" / "kdna.py")
kdna = importlib.util.module_from_spec(_spec)
sys.modules["kdna"] = kdna
_spec.loader.exec_module(kdna)


def _ev(pid, name, comm="nginx", cgroup=5):
    return {"kind": "syscall_span", "pid": pid, "comm": comm, "cgroup_id": cgroup,
            "syscall": {"name": name}}


def test_alphabet_matches_the_page():
    js = (ROOT / "static" / "js" / "kernel-dna.js").read_text()
    body = js[js.index("_buildSeqFamilyMap() {"):]
    page = {letter: set(names.split()) for letter, names in re.findall(r"add\('([ACGT])', `([^`]*)`\)", body)[:4]}
    assert page == {letter: set(names.split()) for letter, names in kdna.FAMILIES.items()}


def test_a_trigram_outside_the_profile_is_a_capital():
    stide = {"accept4|connect|accept4", "connect|accept4|connect"}
    reader = kdna.Reader(stide=stide, width=10)
    lines = []
    for name in ["accept4", "connect"] * 4 + ["clone", "accept4"]:
        lines += reader.feed(_ev(7, name))
    # accept4 connect clone and connect clone accept4 were never seen
    assert lines == ["nginx[7]".ljust(44) + "       1 ccccccccGC"]


def test_lines_are_numbered_per_process_in_blocks_of_ten():
    reader = kdna.Reader(width=20)
    out = []
    for i in range(45):
        out += reader.feed(_ev(9, "connect"))
        out += reader.feed(_ev(11, "setuid", comm="sudo"))
    out += reader.flush()
    nginx = [line for line in out if line.startswith("nginx[9]")]
    assert [line.split()[1] for line in nginx] == ["1", "21", "41"]
    assert nginx[0].endswith("cccccccccc cccccccccc") and nginx[2].endswith("ccccc")
    assert any(line.startswith("sudo[11]") and line.endswith("tttttttttt tttttttttt") for line in out)


def test_codon_table_counts_family_triplets():
    reader = kdna.Reader(stide={"connect|connect|connect"})
    for name in ["connect", "connect", "connect", "clone", "execve", "setuid"]:
        reader.feed(_ev(3, name))
    table = reader.summary()
    rows = {line.split()[2]: line.split() for line in table[2:-2]}
    assert set(rows) == {"CCC", "CCG", "CGG", "GGT"}
    assert rows["CCC"][3] == "0" and rows["GGT"][3] == "1"
    assert rows["GGT"][4:] == ["clone", "execve", "setuid"]
    assert table[-1].split()[1:3] == ["4", "total"]


def test_filters_by_pid_unit_and_comm():
    units = {5: "nginx.service", 6: "cron.service"}
    reader = kdna.Reader(width=1, unit="nginx", unit_of=lambda e: units.get(e["cgroup_id"]))
    assert reader.feed(_ev(1, "connect", cgroup=6)) == []
    assert reader.feed(_ev(2, "connect", cgroup=5))[0].split()[:2] == ["nginx[2]", "nginx"]
    only = kdna.Reader(width=1, pids={2})
    assert only.feed(_ev(1, "connect")) == [] and only.feed(_ev(2, "connect"))
    assert kdna.Reader(width=1, comm="cron").feed(_ev(1, "connect")) == []


def test_markov_bits_end_the_line():
    from kdna import _markov

    m = _markov.MarkovScorer()
    m.observe(["accept4", "connect"] * 200)
    reader = kdna.Reader(markov=m, width=4)
    lines = []
    for name in ["accept4", "connect", "accept4", "clone"]:
        lines += reader.feed(_ev(4, name))
    assert lines[0].endswith("bit accept4→clone")


def test_a_markov_without_contexts_still_ends_the_line():
    class Global:
        """score_window as in a markov.py from before contexts."""
        meta = {}

        def score_window(self, tokens):
            return {"neg_avg_logprob": 3 * math.log(2)}

    reader = kdna.Reader(markov=Global(), width=2)
    assert reader.feed(_ev(4, "accept4")) == []
    assert reader.feed(_ev(4, "connect"))[0].endswith("3.0 bit accept4→connect")


def test_unit_names_fold_like_the_ml_context():
    from kdna import _markov

    for path in ("system.slice/nginx.service", "system.slice/system-ssh.slice/ssh@12-10.0.0.5:22-1.2.3.4:5.service",
                 "user.slice/user-1000.slice/session-41.scope", "init.scope", ""):
        assert kdna.unit_name(path) == _markov.unit_context(path).removeprefix("unit:")
    assert kdna.unit_name(None) is None


def test_replay_reads_a_cut_trace_with_its_units(tmp_path, capsys):
    trace = tmp_path / "20261120T045424-web-siem-kernelai-flood-per-ip.jsonl"
    trace.write_text("\n".join(json.dumps(_ev(6197, n, comm="gunicorn")) for n in ["accept4", "vfork", "execve"]))
    (tmp_path / (trace.stem + ".cgroups.json")).write_text(json.dumps({"5": "system.slice/kernel-ai.service"}))
    assert kdna.main(["--replay", str(trace), "--no-model", "-C", "--color", "never"]) == 0
    out, err = capsys.readouterr()
    assert out.splitlines() == ["> " + trace.name,
                                ("gunicorn[6197]".ljust(23) + " kernel-ai").ljust(44) + "       1 cgg"]
    assert "CGG" in err and "3 syscalls in 1 processes" in err
