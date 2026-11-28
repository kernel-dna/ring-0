import gzip
import json
import random
import re
import time
from collections import Counter
from pathlib import Path

from kernel_ai.ml import align
from kernel_ai.ml.collectors.base import ALLOWED_SYSCALLS

SENSOR = Path(__file__).parents[1] / "sensor" / "cmd" / "kernel-ai-sensor"
T0 = 1795219200.0  # 2026-11-21 00:00 UTC


def _sensor_security_names():
    names = set()
    main = (SENSOR / "main.go").read_text()
    body = main[main.index("func securityNames()"):]
    body = body[:body.index("\n}\n")]
    names |= set(re.findall(r'unix\.SYS_\w+:\s+"(\w+)"', body))
    for path in SENSOR.glob("security_legacy_fork_*.go"):
        names |= set(re.findall(r'unix\.SYS_\w+:\s+"(\w+)"', path.read_text()))
    return names


def test_every_sensor_security_call_has_a_canonical_amino_acid_letter():
    names = _sensor_security_names()
    assert len(names) >= 22
    assert names <= set(align.LETTER_OF)
    assert set(align.LETTER_OF) <= ALLOWED_SYSCALLS
    assert set(align.ALPHABET) <= set("ACDEFGHIKLMNPQRSTVWY")
    assert not set(align.ALPHABET) & set("ACGT")


def test_reads_cover_the_tail_without_a_short_last_read():
    assert align.query_reads("", 4) == []
    assert align.query_reads("IIN", 4) == ["IIN"]
    assert align.query_reads("IINNIINN", 4) == ["IINN", "IINN"]
    assert align.query_reads("IINNIINNK", 4) == ["IINN", "IINN", "INNK"]


def test_semiglobal_finds_the_read_inside_a_longer_reference():
    w = {a: 2.0 for a in align.ALPHABET}
    scores = align.semiglobal("NIK", ["EEENIKEEE", "NIEK", "PPP"], w)
    assert scores[0] == 6.0
    assert scores[1] == 6.0 + align.GAP  # one reference letter skipped inside the alignment
    assert scores[2] == 3 * align.MISMATCH


def test_a_call_the_unit_never_makes_weighs_more_than_a_reshuffle():
    genome = align.Genome(length=8)
    rnd = random.Random(3)
    for _ in range(40):
        genome.add("unit:nginx.service", "".join(rnd.choice("IIIN") for _ in range(64)))
    scorer = genome.scorer("unit:nginx.service")
    assert scorer.novelty("IIINIIIN")[0] == 0.0
    reshuffled = scorer.novelty("NNNNNNNN")[0]
    foreign = scorer.novelty("IIIPIIIN")[0]
    assert scorer.weight["P"] == align.MAX_BITS
    assert foreign > reshuffled > 0.0
    assert scorer.novelty("PPPPPPPP") == (1.0, "")


def test_every_window_of_the_reference_aligns_perfectly_without_the_exact_path():
    genome = align.Genome(length=6)
    rnd = random.Random(5)
    seq = "".join(rnd.choice("INKEVRD") for _ in range(200))
    genome.add("u", seq)
    scorer = genome.scorer("u")
    for i in range(len(seq) - 6 + 1):
        assert scorer._align(seq[i:i + 6])[0] == 0.0


def test_fasta_records_split_and_wrap(tmp_path):
    path = tmp_path / "x.fasta"
    with path.open("w") as fh:
        assert align.write_fasta(fh, "ref0", "unit=u pid=1", "I" * 130, chunk=100) == 2
    lines = path.read_text().splitlines()
    assert lines[0] == ">ref0.1 unit=u pid=1 pos=1"
    assert [len(x) for x in lines[1:3]] == [60, 40]
    assert lines[3] == ">ref0.2 unit=u pid=1 pos=101"


def _line(ts, pid, cgroup, name, comm="nginx"):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + ".000000000Z"
    return json.dumps({"schema": "kernel.event/v1", "kind": "syscall_span", "timestamp": stamp,
                       "pid": pid, "uid": 33, "comm": comm, "cgroup_id": cgroup,
                       "syscall": {"name": name}})


def _day(root, name, t0):
    day = root / name
    day.mkdir(parents=True)
    (day / "cgroups.json").write_text(json.dumps({"5": "system.slice/kernel-ai.service"}))
    lines = [_line(t0 + i, 100 + i // 200, 5, "accept4" if i % 3 else "connect") for i in range(2000)]
    with gzip.open(day / "00.jsonl.gz", "wt") as fh:
        fh.write("\n".join(lines) + "\n")


def test_attack_trace_is_flagged_against_the_held_out_normal(tmp_path):
    _day(tmp_path / "data", "2026-11-19", T0 - 2 * 86400)
    _day(tmp_path / "data", "2026-11-20", T0 - 86400)
    attacks = tmp_path / "attacks"
    attacks.mkdir()
    calls = ["execve"] + ["ptrace", "clone"] * 20
    (attacks / "ptrace_probe.jsonl").write_text(
        "\n".join(_line(T0 + i, 7, 9, name, comm="python") for i, name in enumerate(calls)) + "\n")
    benign = ["accept4", "accept4", "connect"] * 10
    (attacks / "quiet.jsonl").write_text(
        "\n".join(_line(T0 + i, 8, 9, name) for i, name in enumerate(benign)) + "\n")

    assert align.main(["--data", str(tmp_path / "data"), "--ref-days", "2026-11-19",
                       "--heldout-days", "2026-11-20", "--scenarios", str(attacks),
                       "--out", str(tmp_path / "out")]) == 0

    report = json.loads((tmp_path / "out" / "report.json").read_text())
    assert report["heldout"]["flagged"] == 0
    rows = {r["scenario"]: r for r in report["scenarios"]}
    assert rows["ptrace_probe"]["victim"] == "unit:kernel-ai.service"
    assert rows["ptrace_probe"]["flagged"] == rows["ptrace_probe"]["reads"] == 3
    assert rows["quiet"]["flagged"] == 0
    assert "ptrace" in rows["ptrace_probe"]["worst_read"]
    fasta = (tmp_path / "out" / "scenarios.fasta").read_text()
    assert ">ptrace_probe.7 unit=unit:kernel-ai.service" in fasta
    with gzip.open(tmp_path / "out" / "norm.fasta.gz", "rt") as fh:
        norm = fh.read()
    assert Counter(c for line in norm.splitlines() if not line.startswith(">") for c in line) == {"I": 2666, "N": 1334}
