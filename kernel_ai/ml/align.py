"""Syscall sequences as protein FASTA, and how far a trace sits from the normal genome.

Each security syscall becomes one amino-acid letter, so the calls of a process
read as a protein that MAFFT, HMMER or Jalview open as is. Variants of one call
share a letter (accept/accept4, clone/clone3/fork, the setuid and the setgid
families): 16 of the 20 canonical letters and none of A, C, G, T, which are the
syscall families on the Kernel DNA page.

Distance from normal: a trace is cut into reads of ``READ_LEN`` calls per pid,
and a read's novelty is one minus its best semi-global alignment score against
the reference reads of its unit, over its score against itself. A matched
letter is worth its information in that unit, -log2 p, so a call the unit never
makes weighs most. A mismatch costs nothing and a gap a quarter bit, so novelty
is close to the share of the read's information that no normal read accounts
for: a reshuffle of a unit's staple calls stays low, a call it never makes does
not. A read counts as flagged above the 99.9th percentile of a held-out normal
day's reads in the same unit.

    python -m kernel_ai.ml.align --data ~/kernel-ai-eval/prod-normal \\
        --ref-days 2026-11-18 2026-11-19 --heldout-days 2026-11-20 \\
        --alerts ~/kernel-ai-eval/alerts-20261118.json \\
        --windows ~/kernel-ai-eval/alert-windows --scenarios ~/kernel-ai-eval/attacks \\
        --out ~/kernel-ai-eval/align
"""

from __future__ import annotations

import argparse
import gzip
import json
import math
import resource
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator, TextIO

import numpy as np

from kernel_ai.ml.exclusions import WindowIndex
from kernel_ai.ml.replay import ReplayEvent, iter_dataset_events, to_event

# The first name of a letter is the one shown in reports.
ALPHABET: dict[str, tuple[str, ...]] = {
    "E": ("execve",),
    "F": ("execveat",),
    "K": ("clone", "clone3", "fork"),
    "V": ("vfork",),
    "N": ("connect",),
    "I": ("accept4", "accept"),
    "H": ("bind",),
    "L": ("listen",),
    "D": ("unlinkat",),
    "R": ("renameat", "renameat2"),
    "S": ("setresuid", "setuid", "setreuid"),
    "Q": ("setresgid", "setgid", "setregid"),
    "P": ("ptrace",),
    "W": ("process_vm_writev",),
    "M": ("memfd_create",),
    "Y": ("userfaultfd",),
}
LETTER_OF = {name: letter for letter, names in ALPHABET.items() for name in names}
CODE = {letter: i for i, letter in enumerate(ALPHABET)}
_BYTE = {name: ord(letter) for name, letter in LETTER_OF.items()}

READ_LEN = 16
GAP_SEC = 300.0  # a pid silent this long is a new process that reused the number
FASTA_CHUNK = 1000
QUANTILE = 0.999
MIN_CALIBRATION = 1000
MAX_BITS = 12.0
MISMATCH = 0.0
GAP = -0.25
# Where each attack would run on PROD: the web app, or nginx for the two nginx-shaped ones
DEFAULT_VICTIM = "unit:kernel-ai.service"
VICTIMS = {"web_shell_exec": "unit:nginx.service", "web_shell_in_nginx": "unit:nginx.service"}


@dataclass
class Strand:
    context: str
    pid: int
    comm: str
    start: float
    last: float
    # A byte per call: a day of the busiest unit is millions of calls
    letters: bytearray = field(default_factory=bytearray)

    @property
    def seq(self) -> str:
        return self.letters.decode()


def strands(
    events: Iterable[ReplayEvent],
    *,
    context_of: Callable[[ReplayEvent], str] | None = None,
    gap: float = GAP_SEC,
) -> Iterator[Strand]:
    """Letters of each pid in event order; silence longer than ``gap`` starts a new strand."""
    live: dict[int, Strand] = {}
    for ev in events:
        letter = _BYTE.get(ev.syscall)
        if letter is None:
            continue
        context = context_of(ev) if context_of else (ev.context or "-")
        strand = live.get(ev.pid)
        if strand is not None and (ev.ts - strand.last > gap or strand.context != context):
            yield strand
            strand = None
        if strand is None:
            strand = live[ev.pid] = Strand(context, ev.pid, ev.comm, ev.ts, ev.ts)
        strand.letters.append(letter)
        strand.last = ev.ts
    yield from live.values()


def query_reads(seq: str, length: int = READ_LEN) -> list[str]:
    """Non-overlapping reads; the last one is pulled back to end on the final call."""
    if len(seq) <= length:
        return [seq] if seq else []
    reads = [seq[i:i + length] for i in range(0, len(seq) - length + 1, length)]
    if len(seq) % length:
        reads.append(seq[-length:])
    return reads


def decode(read: str) -> str:
    """``IIIIK`` -> ``accept4×4 clone``."""
    out: list[str] = []
    i = 0
    while i < len(read):
        j = i
        while j < len(read) and read[j] == read[i]:
            j += 1
        name = ALPHABET[read[i]][0]
        out.append(name if j - i == 1 else f"{name}×{j - i}")
        i = j
    return " ".join(out)


def information(letters: Counter) -> dict[str, float]:
    """Bits per letter in one unit, from 1 for its staple calls to MAX_BITS for calls it never makes."""
    total = sum(letters.values()) + 0.5 * len(ALPHABET)
    return {
        a: min(MAX_BITS, max(1.0, -math.log2((letters.get(a, 0) + 0.5) / total)))
        for a in ALPHABET
    }


def semiglobal(
    query: str,
    refs: list[str],
    weight: dict[str, float],
    *,
    mismatch: float = MISMATCH,
    gap: float = GAP,
) -> np.ndarray:
    """Best score of ``query`` aligned end to end somewhere inside each of ``refs``."""
    width = max(len(r) for r in refs)
    codes = np.full((len(refs), width), -1, dtype=np.int8)
    for i, ref in enumerate(refs):
        codes[i, :len(ref)] = [CODE[a] for a in ref]
    steps = gap * np.arange(width + 1)
    # Reference letters before the alignment are free, so row 0 is all zeros
    prev = np.zeros((len(refs), width + 1))
    for a in query:
        sub = np.where(codes == CODE[a], weight[a], mismatch)
        sub[codes < 0] = -np.inf
        best = np.maximum(prev[:, :-1] + sub, prev[:, 1:] + gap)
        # A reference letter skipped inside the alignment costs a gap; with a linear
        # gap that is a running maximum of best[k] - gap*k
        row = np.concatenate([prev[:, :1] + gap, best], axis=1)
        prev = np.maximum.accumulate(row - steps, axis=1) + steps
    # ...and so are the reference letters after it
    return prev.max(axis=1)


class Genome:
    """Normal reads per unit: 2L windows at stride L to align against, every L window for an exact hit."""

    def __init__(self, length: int = READ_LEN) -> None:
        self.length = length
        self.reads: dict[str, Counter] = defaultdict(Counter)
        self.exact: dict[str, set[str]] = defaultdict(set)
        self.letters: dict[str, Counter] = defaultdict(Counter)

    def add(self, context: str, seq: str) -> None:
        n = self.length
        self.letters[context].update(seq)
        if len(seq) <= 2 * n:
            self.reads[context][seq] += 1
        else:
            # Any n-window starting at p lies inside the 2n-window starting at p // n * n
            self.reads[context].update(seq[i:i + 2 * n] for i in range(0, len(seq) - n, n))
        if len(seq) < n:
            self.exact[context].add(seq)
        else:
            self.exact[context].update(seq[i:i + n] for i in range(len(seq) - n + 1))

    def scorer(self, context: str) -> "Scorer | None":
        if context not in self.reads:
            return None
        return Scorer(self.reads[context], self.letters[context], [self.exact[context]])

    def host(self) -> "Scorer":
        reads: Counter = Counter()
        letters: Counter = Counter()
        for context in self.reads:
            reads.update(self.reads[context])
            letters.update(self.letters[context])
        return Scorer(reads, letters, list(self.exact.values()))


class Scorer:
    """Novelty of reads against one reference: exact hit, else k-mer candidates, then alignment."""

    def __init__(self, reads: Counter, letters: Counter, exact: list[set[str]], *, candidates: int = 48) -> None:
        self.reads = list(reads)
        self.weight = information(letters)
        self.exact = exact
        self.candidates = candidates
        self.staples = [r for r, _ in reads.most_common(8)]
        self._index: dict[int, dict[str, np.ndarray]] = {}
        self._memo: dict[str, tuple[float, str]] = {}

    def novelty(self, read: str) -> tuple[float, str]:
        """(novelty in [0, 1], the closest normal read)."""
        hit = self._memo.get(read)
        if hit is None:
            hit = (0.0, read) if any(read in s for s in self.exact) else self._align(read)
            self._memo[read] = hit
        return hit

    def _align(self, read: str) -> tuple[float, str]:
        refs = self._shortlist(read)
        scores = semiglobal(read, refs, self.weight)
        best = int(np.argmax(scores))
        own = sum(self.weight[a] for a in read)
        novelty = max(0.0, round(1.0 - max(0.0, float(scores[best])) / own, 6))
        # Nothing in the reference shares a letter in order: there is no nearest read to show
        return novelty, refs[best] if novelty < 1.0 else ""

    def _shortlist(self, read: str) -> list[str]:
        k = min(3, len(read))
        index = self._kmers(k)
        score = np.zeros(len(self.reads))
        for kmer in {read[i:i + k] for i in range(len(read) - k + 1)}:
            ids = index.get(kmer)
            if ids is not None:
                score[ids] += 1.0 + math.log(len(self.reads) / len(ids))
        top = min(self.candidates, len(self.reads))
        ids = np.argpartition(-score, top - 1)[:top] if top < len(self.reads) else np.arange(len(self.reads))
        refs = [self.reads[i] for i in ids if score[i] > 0]
        refs += [r for r in self.staples if r not in refs]
        return refs

    def _kmers(self, k: int) -> dict[str, np.ndarray]:
        if k not in self._index:
            postings: dict[str, list[int]] = defaultdict(list)
            for i, ref in enumerate(self.reads):
                for kmer in {ref[j:j + k] for j in range(len(ref) - k + 1)}:
                    postings[kmer].append(i)
            self._index[k] = {kmer: np.asarray(ids) for kmer, ids in postings.items()}
        return self._index[k]


_T0 = time.monotonic()


def _progress(stage: str) -> None:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024
    print(f"[align] {time.monotonic() - _T0:6.0f}s  peak {peak} MB  {stage}", file=sys.stderr, flush=True)


def _counted(events: Iterable[ReplayEvent], label: str) -> Iterator[ReplayEvent]:
    for n, ev in enumerate(events, 1):
        if n % 2_000_000 == 0:
            _progress(f"{label}: {n // 1_000_000}M calls")
        yield ev


def quantile(values: list[float], q: float) -> float:
    return float(np.quantile(np.asarray(values), q)) if values else 0.0


def read_trace(path: Path) -> list[ReplayEvent]:
    """A cut trace with its ``.cgroups.json`` sidecar, in time order."""
    sidecar = path.with_name(path.name.removesuffix(".jsonl") + ".cgroups.json")
    try:
        cgroups = {int(k): v for k, v in json.loads(sidecar.read_text()).items()}
    except (OSError, ValueError):
        cgroups = {}
    events = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                ev = to_event(json.loads(line), context="unit", cgroups=cgroups)
            except ValueError:
                continue
            if ev is not None:
                events.append(ev)
    return sorted(events, key=lambda e: e.ts)


def write_fasta(fh: TextIO, name: str, description: str, seq: str, *, chunk: int = FASTA_CHUNK) -> int:
    """Records of at most ``chunk`` letters, 60 per line; returns how many were written."""
    written = 0
    for start in range(0, len(seq), chunk):
        part = seq[start:start + chunk]
        suffix = f".{start // chunk + 1}" if len(seq) > chunk else ""
        fh.write(f">{name}{suffix} {description} pos={start + 1}\n")
        fh.writelines(part[j:j + 60] + "\n" for j in range(0, len(part), 60))
        written += 1
    return written


def _describe(strand: Strand) -> str:
    start = datetime.fromtimestamp(strand.start, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"unit={strand.context} pid={strand.pid} comm={strand.comm.replace(' ', '_')} start={start}"


class Calibration:
    """Per-unit thresholds from a held-out normal day; units it never saw get the pooled one."""

    def __init__(self, by_unit: dict[str, list[float]], host: list[float], q: float = QUANTILE) -> None:
        pooled = [v for values in by_unit.values() for v in values]
        self.pooled = quantile(pooled, q)
        self.by_unit = {u: quantile(v, q) for u, v in by_unit.items() if len(v) >= MIN_CALIBRATION}
        self.host = quantile(host, q)
        self.reads = len(pooled)
        self.flagged = sum(v > self.threshold(u) for u, values in by_unit.items() for v in values)
        self.host_flagged = sum(v > self.host for v in host)
        self.units = {
            u: {"reads": len(v), "flagged": sum(x > self.threshold(u) for x in v),
                "q999": round(quantile(v, q), 3), "max": round(max(v), 3)}
            for u, v in by_unit.items() if len(v) >= 100
        }

    def threshold(self, unit: str) -> float:
        return self.by_unit.get(unit, self.pooled)


def score_strands(
    items: Iterable[Strand],
    genome: Genome,
    host: Scorer,
    scorers: dict[str, Scorer | None],
    calib: Calibration | None,
    length: int,
) -> dict:
    """Reads of one trace against their unit and against the whole host."""
    reads = flagged = host_flagged = 0
    worst = (-1.0, "", "", "")
    worst_host = 0.0
    units = Counter()
    for strand in items:
        if strand.context not in scorers:
            scorers[strand.context] = genome.scorer(strand.context)
        scorer = scorers[strand.context]
        units[strand.context] += len(strand.letters)
        for read in query_reads(strand.seq, length):
            novelty, near = (scorer or host).novelty(read)
            novelty_host, _ = host.novelty(read)
            reads += 1
            worst_host = max(worst_host, novelty_host)
            if calib is not None:
                flagged += novelty > calib.threshold(strand.context)
                host_flagged += novelty_host > calib.host
            if novelty > worst[0]:
                worst = (novelty, read, near, strand.context)
    return {
        "reads": reads,
        "flagged": flagged,
        "host_flagged": host_flagged,
        "max_novelty": round(max(worst[0], 0.0), 3),
        "max_host_novelty": round(worst_host, 3),
        "worst_unit": worst[3],
        "worst_read": decode(worst[1]),
        "nearest_normal": decode(worst[2]),
        "units": dict(units.most_common(4)),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data", required=True, help="root of recorded days (<day>/<HH>.jsonl.gz)")
    ap.add_argument("--ref-days", nargs="+", required=True)
    ap.add_argument("--heldout-days", nargs="+", required=True)
    ap.add_argument("--alerts", help="fetch file of kernel_ai.ml.exclusions; its windows stay out of normal")
    ap.add_argument("--windows", help="directory of cut alert windows (index.json + traces)")
    ap.add_argument("--scenarios", help="directory of attack traces (<name>.jsonl + .cgroups.json)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--length", type=int, default=READ_LEN)
    args = ap.parse_args(argv)

    out = Path(args.out).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    data = str(Path(args.data).expanduser())
    exclude = WindowIndex.from_alerts(str(Path(args.alerts).expanduser())) if args.alerts else None
    with (out / "alphabet.tsv").open("w") as fh:
        fh.write("letter\tsyscalls\n")
        fh.writelines(f"{a}\t{','.join(names)}\n" for a, names in ALPHABET.items())

    genome = Genome(args.length)
    report: dict = {"read_len": args.length, "quantile": QUANTILE}
    with gzip.open(out / "norm.fasta.gz", "wt") as fasta:
        calls = n_strands = 0
        ref_events = _counted(iter_dataset_events(data, args.ref_days, context="unit", exclude=exclude), "reference")
        for i, strand in enumerate(strands(ref_events)):
            seq = strand.seq
            genome.add(strand.context, seq)
            write_fasta(fasta, f"ref{i}", _describe(strand), seq)
            calls += len(seq)
            n_strands += 1
        report["reference"] = {"days": args.ref_days, "calls": calls, "strands": n_strands, "units": len(genome.reads),
                               "unique_reads": sum(len(r) for r in genome.reads.values())}
        _progress(f"reference: {calls} calls, {report['reference']['unique_reads']} unique reads")
        heldout_events = _counted(iter_dataset_events(data, args.heldout_days, context="unit", exclude=exclude), "held-out")
        heldout = list(strands(heldout_events))
        for i, strand in enumerate(heldout):
            write_fasta(fasta, f"heldout{i}", _describe(strand), strand.seq)
    _progress(f"held-out: {len(heldout)} strands")

    host = genome.host()
    scorers: dict[str, Scorer | None] = {}
    by_unit: dict[str, list[float]] = defaultdict(list)
    host_values: list[float] = []
    new_units = Counter()
    for strand in heldout:
        if strand.context not in scorers:
            scorers[strand.context] = genome.scorer(strand.context)
        scorer = scorers[strand.context]
        if scorer is None:
            new_units[strand.context] += len(strand.letters)
        for read in query_reads(strand.seq, args.length):
            by_unit[strand.context].append((scorer or host).novelty(read)[0])
            host_values.append(host.novelty(read)[0])
    calib = Calibration(by_unit, host_values)
    _progress(f"calibrated on {calib.reads} held-out reads")
    report["heldout"] = {
        "days": args.heldout_days,
        "calls": sum(len(s.letters) for s in heldout),
        "reads": calib.reads,
        "flagged": calib.flagged,
        "host_flagged": calib.host_flagged,
        "host_threshold": round(calib.host, 3),
        "pooled_threshold": round(calib.pooled, 3),
        "unit_thresholds": {u: round(t, 3) for u, t in sorted(calib.by_unit.items())},
        "units": dict(sorted(calib.units.items(), key=lambda kv: -kv[1]["reads"])),
        "host_max": round(max(host_values, default=0.0), 3),
        "units_not_in_reference": dict(new_units.most_common()),
    }

    if args.windows:
        root = Path(args.windows).expanduser()
        index = json.loads((root / "index.json").read_text())
        rows = index if isinstance(index, list) else index.get("windows", [])
        windows = []
        with (out / "alert-windows.fasta").open("w") as fasta:
            for row in rows:
                path = root / row["file"]
                items = list(strands(read_trace(path)))
                for strand in items:
                    write_fasta(fasta, f"{path.stem}.{strand.pid}", f"{_describe(strand)} labels={','.join(row['labels'])}",
                                strand.seq)
                windows.append({"file": row["file"], "labels": row["labels"], "scope": row["scope"],
                                **score_strands(items, genome, host, scorers, calib, args.length)})
        report["windows"] = windows
        _progress(f"{len(windows)} alert windows")

    if args.scenarios:
        root = Path(args.scenarios).expanduser()
        scenarios = []
        with (out / "scenarios.fasta").open("w") as fasta:
            for path in sorted(root.glob("*.jsonl")):
                victim = VICTIMS.get(path.stem, DEFAULT_VICTIM)
                items = list(strands(read_trace(path), context_of=lambda ev, v=victim: v))
                for strand in items:
                    write_fasta(fasta, f"{path.stem}.{strand.pid}", f"{_describe(strand)} scenario={path.stem}", strand.seq)
                scenarios.append({"scenario": path.stem, "victim": victim,
                                  **score_strands(items, genome, host, scorers, calib, args.length)})
        report["scenarios"] = scenarios

    (out / "report.json").write_text(json.dumps(report, indent=1, ensure_ascii=False))
    print(json.dumps({k: report[k] for k in ("reference", "heldout")}, indent=1, ensure_ascii=False))
    for row in report.get("scenarios", []):
        print(f"{row['scenario']:<20} reads {row['reads']:>4} flagged {row['flagged']:>3} max {row['max_novelty']:.2f} "
              f"host {row['host_flagged']:>3}/{row['max_host_novelty']:.2f}  {row['worst_read']}  ~  {row['nearest_normal']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
