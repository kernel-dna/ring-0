"""Live-host calibration for Stage 1 z and Stage 2 IsolationForest emit."""

import time
from types import SimpleNamespace

from kernel_ai.ml.baseline import Score
from kernel_ai.ml.config import MLConfig
from kernel_ai.ml.worker import _build_anomalies


def _score(name: str, z: float) -> Score:
    return Score(name=name, value=100.0 + z, mean=100.0, std=1.0, z=z, warm=False)


def test_calibrated_defaults():
    cfg = MLConfig()
    assert cfg.z_warn == 6.0
    assert cfg.z_crit == 7.0
    assert cfg.if_cooldown_sec == 45.0
    assert cfg.if_min_score == 0.10


def test_stage1_drops_poll_band_keeps_real_spikes():
    cfg = SimpleNamespace(z_warn=6.0, z_crit=7.0, alpha=0.03)
    scores = {
        "ctxt_per_sec": _score("ctxt_per_sec", 4.5),
        "tcp_retrans_per_sec": _score("tcp_retrans_per_sec", 5.2),
        "pgfault_per_sec": _score("pgfault_per_sec", 10.2),
        "cpu_busy_pct": _score("cpu_busy_pct", 6.5),
    }
    out = _build_anomalies(scores, cfg)
    features = {row["feature"] for row in out}
    assert features == {"cpu_busy_pct"}
    assert out[0]["severity"] == "medium"

    scores["pgfault_per_sec"] = _score("pgfault_per_sec", 16.4)
    scores["ctxt_per_sec"] = _score("ctxt_per_sec", 11.2)
    out = _build_anomalies(scores, cfg)
    by_feat = {row["feature"]: row for row in out}
    assert set(by_feat) >= {"cpu_busy_pct", "pgfault_per_sec", "ctxt_per_sec"}
    assert by_feat["pgfault_per_sec"]["severity"] == "high"
    assert by_feat["ctxt_per_sec"]["severity"] == "medium"


def _s12_worker(*, emit1: bool, emit2: bool, log_every: float = 0.0):
    """A worker stripped to what _tick touches for Stages 1-2 (no DB, no procfs)."""
    from kernel_ai.ml.worker import MLWorker

    worker = MLWorker.__new__(MLWorker)
    worker.cfg = SimpleNamespace(
        stage1_emit=emit1, stage2_emit=emit2, stage12_log_every_sec=log_every,
        z_warn=6.0, z_crit=7.0, alpha=0.03, if_min_score=0.10, if_cooldown_sec=45.0,
        enable_stage4=False, enable_stage5=False, enable_stage7=False,
        enable_stage8=False, enable_stage9=False, store_features=False,
    )
    worker.extractor = SimpleNamespace(collect=lambda: {"procs_running": 108.0})
    worker.baseline = SimpleNamespace(
        update_and_score=lambda f, m: {"procs_running": _score("procs_running", 8.0)}
    )
    worker._min_std = {}
    worker.model = SimpleNamespace(score_one=lambda f: (True, 0.2))
    worker._last_if_emit = 0.0
    written: list[dict] = []
    worker.store = SimpleNamespace(insert_anomalies=written.extend)
    worker._reset_held(time.time())
    return worker, written


def test_stage12_write_by_default():
    worker, written = _s12_worker(emit1=True, emit2=True)
    assert worker._tick() == 2
    assert sorted(a["source"] for a in written) == ["stage1_baseline", "stage2_isoforest"]


def test_stage12_off_still_scores_and_reports_what_it_held(caplog):
    worker, written = _s12_worker(emit1=False, emit2=False)
    with caplog.at_level("INFO", logger="kernel_ai.ml.worker"):
        assert worker._tick() == 0
    assert written == []
    line = next(r.getMessage() for r in caplog.records if "not emitted" in r.getMessage())
    assert "stage1=1 [procs_running:1]" in line and "stage2=1 max_if_score=0.200" in line


def test_stage2_held_count_respects_the_cooldown():
    worker, written = _s12_worker(emit1=False, emit2=False, log_every=3600.0)
    for _ in range(3):
        worker._tick()
    # Stage 1 has no cooldown and would have written every tick; Stage 2 once.
    assert worker._held_s1 == {"procs_running": 3}
    assert worker._held_s2 == 1
    assert written == []


def test_stage1_off_leaves_stage2_writing():
    worker, written = _s12_worker(emit1=False, emit2=True)
    worker._tick()
    assert [a["source"] for a in written] == ["stage2_isoforest"]
