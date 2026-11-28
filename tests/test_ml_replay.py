from dataclasses import replace

from kernel_ai.ml.collectors.base import SyscallEvent
from kernel_ai.ml.config import MLConfig
from kernel_ai.ml.replay import alerts, quantiles, replay, summarize, to_event, TickScore
from kernel_ai.ml.sequence import StideModel


def _cfg(**kw):
    base = dict(interval_sec=2.0, seq_n=3, seq_window=400, seq_pid_min_window=4,
                seq_min_window=120, stage8_window=64, seq_flush_sec=30.0,
                seq_pid_idle_events=5000, seq_cooldown_sec=30.0, stage8_cooldown_sec=120.0)
    base.update(kw)
    return replace(MLConfig(), **base)


class _Deep:
    """Scores a window by the share of ``ptrace`` in it, so tests can steer it."""

    def score_tokens(self, tokens, context=None):
        return {"neg_avg_logprob": 10.0 * tokens.count("ptrace") / len(tokens),
                "worst_tokens": ["ptrace"]}


def _ev(ts, pid, name, comm="d"):
    return SyscallEvent(ts=ts, pid=pid, uid=0, comm=comm, syscall=name)


def test_to_event_filters_like_the_collector():
    ok = {"kind": "syscall_span", "timestamp": "2026-11-19T10:00:01.250000000Z",
          "pid": 7, "uid": 33, "comm": "x" * 80, "syscall": {"name": "connect"}}
    ev = to_event(ok)
    assert ev.syscall == "connect" and len(ev.comm) == 64
    assert abs(ev.ts - 1795082401.25) < 1e-6
    assert to_event({**ok, "syscall": {"name": "read"}}) is None
    assert to_event({**ok, "kind": "tcp_retransmit"}) is None
    assert to_event({**ok, "timestamp": "garbage"}) is None


def test_ticks_follow_event_time_and_skip_silence():
    evs = [_ev(1000 + i * 0.1, 1, "connect") for i in range(40)]
    evs += [_ev(5000 + i * 0.1, 1, "connect") for i in range(10)]
    res = replay(evs, _cfg(), stide=None, deep=None)
    assert res.events == 50
    assert res.ticks == 3


def test_only_changed_pid_windows_are_rescored():
    stide = StideModel(n=3, ngrams={"connect|connect|connect"})
    evs = [_ev(1000 + i * 0.1, 1, "connect") for i in range(30)]
    evs += [_ev(1003 + i * 0.1, 2, n) for i, n in enumerate(["clone", "ptrace", "ptrace"] * 3)]
    evs += [_ev(1010 + i * 0.1, 1, "connect") for i in range(30)]
    res = replay(evs, _cfg(), stide=stide, deep=None)
    scored = [(s.pid, round(s.score, 2)) for s in res.stage4]
    assert (2, 1.0) in scored
    # pid 2 went quiet; its hostile window must not be reported again later.
    assert scored[-1][0] == 1


def test_cooldown_and_grid():
    scores = [TickScore(t, 7.0, 1, "a") for t in range(0, 600, 2)]
    assert len(alerts(scores, 6.5, 120.0)) == 5
    assert alerts(scores, 7.5, 120.0) == []
    q = quantiles([float(i) for i in range(1001)])
    assert q["p50"] == 500 and q["p99"] == 990 and q["max"] == 1000


def test_summary_counts_stage8_alerts_per_day():
    evs = [_ev(1000 + i * 0.05, 9, n, comm="evil")
           for i, n in enumerate(["clone", "ptrace", "ptrace", "openat"] * 20)]
    res = replay(evs, _cfg(), stide=None, deep=_Deep())
    out = summarize(res, _cfg())
    row = {r["threshold"]: r for r in out["stage8"]["grid"]}
    assert row[4.0]["alerts"] == 1 and row[4.0]["top_comms"][0][0] == "evil"
    assert row[9.0]["alerts"] == 0


def test_worst_transition_sees_the_whole_tick_not_only_the_tail():
    from kernel_ai.ml.sequence_deep.markov import MarkovScorer

    class _Wrap:
        def __init__(self, m):
            self.m = m

        def score_tokens(self, tokens, context=None):
            return self.m.score_window(tokens, context=context)

    m = MarkovScorer()
    m.observe(["accept4", "connect"] * 500)
    names = ["accept4", "connect"] * 30 + ["clone"] + ["accept4", "connect"] * 60
    evs = [_ev(1000 + i * 0.01, 5, n, comm="nginx") for i, n in enumerate(names)]
    res = replay(evs, _cfg(), stide=None, deep=_Wrap(m))
    assert len(res.stage8) == 1
    # The clone is 120 tokens before the end of the tick: outside tokens[-64:].
    assert "clone" not in res.stage8[0].detail
    assert "clone" in res.stage8_worst[0].detail
    assert res.stage8_worst[0].score > 5.0


def test_unit_context_replaces_comm_when_the_id_is_known():
    obj = {"kind": "syscall_span", "timestamp": "2026-11-19T10:00:01Z", "pid": 7,
           "comm": "python3", "cgroup_id": 55, "syscall": {"name": "connect"}}
    by_unit = to_event(obj, context="unit", cgroups={55: "system.slice/kernel-ai-ml.service"})
    assert by_unit.context == "unit:kernel-ai-ml.service"
    assert to_event({**obj, "cgroup_id": 56}, context="unit", cgroups={55: "x"}).context == "python"
    assert to_event(obj).context == "python"
