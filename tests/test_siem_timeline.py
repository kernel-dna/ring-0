from kernel_ai.services import siem


def test_timeline_covers_the_window_past_the_alert_limit(monkeypatch):
    monkeypatch.setattr(siem, "_load_config", lambda: {
        "url": "https://es.example", "api_key": "k", "ca": "", "index": "x", "tag": "kernel-ai"})
    seen = {}

    def search(cfg, body, timeout=6.0):
        seen["body"] = body
        return {
            "hits": {"total": {"value": 6413}, "hits": []},
            "aggregations": {"timeline": {"buckets": [
                {"key_as_string": "2026-11-20T07:00:00.000Z", "doc_count": 1040,
                 "sev": {"buckets": [{"key": "medium", "doc_count": 990}, {"key": "high", "doc_count": 50}]},
                 "rule": {"buckets": [{"key": "Web: flood from single source IP", "doc_count": 990}]}},
                {"key_as_string": "2026-11-20T07:15:00.000Z", "doc_count": 3,
                 "sev": {"buckets": [{"key": "medium", "doc_count": 3}]},
                 "rule": {"buckets": [{"key": "Web: sensitive file / dotfile probing", "doc_count": 3}]}},
            ]}},
        }

    monkeypatch.setattr(siem, "_es_search", search)
    siem._cache.clear()
    out = siem.get_siem_alerts(hours=24, limit=300)
    assert seen["body"]["aggs"]["timeline"]["date_histogram"]["fixed_interval"] == "15m"
    assert out["timeline"]["interval_min"] == 15
    assert out["timeline"]["buckets"][0] == {
        "time": "2026-11-20T07:00:00.000Z", "count": 1040, "severity": "high",
        "rule": "Web: flood from single source IP"}
    assert out["timeline"]["buckets"][1]["severity"] == "medium"
    siem._cache.clear()


def test_alerts_carry_the_attack_time_and_the_size_of_their_fragment(monkeypatch):
    monkeypatch.setattr(siem, "_load_config", lambda: {
        "url": "https://es.example", "api_key": "k", "ca": "", "index": "x", "tag": "kernel-ai"})
    seen = {}

    def search(cfg, body, timeout=6.0):
        seen["body"] = body
        return {"hits": {"total": {"value": 2}, "hits": [
            {"_id": "a1", "_source": {"@timestamp": "2026-11-22T20:15:40.000Z",
                                      "kibana.alert.original_time": "2026-11-22T20:15:03.120Z",
                                      "kibana.alert.rule.name": "Web: sensitive file / dotfile probing"}},
            {"_id": "a2", "_source": {"@timestamp": "2026-11-22T20:16:00.000Z",
                                      "kibana.alert.original_time": "2026-11-22T20:14:00.000Z",
                                      "kibana.alert.rule.name": "SSH: multiple failed logins"}},
        ]}}

    monkeypatch.setattr(siem, "_es_search", search)
    monkeypatch.setattr(siem._kernel_events, "fragment_sizes", lambda: {"a1": 7, "gone": 3})
    siem._cache.clear()
    out = siem.get_siem_alerts(hours=1, limit=300)
    siem._cache.clear()

    assert "kibana.alert.original_time" in seen["body"]["_source"]
    first, second = out["alerts"]
    assert (first["time"], first["event_time"], first["fragment"]) == (
        "2026-11-22T20:15:40.000Z", "2026-11-22T20:15:03.120Z", 7)
    assert second["event_time"] == "2026-11-22T20:14:00.000Z"
    assert "fragment" not in second
