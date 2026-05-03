"""Tests for the escalation subsystem (SeverityEngine + AlertRouter)."""

import os
import pytest
from unittest.mock import MagicMock

from src.escalation.severity_engine import SeverityEngine, ScoredAlert, SEVERITY_BASE_SCORES
from src.escalation.alert_router import AlertRouter, RoutingResult


ESCALATION_CONFIG = "configs/escalation_policies.yaml"


def make_rule_match(rule_id="CQAS-001", severity="high", event=None):
    m = MagicMock()
    m.rule_id = rule_id
    m.rule_name = f"Test Rule {rule_id}"
    m.severity = severity
    m.event = event or {
        "event_type": "network",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 22,
        "timestamp": "2024-01-01T00:00:00Z",
    }
    return m


class TestSeverityEngine:

    @pytest.fixture
    def engine(self):
        return SeverityEngine()

    def test_score_returns_scored_alert(self, engine):
        match = make_rule_match(severity="high")
        scored = engine.score(match)
        assert isinstance(scored, ScoredAlert)

    def test_score_has_required_fields(self, engine):
        match = make_rule_match(severity="medium")
        scored = engine.score(match)
        assert hasattr(scored, "alert_id")
        assert hasattr(scored, "score")
        assert hasattr(scored, "computed_severity")
        assert hasattr(scored, "rule_id")

    def test_base_score_reflects_severity(self, engine):
        for severity, expected_base in SEVERITY_BASE_SCORES.items():
            match = make_rule_match(severity=severity)
            scored = engine.score(match)
            assert scored.score >= expected_base * 0.8

    def test_known_bad_ip_increases_score(self):
        engine_with_ti = SeverityEngine(known_bad_ips={"198.51.100.99"})
        base_engine = SeverityEngine()
        event = {
            "event_type": "network",
            "src_ip": "198.51.100.99",
            "dst_ip": "10.0.0.1",
        }
        match = make_rule_match(severity="medium", event=event)
        score_with_ti = engine_with_ti.score(match).score
        score_base = base_engine.score(match).score
        assert score_with_ti > score_base

    def test_critical_asset_increases_score(self):
        engine_with_asset = SeverityEngine(critical_assets={"dc01.corp.local"})
        base_engine = SeverityEngine()
        event = {
            "event_type": "authentication",
            "src_ip": "10.0.0.50",
            "hostname": "dc01.corp.local",
        }
        match = make_rule_match(severity="high", event=event)
        score_high = engine_with_asset.score(match).score
        score_base = base_engine.score(match).score
        assert score_high >= score_base

    def test_score_capped_at_1(self):
        engine = SeverityEngine(known_bad_ips={"1.1.1.1"}, critical_assets={"srv01"})
        event = {"src_ip": "1.1.1.1", "hostname": "srv01", "bytes_sent": 200_000_000,
                 "dst_ip": "2.2.2.2", "dst_port": 445}
        match = make_rule_match(severity="critical", event=event)
        scored = engine.score(match, context={"after_hours": True, "repeated_source": True})
        assert scored.score <= 1.0

    def test_score_many(self, engine):
        matches = [make_rule_match(severity="high") for _ in range(3)]
        scored_list = engine.score_many(matches)
        assert len(scored_list) == 3

    def test_scored_alert_to_dict(self, engine):
        match = make_rule_match()
        scored = engine.score(match)
        d = scored.to_dict()
        assert "alert_id" in d
        assert "score" in d
        assert "computed_severity" in d
        assert "rule_id" in d
        assert "event_summary" in d


@pytest.mark.skipif(
    not os.path.exists(ESCALATION_CONFIG),
    reason="escalation_policies.yaml not present",
)
class TestAlertRouter:

    @pytest.fixture
    def router(self):
        return AlertRouter(ESCALATION_CONFIG, dry_run=True)

    def make_scored_alert(self, severity="high"):
        match = make_rule_match(severity=severity)
        engine = SeverityEngine()
        return engine.score(match)

    def test_route_returns_routing_result(self, router):
        scored = self.make_scored_alert("high")
        scored.computed_severity = "high"
        result = router.route(scored)
        assert isinstance(result, RoutingResult)

    def test_routing_result_has_correct_alert_id(self, router):
        scored = self.make_scored_alert()
        scored.computed_severity = "medium"
        result = router.route(scored)
        assert result.alert_id == scored.alert_id

    def test_dry_run_does_not_raise(self, router):
        scored = self.make_scored_alert()
        scored.computed_severity = "critical"
        result = router.route(scored)
        assert result is not None

    def test_route_many_returns_list(self, router):
        scored_alerts = [self.make_scored_alert("medium") for _ in range(3)]
        for a in scored_alerts:
            a.computed_severity = "medium"
        results = router.route_many(scored_alerts)
        assert len(results) == 3

    def test_routing_log_tracks_results(self, router):
        scored = self.make_scored_alert()
        scored.computed_severity = "high"
        router.route(scored)
        log = router.get_routing_log()
        assert len(log) >= 1

    def test_routing_result_to_dict(self, router):
        scored = self.make_scored_alert()
        scored.computed_severity = "low"
        result = router.route(scored)
        d = result.to_dict()
        assert "alert_id" in d
        assert "severity" in d
        assert "channels_notified" in d
        assert "success" in d
        assert "routed_at" in d
