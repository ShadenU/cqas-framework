"""Tests for the detection engine (RuleEngine + CorrelationEngine)."""

import os
import pytest

from src.detection.rule_engine import RuleEngine, RuleMatch
from src.detection.correlation import CorrelationEngine, CorrelatedIncident


RULES_CONFIG = "configs/siem_rules.yaml"


@pytest.fixture
def sample_auth_failure_event():
    return {
        "event_type": "authentication",
        "action": "failure",
        "src_ip": "10.0.0.50",
        "dst_ip": "10.0.0.1",
        "username": "admin",
        "timestamp": "2024-01-01T00:00:00Z",
    }


@pytest.fixture
def sample_network_event():
    return {
        "event_type": "network",
        "action": "drop",
        "src_ip": "10.0.0.100",
        "dst_ip": "10.0.0.1",
        "dst_port": 22,
        "timestamp": "2024-01-01T00:01:00Z",
    }


@pytest.mark.skipif(
    not os.path.exists(RULES_CONFIG),
    reason="siem_rules.yaml not present",
)
class TestRuleEngine:

    @pytest.fixture
    def engine(self):
        return RuleEngine(RULES_CONFIG)

    def test_loads_rules(self, engine):
        assert len(engine.rules) > 0

    def test_all_rules_have_required_fields(self, engine):
        for rule in engine.rules:
            assert "rule_id" in rule
            assert "name" in rule
            assert "severity" in rule
            assert "conditions" in rule

    def test_evaluate_returns_list(self, engine, sample_auth_failure_event):
        matches = engine.evaluate(sample_auth_failure_event)
        assert isinstance(matches, list)

    def test_evaluate_many_returns_list(self, engine, sample_auth_failure_event):
        events = [sample_auth_failure_event] * 5
        matches = engine.evaluate_many(events)
        assert isinstance(matches, list)

    def test_brute_force_rule_triggers_after_threshold(self, engine):
        # Rule CQAS-002: 10 failures in 300 seconds
        events = [
            {
                "event_type": "authentication",
                "action": "failure",
                "src_ip": "192.168.99.1",
                "username": "admin",
            }
        ] * 11
        matches = engine.evaluate_many(events)
        rule_ids = [m.rule_id for m in matches]
        assert "CQAS-002" in rule_ids

    def test_brute_force_rule_does_not_trigger_below_threshold(self, engine):
        events = [
            {
                "event_type": "authentication",
                "action": "failure",
                "src_ip": "192.168.99.2",
                "username": "admin",
            }
        ] * 3
        matches = engine.evaluate_many(events)
        rule_ids = [m.rule_id for m in matches]
        assert "CQAS-002" not in rule_ids

    def test_port_scan_rule_triggers(self, engine):
        # Rule CQAS-001: 20 distinct dst_ports from one src_ip in 60s
        events = [
            {
                "event_type": "network",
                "src_ip": "192.168.99.3",
                "dst_ip": "10.0.0.1",
                "dst_port": port,
                "action": "drop",
            }
            for port in range(1, 22)
        ]
        matches = engine.evaluate_many(events)
        rule_ids = [m.rule_id for m in matches]
        assert "CQAS-001" in rule_ids

    def test_rule_match_has_correct_attributes(self, engine):
        events = [
            {"event_type": "authentication", "action": "failure", "src_ip": "10.5.5.5"}
        ] * 15
        matches = engine.evaluate_many(events)
        for match in matches:
            assert hasattr(match, "rule_id")
            assert hasattr(match, "rule_name")
            assert hasattr(match, "severity")
            assert hasattr(match, "event")
            assert hasattr(match, "matched_at")

    def test_rule_match_to_dict(self, engine):
        events = [
            {"event_type": "authentication", "action": "failure", "src_ip": "10.6.6.6"}
        ] * 15
        matches = engine.evaluate_many(events)
        if matches:
            d = matches[0].to_dict()
            assert "rule_id" in d
            assert "severity" in d
            assert "event_summary" in d


class TestCorrelationEngine:

    def test_ingest_single_event_no_incident(self):
        engine = CorrelationEngine()
        incidents = engine.ingest({
            "event_type": "authentication",
            "action": "failure",
            "src_ip": "10.0.0.50",
        })
        assert isinstance(incidents, list)

    def test_brute_force_to_success_chain(self):
        engine = CorrelationEngine()
        src = "10.0.100.1"
        # Inject 5 failures then 1 success
        for _ in range(5):
            engine.ingest({"event_type": "authentication", "action": "failure", "src_ip": src})
        incidents = engine.ingest({"event_type": "authentication", "action": "success", "src_ip": src})
        all_incidents = engine.get_incidents()
        chain_names = [i.chain_name for i in all_incidents]
        assert "brute_force_to_success" in chain_names

    def test_correlated_incident_to_dict(self):
        engine = CorrelationEngine()
        src = "10.0.100.2"
        for _ in range(5):
            engine.ingest({"event_type": "authentication", "action": "failure", "src_ip": src})
        engine.ingest({"event_type": "authentication", "action": "success", "src_ip": src})
        incidents = engine.get_incidents()
        if incidents:
            d = incidents[0].to_dict()
            assert "chain_name" in d
            assert "severity" in d
            assert "events" in d

    def test_ingest_many(self):
        engine = CorrelationEngine()
        events = [
            {"event_type": "authentication", "action": "failure", "src_ip": "10.0.0.55"},
            {"event_type": "network", "action": "drop", "src_ip": "10.0.0.55", "dst_port": 80},
        ]
        incidents = engine.ingest_many(events)
        assert isinstance(incidents, list)

    def test_different_sources_dont_correlate(self):
        engine = CorrelationEngine()
        for i in range(5):
            engine.ingest({"event_type": "authentication", "action": "failure", "src_ip": f"10.0.{i}.1"})
        # Each event comes from a different IP, should not form a brute_force_to_success chain
        all_incidents = engine.get_incidents()
        bf_incidents = [i for i in all_incidents if i.chain_name == "brute_force_to_success"]
        assert len(bf_incidents) == 0
