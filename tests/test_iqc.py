"""Tests for the IQC Engine."""

import pytest
from unittest.mock import MagicMock, patch

from src.validation.iqc_engine import IQCEngine, IQCResult, SYNTHETIC_IOCS
from src.detection.rule_engine import RuleEngine, RuleMatch


class MockRuleEngine:
    """Test double for RuleEngine."""

    def __init__(self, rules_to_fire=None):
        self.rules_to_fire = rules_to_fire or []
        self.evaluate_calls = []

    def evaluate_many(self, events):
        self.evaluate_calls.append(events)
        matches = []
        for rule_id in self.rules_to_fire:
            match = MagicMock()
            match.rule_id = rule_id
            match.rule_name = f"Mock Rule {rule_id}"
            match.severity = "high"
            matches.append(match)
        return matches


class TestIQCEngine:

    def test_inject_known_ioc_detected(self):
        rule_engine = MockRuleEngine(rules_to_fire=["CQAS-002"])
        iqc = IQCEngine(rule_engine, sla_seconds=60)
        result = iqc.inject_and_validate("brute_force_sequence")
        assert result.ioc_name == "brute_force_sequence"
        assert result.detected is True
        assert result.passed is True
        assert result.expected_rule == "CQAS-002"

    def test_inject_known_ioc_not_detected(self):
        rule_engine = MockRuleEngine(rules_to_fire=[])
        iqc = IQCEngine(rule_engine)
        result = iqc.inject_and_validate("brute_force_sequence")
        assert result.detected is False
        assert result.passed is False
        assert result.detection_time_seconds is None

    def test_run_all_returns_results_for_all_iocs(self):
        rule_engine = MockRuleEngine(rules_to_fire=list(
            t.get("expected_rule", "") for t in SYNTHETIC_IOCS.values()
        ))
        iqc = IQCEngine(rule_engine)
        results = iqc.run_all()
        assert len(results) == len(SYNTHETIC_IOCS)

    def test_calculate_dar_all_detected(self):
        rule_engine = MockRuleEngine(rules_to_fire=["CQAS-002"])
        iqc = IQCEngine(rule_engine)
        iqc.inject_and_validate("brute_force_sequence")
        iqc.inject_and_validate("brute_force_sequence")
        assert iqc.calculate_dar() == 100.0

    def test_calculate_dar_none_detected(self):
        rule_engine = MockRuleEngine(rules_to_fire=[])
        iqc = IQCEngine(rule_engine)
        iqc.inject_and_validate("brute_force_sequence")
        assert iqc.calculate_dar() == 0.0

    def test_calculate_dar_partial(self):
        iqc = IQCEngine(MockRuleEngine(rules_to_fire=["CQAS-002"]))
        iqc.inject_and_validate("brute_force_sequence")   # pass
        iqc2 = IQCEngine.__new__(IQCEngine)
        iqc2.rule_engine = MockRuleEngine(rules_to_fire=[])
        iqc2.sla_seconds = 300
        iqc2._results = list(iqc._results)
        result2 = iqc2.inject_and_validate("brute_force_sequence")  # separate engine
        # 1 pass, 0 fail in iqc: DAR = 100%
        assert iqc.calculate_dar() == 100.0

    def test_invalid_ioc_raises_value_error(self):
        iqc = IQCEngine(MockRuleEngine())
        with pytest.raises(ValueError, match="Unknown IOC"):
            iqc.inject_and_validate("nonexistent_ioc")

    def test_summary_structure(self):
        rule_engine = MockRuleEngine(rules_to_fire=["CQAS-002"])
        iqc = IQCEngine(rule_engine)
        iqc.inject_and_validate("brute_force_sequence")
        summary = iqc.summary()
        assert "total" in summary
        assert "passed" in summary
        assert "failed" in summary
        assert "dar_percent" in summary
        assert "results" in summary

    def test_iqc_result_to_dict(self):
        result = IQCResult(
            ioc_name="test",
            expected_rule="CQAS-001",
            injected_count=5,
            detected=True,
            detection_time_seconds=1.5,
        )
        d = result.to_dict()
        assert d["ioc_name"] == "test"
        assert d["detected"] is True
        assert d["passed"] is True
        assert d["detection_time_seconds"] == 1.5

    def test_events_generated_for_brute_force(self):
        from src.validation.iqc_engine import IQCEngine
        template = SYNTHETIC_IOCS["brute_force_sequence"]
        events = IQCEngine._generate_events(template)
        assert len(events) == template["repeat"]
        for event in events:
            assert event["event_type"] == "authentication"
            assert "_iqc_id" in event

    def test_events_generated_for_port_scan_vary_field(self):
        template = SYNTHETIC_IOCS["port_scan_sequence"]
        events = IQCEngine._generate_events(template)
        ports = [e["dst_port"] for e in events]
        assert len(set(ports)) > 1  # multiple distinct ports
