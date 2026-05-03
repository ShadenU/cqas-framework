"""EPT Engine — External Proficiency Testing via scripted attack simulations."""

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.utils.helpers import load_config
from src.utils.logger import get_logger

logger = get_logger(__name__)


class EPTResult:
    """Result of a single attack simulation scenario."""

    def __init__(
        self,
        scenario_name: str,
        scenario_description: str,
        expected_rules: List[str],
        detected_rules: List[str],
        simulation_duration_seconds: float,
        sla_seconds: int,
        details: Optional[Dict] = None,
    ) -> None:
        self.scenario_name = scenario_name
        self.scenario_description = scenario_description
        self.expected_rules = expected_rules
        self.detected_rules = detected_rules
        self.simulation_duration_seconds = simulation_duration_seconds
        self.sla_seconds = sla_seconds
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.details = details or {}

    @property
    def passed(self) -> bool:
        return all(r in self.detected_rules for r in self.expected_rules)

    @property
    def detection_rate(self) -> float:
        if not self.expected_rules:
            return 100.0
        detected_count = sum(1 for r in self.expected_rules if r in self.detected_rules)
        return (detected_count / len(self.expected_rules)) * 100.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_name": self.scenario_name,
            "scenario_description": self.scenario_description,
            "expected_rules": self.expected_rules,
            "detected_rules": self.detected_rules,
            "passed": self.passed,
            "detection_rate": self.detection_rate,
            "simulation_duration_seconds": self.simulation_duration_seconds,
            "within_sla": self.simulation_duration_seconds <= self.sla_seconds,
            "timestamp": self.timestamp,
            "details": self.details,
        }


class EPTEngine:
    """External Proficiency Testing engine.

    Runs scripted attack simulations and validates that the detection pipeline
    identifies the expected rules within the SLA window.

    Args:
        rule_engine: RuleEngine instance.
        correlation_engine: CorrelationEngine instance.
        scenarios_config_path: Path to attack_simulation.yaml.
        dry_run: If True, generate events without sending to external systems.
    """

    def __init__(
        self,
        rule_engine: Any,
        correlation_engine: Any,
        scenarios_config_path: str,
        dry_run: bool = True,
    ) -> None:
        self.rule_engine = rule_engine
        self.correlation_engine = correlation_engine
        config = load_config(scenarios_config_path)
        self.scenarios: Dict[str, Dict] = config.get("scenarios", {})
        self.dry_run = dry_run
        self._results: List[EPTResult] = []
        logger.info(f"EPTEngine loaded {len(self.scenarios)} scenarios (dry_run={dry_run})")

    def run_scenario(self, scenario_name: str) -> EPTResult:
        """Run a single attack simulation scenario.

        Args:
            scenario_name: Key from the scenarios config.

        Returns:
            EPTResult for the scenario.

        Raises:
            KeyError: If scenario_name is not defined.
        """
        if scenario_name not in self.scenarios:
            raise KeyError(f"Unknown scenario: {scenario_name}")

        scenario = self.scenarios[scenario_name]
        params = scenario.get("parameters", {})
        expected_detections = scenario.get("expected_detections", [])
        expected_rules = [d["rule_id"] for d in expected_detections]
        sla_seconds = max(
            (d.get("max_detection_time_seconds", 300) for d in expected_detections),
            default=300,
        )

        logger.info(f"EPT: Running scenario '{scenario_name}' (dry_run={self.dry_run})")
        start = time.monotonic()

        events = self._generate_scenario_events(scenario_name, scenario, params)
        rule_matches = self.rule_engine.evaluate_many(events)
        self.correlation_engine.ingest_many(events)

        elapsed = time.monotonic() - start
        detected_rules = list({m.rule_id for m in rule_matches})

        result = EPTResult(
            scenario_name=scenario_name,
            scenario_description=scenario.get("description", ""),
            expected_rules=expected_rules,
            detected_rules=detected_rules,
            simulation_duration_seconds=elapsed,
            sla_seconds=sla_seconds,
            details={
                "events_generated": len(events),
                "all_matches": [m.rule_id for m in rule_matches],
                "mitre_tactic": scenario.get("mitre_tactic"),
                "mitre_technique": scenario.get("mitre_technique"),
            },
        )
        self._results.append(result)

        status = "PASS" if result.passed else "FAIL"
        logger.info(
            f"EPT {status}: scenario='{scenario_name}' "
            f"detection_rate={result.detection_rate:.1f}% "
            f"duration={elapsed:.2f}s"
        )
        return result

    def run_all(self) -> List[EPTResult]:
        """Run all loaded scenarios.

        Returns:
            List of EPTResult objects.
        """
        return [self.run_scenario(name) for name in self.scenarios]

    def calculate_coverage(self) -> float:
        """Calculate the overall EPT detection coverage.

        Returns:
            Coverage percentage (0.0 – 100.0).
        """
        if not self._results:
            return 0.0
        total_expected = sum(len(r.expected_rules) for r in self._results)
        if total_expected == 0:
            return 100.0
        total_detected = sum(
            sum(1 for rule in r.expected_rules if rule in r.detected_rules)
            for r in self._results
        )
        return (total_detected / total_expected) * 100.0

    def get_results(self) -> List[EPTResult]:
        return list(self._results)

    def summary(self) -> Dict[str, Any]:
        total = len(self._results)
        passed = sum(1 for r in self._results if r.passed)
        return {
            "total_scenarios": total,
            "passed": passed,
            "failed": total - passed,
            "coverage_percent": self.calculate_coverage(),
            "results": [r.to_dict() for r in self._results],
        }

    # ------------------------------------------------------------------ #
    # Event generation for each scenario type                              #
    # ------------------------------------------------------------------ #

    def _generate_scenario_events(
        self, name: str, scenario: Dict, params: Dict
    ) -> List[Dict[str, Any]]:
        generators = {
            "port_scan": self._gen_port_scan,
            "brute_force": self._gen_brute_force,
            "lateral_movement": self._gen_lateral_movement,
            "data_exfiltration": self._gen_data_exfiltration,
            "dns_tunneling": self._gen_dns_tunneling,
        }
        gen = generators.get(name)
        if gen:
            return gen(params)
        return self._gen_generic(name, params)

    def _gen_port_scan(self, params: Dict) -> List[Dict]:
        src = params.get("source_host", "10.99.1.1")
        dst = params.get("target_subnet", "10.0.0.1").split("/")[0]
        ports = params.get("ports", list(range(1, 26)))
        events = []
        for port in ports:
            events.append({
                "event_type": "network",
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": port,
                "action": "drop",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "_ept_id": str(uuid.uuid4()),
            })
        return events

    def _gen_brute_force(self, params: Dict) -> List[Dict]:
        src = params.get("source_host", "10.99.1.2")
        target = params.get("target_host", "10.0.0.50")
        attempts = params.get("attempts_per_minute", 30)
        events = []
        for i in range(attempts):
            events.append({
                "event_type": "authentication",
                "action": "failure",
                "src_ip": src,
                "dst_ip": target,
                "dst_port": params.get("target_port", 22),
                "username": f"user_{i % 5}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "_ept_id": str(uuid.uuid4()),
            })
        return events

    def _gen_lateral_movement(self, params: Dict) -> List[Dict]:
        src = params.get("source_host", "10.99.1.3")
        targets = params.get("target_hosts", ["10.0.0.10", "10.0.0.20"])
        events = []
        for target in targets:
            events.append({
                "event_type": "network",
                "src_ip": src,
                "dst_ip": target,
                "dst_port": params.get("port", 445),
                "action": "accept",
                "protocol": "smb",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "_ept_id": str(uuid.uuid4()),
            })
        return events

    def _gen_data_exfiltration(self, params: Dict) -> List[Dict]:
        src = params.get("source_host", "10.99.1.4")
        dst = params.get("destination_ip", "198.51.100.10")
        size_mb = params.get("transfer_size_mb", 150)
        return [{
            "event_type": "network",
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": params.get("destination_port", 443),
            "action": "accept",
            "bytes_sent": size_mb * 1024 * 1024,
            "direction": "outbound",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "_ept_id": str(uuid.uuid4()),
        }]

    def _gen_dns_tunneling(self, params: Dict) -> List[Dict]:
        src = params.get("source_host", "10.99.1.5")
        domain = params.get("c2_domain", "test.example.com")
        count = params.get("query_rate_per_minute", 120)
        avg_len = params.get("avg_query_length", 120)
        events = []
        for i in range(count):
            subdomain = "a" * (avg_len - len(domain) - 1)
            events.append({
                "event_type": "dns",
                "src_ip": src,
                "query": f"{subdomain}.{domain}",
                "query_length": avg_len,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "_ept_id": str(uuid.uuid4()),
            })
        return events

    @staticmethod
    def _gen_generic(name: str, params: Dict) -> List[Dict]:
        return [{
            "event_type": "unknown",
            "scenario": name,
            "params": params,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "_ept_id": str(uuid.uuid4()),
        }]
