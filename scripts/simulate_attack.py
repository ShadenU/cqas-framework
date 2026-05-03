#!/usr/bin/env python3
"""Script to simulate attacks for EPT testing."""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.detection.rule_engine import RuleEngine
from src.detection.correlation import CorrelationEngine
from src.validation.ept_engine import EPTEngine
from src.utils.logger import get_logger

logger = get_logger("simulate_attack")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CQAS EPT Attack Simulation Tool")
    parser.add_argument("--rules", default="configs/siem_rules.yaml")
    parser.add_argument("--scenarios", default="configs/attack_simulation.yaml")
    parser.add_argument("--scenario", default=None, help="Specific scenario name (default: all)")
    parser.add_argument("--output", default=None)
    parser.add_argument("--live", action="store_true", help="Run live (not dry-run). USE WITH CAUTION.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    for path in [args.rules, args.scenarios]:
        if not os.path.exists(path):
            logger.error(f"Config not found: {path}")
            return 1

    dry_run = not args.live
    if not dry_run:
        logger.warning("LIVE MODE: Attack simulation events will be injected into the detection pipeline")

    rule_engine = RuleEngine(args.rules)
    correlation_engine = CorrelationEngine()
    ept_engine = EPTEngine(rule_engine, correlation_engine, args.scenarios, dry_run=dry_run)

    if args.scenario:
        result = ept_engine.run_scenario(args.scenario)
        summary = {
            "total_scenarios": 1,
            "passed": int(result.passed),
            "failed": int(not result.passed),
            "coverage_percent": result.detection_rate,
            "results": [result.to_dict()],
        }
    else:
        ept_engine.run_all()
        summary = ept_engine.summary()

    print(json.dumps(summary, indent=2))

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as fh:
            json.dump(summary, fh, indent=2)
        logger.info(f"Simulation report written to {args.output}")

    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
