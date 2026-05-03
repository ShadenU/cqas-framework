#!/usr/bin/env python3
"""Script to inject synthetic IOCs for IQC testing."""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.detection.rule_engine import RuleEngine
from src.validation.iqc_engine import IQCEngine, SYNTHETIC_IOCS
from src.utils.logger import get_logger

logger = get_logger("inject_ioc")

DEFAULT_RULES_CONFIG = "configs/siem_rules.yaml"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CQAS IQC IOC Injection Tool")
    parser.add_argument("--config", default=DEFAULT_RULES_CONFIG, help="Path to siem_rules.yaml")
    parser.add_argument("--ioc", default=None, help="Specific IOC name to inject (default: all)")
    parser.add_argument("--sla", type=int, default=300, help="SLA window in seconds")
    parser.add_argument("--output", default=None, help="Output JSON report path")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be injected without running")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.dry_run:
        print("=== DRY RUN: Available IOCs ===")
        for ioc_name, template in SYNTHETIC_IOCS.items():
            print(f"  - {ioc_name}: expected_rule={template.get('expected_rule')} repeat={template.get('repeat', 1)}")
        return 0

    if not os.path.exists(args.config):
        logger.error(f"Rules config not found: {args.config}")
        return 1

    rule_engine = RuleEngine(args.config)
    iqc_engine = IQCEngine(rule_engine, sla_seconds=args.sla)

    if args.ioc:
        if args.ioc not in SYNTHETIC_IOCS:
            logger.error(f"Unknown IOC: {args.ioc}. Available: {list(SYNTHETIC_IOCS.keys())}")
            return 1
        result = iqc_engine.inject_and_validate(args.ioc)
        summary = {"total": 1, "passed": int(result.passed), "failed": int(not result.passed),
                   "dar_percent": 100.0 if result.passed else 0.0, "results": [result.to_dict()]}
    else:
        iqc_engine.run_all()
        summary = iqc_engine.summary()

    print(json.dumps(summary, indent=2))

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as fh:
            json.dump(summary, fh, indent=2)
        logger.info(f"Report written to {args.output}")

    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
