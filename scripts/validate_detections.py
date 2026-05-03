#!/usr/bin/env python3
"""Script to validate detection accuracy across IQC and EPT results."""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.detection.rule_engine import RuleEngine
from src.detection.correlation import CorrelationEngine
from src.validation.iqc_engine import IQCEngine
from src.validation.ept_engine import EPTEngine
from src.validation.validation_controller import ValidationController
from src.utils.logger import get_logger

logger = get_logger("validate_detections")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CQAS Detection Validation Tool")
    parser.add_argument("--rules", default="configs/siem_rules.yaml")
    parser.add_argument("--scenarios", default="configs/attack_simulation.yaml")
    parser.add_argument("--mode", choices=["iqc", "ept", "full"], default="full")
    parser.add_argument("--output", default=None, help="Output JSON report path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    for path in [args.rules, args.scenarios]:
        if not os.path.exists(path):
            logger.error(f"Config not found: {path}")
            return 1

    rule_engine = RuleEngine(args.rules)
    correlation_engine = CorrelationEngine()
    iqc_engine = IQCEngine(rule_engine)
    ept_engine = EPTEngine(rule_engine, correlation_engine, args.scenarios, dry_run=True)

    controller = ValidationController(iqc_engine, ept_engine)

    if args.mode == "iqc":
        report = controller.run_iqc()
    elif args.mode == "ept":
        report = controller.run_ept()
    else:
        report = controller.run_full_validation()

    print(json.dumps(report, indent=2, default=str))

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as fh:
            json.dump(report, fh, indent=2, default=str)
        logger.info(f"Validation report written to {args.output}")

    grade = report.get("grade", report.get("dar_percent", 0))
    return 0 if grade not in ("D", "F") else 1


if __name__ == "__main__":
    sys.exit(main())
