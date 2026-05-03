#!/usr/bin/env python3
"""Script to run root cause analysis on IQC/EPT failures."""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.detection.rule_engine import RuleEngine
from src.detection.correlation import CorrelationEngine
from src.validation.iqc_engine import IQCEngine
from src.validation.ept_engine import EPTEngine
from src.rca.root_cause import RootCauseAnalyzer
from src.rca.failure_analysis import FailureAnalysis
from src.utils.logger import get_logger

logger = get_logger("rca_analysis")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CQAS Root Cause Analysis Tool")
    parser.add_argument("--rules", default="configs/siem_rules.yaml")
    parser.add_argument("--scenarios", default="configs/attack_simulation.yaml")
    parser.add_argument("--output", default=None)
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

    logger.info("Running IQC and EPT to collect failure data for RCA...")
    iqc_results = iqc_engine.run_all()
    ept_engine.run_all()
    ept_results = ept_engine.get_results()

    rca = RootCauseAnalyzer(rule_engine=rule_engine)
    failure_analysis = FailureAnalysis()

    findings = []
    for result in iqc_results:
        if not result.detected:
            findings.append(rca.analyze_iqc_failure(result))

    for result in ept_results:
        if not result.passed:
            findings.extend(rca.analyze_ept_failure(result))

    failure_analysis.add_findings(findings)
    report = failure_analysis.report()

    print(json.dumps(report, indent=2))

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as fh:
            json.dump(report, fh, indent=2)
        logger.info(f"RCA report written to {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
