#!/usr/bin/env python3
"""Script to calculate and report CQAS quality metrics."""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.detection.rule_engine import RuleEngine
from src.detection.correlation import CorrelationEngine
from src.validation.iqc_engine import IQCEngine
from src.validation.ept_engine import EPTEngine
from src.metrics.performance_metrics import PerformanceMetrics
from src.metrics.scoring import ScoringEngine
from src.utils.logger import get_logger

logger = get_logger("metrics_calculator")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CQAS Metrics Calculator")
    parser.add_argument("--rules", default="configs/siem_rules.yaml")
    parser.add_argument("--scenarios", default="configs/attack_simulation.yaml")
    parser.add_argument("--output", default=None)
    parser.add_argument("--format", choices=["json", "text"], default="json")
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

    logger.info("Running IQC and EPT for metrics calculation...")
    iqc_results = iqc_engine.run_all()
    ept_engine.run_all()
    ept_summary = ept_engine.summary()

    perf = PerformanceMetrics()
    scorer = ScoringEngine()

    metrics_report = perf.full_report(iqc_results=iqc_results)
    quality_score = scorer.score_from_metrics_report(
        metrics_report, ept_coverage=ept_summary.get("coverage_percent", 100.0)
    )

    full_report = {
        "metrics": metrics_report,
        "ept_summary": ept_summary,
        "quality_score": quality_score.to_dict(),
        "trend": scorer.trend_summary(),
    }

    if args.format == "text":
        q = quality_score
        print(f"\n{'='*50}")
        print(f"  CQAS Quality Report")
        print(f"{'='*50}")
        print(f"  Overall Score:    {q.composite_score:.1f}/100 (Grade: {q.grade})")
        print(f"  DAR:              {metrics_report['dar_percent']:.1f}%")
        print(f"  FPR:              {metrics_report['fpr_percent']:.1f}%")
        print(f"  MTTR:             {metrics_report['mttr_minutes']:.1f} min")
        print(f"  SLA Compliance:   {metrics_report['sla_compliance_percent']:.1f}%")
        print(f"  EPT Coverage:     {ept_summary.get('coverage_percent', 100.0):.1f}%")
        print(f"{'='*50}\n")
    else:
        print(json.dumps(full_report, indent=2))

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as fh:
            json.dump(full_report, fh, indent=2)
        logger.info(f"Metrics report written to {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
