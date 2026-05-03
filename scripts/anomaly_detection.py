#!/usr/bin/env python3
"""Script to run anomaly detection checks against baseline models."""

import argparse
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.anomaly.baseline_model import BaselineModel
from src.anomaly.delta_checker import DeltaChecker
from src.utils.logger import get_logger

logger = get_logger("anomaly_detection")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CQAS Anomaly Detection Tool")
    parser.add_argument("--mode", choices=["collect", "check", "demo"], default="demo")
    parser.add_argument("--thresholds", default="configs/anomaly_thresholds.yaml")
    parser.add_argument("--baseline-dir", default="data/baselines")
    parser.add_argument("--output", default=None)
    return parser.parse_args()


def demo_mode(baseline_dir: str, thresholds_config: str) -> dict:
    """Run a demonstration of anomaly detection with synthetic data."""
    model = BaselineModel(baseline_dir=baseline_dir, min_data_points=10)

    # Build synthetic baselines
    rng = np.random.default_rng(42)
    observations = {
        "10.0.0.1": list(rng.normal(5, 2, 100).clip(0).tolist()),
        "10.0.0.2": list(rng.normal(3, 1, 100).clip(0).tolist()),
    }
    model.fit("failed_logins", observations)

    checker = DeltaChecker(model, thresholds_config)

    test_observations = [
        {"metric_name": "failed_logins", "group_key": "10.0.0.1", "value": 6.0},
        {"metric_name": "failed_logins", "group_key": "10.0.0.2", "value": 45.0},  # anomaly
        {"metric_name": "failed_logins", "group_key": "10.0.0.1", "value": 4.5},
    ]

    alerts = checker.check_batch(test_observations)
    return {
        "mode": "demo",
        "observations_tested": len(test_observations),
        "anomalies_detected": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }


def main() -> int:
    args = parse_args()

    if not os.path.exists(args.thresholds):
        logger.error(f"Thresholds config not found: {args.thresholds}")
        return 1

    if args.mode == "demo":
        report = demo_mode(args.baseline_dir, args.thresholds)
    else:
        logger.info(f"Mode '{args.mode}' requires live SIEM data integration. Use 'demo' for testing.")
        return 0

    print(json.dumps(report, indent=2))

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as fh:
            json.dump(report, fh, indent=2)

    return 0


if __name__ == "__main__":
    sys.exit(main())
