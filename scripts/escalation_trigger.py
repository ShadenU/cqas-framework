#!/usr/bin/env python3
"""Script to trigger escalation workflows for scored alerts."""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.detection.rule_engine import RuleEngine
from src.escalation.severity_engine import SeverityEngine
from src.escalation.alert_router import AlertRouter
from src.utils.helpers import load_config
from src.utils.logger import get_logger

logger = get_logger("escalation_trigger")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CQAS Escalation Trigger Tool")
    parser.add_argument("--rules", default="configs/siem_rules.yaml")
    parser.add_argument("--escalation", default="configs/escalation_policies.yaml")
    parser.add_argument("--events", default=None, help="JSON file with test events")
    parser.add_argument("--output", default=None)
    parser.add_argument("--dry-run", action="store_true", default=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    for path in [args.rules, args.escalation]:
        if not os.path.exists(path):
            logger.error(f"Config not found: {path}")
            return 1

    rule_engine = RuleEngine(args.rules)
    escalation_config = load_config(args.escalation)
    severity_engine = SeverityEngine(escalation_config=escalation_config)
    router = AlertRouter(args.escalation, dry_run=args.dry_run)

    # Load test events or use built-in demo events
    if args.events and os.path.exists(args.events):
        with open(args.events) as fh:
            events = json.load(fh)
    else:
        events = [
            {"event_type": "authentication", "action": "failure", "src_ip": "10.0.0.50",
             "username": "admin", "timestamp": "2024-01-01T00:00:00Z"},
            {"event_type": "network", "action": "accept", "src_ip": "10.0.0.100",
             "dst_ip": "198.51.100.10", "bytes_sent": 200000000, "direction": "outbound",
             "timestamp": "2024-01-01T00:01:00Z"},
        ]

    # Run detection → scoring → routing pipeline
    all_routing_results = []
    for event in events:
        matches = rule_engine.evaluate(event)
        scored = severity_engine.score_many(matches)
        routing = router.route_many(scored)
        all_routing_results.extend(routing)

    report = {
        "events_processed": len(events),
        "alerts_generated": len(all_routing_results),
        "routing_results": [r.to_dict() for r in all_routing_results],
    }

    print(json.dumps(report, indent=2))

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as fh:
            json.dump(report, fh, indent=2)

    return 0


if __name__ == "__main__":
    sys.exit(main())
