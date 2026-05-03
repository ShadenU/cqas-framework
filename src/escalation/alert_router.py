"""Alert router — dispatches scored alerts to the appropriate channels."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from src.utils.helpers import load_config
from src.utils.logger import get_logger

logger = get_logger(__name__)


class RoutingResult:
    """Records the outcome of routing an alert."""

    def __init__(
        self,
        alert_id: str,
        severity: str,
        channels_notified: List[str],
        success: bool,
        errors: Optional[List[str]] = None,
    ) -> None:
        self.alert_id = alert_id
        self.severity = severity
        self.channels_notified = channels_notified
        self.success = success
        self.errors = errors or []
        self.routed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "severity": self.severity,
            "channels_notified": self.channels_notified,
            "success": self.success,
            "errors": self.errors,
            "routed_at": self.routed_at,
        }


class AlertRouter:
    """Routes ScoredAlerts to notification channels based on severity.

    Channels supported: slack, email (log-only stub), log, webhook.

    Args:
        escalation_config_path: Path to escalation_policies.yaml.
        dry_run: If True, log routing decisions without actually sending.
    """

    def __init__(self, escalation_config_path: str, dry_run: bool = True) -> None:
        config = load_config(escalation_config_path)
        self.severity_levels: Dict[str, Dict] = config.get("severity_levels", {})
        self.dry_run = dry_run
        self._routing_log: List[RoutingResult] = []
        logger.info(f"AlertRouter initialized (dry_run={dry_run})")

    def route(self, scored_alert: Any) -> RoutingResult:
        """Route a ScoredAlert to configured channels.

        Args:
            scored_alert: ScoredAlert object with score, computed_severity, etc.

        Returns:
            RoutingResult documenting the routing action.
        """
        severity = scored_alert.computed_severity
        level_config = self.severity_levels.get(severity, {})
        channels = level_config.get("notification_channels", [])

        notified = []
        errors = []

        for channel in channels:
            chan_type = channel.get("type", "log")
            try:
                if self.dry_run:
                    logger.info(
                        f"[DRY RUN] Would route alert {scored_alert.alert_id} "
                        f"to channel type={chan_type} severity={severity}"
                    )
                    notified.append(f"{chan_type}:dry_run")
                elif chan_type == "slack":
                    self._send_slack(scored_alert, channel)
                    notified.append("slack")
                elif chan_type == "webhook":
                    self._send_webhook(scored_alert, channel)
                    notified.append("webhook")
                else:
                    self._log_alert(scored_alert, chan_type)
                    notified.append(f"{chan_type}:logged")
            except Exception as exc:
                err = f"Failed to notify {chan_type}: {exc}"
                logger.error(err)
                errors.append(err)

        result = RoutingResult(
            alert_id=scored_alert.alert_id,
            severity=severity,
            channels_notified=notified,
            success=len(errors) == 0,
            errors=errors,
        )
        self._routing_log.append(result)
        return result

    def route_many(self, scored_alerts: List[Any]) -> List[RoutingResult]:
        """Route multiple ScoredAlerts.

        Args:
            scored_alerts: List of ScoredAlert objects.

        Returns:
            List of RoutingResult objects.
        """
        return [self.route(alert) for alert in scored_alerts]

    def get_routing_log(self) -> List[RoutingResult]:
        return list(self._routing_log)

    # ------------------------------------------------------------------ #
    # Channel implementations                                              #
    # ------------------------------------------------------------------ #

    def _send_slack(self, alert: Any, channel_config: Dict) -> None:
        webhook_url = channel_config.get("webhook_url", "")
        if not webhook_url:
            raise ValueError("No webhook_url configured for Slack channel")
        payload = {
            "text": (
                f":rotating_light: *CQAS Alert*\n"
                f"*Severity:* {alert.computed_severity.upper()}\n"
                f"*Rule:* {alert.rule_id} — {alert.rule_name}\n"
                f"*Score:* {alert.score:.3f}\n"
                f"*Source IP:* {alert.event.get('src_ip', 'unknown')}\n"
                f"*Alert ID:* `{alert.alert_id}`"
            )
        }
        resp = requests.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()

    def _send_webhook(self, alert: Any, channel_config: Dict) -> None:
        url = channel_config.get("url", "")
        if not url:
            raise ValueError("No url configured for webhook channel")
        payload = alert.to_dict() if hasattr(alert, "to_dict") else {}
        resp = requests.post(url, json=payload, timeout=10)
        resp.raise_for_status()

    def _log_alert(self, alert: Any, channel_type: str) -> None:
        logger.info(
            f"Alert routed to {channel_type}",
            extra={
                "alert_id": alert.alert_id,
                "severity": alert.computed_severity,
                "score": alert.score,
                "rule_id": alert.rule_id,
            },
        )
