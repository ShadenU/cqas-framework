"""Delta checker — detects statistical deviations from baselines."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.utils.helpers import load_config
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AnomalyAlert:
    """Represents a detected statistical anomaly."""

    def __init__(
        self,
        metric_name: str,
        group_key: str,
        observed_value: float,
        baseline_mean: float,
        baseline_std: float,
        z_score: float,
        severity: str,
        threshold_config: Dict[str, Any],
    ) -> None:
        self.metric_name = metric_name
        self.group_key = group_key
        self.observed_value = observed_value
        self.baseline_mean = baseline_mean
        self.baseline_std = baseline_std
        self.z_score = z_score
        self.severity = severity
        self.threshold_config = threshold_config
        self.detected_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metric_name": self.metric_name,
            "group_key": self.group_key,
            "observed_value": self.observed_value,
            "baseline_mean": self.baseline_mean,
            "baseline_std": self.baseline_std,
            "z_score": round(self.z_score, 3),
            "severity": self.severity,
            "detected_at": self.detected_at,
            "description": (
                f"{self.metric_name} for '{self.group_key}' is "
                f"{self.observed_value:.1f} (baseline mean={self.baseline_mean:.1f}, "
                f"z={self.z_score:.2f})"
            ),
        }


class DeltaChecker:
    """Checks current metric observations against stored baselines.

    For each observation, computes the z-score and compares against
    warning and critical thresholds defined in the config.

    Args:
        baseline_model: Fitted BaselineModel instance.
        thresholds_config_path: Path to anomaly_thresholds.yaml.
    """

    def __init__(self, baseline_model: Any, thresholds_config_path: str) -> None:
        self.baseline_model = baseline_model
        config = load_config(thresholds_config_path)
        self.thresholds: Dict[str, Dict] = config.get("thresholds", {})
        self.global_config = config.get("global", {})
        logger.info(f"DeltaChecker loaded {len(self.thresholds)} metric thresholds")

    def check(
        self, metric_name: str, group_key: str, observed_value: float
    ) -> Optional[AnomalyAlert]:
        """Check a single observation against the baseline.

        Args:
            metric_name: Metric name matching a key in thresholds config.
            group_key: Asset/group identifier (e.g., IP address).
            observed_value: The measured value.

        Returns:
            AnomalyAlert if a threshold is exceeded, else None.
        """
        threshold_cfg = self.thresholds.get(metric_name)
        if threshold_cfg is None:
            return None

        z_score = self.baseline_model.get_z_score(metric_name, group_key, observed_value)
        baseline = self.baseline_model.get_baseline(metric_name, group_key)

        if z_score is None or baseline is None:
            absolute_max = threshold_cfg.get("absolute_max")
            if absolute_max and observed_value >= absolute_max:
                return AnomalyAlert(
                    metric_name=metric_name,
                    group_key=group_key,
                    observed_value=observed_value,
                    baseline_mean=0.0,
                    baseline_std=0.0,
                    z_score=float("inf"),
                    severity="critical",
                    threshold_config=threshold_cfg,
                )
            return None

        critical_z = threshold_cfg.get(
            "critical_z_score",
            self.global_config.get("z_score_threshold", 3.0),
        )
        warning_z = threshold_cfg.get("warning_z_score", critical_z * 0.7)

        absolute_max = threshold_cfg.get("absolute_max") or threshold_cfg.get("absolute_max_bytes")

        severity = None
        if absolute_max and observed_value >= absolute_max:
            severity = "critical"
        elif abs(z_score) >= critical_z:
            severity = "critical"
        elif abs(z_score) >= warning_z:
            severity = "warning"

        if severity is None:
            return None

        alert = AnomalyAlert(
            metric_name=metric_name,
            group_key=group_key,
            observed_value=observed_value,
            baseline_mean=baseline["mean"],
            baseline_std=baseline["std"],
            z_score=z_score,
            severity=severity,
            threshold_config=threshold_cfg,
        )
        logger.info(
            f"Anomaly detected: {metric_name}/{group_key} "
            f"z={z_score:.2f} severity={severity}"
        )
        return alert

    def check_batch(
        self, observations: List[Dict[str, Any]]
    ) -> List[AnomalyAlert]:
        """Check a list of metric observations.

        Each observation dict should have: metric_name, group_key, value.

        Args:
            observations: List of observation dicts.

        Returns:
            List of AnomalyAlert objects for exceeded thresholds.
        """
        alerts = []
        for obs in observations:
            metric = obs.get("metric_name", "")
            group = obs.get("group_key", "")
            value = float(obs.get("value", 0))
            alert = self.check(metric, group, value)
            if alert:
                alerts.append(alert)
        return alerts
