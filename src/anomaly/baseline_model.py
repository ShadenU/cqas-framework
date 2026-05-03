"""Baseline model — computes statistical baselines from historical event data."""

import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from src.utils.logger import get_logger

logger = get_logger(__name__)


class BaselineModel:
    """Builds and persists per-asset statistical behavioral baselines.

    For each metric and group_by key, computes:
    - mean, standard deviation, min, max
    - data point count

    Baselines are built from a list of aggregated metric observations.

    Args:
        baseline_dir: Directory for persisting baseline JSON files.
        min_data_points: Minimum observations required to establish a baseline.
    """

    def __init__(
        self,
        baseline_dir: str = "data/baselines",
        min_data_points: int = 30,
    ) -> None:
        self.baseline_dir = baseline_dir
        self.min_data_points = min_data_points
        os.makedirs(baseline_dir, exist_ok=True)
        # metric_name -> group_key -> {"mean": float, "std": float, ...}
        self._baselines: Dict[str, Dict[str, Dict]] = {}

    def fit(self, metric_name: str, observations: Dict[str, List[float]]) -> None:
        """Compute baseline statistics for a metric across multiple groups.

        Args:
            metric_name: Name of the metric (e.g., 'failed_logins_per_hour').
            observations: Dict mapping group_key (e.g., IP/hostname) to list of values.
        """
        if metric_name not in self._baselines:
            self._baselines[metric_name] = {}

        for group_key, values in observations.items():
            if len(values) < self.min_data_points:
                logger.debug(
                    f"Skipping baseline for {metric_name}/{group_key}: "
                    f"only {len(values)} data points (min={self.min_data_points})"
                )
                continue

            arr = np.array(values, dtype=float)
            self._baselines[metric_name][group_key] = {
                "mean": float(np.mean(arr)),
                "std": float(np.std(arr)),
                "min": float(np.min(arr)),
                "max": float(np.max(arr)),
                "count": len(values),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }

        logger.info(
            f"Baseline fitted for metric '{metric_name}' "
            f"({len(self._baselines[metric_name])} groups)"
        )

    def get_baseline(self, metric_name: str, group_key: str) -> Optional[Dict]:
        """Retrieve baseline stats for a specific metric and group.

        Args:
            metric_name: Metric name.
            group_key: Group identifier (e.g., IP address).

        Returns:
            Dict with mean, std, min, max, count — or None if not found.
        """
        return self._baselines.get(metric_name, {}).get(group_key)

    def get_z_score(
        self, metric_name: str, group_key: str, observed_value: float
    ) -> Optional[float]:
        """Compute z-score of an observed value against the stored baseline.

        Args:
            metric_name: Metric name.
            group_key: Group identifier.
            observed_value: The current observation.

        Returns:
            Z-score float, or None if no baseline exists or std is zero.
        """
        baseline = self.get_baseline(metric_name, group_key)
        if baseline is None:
            return None
        std = baseline["std"]
        if std == 0:
            return 0.0
        return (observed_value - baseline["mean"]) / std

    def save(self, filename: Optional[str] = None) -> str:
        """Persist baselines to a JSON file.

        Args:
            filename: Optional filename override. Defaults to 'baselines.json'.

        Returns:
            Full path to the saved file.
        """
        if filename is None:
            filename = "baselines.json"
        filepath = os.path.join(self.baseline_dir, filename)
        with open(filepath, "w") as fh:
            json.dump(self._baselines, fh, indent=2)
        logger.info(f"Baselines saved to {filepath}")
        return filepath

    def load(self, filename: Optional[str] = None) -> None:
        """Load baselines from a JSON file.

        Args:
            filename: Optional filename override. Defaults to 'baselines.json'.
        """
        if filename is None:
            filename = "baselines.json"
        filepath = os.path.join(self.baseline_dir, filename)
        if not os.path.exists(filepath):
            logger.warning(f"Baseline file not found: {filepath}")
            return
        with open(filepath, "r") as fh:
            self._baselines = json.load(fh)
        logger.info(f"Baselines loaded from {filepath}")

    def all_metrics(self) -> List[str]:
        """Return list of all metric names with stored baselines."""
        return list(self._baselines.keys())

    def all_groups(self, metric_name: str) -> List[str]:
        """Return all group keys for a given metric."""
        return list(self._baselines.get(metric_name, {}).keys())
