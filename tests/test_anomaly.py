"""Tests for the anomaly detection subsystem (BaselineModel + DeltaChecker)."""

import os
import pytest
import numpy as np

from src.anomaly.baseline_model import BaselineModel
from src.anomaly.delta_checker import DeltaChecker


THRESHOLDS_CONFIG = "configs/anomaly_thresholds.yaml"


@pytest.fixture
def baseline_model(tmp_path):
    model = BaselineModel(baseline_dir=str(tmp_path), min_data_points=10)
    # Build baselines for failed_logins with two groups
    observations = {
        "10.0.0.1": [float(x) for x in range(1, 12)],  # 11 values
        "10.0.0.2": [2.0] * 20,  # mean=2, std=0
    }
    model.fit("failed_logins", observations)
    return model


class TestBaselineModel:

    def test_fit_stores_baseline(self, baseline_model):
        bl = baseline_model.get_baseline("failed_logins", "10.0.0.1")
        assert bl is not None
        assert "mean" in bl
        assert "std" in bl
        assert "count" in bl

    def test_fit_skips_insufficient_data(self, tmp_path):
        model = BaselineModel(baseline_dir=str(tmp_path), min_data_points=50)
        model.fit("metric", {"ip1": [1.0] * 10})
        assert model.get_baseline("metric", "ip1") is None

    def test_z_score_calculation(self, baseline_model):
        bl = baseline_model.get_baseline("failed_logins", "10.0.0.1")
        mean = bl["mean"]
        # Observed value at exactly the mean should have z-score ~0
        z = baseline_model.get_z_score("failed_logins", "10.0.0.1", mean)
        assert abs(z) < 0.01

    def test_z_score_returns_none_for_missing_baseline(self, baseline_model):
        z = baseline_model.get_z_score("failed_logins", "nonexistent_ip", 10.0)
        assert z is None

    def test_z_score_zero_std(self, baseline_model):
        # "10.0.0.2" has std=0
        z = baseline_model.get_z_score("failed_logins", "10.0.0.2", 5.0)
        assert z == 0.0

    def test_save_and_load(self, baseline_model, tmp_path):
        saved_path = baseline_model.save("test_baseline.json")
        assert os.path.exists(saved_path)

        new_model = BaselineModel(baseline_dir=str(tmp_path))
        new_model.load("test_baseline.json")
        bl = new_model.get_baseline("failed_logins", "10.0.0.1")
        assert bl is not None

    def test_load_missing_file_does_not_raise(self, tmp_path):
        model = BaselineModel(baseline_dir=str(tmp_path))
        model.load("does_not_exist.json")  # should warn, not raise

    def test_all_metrics(self, baseline_model):
        metrics = baseline_model.all_metrics()
        assert "failed_logins" in metrics

    def test_all_groups(self, baseline_model):
        groups = baseline_model.all_groups("failed_logins")
        assert "10.0.0.1" in groups
        assert "10.0.0.2" in groups


@pytest.mark.skipif(
    not os.path.exists(THRESHOLDS_CONFIG),
    reason="anomaly_thresholds.yaml not present",
)
class TestDeltaChecker:

    @pytest.fixture
    def checker(self, baseline_model):
        return DeltaChecker(baseline_model, THRESHOLDS_CONFIG)

    def test_normal_observation_no_alert(self, checker):
        # Mean for 10.0.0.1 is ~6, sending 6 → z-score ~0 → no alert
        bl = checker.baseline_model.get_baseline("failed_logins", "10.0.0.1")
        alert = checker.check("failed_logins", "10.0.0.1", bl["mean"])
        assert alert is None

    def test_anomalous_high_value_triggers_alert(self, checker):
        # Very high value should trigger
        alert = checker.check("failed_logins", "10.0.0.1", 1000.0)
        assert alert is not None
        assert alert.severity in ("warning", "critical")

    def test_alert_has_correct_fields(self, checker):
        alert = checker.check("failed_logins", "10.0.0.1", 9999.0)
        assert alert is not None
        d = alert.to_dict()
        assert "metric_name" in d
        assert "group_key" in d
        assert "z_score" in d
        assert "severity" in d
        assert "detected_at" in d

    def test_unknown_metric_returns_none(self, checker):
        alert = checker.check("unknown_metric_xyz", "10.0.0.1", 100.0)
        assert alert is None

    def test_check_batch_returns_list(self, checker):
        obs = [
            {"metric_name": "failed_logins", "group_key": "10.0.0.1", "value": 9999.0},
            {"metric_name": "failed_logins", "group_key": "10.0.0.2", "value": 2.0},
        ]
        alerts = checker.check_batch(obs)
        assert isinstance(alerts, list)
        assert len(alerts) >= 1  # at least the extreme value should trigger
