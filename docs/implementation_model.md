# CQAS Implementation Model

## Prerequisites

- Python 3.9+
- Docker and Docker Compose (for full infrastructure)
- Access to a SIEM or log source (Elasticsearch recommended)
- Network access for alert notifications

## Phase 1: Foundation Setup (Week 1-2)

### 1.1 Install and Configure

```bash
git clone https://github.com/ShadenU/cqas-framework.git
cd cqas-framework
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` with your environment-specific values:
- SIEM connection details
- Notification channel credentials
- Baseline window and threshold values

### 1.2 Start Infrastructure

```bash
docker-compose up -d elasticsearch kibana grafana
# Wait for Elasticsearch to be healthy
docker-compose up -d cqas-app
```

### 1.3 Verify Installation

```bash
pytest tests/ -v --cov=src --cov-report=term-missing
```

## Phase 2: Baseline Collection (Week 3-6)

Before anomaly detection is meaningful, you must collect baseline data.

### 2.1 Configure Asset Profiles

Edit `configs/baseline_profiles.yaml` to match your environment:
- Identify asset types (workstation, server, dc, network_device)
- Adjust mean/std_dev values to reflect your network's normal behavior
- Set appropriate maximum thresholds

### 2.2 Run Baseline Collection

```bash
python scripts/anomaly_detection.py --mode collect --days 30
```

This will:
- Poll your SIEM for 30 days of historical data
- Compute per-asset behavioral baselines
- Store baseline models in `data/baselines/`

## Phase 3: Detection Validation (Week 7-8)

### 3.1 IQC — IOC Injection

```bash
python scripts/inject_ioc.py --config configs/siem_rules.yaml --dry-run
python scripts/inject_ioc.py --config configs/siem_rules.yaml
```

Review the injection report and check that all expected alerts fired.

### 3.2 EPT — Attack Simulation

```bash
# IMPORTANT: Only run against authorized test environments
python scripts/simulate_attack.py --scenario port_scan --target 10.0.99.0/24
python scripts/simulate_attack.py --scenario brute_force --target 10.0.99.50
```

### 3.3 Validate Detection Results

```bash
python scripts/validate_detections.py --report results/validation_report.json
```

## Phase 4: Operationalize (Week 9+)

### 4.1 Schedule Regular Validation

Add to cron or use the built-in scheduler:

```python
import schedule
from scripts.inject_ioc import run_iqc_cycle

schedule.every().day.at("02:00").do(run_iqc_cycle)
```

### 4.2 Configure Escalation Policies

Edit `configs/escalation_policies.yaml` to set:
- Response time SLAs per severity
- Notification channel routing
- Auto-escalation triggers

### 4.3 Configure Dashboards

Import the provided dashboards:
- Grafana: Import `dashboards/grafana_dashboard.json`
- Kibana: Import `dashboards/kibana_dashboard.ndjson`

### 4.4 Set Up Metric Reporting

```bash
# Run daily metrics calculation
python scripts/metrics_calculator.py --output reports/daily_metrics.json
```

## Operational Runbook

### Daily Operations
1. Review overnight alerts in Grafana/Kibana
2. Check DAR metric — alert if below 95%
3. Review FPR — investigate if above 5%
4. Acknowledge and close low-priority tickets

### Weekly Operations
1. Run IQC validation cycle
2. Review anomaly baseline drift
3. Check SLA compliance for all severity levels
4. Update threat intelligence feeds

### Monthly Operations
1. Run full EPT attack simulation suite
2. Perform RCA on any detection failures from the month
3. Review and tune detection rules
4. Update baselines with fresh 30-day data
5. Generate monthly quality scorecard
