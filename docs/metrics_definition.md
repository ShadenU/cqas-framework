# CQAS Metrics Definitions

## Core Quality Metrics

### DAR — Detection Accuracy Rate

**Definition**: The percentage of known threats (injected IOCs or simulated attacks) that were successfully detected by the security monitoring pipeline.

**Formula**:
```
DAR = (True Positives / (True Positives + False Negatives)) × 100%
```

**Target**: ≥ 95%

**Calculation Method**:
1. Inject N synthetic IOC events over a defined period
2. Count how many generated a corresponding alert (True Positives)
3. Count how many did NOT generate an alert (False Negatives)
4. DAR = TP / (TP + FN) × 100

**Frequency**: Calculated per IQC/EPT cycle (daily recommended)

---

### FPR — False Positive Rate

**Definition**: The percentage of all generated alerts that are false positives (legitimate activity incorrectly flagged as malicious).

**Formula**:
```
FPR = (False Positives / (False Positives + True Negatives)) × 100%
```

**Alternative Formula** (commonly used in SOC context):
```
FPR = (False Positives / Total Alerts) × 100%
```

**Target**: ≤ 5%

**Calculation Method**:
1. Collect all alerts over the measurement period
2. Classify each as TP or FP through analyst review or automated validation
3. FPR = FP / Total Alerts × 100

**Frequency**: Calculated daily from the previous day's alert queue

---

### MTTR — Mean Time to Respond

**Definition**: The average time elapsed from when an alert is generated to when it is fully resolved (closed with documented disposition).

**Formula**:
```
MTTR = Σ(Resolution Time - Alert Creation Time) / Number of Resolved Alerts
```

**Target**: Varies by severity:
- Critical: ≤ 15 minutes
- High: ≤ 60 minutes
- Medium: ≤ 4 hours
- Low: ≤ 24 hours

**Frequency**: Calculated per shift and per day

---

### MTTD — Mean Time to Detect

**Definition**: The average time elapsed between when a threat event occurs and when the SIEM/detection system generates the first alert.

**Formula**:
```
MTTD = Σ(Alert Timestamp - Event Timestamp) / Number of Detected Events
```

**Target**: ≤ 5 minutes for rule-based detections

**Frequency**: Measured during IQC/EPT exercises

---

### Escalation Accuracy

**Definition**: The percentage of alerts that were escalated to the correct severity level (verified through post-incident review or IQC validation).

**Formula**:
```
Escalation Accuracy = (Correctly Escalated / Total Escalated) × 100%
```

**Target**: ≥ 90%

---

### SLA Compliance Rate

**Definition**: The percentage of alerts that were acknowledged and resolved within the defined SLA for their severity level.

**Formula**:
```
SLA Compliance = (Alerts Resolved Within SLA / Total Alerts) × 100%
```

**Target**: ≥ 98% for critical, ≥ 95% for high

---

### Coverage Score

**Definition**: The percentage of MITRE ATT&CK tactics and techniques covered by active detection rules.

**Formula**:
```
Coverage Score = (Techniques with Detection Rules / Total Relevant Techniques) × 100%
```

**Target**: ≥ 70% of high-priority techniques

---

## Composite Quality Score

The CQAS Overall Quality Score is a weighted composite of the above metrics:

```
Quality Score = (DAR × 0.35) + ((100 - FPR) × 0.25) + 
                (MTTR_SLA_Compliance × 0.20) + 
                (Escalation_Accuracy × 0.10) + 
                (Coverage_Score × 0.10)
```

**Grade Scale**:
- A: 90-100 — Excellent SOC quality
- B: 80-89 — Good, minor improvements needed
- C: 70-79 — Acceptable, focus on improvement areas
- D: 60-69 — Poor, significant remediation required
- F: < 60 — Critical failures, immediate action needed
