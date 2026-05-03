# QA to Cybersecurity Concept Mapping

## Overview

This document describes how traditional Quality Assurance (QA) and quality management concepts translate into cybersecurity operations within the CQAS framework.

## Concept Mapping Table

| Traditional QA Concept | Definition | CQAS Implementation |
|---|---|---|
| **Internal Quality Control (IQC)** | Testing your own process with known samples | Injecting synthetic IOCs into the live detection pipeline |
| **External Proficiency Testing (EPT)** | Independent third-party testing | Authorized attack simulations (red team exercises) |
| **Statistical Process Control (SPC)** | Using statistics to monitor process stability | Behavioral baseline + z-score anomaly detection |
| **Control Chart** | Visual tool showing process variation over time | DAR/FPR trend charts in Grafana |
| **Root Cause Analysis (RCA)** | Structured investigation of defect causes | Post-incident analysis of detection failures |
| **Corrective Action / Preventive Action (CAPA)** | Fixes for known defects + prevention of recurrence | Rule tuning, playbook updates, training |
| **Measurement Uncertainty** | Quantified doubt in a measurement result | False positive/negative confidence intervals |
| **Traceability** | Linking results back to standards/methods | MITRE ATT&CK technique mapping per rule |
| **Fitness for Purpose** | Does the tool do what it claims? | Detection coverage validation against threat scenarios |
| **Process Capability (Cp/Cpk)** | How well a process meets specifications | DAR vs. target (e.g., ≥95% detection rate) |

## Detailed Mappings

### IQC → Synthetic IOC Injection

In a laboratory, IQC involves analyzing a sample with a **known concentration** and comparing the measured result to the expected result. If the result falls outside the acceptable range, the system flags a quality failure.

In CQAS:
- **Known sample** = synthetic event with a known IOC (malicious IP, hash, domain)
- **Measured result** = whether the detection pipeline generated an alert
- **Acceptable range** = alert generated within the SLA window (e.g., < 5 minutes)
- **Quality failure** = missed detection (false negative)

### EPT → Attack Simulation

In a laboratory, EPT involves sending **blind samples** to external evaluators who don't know the expected results. Their results are compared against consensus values.

In CQAS:
- **Blind sample** = a scripted attack scenario run against the SOC
- **External evaluator** = red team or automated simulation engine
- **Consensus value** = expected detection based on MITRE coverage
- **Proficiency score** = percentage of attacks detected

### SPC → Behavioral Anomaly Detection

In manufacturing, SPC uses **control charts** (X-bar, R-charts) to distinguish between:
- **Common cause variation**: Random noise inherent to the process (normal)
- **Special cause variation**: Systematic deviation indicating a problem (anomaly)

In CQAS:
- **Process measurement** = network bytes, login attempts, process creation rate
- **Control limits** = baseline mean ± (z_threshold × std_dev)
- **Common cause** = daily variation within limits
- **Special cause** = statistical outlier that may indicate an attack

### CAPA → Rule Tuning

When a lab identifies a systematic measurement error, it raises a CAPA (Corrective and Preventive Action):
1. **Corrective action**: Fix the immediate problem (e.g., re-calibrate instrument)
2. **Preventive action**: Prevent recurrence (e.g., increase calibration frequency)

In CQAS:
1. **Corrective action**: Update the detection rule that missed the threat
2. **Preventive action**: Add coverage for similar attack variants
