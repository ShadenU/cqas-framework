# Use Case: SOC Validation

## Overview

CQAS can be used to continuously validate that a Security Operations Center (SOC) is operating at the required quality level.

## Problem

Many SOCs lack objective measurement of their detection effectiveness. Without systematic testing, detection gaps go unnoticed until a breach occurs.

## CQAS Solution

### IQC Validation Cycle (Daily)
1. CQAS injects 10-20 synthetic malicious events across different attack categories
2. The injection includes realistic network traffic patterns to avoid easy filtering
3. CQAS monitors the SIEM for corresponding alerts within a 5-minute window
4. DAR is calculated and reported to the SOC manager

### EPT Validation Cycle (Monthly)
1. The CQAS EPT engine runs the full attack simulation suite (port scan, brute force, lateral movement, exfiltration)
2. Results are compared against expected detection coverage from MITRE ATT&CK mapping
3. A comprehensive EPT report is generated with pass/fail for each scenario

## Expected Outcomes

- SOC maintains ≥95% DAR with continuous feedback loop
- Detection rule gaps identified within 24 hours of creation
- Monthly EPT report provides compliance evidence for auditors
- Alert fatigue reduced by tracking and reducing FPR

## Metrics Tracked

- DAR (daily)
- FPR (daily)
- MTTR per severity tier (daily)
- EPT coverage score (monthly)
