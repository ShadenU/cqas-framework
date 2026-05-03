# CQAS Architecture Diagrams

This directory contains architecture diagrams describing the CQAS framework components and data flows.

## Diagrams

### 1. High-Level System Architecture (`system_overview.png`)
Shows the major layers of the CQAS framework:
- **Ingestion Layer**: LogCollector → LogParser → Event Bus
- **Detection Engine**: RuleEngine + CorrelationEngine
- **Validation Engine**: IQCEngine (IQC) + EPTEngine (EPT)
- **Anomaly Detection**: BaselineModel + DeltaChecker
- **Escalation Engine**: SeverityEngine + AlertRouter
- **RCA Engine**: RootCauseAnalyzer + FailureAnalysis
- **Metrics & Reporting**: PerformanceMetrics + ScoringEngine + Dashboards

### 2. Data Flow Diagram (`data_flow.png`)
Illustrates how raw log data flows through the system:
```
Raw Logs → Ingest → Normalize → Detect → Correlate → Score → Escalate → Report
               ↑                    ↓
         Attack Simulation     Validation (IQC/EPT)
```

### 3. IQC/EPT Testing Pipeline (`validation_pipeline.png`)
Shows how synthetic IOCs and attack simulations feed into the validation loop:
- Synthetic event injection points in the pipeline
- Expected vs. actual detection comparison
- DAR and FPR calculation flow

### 4. Deployment Architecture (`deployment.png`)
Docker Compose service topology:
- Elasticsearch ← Logstash ← Application
- Kibana → Elasticsearch
- Grafana → Prometheus/Elasticsearch
- CQAS App container orchestration

### 5. MITRE ATT&CK Coverage Map (`mitre_coverage.png`)
Heatmap showing which MITRE ATT&CK tactics and techniques are covered by CQAS rules.

## Generating Diagrams

Diagrams are generated using [draw.io](https://app.diagrams.net/) source files (`.drawio`) in this directory.
To regenerate PNG exports, open each `.drawio` file and export as PNG at 150 DPI.
