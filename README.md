# EKS-IDS: Explainable IDS/IPS for Amazon EKS

A software-engineering-focused reference implementation inspired by AWS's layered EKS security architecture. It combines Kubernetes audit events, container runtime events, network-flow events and GuardDuty findings; applies transparent rules; and generates scoped containment recommendations.

## What is implemented
- Normalization-by-contract for Kubernetes audit, Falco/Tetragon-like runtime, VPC Flow/Hubble-like flow and GuardDuty/EventBridge records.
- Explainable detections: privileged/hostPath workload creation, Kubernetes Secret enumeration, cluster-admin binding, exec into sensitive namespaces, suspicious shell execution, sensitive-file access, port-scan bursts, known-bad egress and large external transfers.
- Per-Pod sliding-window aggregation for port-scan detection.
- Response planner: recommendation-only Kubernetes quarantine NetworkPolicy plus a Suricata-compatible `drop` rule for export to AWS Network Firewall.
- Deterministic replay/evaluation harness, unit tests, sample telemetry and deployment policy templates.

## Run locally
Python 3.10+ recommended.
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=src python scripts/replay.py fixtures/attack_events.jsonl
PYTHONPATH=src python scripts/evaluate.py
PYTHONPATH=src python scripts/generate_policy.py --namespace payments --pod checkout --label app=checkout
PYTHONPATH=src pytest -q
```
Outputs are written to `results/`.

## AWS mapping
- EKS Protection / GuardDuty: Kubernetes audit-log findings.
- GuardDuty Runtime Monitoring: OS/runtime process, file and network events from the EKS security agent.
- VPC Flow Logs / CloudWatch: network metadata and operational telemetry.
- EventBridge: route GuardDuty findings to a customer-owned response workflow.
- AWS Network Firewall: Suricata-compatible stateful IPS rules; only sees traffic routed through its endpoints.
- EKS VPC CNI NetworkPolicy: Pod-level L3/L4 segmentation when the supported network-policy feature is enabled.

This project does not reproduce GuardDuty's proprietary detection logic. It accepts GuardDuty finding envelopes as upstream input and adds transparent, student-implemented rules around normalized events.

## Safety and correctness boundaries
- All response actions default to `recommendation_only`; no AWS API or Kubernetes API mutation is performed.
- A generated NetworkPolicy is additive, requires a CNI that enforces NetworkPolicy, and is not a universal override of other allow policies. Validate the selector and service impact before applying.
- NetworkPolicy cannot remediate host compromise, revoke IAM permissions, or undo Secret exposure. Those require separate IAM/RBAC, node/runtime, and credential-rotation workflows.
- The sample threat IPs are TEST-NET documentation addresses, not live malicious infrastructure.
- The evaluation is synthetic controlled event replay (400 benign and 100 attack cases, with authorized-admin false positives and incomplete-telemetry false negatives). It is not an AWS/GuardDuty performance claim, live EKS measurement, or real attack test.

## Architecture and research
See `docs/ARCHITECTURE.md`, `docs/EXPERIMENT.md`, and the IEEE paper in `paper/`.
