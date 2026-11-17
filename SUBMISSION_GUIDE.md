# Submission and viva guide

## What to submit
1. IEEE-style paper PDF and source.
2. Source project ZIP with tests, event fixtures, policy templates and results.
3. Gamma deck generated from the supplied research brief and prompt.
4. Screenshots of the local replay, evaluation output and passing tests (capture on your own machine if required by the course).

## Exact reproduction
```bash
cd aws_eks_ids_ips_project
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=src python scripts/replay.py fixtures/attack_events.jsonl
PYTHONPATH=src python scripts/evaluate.py
PYTHONPATH=src pytest -q
```

## Viva answers
- **Why AWS?** EKS plus GuardDuty, Network Firewall, WAF/Shield, EventBridge and Kubernetes NetworkPolicy provide a documented, layered architecture.
- **Is GuardDuty an IPS?** GuardDuty primarily generates findings. Prevention comes from separately configured enforcement points or customer-defined automation.
- **What is the implementation?** A deterministic multi-source event normalizer/rules engine, time-window port-scan detector, evidence-rich alerts, and guarded response artefact generation.
- **Why no AI?** Rules are transparent, reproducible and easy to audit. The goal is to demonstrate telemetry fusion and response engineering, not train an opaque model.
- **What is innovative?** A compact cross-layer correlation and response bridge that maps audit/runtime/flow findings to a specific Kubernetes quarantine recommendation and a Suricata rule export, with approval-first safeguards.
- **Are the results from AWS?** No. They are from controlled synthetic event replay. The paper states this explicitly.
- **Why are metrics not 100%?** Legitimate admin actions intentionally create false positives; 20% of attack cases have incomplete telemetry, creating false negatives.
- **What is missing?** Live EKS telemetry, real attack traffic, policy apply/rollback validation, AWS cost and production overhead measurements.
