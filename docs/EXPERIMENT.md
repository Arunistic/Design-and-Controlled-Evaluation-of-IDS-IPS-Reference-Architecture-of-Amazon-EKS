# Experimental design and results

## Objective
Measure the coverage/processing trade-off of a transparent multi-source rule engine against single-source variants using controlled, repeatable event replay.

## Dataset construction
- Seed: `20261111`.
- 400 benign cases and 100 attack cases.
- Attack families: privileged/hostPath workload creation, Secret enumeration, suspicious shell execution, port-scan burst, known-bad outbound connection.
- Benign traffic includes normal deployment/runtime/flow events and 5% authorized-but-risky admin actions (for example, an approved Secret listing) to expose rule false positives.
- 20% of attack cases deliberately have incomplete or non-indicative telemetry to represent an observability gap and expose false negatives.
- The known-bad IPs are documentation-only TEST-NET addresses, not real threat infrastructure.

## Compared variants
1. Audit-only rules.
2. Runtime-only rules.
3. Network-only rules.
4. Multi-source fused rules.

A case is positive if any alert is produced. This is a case-level controlled replay, not per-packet or per-event classification.

## Results

| Variant | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Audit-only | 31 | 20 | 380 | 69 | 0.608 | 0.310 | 0.411 | 0.050 |
| Runtime-only | 15 | 0 | 400 | 85 | 1.000 | 0.150 | 0.261 | 0.000 |
| Network-only | 34 | 0 | 400 | 66 | 1.000 | 0.340 | 0.507 | 0.000 |
| Multi-source fused rules | 80 | 20 | 380 | 20 | 0.800 | 0.800 | 0.800 | 0.050 |

The fused detector raises recall from 0.31/0.15/0.34 to 0.80 versus the single-source variants, while retaining the 0.05 FPR introduced by legitimate-but-sensitive admin actions. The result illustrates complementarity of control-plane, runtime and network evidence. It does not establish production effectiveness: synthetic scenarios were constructed around the rules, class prevalence is chosen, and no live EKS/GuardDuty sensor was measured.

## Runtime cost
On the execution machine, mean engine processing was approximately 0.0135 ms per case and p95 approximately 0.0435 ms for the fused rules path. This is in-process replay timing only. It excludes log delivery, event parsing at scale, AWS service latency, API calls, Kubernetes scheduling, policy propagation and verification. It must not be represented as end-to-end detection or isolation latency.

## Reproducibility
```bash
PYTHONPATH=src python scripts/evaluate.py
PYTHONPATH=src pytest -q
```
Outputs: `results/evaluation.json`, `results/evaluation.csv`.

## Evaluation threats and next step
The replay is synthetic and designed to test rule logic, not benchmark AWS GuardDuty. A stronger follow-up would deploy a disposable multi-node EKS cluster (or a local Kubernetes cluster with a compatible CNI), enable EKS audit logging, GuardDuty EKS Protection/Runtime Monitoring, generate safe test events, export CloudWatch/GuardDuty/EventBridge records, and measure detection time, false positives, policy propagation, resource overhead and service impact. Cloud charges and permissions must be approved before using an AWS account.
