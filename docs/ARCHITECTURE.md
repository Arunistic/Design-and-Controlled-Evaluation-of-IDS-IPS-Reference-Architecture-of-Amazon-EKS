# Architecture and provider mapping

## Scope
The reference system models a customer-operated security layer around Amazon EKS. It does not claim to reproduce AWS proprietary GuardDuty detections. It consumes normalized security events and implements additional transparent rules and guarded response recommendations.

## AWS architecture roles

| Layer | AWS/Kubernetes service | What it observes or enforces | IDS/IPS role |
|---|---|---|---|
| Kubernetes control plane | EKS audit logging + GuardDuty EKS Protection | Kubernetes API actor, verb, resource and request context | Managed control-plane threat detection |
| Container/node runtime | GuardDuty Runtime Monitoring (`aws-guardduty-agent`) | Process, file and network runtime behavior, with workload context | Managed runtime IDS |
| Network metadata | VPC Flow Logs / CloudWatch | Flow metadata, bytes, addresses, ports, accept/reject | Network visibility; not payload DPI |
| Inline network inspection | AWS Network Firewall | Routed traffic; stateful Suricata-compatible rules | Alert/drop IPS when traffic traverses firewall endpoints |
| HTTP application edge | AWS WAF (+ ALB/API Gateway/CloudFront) | HTTP(S) request patterns and rate/managed rules | L7 prevention |
| DDoS | AWS Shield | DDoS attack signals and mitigation | Managed DDoS detection/mitigation |
| Pod segmentation | Kubernetes NetworkPolicy via supported EKS VPC CNI | Pod ingress/egress L3/L4 | East-west and egress prevention |
| Correlation / response | Security Hub, Detective, EventBridge, Lambda/Step Functions | Findings, investigation context, event routing | Orchestration; customer defines response |

## Proposed event path

1. EKS audit records, runtime observations, network flow records and GuardDuty findings are converted into a common event envelope.
2. The `EKSIDS` engine applies deterministic rules and a per-Pod sliding window for port-scan detection.
3. An alert includes rule ID, severity, event evidence, workload identity and a suggested response.
4. For eligible pod-level network threats, the response planner emits a scoped deny-ingress/deny-egress NetworkPolicy manifest. For known-bad external IPs, it can emit a Suricata-compatible `drop` rule for operator review.
5. Human approval, policy validation, rollout, verification and rollback are separate operational steps. The prototype defaults to recommendation-only mode.

## Why this is AWS-aligned
- GuardDuty EKS Protection is an upstream managed detector for Kubernetes audit activity.
- GuardDuty Runtime Monitoring is an upstream managed runtime detector, not the student's custom engine.
- EventBridge is the event routing seam for customer-owned automation.
- Network Firewall is the routed network IPS option and supports Suricata-compatible stateful rules.
- Kubernetes NetworkPolicy is the pod-level enforcement primitive. The CNI must actually implement it.

## GCP comparison
Google Cloud's analogous stack is not a one-to-one clone. Security Command Center provides threat findings from log-based, agentless and runtime detectors; Container Threat Detection monitors GKE runtime behavior. Cloud IDS uses packet mirroring and a managed threat-detection engine for network traffic. GKE Dataplane V2 (Cilium-based) and Kubernetes NetworkPolicy/ClusterNetworkPolicy provide pod-level controls. This supports the same layered principle: audit/runtime detection + network inspection + Kubernetes policy enforcement. AWS remains the primary implementation target because the selected case study is Amazon EKS.

## Important boundaries
- GuardDuty EKS Protection audit-log monitoring and Runtime Monitoring are different protection plans.
- Current AWS documentation states Runtime Monitoring supports EKS on EC2 and EKS Auto Mode, but not EKS on Fargate or EKS Hybrid Nodes.
- AWS Network Firewall only inspects traffic that is routed through its endpoints; it is not a universal sensor for all pod-to-pod flows.
- VPC Flow Logs are metadata, not full packet capture.
- NetworkPolicy is L3/L4 and additive; it is not a universal deny override, IAM revocation, host isolation, or credential rotation mechanism.
- The generated policy must use a unique, verified workload label selector. A pod name is not itself a Kubernetes label selector.
