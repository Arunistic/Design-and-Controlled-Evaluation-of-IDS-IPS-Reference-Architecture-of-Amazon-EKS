"""Explainable, event-driven IDS/IPS reference implementation for AWS EKS.
Consumes normalized Kubernetes audit, Falco-like runtime, VPC-flow and GuardDuty events.
No AWS credentials or live cluster are required for the reproducible offline experiment.
"""
from __future__ import annotations
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any
import ipaddress, json, re

SENSITIVE_NAMESPACES = {"kube-system", "kube-public"}
SENSITIVE_FILES = ("/etc/shadow", "/var/run/secrets", "/root/.ssh", "/etc/kubernetes")

@dataclass
class Alert:
    rule_id: str
    severity: str
    category: str
    message: str
    namespace: str | None = None
    pod: str | None = None
    actor: str | None = None
    evidence: dict[str, Any] | None = None
    response: dict[str, Any] | None = None

class EKSIDS:
    """Small deterministic rules engine with bounded per-pod network windows."""
    def __init__(self, scan_threshold: int = 8, window_seconds: int = 60,
                 external_bytes_threshold: int = 10_000_000,
                 known_bad_ips: set[str] | None = None):
        self.scan_threshold = scan_threshold
        self.window_seconds = window_seconds
        self.external_bytes_threshold = external_bytes_threshold
        self.known_bad_ips = known_bad_ips or {"198.51.100.66", "203.0.113.77"}
        self.flows: dict[str, deque] = defaultdict(deque)
        self.pod_signals: dict[str, deque] = defaultdict(deque)
        self.alert_keys: set[tuple] = set()

    def process(self, event: dict[str, Any]) -> list[Alert]:
        kind = str(event.get("kind", "")).lower()
        alerts: list[Alert] = []
        ns = event.get("namespace") or event.get("pod_namespace")
        pod = event.get("pod") or event.get("pod_name")
        actor = event.get("actor") or event.get("user")
        ts = float(event.get("ts", 0))
        if kind in {"k8s_audit", "audit"}:
            verb, resource = str(event.get("verb", "")).lower(), str(event.get("resource", "")).lower()
            obj = event.get("object", {}) or {}
            if resource in {"pods", "pod"} and verb in {"create", "patch", "update"}:
                spec = obj.get("spec", obj)
                containers = spec.get("containers", []) if isinstance(spec, dict) else []
                privileged = any(c.get("securityContext", {}).get("privileged", False) for c in containers)
                hostpaths = any(v.get("hostPath") for v in spec.get("volumes", [])) if isinstance(spec, dict) else False
                if privileged or hostpaths or event.get("privileged") or event.get("host_path"):
                    alerts.append(self._alert("K8S-001", "CRITICAL", "privilege_escalation",
                        "Workload created with privileged mode or hostPath access", ns, pod, actor,
                        {"privileged": bool(privileged or event.get("privileged")), "hostPath": bool(hostpaths or event.get("host_path"))}, "review_workload_and_node_exposure"))
            if resource in {"secrets", "secret"} and verb in {"list", "get", "watch"}:
                alerts.append(self._alert("K8S-002", "HIGH", "credential_access", "Kubernetes Secret enumeration/access observed", ns, pod, actor, {"verb": verb}, "review_rbac_and_rotate_exposed_credentials"))
            if resource in {"clusterrolebindings", "rolebindings"} and verb in {"create", "update", "patch"} and ("cluster-admin" in str(event).lower() or event.get("role") == "cluster-admin"):
                alerts.append(self._alert("K8S-003", "CRITICAL", "privilege_escalation", "Binding grants cluster-admin privileges", ns, pod, actor, {"verb": verb}, "review_binding_and_revoke_if_unauthorized"))
            if verb == "create" and resource in {"pods/exec", "exec"} and ns in SENSITIVE_NAMESPACES:
                alerts.append(self._alert("K8S-004", "HIGH", "suspicious_execution", "Interactive exec into a sensitive system namespace", ns, pod, actor, {}, "review_session_and_preserve_audit_evidence"))
        elif kind in {"falco", "runtime", "tetragon"}:
            proc = str(event.get("process", event.get("proc_name", ""))).lower()
            filename = str(event.get("file", event.get("filename", "")))
            if proc in {"sh", "bash", "dash", "zsh", "nc", "ncat", "socat"} and (event.get("container") or pod):
                alerts.append(self._alert("RT-001", "HIGH", "suspicious_execution", f"Suspicious process execution: {proc}", ns, pod, actor, {"process": proc}, "isolate_pod_after_operator_approval"))
            if any(x in filename for x in SENSITIVE_FILES):
                alerts.append(self._alert("RT-002", "HIGH", "credential_access", "Sensitive host/container file access", ns, pod, actor, {"file": filename}, "preserve_evidence_and_review_credentials"))
        elif kind in {"vpc_flow", "flow", "hubble"}:
            src = str(event.get("src_ip", "")); dst = str(event.get("dst_ip", "")); dport = int(event.get("dst_port", 0) or 0)
            key = str(event.get("pod_uid") or pod or src)
            bucket = self.flows[key]
            bucket.append((ts, dport, dst, int(event.get("bytes", 0) or 0)))
            while bucket and ts - bucket[0][0] > self.window_seconds: bucket.popleft()
            ports = {x[1] for x in bucket if x[1] > 0}
            if len(ports) >= self.scan_threshold:
                alerts.append(self._alert("NET-001", "HIGH", "reconnaissance", "Pod contacted many destination ports in a short window", ns, pod, actor, {"unique_ports": len(ports), "window_seconds": self.window_seconds}, "quarantine_pod_and_review_flow_logs"))
                # Avoid repeated scan alerts for every subsequent flow in the same burst.
                bucket.clear()
            if dst in self.known_bad_ips:
                alerts.append(self._alert("NET-002", "CRITICAL", "command_and_control", "Outbound connection to configured threat-intelligence indicator", ns, pod, actor, {"destination_ip": dst}, "block_egress_and_investigate_workload"))
            try: external = not ipaddress.ip_address(dst).is_private
            except ValueError: external = False
            if external and int(event.get("bytes", 0) or 0) >= self.external_bytes_threshold:
                alerts.append(self._alert("NET-003", "MEDIUM", "possible_exfiltration", "Large outbound flow to an external address", ns, pod, actor, {"destination_ip": dst, "bytes": int(event.get("bytes", 0))}, "review_data_transfer_and_egress_policy"))
        elif kind in {"guardduty", "guardduty_finding", "eventbridge"}:
            detail = event.get("detail", event)
            finding_type = detail.get("type", detail.get("findingType", "GuardDuty finding"))
            severity_num = float(detail.get("severity", 5) or 5)
            severity = "CRITICAL" if severity_num >= 8 else "HIGH" if severity_num >= 6 else "MEDIUM"
            resource = detail.get("resource", {}) or {}
            eks = resource.get("eksClusterDetails", {}) or {}
            ns = ns or eks.get("nameSpaceName")
            pod = pod or eks.get("kubernetesDetails", {}).get("kubernetesWorkloadDetails", {}).get("name")
            alerts.append(self._alert("AWS-GD", severity, "managed_detection", f"GuardDuty finding: {finding_type}", ns, pod, actor, {"finding_type": finding_type, "severity": severity_num}, "triage_guardduty_finding_and_apply_control_if_confirmed"))
        # Cross-layer correlation: suspicious shell execution followed by a known-bad
        # outbound connection from the same Pod within the configured time window.
        current = self._dedupe(alerts)
        if ns and pod:
            key = f"{ns}/{pod}"
            signal_bucket = self.pod_signals[key]
            for alert in current:
                signal_bucket.append((ts, alert.category, alert.rule_id))
            while signal_bucket and ts - signal_bucket[0][0] > self.window_seconds:
                signal_bucket.popleft()
            categories = {item[1] for item in signal_bucket}
            if "suspicious_execution" in categories and "command_and_control" in categories:
                composite = self._alert("CORR-001", "CRITICAL", "multi_stage_compromise",
                    "Suspicious process execution and known-bad egress observed from the same Pod",
                    ns, pod, actor, {"correlated_rules": [x[2] for x in signal_bucket]},
                    "prioritize_pod_containment_and_incident_response")
                if composite: current.append(composite)
        return current

    def _alert(self, rid, sev, cat, msg, ns, pod, actor, evidence, action):
        key = (rid, ns, pod, actor, json.dumps(evidence, sort_keys=True))
        if key in self.alert_keys: return None
        self.alert_keys.add(key)
        response = {"mode": "recommendation_only", "action": action}
        if ns and pod and rid in {"RT-001", "NET-001", "NET-002"}:
            response["network_policy"] = {"namespace": ns, "pod": pod, "intent": "quarantine"}
        return Alert(rid, sev, cat, msg, ns, pod, actor, evidence, response)

    @staticmethod
    def _dedupe(alerts): return [a for a in alerts if a is not None]

def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip(): yield json.loads(line)

def alert_dict(alert): return asdict(alert)
