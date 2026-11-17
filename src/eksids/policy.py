"""Generate a scoped quarantine NetworkPolicy; never apply it automatically."""
import yaml

def quarantine_policy(namespace: str, pod: str, labels: dict[str, str] | None = None):
    if not namespace or not pod: raise ValueError("namespace and pod are required")
    # The operator must ensure the target label uniquely identifies the intended workload.
    if not labels:
        raise ValueError("provide verified labels that uniquely select the target Pod/workload")
    selector = labels
    return {
      "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
      "metadata": {"name": "incident-quarantine", "namespace": namespace,
                   "labels": {"app.kubernetes.io/managed-by": "eksids-reference"}},
      "spec": {"podSelector": {"matchLabels": selector},
               "policyTypes": ["Ingress", "Egress"]}
    }

def suricata_block_rule(ip: str, sid: int = 9000001):
    return f"drop ip any any -> {ip} any (msg:\"EKSIDS threat-intel egress block\"; sid:{sid}; rev:1;)"
