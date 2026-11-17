import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from eksids import EKSIDS, quarantine_policy, suricata_block_rule

def test_privileged_pod_detected():
    e=EKSIDS(); a=e.process({"kind":"k8s_audit","namespace":"payments","pod":"bad","verb":"create","resource":"pods","privileged":True})
    assert a and a[0].rule_id=="K8S-001" and a[0].severity=="CRITICAL"
def test_secret_access_detected():
    a=EKSIDS().process({"kind":"audit","namespace":"payments","verb":"list","resource":"secrets","actor":"sa"})
    assert a and a[0].rule_id=="K8S-002"
def test_scan_detected_after_threshold():
    e=EKSIDS(scan_threshold=5); out=[]
    for i in range(5): out += e.process({"kind":"flow","ts":i,"pod":"p","dst_ip":"10.0.0.2","dst_port":3000+i})
    assert any(x.rule_id=="NET-001" for x in out)
def test_bad_ip_detected():
    a=EKSIDS().process({"kind":"flow","pod":"p","dst_ip":"198.51.100.66","dst_port":443})
    assert a and a[0].rule_id=="NET-002"
def test_benign_event_no_alert():
    assert not EKSIDS().process({"kind":"runtime","pod":"api","process":"python","namespace":"app"})
def test_quarantine_policy_is_scoped_and_deny_all():
    p=quarantine_policy("payments","checkout",{"app":"checkout"})
    assert p['spec']['podSelector']['matchLabels']=={'app':'checkout'}
    assert p['spec']['policyTypes']==['Ingress','Egress']
def test_suricata_export():
    assert 'drop ip' in suricata_block_rule('198.51.100.66')

def test_cross_layer_correlation_escalates_same_pod():
    e=EKSIDS()
    a=e.process({"kind":"runtime","ts":10,"namespace":"payments","pod":"compromised","process":"bash"})
    b=e.process({"kind":"flow","ts":20,"namespace":"payments","pod":"compromised","dst_ip":"198.51.100.66","dst_port":443})
    assert any(x.rule_id=="CORR-001" and x.severity=="CRITICAL" for x in b)
