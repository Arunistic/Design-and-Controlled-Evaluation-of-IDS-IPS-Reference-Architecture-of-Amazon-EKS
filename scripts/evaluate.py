"""Deterministic controlled event-replay evaluation; not AWS production telemetry."""
import json, random, sys, time, csv
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from eksids import EKSIDS

def make_cases(seed=20261111, n=100):
    r=random.Random(seed); cases=[]
    # Benign Kubernetes operations, normal runtime processes and low-rate service flows.
    # Include 5% authorized-but-risky admin/debug actions to expose rule false positives.
    for i in range(n*4):
        ns=r.choice(['frontend','backend','payments']); pod=f"app-{i}"
        events=[{"kind":"k8s_audit","ts":i,"namespace":ns,"pod":pod,"actor":"system:serviceaccount:app:deployer","verb":"create","resource":"deployments","object":{}}]
        events += [{"kind":"runtime","ts":i+1,"namespace":ns,"pod":pod,"process":r.choice(['python','java','nginx'])}]
        events += [{"kind":"vpc_flow","ts":i+2,"namespace":ns,"pod":pod,"src_ip":"10.0.1.5","dst_ip":"10.0.2.8","dst_port":r.choice([443,5432,6379]),"bytes":r.randint(100,50000)}]
        if i < int(n*4*0.05):
            events = [{"kind":"k8s_audit","ts":i,"namespace":"payments","pod":pod,"actor":"approved-platform-admin","verb":"list","resource":"secrets"}]
        cases.append((False,events))
    # Five attack families. 20% are deliberately telemetry-incomplete/evasive cases.
    for i in range(n):
        if i >= int(n*0.80):
            cases.append((True,[{"kind":"runtime","ts":90000+i,"namespace":"payments","pod":f"attack-{i}","process":"python"}]))
            continue
        pod=f"attack-{i}"; ns="payments"
        attack=r.randrange(5); t=10000+i*100
        if attack==0: # privileged workload / hostPath
            ev={"kind":"k8s_audit","ts":t,"namespace":ns,"pod":pod,"actor":"unknown-user","verb":"create","resource":"pods","privileged":True,"host_path":True}
        elif attack==1: # secret discovery
            ev={"kind":"k8s_audit","ts":t,"namespace":ns,"pod":pod,"actor":"compromised-sa","verb":"list","resource":"secrets"}
        elif attack==2: # shell + sensitive file access
            ev={"kind":"runtime","ts":t,"namespace":ns,"pod":pod,"process":"bash","container":"web"}
        elif attack==3: # port scan burst
            events=[{"kind":"vpc_flow","ts":t+j,"namespace":ns,"pod":pod,"src_ip":"10.0.1.9","dst_ip":"10.0.2.10","dst_port":2000+j,"bytes":200} for j in range(10)]
            cases.append((True,events)); continue
        else: # C2 IOC
            ev={"kind":"vpc_flow","ts":t,"namespace":ns,"pod":pod,"src_ip":"10.0.1.9","dst_ip":"198.51.100.66","dst_port":443,"bytes":4096}
        cases.append((True,[ev]))
    r.shuffle(cases); return cases

def metrics_for(cases, allowed_kinds=None):
    tp=fp=tn=fn=0; lat=[]
    for truth,events in cases:
        engine=EKSIDS(); start=time.perf_counter_ns(); alerts=[]
        selected=[e for e in events if allowed_kinds is None or e.get("kind") in allowed_kinds]
        for e in selected: alerts.extend(engine.process(e))
        lat.append((time.perf_counter_ns()-start)/1e6)
        pred=bool(alerts)
        if truth and pred: tp+=1
        elif truth and not pred: fn+=1
        elif not truth and pred: fp+=1
        else: tn+=1
    precision=tp/(tp+fp) if tp+fp else 0; recall=tp/(tp+fn) if tp+fn else 0
    f1=2*precision*recall/(precision+recall) if precision+recall else 0
    fpr=fp/(fp+tn) if fp+tn else 0
    return {"tp":tp,"fp":fp,"tn":tn,"fn":fn,"precision":precision,"recall":recall,"f1":f1,"false_positive_rate":fpr,"mean_processing_ms_per_case":sum(lat)/len(lat),"p95_processing_ms_per_case":sorted(lat)[int(.95*(len(lat)-1))]}

def main():
    cases=make_cases(); variants={
      "audit_only": {"k8s_audit","audit"},
      "runtime_only": {"runtime","falco","tetragon"},
      "network_only": {"flow","vpc_flow","hubble"},
      "multi_source_fused_rules": None
    }
    comparisons={name:metrics_for(cases,kinds) for name,kinds in variants.items()}
    result={"experiment":"deterministic synthetic event replay","seed":20261111,"benign_cases":400,"attack_cases":100,"attack_families":["privileged_or_hostPath_workload","secret_enumeration","suspicious_shell_execution","port_scan","known_bad_egress"],"comparisons":comparisons,"limitations":"Synthetic controlled replay with authorized-admin false-positive cases and telemetry-incomplete attack cases; not a real AWS GuardDuty benchmark, live EKS deployment, or representative production prevalence."}
    (ROOT/'results/evaluation.json').write_text(json.dumps(result,indent=2))
    with open(ROOT/'results/evaluation.csv','w',newline='') as f:
        w=csv.writer(f); w.writerow(["variant","tp","fp","tn","fn","precision","recall","f1","false_positive_rate","mean_processing_ms_per_case","p95_processing_ms_per_case"])
        for name,m in comparisons.items(): w.writerow([name]+[m[k] for k in ["tp","fp","tn","fn","precision","recall","f1","false_positive_rate","mean_processing_ms_per_case","p95_processing_ms_per_case"]])
    print(json.dumps(result,indent=2))
if __name__=='__main__': main()
