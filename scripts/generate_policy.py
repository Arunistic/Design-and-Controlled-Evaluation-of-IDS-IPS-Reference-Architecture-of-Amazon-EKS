import argparse, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from eksids.policy import quarantine_policy
import yaml
p=argparse.ArgumentParser(description='Generate (do not apply) a scoped Pod quarantine NetworkPolicy')
p.add_argument('--namespace',required=True); p.add_argument('--pod',required=True); p.add_argument('--label',action='append',required=True,help='Verified selector label key=value; repeat for multiple labels')
p.add_argument('--output',default=str(ROOT/'results/quarantine-networkpolicy.yaml'))
a=p.parse_args(); labels={}
for item in a.label:
    if '=' not in item: p.error('--label must be key=value')
    k,v=item.split('=',1); labels[k]=v
policy=quarantine_policy(a.namespace,a.pod,labels)
Path(a.output).write_text(yaml.safe_dump(policy,sort_keys=False))
print(f"Wrote recommendation only: {a.output}\nReview the selector and service impact before applying.")
