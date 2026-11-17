import argparse, json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from eksids import EKSIDS, quarantine_policy
from eksids.engine import load_jsonl, alert_dict
p=argparse.ArgumentParser(); p.add_argument('events'); p.add_argument('--out',default=str(ROOT/'results/replay_alerts.json')); a=p.parse_args()
engine=EKSIDS(); alerts=[]
for e in load_jsonl(a.events): alerts += [alert_dict(x) for x in engine.process(e)]
Path(a.out).write_text(json.dumps(alerts,indent=2))
print(json.dumps(alerts,indent=2)); print(f"\n{len(alerts)} alerts -> {a.out}")
