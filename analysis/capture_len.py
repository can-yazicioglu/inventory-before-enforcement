#!/usr/bin/env python3
"""How long must a capture be before the frozen primary metric can be evaluated at all?
Each device's first learning episode is cut to its first `units` active days. An episode is evaluable when GT-C
(target 0.3) fires early enough to leave H further days inside the capture.
Usage: capture_len.py <out.csv> <scored.parquet>..."""
import sys, pandas as pd, numpy as np
pd.set_option('display.width', 250)
rows = []
for path in sys.argv[2:]:
    s = pd.read_parquet(path); s = s[(s.origin == 0) & s.gran.isin(['port', 'svc', 'net']) & (s['T'] >= 7)].copy()
    s['gtc'] = s.gt_u95 + (s.gt_pr - s['gt']); s['dev'] = s.site + '/' + s.device
    for (ds, g), q in s.groupby(['dataset', 'gran']):
        K = q.groupby('dev').K.first(); first = q[q.gtc <= 0.3].groupby('dev')['T'].min().reindex(K.index)
        for cap in (20, 24, 28, 35, 42):
            ok = K >= cap
            if ok.sum() < 5: continue
            f = first[ok]
            rows.append(dict(dataset=ds, gran=g, units=cap, devices=int(ok.sum()), certified_by_end=(f <= cap - 1).mean(),
                             evaluable_H14=(f <= cap - 14).mean(), evaluable_H7=(f <= cap - 7).mean()))
r = pd.DataFrame(rows); r.to_csv(sys.argv[1], index=False)
print(r.pivot_table(index=['dataset', 'gran'], columns='units', values=['evaluable_H14', 'evaluable_H7']).round(2).to_string())
