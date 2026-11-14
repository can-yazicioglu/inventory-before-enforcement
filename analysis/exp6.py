#!/usr/bin/env python3
"""Exp 6: sensitivity to the sampling unit (1 h, 6 h, 1 day). Usage: exp6.py <inc_dir> <out_dir>"""
import sys, numpy as np, pandas as pd
import os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import gtlib
inc, out = sys.argv[1:3]
rows = []
for gran in ('port', 'svc'):
    for name, expr, per_day in (('1h', 'hr', 24), ('6h', "time_bucket(INTERVAL 6 HOUR, hr)", 4), ('1d', "CAST(hr AS DATE)", 1)):
        acc = {}
        for ds, site, dev, units, types, M, W in gtlib.load_matrices(f'{inc}/inc_hour_{gran}.parquet', gran, unit_col=expr, min_units=10 * per_day):
            S, K = M.shape
            cum = np.cumsum(M, axis=1); first = np.argmax(M, axis=1); nb = np.bincount(first, minlength=K)
            t0 = 7 * per_day
            q1 = (cum[:, t0 - 1:K - 1] == 1).sum(axis=0)             # Q1 after T = t0..K-1 units
            T = np.arange(t0, K)
            a = acc.setdefault(ds, [0.0, 0.0, 0, 0.0])
            a[0] += nb[t0:K].sum(); a[1] += (q1 / T).sum(); a[2] += len(T); a[3] += K / per_day
        for ds, a in acc.items():
            rows.append(dict(gran=gran, unit=name, dataset=ds, ratio_next=a[0] / a[1], new_per_day=a[0] / a[2] * per_day,
                             gt_per_day=a[1] / a[2] * per_day, active_days=a[3]))
o = pd.DataFrame(rows).sort_values(['dataset', 'gran', 'unit']); o.to_csv(f'{out}/unit_sensitivity.csv', index=False)
print(o.round(3).to_string(index=False))

