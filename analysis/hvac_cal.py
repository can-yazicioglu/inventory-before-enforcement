#!/usr/bin/env python3
"""Explicit calibration for the HVAC control network (6 h and 1 h sampling units).
Same definition as extra.py part (1): rows T >= 7 with a known next-unit outcome, ratio = realised new types / Good-Turing estimate,
pooled over devices (cluster bootstrap interval) and per device (median over devices with a non-zero estimate, no smoothing).
silent_devices: nodes with a zero estimate and no new type. smoothed_median_old: median of (y + 0.5) / (p + 0.5), the definition the
first report used. Usage: hvac_cal.py <val_dir> <out.csv>"""
import sys, numpy as np, pandas as pd
root, outp = sys.argv[1:3]
rng = np.random.default_rng(2026)
rows = []
for unit in ('6h', '1h'):
    s = pd.read_parquet(f'{root}/res_hvac_{unit}/scored.parquet')
    c = s[(s['T'] >= 7) & (s.y1 >= 0)]
    for g, q in c.groupby('gran'):
        a = q.groupby('device').agg(y=('y1', 'sum'), p=('gt', 'sum'), pc=('gt_pr', 'sum'))
        idx = rng.integers(0, len(a), (4000, len(a)))
        pb = a.y.values[idx].sum(1) / np.maximum(a.p.values[idx].sum(1), 1e-12)
        pos = a[a.p > 0]; r = (pos.y / pos.p).values
        rows.append(dict(unit=unit, gran=g, devices=len(a), pooled=a.y.sum() / a.p.sum(), pooled_lo=np.quantile(pb, .025),
                         pooled_hi=np.quantile(pb, .975), pooled_corrected=a.y.sum() / a.pc.sum(), dev_with_pred=len(pos),
                         dev_median=np.median(r), silent_devices=int(((a.p == 0) & (a.y == 0)).sum()),
                         smoothed_median_old=np.median((a.y + .5) / (a.p + .5)), new_types=int(a.y.sum())))
r = pd.DataFrame(rows); r.to_csv(outp, index=False)
pd.set_option('display.width', 250); print(r.round(3).to_string(index=False))
