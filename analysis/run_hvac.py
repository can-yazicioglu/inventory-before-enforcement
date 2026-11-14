#!/usr/bin/env python3
"""HVAC control network (7 days): exploratory analysis with sub-day sampling units.
Usage: run_hvac.py <inc_dir> <out_root>"""
import sys, os, numpy as np, pandas as pd
import os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import gtlib, scores
inc, root = sys.argv[1:3]
for name, expr, minu in (('6h', "time_bucket(INTERVAL 6 HOUR, hr)", 12), ('1h', 'hr', 48)):
    rows = []; P = []
    for gran in ('port', 'svc', 'net'):
        for ds, site, dev, units, types, M, W in gtlib.load_matrices(f'{inc}/inc_hour_{gran}.parquet', gran, unit_col=expr,
                                                                     min_units=minu, where="AND dataset = 'hvac'"):
            for r in gtlib.series(M, W):
                r.update(dataset='hvac_' + name, site=site, device=dev, gran=gran, origin=0, gap=1, span14=14); rows.append(r)
            t = gtlib.halves_perm_test(M, rng=np.random.default_rng(1))
            if t: t.update(gran=gran, device=dev); P.append(t)
    out = f'{root}/res_hvac_{name}'; os.makedirs(out, exist_ok=True)
    s = scores.add_scores(pd.DataFrame(rows)); s.to_parquet(f'{out}/scored.parquet', index=False)
    p = pd.DataFrame(P)
    print(name, 'devices', s.device.nunique(), '| exchangeability excess by gran:',
          p.groupby('gran').apply(lambda d: round(d.obs.sum() / max(d.null_mean.sum(), 1e-9), 2)).to_dict(),
          '| share p<0.05:', p.groupby('gran').p.apply(lambda x: round((x < .05).mean(), 2)).to_dict())
    q = s[s['T'] >= 7]
    d = q.groupby(['gran', 'device']).agg(y=('y1', 'sum'), g=('gt', 'sum'), n=('y1', 'size'), types=('sobs', 'max')).reset_index()
    d['r'] = (d.y + .5) / (d.g + .5)
    print('   median types per host:', d.groupby('gran').types.median().to_dict(), '| median calibration:', d.groupby('gran').r.median().round(2).to_dict(),
          '| new types per unit after T>=7:', (d.groupby('gran').y.sum() / d.groupby('gran').n.sum()).round(3).to_dict())

