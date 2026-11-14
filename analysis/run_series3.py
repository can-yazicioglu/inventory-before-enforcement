#!/usr/bin/env python3
"""Compute estimator inputs, outcomes and exchangeability tests for every device and granularity.
Usage: run_series.py <inc_day.parquet> <out_dir>"""
import sys, numpy as np, pandas as pd
import os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gtlib

inc, out = sys.argv[1:3]
rng = np.random.default_rng(7)
STEP = 21
S_rows, P_rows = [], []
import os
GRANS = tuple(os.environ.get('GT_GRANS', 'proto,port,svc,dom,net,host').split(','))
for gran in GRANS:
    for ds, site, dev, units, types, M, W in gtlib.load_matrices(inc, gran):
        K = M.shape[1]
        U = pd.to_datetime(pd.Series(units)).reset_index(drop=True)
        for o in range(0, max(1, K - 20), STEP):          # rolling origins: a fresh learning episode every STEP days
            Mo = M[:, o:]; keep = Mo.any(axis=1)
            for r in gtlib.series(Mo[keep], W[keep][:, o:]):
                T = r['T']
                r.update(dataset=ds, site=site, device=dev, gran=gran, origin=o,
                         gap=int((U[o + T] - U[o + T - 1]).days),                       # calendar days since the previous active day
                         span14=int((U[min(o + T + 13, K - 1)] - U[o + T]).days) + 1)   # calendar span of the next 14 active days
                S_rows.append(r)
        for block in (1, 7):
            t = gtlib.halves_perm_test(M, rng=rng, block=block)
            if t:
                t.update(dataset=ds, site=site, device=dev, gran=gran, block=block, K=M.shape[1]); P_rows.append(t)
    print(gran, len(S_rows), flush=True)
pd.DataFrame(S_rows).to_parquet(f'{out}/series.parquet', index=False)
pd.DataFrame(P_rows).to_parquet(f'{out}/permtest.parquet', index=False)

