#!/usr/bin/env python3
"""Alert-day analogue of Proposition 1 (added in the 12 Nov 2026 audit, exploratory, not part of the frozen rule).
D(T) = number of the first T days that carry at least one type seen on no other of those days.
Under exchangeable days: P(new type on day T+1) = E[D(T+1)]/(T+1) <= E[D(T)]/T, and the finite-sample prediction bound
P(new type on day T+1) <= (D(T)+1)/(T+1) holds without any independence between types.
Outputs calibration of D/T against realised alert days, and coverage of the conformal count bound.
Usage: alertday.py <inc_day.parquet> <out.csv>"""
import sys, collections, math
import duckdb, numpy as np, pandas as pd
inc, outp = sys.argv[1:3]
con = duckdb.connect()
rows = con.execute(f"SELECT dataset, site, device, gran, day, ftype FROM read_parquet('{inc}') WHERE gran IN ('port','svc','net') GROUP BY ALL").fetchall()
by = collections.defaultdict(lambda: collections.defaultdict(set))
for ds, site, dev, gran, day, ft in rows: by[(ds, gran, site, dev)][day].add(ft)
out = []
for (ds, gran, site, dev), dd in by.items():
    days = sorted(dd)[1:-1]
    if len(days) < 10: continue
    sets = [dd[d] for d in days]; K = len(sets)
    count = collections.Counter(); owner = {}           # type -> index of its only day while it is a singleton
    uniq = collections.Counter()                         # day index -> number of types unique to that day so far
    for i, s in enumerate(sets):
        if i >= 7:                                       # prediction for day i from the first T = i days
            T = i
            n_new = sum(1 for t in s if count[t] == 0)
            D = sum(1 for v in uniq.values() if v > 0); q1 = sum(uniq.values())
            sc = sorted([uniq.get(j, 0) for j in range(T)])
            k = math.ceil(0.9 * (T + 1))
            conf90 = sc[k - 1] if k <= T else np.inf     # conformal 90% upper prediction bound for the count of new types
            out.append((ds, gran, f'{site}/{dev}', T, n_new, int(n_new > 0), D, q1, D / T, (D + 1) / (T + 1), q1 / T, conf90))
        for t in s:
            c = count[t]
            if c == 0: owner[t] = i; uniq[i] += 1
            elif c == 1: uniq[owner[t]] -= 1; del owner[t]
            count[t] = c + 1
df = pd.DataFrame(out, columns=['dataset', 'gran', 'dev', 'T', 'new', 'alert', 'D', 'q1', 'pa', 'pa_bound', 'gt', 'conf90'])
df.to_parquet(outp.replace('.csv', '.parquet'), index=False)
rng = np.random.default_rng(5)
res = []
for (ds, g), q in df.groupby(['dataset', 'gran']):
    a = q.groupby('dev').agg(al=('alert', 'sum'), pa=('pa', 'sum'), pb=('pa_bound', 'sum'), y=('new', 'sum'), g=('gt', 'sum'), n=('alert', 'size'))
    idx = rng.integers(0, len(a), (4000, len(a)))
    r = a.al.values[idx].sum(1) / a.pa.values[idx].sum(1); r2 = a.y.values[idx].sum(1) / a.g.values[idx].sum(1)
    fin = np.isfinite(q.conf90)
    res.append(dict(dataset=ds, gran=g, devices=len(a), rows=len(q), alert_rate=q.alert.mean(), pred_alert=q.pa.mean(),
                    ratio_alert=a.al.sum() / a.pa.sum(), ra_lo=np.quantile(r, .025), ra_hi=np.quantile(r, .975),
                    ratio_alert_vs_bound=a.al.sum() / a.pb.sum(),
                    ratio_types=a.y.sum() / a.g.sum(), rt_lo=np.quantile(r2, .025), rt_hi=np.quantile(r2, .975),
                    conf90_cover=(q.new[fin] <= q.conf90[fin]).mean(), conf90_rows=int(fin.sum()),
                    conf90_zero_share=(q.conf90[fin] == 0).mean()))
r = pd.DataFrame(res); r.to_csv(outp, index=False)
pd.set_option('display.width', 250); print(r.round(3).to_string(index=False))
