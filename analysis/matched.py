#!/usr/bin/env python3
"""GT-C at its nominal target against a quiet-streak rule whose length is tuned (in hindsight) to certify the same
share of learning episodes. Paired cluster bootstrap over devices for the difference in violation rate: for the rate of new
flow types (diff_viol) and, since 25 Nov 2026, for the alert-day rate, the primary metric (diffA_viol), on the same bootstrap
samples. The streak length is the one between 5 and 60 days whose share is closest to that of GT-C, the shorter one on a tie.
Usage: matched.py <out.csv> <scored.parquet>..."""
import sys, pandas as pd, numpy as np
pd.set_option('display.width', 250)
rows = []; rng = np.random.default_rng(9)
for path in sys.argv[2:]:
    s = pd.read_parquet(path); s = s[s.gran.isin(['port', 'svc', 'net']) & (s['T'] >= 7) & (s.y14 >= 0)].copy()
    s['gtc'] = s.gt_u95 + (s.gt_pr - s['gt']); s['dev'] = s.site + '/' + s.device; s['rate'] = s.y14 / 14; s['adr'] = s.alertdays14 / 14
    for (ds, g), q in s.groupby(['dataset', 'gran']):
        ep = [d.sort_values('T') for _, d in q.groupby(['dev', 'origin'])]; n = len(ep)
        def stop(fn): return pd.concat([d[fn(d)].head(1) for d in ep])
        a = stop(lambda d: d.gtc <= 0.3); best = None
        for sdays in range(5, 61):
            b = stop(lambda d: d.streak >= sdays)
            if best is None or abs(len(b) - len(a)) < abs(len(best[1]) - len(a)): best = (sdays, b)
        sd, b = best
        devs = sorted(set(q.dev))
        A = a.groupby('dev').agg(v=('rate', lambda x: (x > 0.3).sum()), n=('rate', 'size')).reindex(devs).fillna(0)
        B = b.groupby('dev').agg(v=('rate', lambda x: (x > 0.3).sum()), n=('rate', 'size')).reindex(devs).fillna(0)
        idx = rng.integers(0, len(devs), (3000, len(devs)))
        da = A.v.values[idx].sum(1) / np.maximum(A.n.values[idx].sum(1), 1); db = B.v.values[idx].sum(1) / np.maximum(B.n.values[idx].sum(1), 1)
        AA = a.groupby('dev').agg(v=('adr', lambda x: (x > 0.3).sum()), n=('adr', 'size')).reindex(devs).fillna(0)
        BA = b.groupby('dev').agg(v=('adr', lambda x: (x > 0.3).sum()), n=('adr', 'size')).reindex(devs).fillna(0)
        dA = BA.v.values[idx].sum(1) / np.maximum(BA.n.values[idx].sum(1), 1) - AA.v.values[idx].sum(1) / np.maximum(AA.n.values[idx].sum(1), 1)
        rows.append(dict(dataset=ds, gran=g, episodes=n, gtc_cert=len(a) / n, gtc_viol=(a.rate > 0.3).mean(), gtc_violA=(a.adr > 0.3).mean(),
                         gtc_medT=a['T'].median(), streak_days=sd, streak_cert=len(b) / n, streak_viol=(b.rate > 0.3).mean(),
                         streak_violA=(b.adr > 0.3).mean(), streak_medT=b['T'].median(),
                         diff_viol=(b.rate > 0.3).mean() - (a.rate > 0.3).mean(), diff_lo=np.quantile(db - da, .025), diff_hi=np.quantile(db - da, .975),
                         diffA_viol=(b.adr > 0.3).mean() - (a.adr > 0.3).mean(), diffA_lo=np.quantile(dA, .025), diffA_hi=np.quantile(dA, .975)))
r = pd.DataFrame(rows); r.to_csv(sys.argv[1], index=False); print(r.round(2).to_string(index=False))
