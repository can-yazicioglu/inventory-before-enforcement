#!/usr/bin/env python3
"""Independent checks: (1) simulation of Proposition 1 under exchangeable days with dependent, heterogeneous types,
(2) brute-force recount of estimator inputs and outcomes for random real devices.
Usage: verify.py [inc_day.parquet] [series.parquet]"""
import sys, numpy as np, pandas as pd, duckdb
import os; DATA = os.environ.get('IBE_DATA', 'data')
import os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import gtlib
rng = np.random.default_rng(42)
# (1) days i.i.d. given latent type rates; types correlated through a daily "mode" (dependence across types is allowed)
S, K, R = 400, 41, 4000
p = rng.beta(0.15, 3.0, S)                                  # heavy-tailed type frequencies, many rare types
num = np.zeros(K); den = np.zeros(K); den_exact = np.zeros(K)
for _ in range(R):
    mode = rng.random(K) < 0.3                               # on "mode" days rare types are three times as likely
    P = np.minimum(1, p[:, None] * np.where(mode, 3.0, 1.0)[None, :])
    M = rng.random((S, K)) < P
    cum = np.cumsum(M, axis=1); first = np.where(M.any(axis=1), np.argmax(M, axis=1), K)
    for T in (5, 10, 20, 40):
        num[T] += (first == T).sum(); den[T] += (cum[:, T - 1] == 1).sum() / T; den_exact[T] += (cum[:, T] == 1).sum() / (T + 1)
for T in (5, 10, 20, 40):
    print(f'sim T={T}: E[N_T+1]={num[T]/R:.4f}  E[Q1(T+1)]/(T+1)={den_exact[T]/R:.4f}  E[Q1(T)]/T={den[T]/R:.4f}  ratio={num[T]/den[T]:.3f}')
# (2) brute force on real data
con = duckdb.connect()
inc = sys.argv[1] if len(sys.argv) > 1 else DATA + '/v3/inc_base/inc_day.parquet'
s = pd.read_parquet(sys.argv[2] if len(sys.argv) > 2 else DATA + '/v3/res_base/series.parquet'); s = s[s.origin == 0]
bad = 0; n = 0
keys = s[['site', 'device', 'gran']].drop_duplicates().sample(12, random_state=1)
for site, dev, gran in keys.itertuples(index=False):
    d = con.execute(f"SELECT day, ftype, n FROM read_parquet('{inc}') WHERE site='{site}' AND device='{dev}' AND gran='{gran}'").df()
    days = sorted(d.day.unique())[1:-1]; sets = [set(d[d.day == x].ftype) for x in days]
    rows = s[(s.site == site) & (s.device == dev) & (s.gran == gran)].set_index('T')
    for T in rng.choice(rows.index.values, 4):
        cnt = {}
        for x in sets[:T]:
            for t in x: cnt[t] = cnt.get(t, 0) + 1
        q1 = sum(v == 1 for v in cnt.values()); new = len(sets[T] - set(cnt))
        y14 = len(set().union(*sets[T:T + 14]) - set(cnt)) if T + 14 <= len(days) else -1
        r = rows.loc[T]; n += 1
        if (q1, new, y14, len(cnt)) != (r.q1, r.y1, r.y14, r.sobs): bad += 1; print('MISMATCH', site, dev, gran, T, (q1, new, y14, len(cnt)), (r.q1, r.y1, r.y14, r.sobs))
print(f'brute-force checks: {n}, mismatches: {bad}')

