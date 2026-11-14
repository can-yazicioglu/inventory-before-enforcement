#!/usr/bin/env python3
"""Exp 1: exchangeability tests and point-estimator calibration. Usage: exp1.py <res_dir> [Tmin]"""
import sys, numpy as np, pandas as pd
import os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import gtlib
res = sys.argv[1]; Tmin = int(sys.argv[2]) if len(sys.argv) > 2 else 7
pd.set_option('display.width', 250)
G = ['proto', 'port', 'svc', 'dom', 'net', 'host']
p = pd.read_parquet(f'{res}/permtest.parquet')
p['ratio'] = p.obs / p.null_mean.clip(lower=0.5)
t = p.groupby(['dataset', 'block', 'gran']).agg(devices=('p', 'size'), obs=('obs', 'sum'), null=('null_mean', 'sum'),
                                               sig05=('p', lambda s: (s < 0.05).mean())).reset_index()
t['excess'] = t.obs / t.null
t['gran'] = pd.Categorical(t.gran, G); t = t.sort_values(['dataset', 'block', 'gran'])
print('Exchangeability test (types first seen in 2nd half: observed vs permuted halves)')
print(t.round(3).to_string(index=False))

s = pd.read_parquet(f'{res}/series.parquet'); s = s[s['T'] >= Tmin].copy()
def ext(h): return np.array([gtlib.chao_ext(T, a, b, h) for T, a, b in zip(s['T'], s.q1, s.q2)])
out = []
for h in (1, 7, 14):
    y = s[f'y{h}'].values; ok = y >= 0
    preds = {'GT': h * s.q1 / s['T'], 'Chao': ext(h), 'DR7': h * s.d7, 'DR14': h * s.d14,
             'GT+B7': ext(h) + h * s.b7 / s.w7, 'GT+B14': ext(h) + h * s.b14 / s.w14}
    for name, pr in preds.items():
        d = pd.DataFrame(dict(dataset=s.dataset, gran=s.gran, y=y, p=np.asarray(pr)))[ok]
        for (ds, g), q in d.groupby(['dataset', 'gran']):
            mu = np.maximum(q.p, 1e-3)
            dev = 2 * np.mean(np.where(q.y > 0, q.y * np.log(q.y / mu), 0) - (q.y - mu))
            out.append(dict(H=h, dataset=ds, gran=g, est=name, n=len(q), ratio=q.y.sum() / max(q.p.sum(), 1e-9),
                            mae=np.abs(q.y - q.p).mean(), dev=dev))
o = pd.DataFrame(out)
for metric in ('ratio', 'dev'):
    for h in (1, 7, 14):
        t = o[o.H == h].pivot_table(index=['dataset', 'gran'], columns='est', values=metric)
        t = t.reindex(columns=['GT', 'Chao', 'DR7', 'DR14', 'GT+B7', 'GT+B14'])
        t = t.reindex([(d, g) for d in ('homes', 'unsw') for g in G if (d, g) in t.index])
        print(f'\n{metric} (actual/predicted if ratio; mean Poisson deviance if dev), horizon {h}, T >= {Tmin}')
        print(t.round(3).to_string())
o.to_csv(f'{res}/exp1_point.csv', index=False)

