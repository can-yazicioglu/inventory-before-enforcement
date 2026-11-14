#!/usr/bin/env python3
"""Consolidated evaluation over learning episodes. Writes CSV tables into <res_dir>/tables.
Usage: eval_all.py <res_dir> [H] [Tmin]"""
import sys, os, numpy as np, pandas as pd
res = sys.argv[1]; H = int(sys.argv[2]) if len(sys.argv) > 2 else 14; Tmin = int(sys.argv[3]) if len(sys.argv) > 3 else 7
out = f'{res}/tables'; os.makedirs(out, exist_ok=True)
G = ['proto', 'port', 'svc', 'svcx', 'dom', 'net', 'host']
s = pd.read_parquet(f'{res}/scored.parquet')
s['gtc'] = s.gt_u95 + (s.gt_pr - s['gt'])
s['gtmax'] = np.maximum(s.gt_u95, s.gt_conf.fillna(np.inf))
s['wshare'] = s.wq1 / s.rec_obs.clip(lower=1)                       # cost-weighted Good-Turing: predicted blocked-record share
s['dev'] = s.site + '/' + s.device
s = s[(s['T'] >= Tmin) & (s[f'y{H}'] >= 0)].copy()
s['rate'] = s[f'y{H}'] / H; s['adr'] = s[f'alertdays{H}'] / H
rng = np.random.default_rng(11)

def boot(d, num, den, B=1000):
    """cluster bootstrap CI of sum(num)/sum(den) over devices"""
    a = d.groupby('dev')[[num, den]].sum().values
    if len(a) < 3: return (np.nan, np.nan)
    idx = rng.integers(0, len(a), (B, len(a)))
    r = a[idx, 0].sum(axis=1) / np.maximum(a[idx, 1].sum(axis=1), 1e-12)
    return tuple(np.quantile(r, [.025, .975]))

# 1. calibration ------------------------------------------------------------------------------------------------
rows = []
for (ds, g), q in s.groupby(['dataset', 'gran']):
    q = q.copy(); r = dict(dataset=ds, gran=g, devices=q.dev.nunique(), episodes=q.groupby(['dev', 'origin']).ngroups, rows=len(q))
    for name, col in (('gt', 'gt'), ('gt_pr', 'gt_pr')):
        q['_p'] = q[col]
        r[f'{name}_next'] = q.y1.sum() / q._p.sum(); lo, hi = boot(q, 'y1', '_p'); r[f'{name}_next_ci'] = f'[{lo:.2f},{hi:.2f}]'
        r[f'{name}_H'] = q.rate.sum() / q._p.sum()
    for name, col in (('ucb', 'gt_u95'), ('gtc', 'gtc'), ('gtmax', 'gtmax'), ('streak', 'streak_u95')):
        ok = q[col].notna()
        r[f'cov_{name}'] = (q.rate[ok] <= q[col][ok]).mean(); r[f'covA_{name}'] = (q.adr[ok] <= q[col][ok]).mean()
    q['_pb'] = q.wshare * q[f'rec{H}']
    r['wgt_ratio'] = q[f'blk{H}'].sum() / max(q._pb.sum(), 1e-9)
    r['blk_share_pct'] = 100 * q[f'blk{H}'].sum() / q[f'rec{H}'].sum()
    q['_pb1'] = q.wshare * q.rec1; r['wgt_ratio_next'] = q.blk1.sum() / max(q._pb1.sum(), 1e-9)
    rows.append(r)
cal = pd.DataFrame(rows); cal['gran'] = pd.Categorical(cal.gran, G); cal = cal.sort_values(['dataset', 'gran'])
cal.to_csv(f'{out}/calibration_H{H}.csv', index=False)

# 2. sequential stopping ----------------------------------------------------------------------------------------
RULES = {'GT point': 'gt', 'GT-UCB': 'gt_u95', 'GT-C': 'gtc', 'GT-max(conf)': 'gtmax', 'quiet streak': 'streak_u95', 'recent rate': 'd14'}
rows = []
for (ds, g), q in s.groupby(['dataset', 'gran']):
    ep = [d.sort_values('T') for _, d in q.groupby(['dev', 'origin'])]
    for eps in (0.1, 0.3, 1.0):
        def add(name, st):
            r = dict(dataset=ds, gran=g, eps=eps, rule=name, episodes=len(ep), stopped=len(st) / len(ep))
            if len(st):
                st = st.assign(v=(st.rate > eps).astype(float), va=(st.adr > eps).astype(float), one=1.0,
                               blk=st[f'blk{H}'], rec=st[f'rec{H}'])
                lo, hi = boot(st, 'v', 'one'); lo2, hi2 = boot(st, 'va', 'one')
                r.update(med_T=st['T'].median(), viol=st.v.mean(), viol_lo=lo, viol_hi=hi, violA=st.va.mean(), violA_lo=lo2,
                         violA_hi=hi2, rate=st.rate.mean(), adr=st.adr.mean(), blk_med_pct=100 * (st.blk / st.rec.clip(lower=1)).median())
            rows.append(r)
        for name, col in RULES.items():
            add(name, pd.concat([d[d[col] <= eps].head(1) for d in ep]))
        for T in (7, 14, 21, 28):
            add(f'fixed {T}', pd.concat([d[d['T'] == T] for d in ep]))
seq = pd.DataFrame(rows); seq['gran'] = pd.Categorical(seq.gran, G); seq.to_csv(f'{out}/sequential_H{H}.csv', index=False)

pd.set_option('display.width', 250)
print(cal[['dataset', 'gran', 'devices', 'episodes', 'gt_next', 'gt_next_ci', 'gt_H', 'gt_pr_next', 'cov_ucb', 'cov_gtc', 'cov_gtmax',
           'covA_ucb', 'covA_gtc', 'wgt_ratio_next', 'blk_share_pct']].round(2).to_string(index=False))
t = seq[(seq.eps == 0.3) & seq.gran.isin(['port', 'svc', 'net']) & seq.rule.isin(['GT-UCB', 'GT-C', 'quiet streak', 'fixed 14', 'fixed 28'])]
t = t.assign(viol=[f'{v:.2f} [{a:.2f},{b:.2f}]' for v, a, b in zip(t.viol, t.viol_lo, t.viol_hi)],
             violA=[f'{v:.2f} [{a:.2f},{b:.2f}]' for v, a, b in zip(t.violA, t.violA_lo, t.violA_hi)])
print(t[['dataset', 'gran', 'rule', 'episodes', 'stopped', 'med_T', 'viol', 'violA', 'rate', 'adr']].round(2).to_string(index=False))

