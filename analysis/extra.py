#!/usr/bin/env python3
"""Extra analyses added in the 12 Nov 2026 audit. No change to the frozen method: these only describe it better.
(1) calibration with an explicit definition (pooled, per-device, reliability bins)
(2) risk-coverage curves: each rule's score is thresholded at many values and judged against one fixed target
(3) paired cluster-bootstrap difference GT-C vs fixed 14 on the same episodes
Usage: extra.py <res_dir> [H]"""
import sys, os, numpy as np, pandas as pd
res = sys.argv[1]; H = int(sys.argv[2]) if len(sys.argv) > 2 else 14
out = f'{res}/tables'; os.makedirs(out, exist_ok=True)
pd.set_option('display.width', 250)
s = pd.read_parquet(f'{res}/scored.parquet')
s['gtc'] = s.gt_u95 + (s.gt_pr - s['gt']); s['dev'] = s.site + '/' + s.device
GR = [g for g in ('port', 'svc', 'svcx', 'net') if g in set(s.gran)]
s = s[s.gran.isin(GR)]
rng = np.random.default_rng(2026)

# (1) calibration -------------------------------------------------------------------------------------------------
# Rows: origin 0 only (each device-day counted once), T >= 7, next-day outcome known.
c = s[(s.origin == 0) & (s['T'] >= 7) & (s.y1 >= 0)]
rows = []
for (ds, g), q in c.groupby(['dataset', 'gran']):
    a = q.groupby('dev').agg(y=('y1', 'sum'), p=('gt', 'sum'), pc=('gt_pr', 'sum'), n=('y1', 'size'))
    idx = rng.integers(0, len(a), (4000, len(a)))
    pooled = a.y.sum() / a.p.sum(); pb = a.y.values[idx].sum(1) / a.p.values[idx].sum(1)
    pooled_c = a.y.sum() / a.pc.sum()
    pos = a[a.p > 0]; r = (pos.y / pos.p).values; rc = (pos.y / pos.pc).values
    j = rng.integers(0, len(r), (4000, len(r))); mb = np.median(r[j], axis=1)
    rows.append(dict(dataset=ds, gran=g, devices=len(a), rows=len(q), pooled=pooled, pooled_lo=np.quantile(pb, .025), pooled_hi=np.quantile(pb, .975),
                     pooled_corrected=pooled_c, dev_with_pred=len(pos), dev_median=np.median(r), dev_med_lo=np.quantile(mb, .025),
                     dev_med_hi=np.quantile(mb, .975), dev_q25=np.quantile(r, .25), dev_q75=np.quantile(r, .75),
                     dev_median_corrected=np.median(rc), share_dev_over1=(r > 1).mean(),
                     zero_pred_devices=int((a.p == 0).sum()), zero_pred_with_new=int(((a.p == 0) & (a.y > 0)).sum())))
cal = pd.DataFrame(rows); cal.to_csv(f'{out}/calibration_explicit.csv', index=False)
print('(1) calibration, origin 0, T>=7: pooled = sum(actual)/sum(predicted); dev_median over devices with a non-zero prediction')
print(cal.round(2).to_string(index=False))
rows = []
bins = [0, 1e-9, 0.1, 0.3, 1.0, 3.0, 1e9]; lab = ['0', '(0,0.1]', '(0.1,0.3]', '(0.3,1]', '(1,3]', '>3']
for (ds, g), q in c.groupby(['dataset', 'gran']):
    b = pd.cut(q['gt'], bins, labels=lab, right=True, include_lowest=True)
    for k, x in q.groupby(b, observed=True):
        rows.append(dict(dataset=ds, gran=g, bin=k, rows=len(x), devices=x.dev.nunique(), predicted=x['gt'].mean(), actual=x.y1.mean(),
                         actual_corrected_pred=x.gt_pr.mean()))
rel = pd.DataFrame(rows); rel.to_csv(f'{out}/reliability_bins.csv', index=False)
print('\nreliability by predicted-rate bin (mean predicted vs mean actual new types next day)')
print(rel[rel.gran.isin(['svc', 'net'])].round(3).to_string(index=False))

# (2) risk-coverage ---------------------------------------------------------------------------------------------
e = s[(s['T'] >= 7) & (s[f'y{H}'] >= 0)].copy()
e['rate'] = e[f'y{H}'] / H; e['adr'] = e[f'alertdays{H}'] / H
SC = {'GT-C': 'gtc', 'GT-UCB': 'gt_u95', 'GT point': 'gt', 'quiet streak': 'streak_u95', 'recent rate': 'd14'}
TH = [0.05, 0.075, 0.1, 0.15, 0.2, 0.25, 0.3, 0.4, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0]
rows = []
for (ds, g), q in e.groupby(['dataset', 'gran']):
    ep = [d.sort_values('T') for _, d in q.groupby(['dev', 'origin'])]
    for target in (0.3, 1.0):
        for name, col in SC.items():
            for th in TH:
                st = pd.concat([d[d[col] <= th].head(1) for d in ep])
                rows.append(dict(dataset=ds, gran=g, target=target, rule=name, theta=th, episodes=len(ep), certified=len(st) / len(ep),
                                 med_T=st['T'].median() if len(st) else np.nan,
                                 viol=(st.rate > target).mean() if len(st) else np.nan, violA=(st.adr > target).mean() if len(st) else np.nan,
                                 bad_share=(st.rate > target).sum() / len(ep)))
        for T in (7, 10, 14, 21, 28, 35, 42, 56):
            st = pd.concat([d[d['T'] == T] for d in ep])
            if len(st):
                rows.append(dict(dataset=ds, gran=g, target=target, rule='fixed', theta=T, episodes=len(ep), certified=len(st) / len(ep), med_T=T,
                                 viol=(st.rate > target).mean(), violA=(st.adr > target).mean(), bad_share=(st.rate > target).sum() / len(ep)))
rc = pd.DataFrame(rows); rc.to_csv(f'{out}/risk_coverage_H{H}.csv', index=False)
print('\n(2) risk-coverage at target 0.3/day: certified share -> violation (type rate) for each rule threshold')
for (ds, g), q in rc[rc.target == 0.3].groupby(['dataset', 'gran']):
    p = q[q.rule != 'fixed'].pivot_table(index='theta', columns='rule', values=['certified', 'viol'])
    print(f'\n{ds} / {g}'); print(p.round(2).to_string())
    print(q[q.rule == 'fixed'][['theta', 'certified', 'viol', 'violA']].round(2).to_string(index=False))

# (3) paired difference GT-C vs fixed 14 on episodes where both fire --------------------------------------------
rows = []
for (ds, g), q in e.groupby(['dataset', 'gran']):
    recs = []
    for (dev, o), d in q.groupby(['dev', 'origin']):
        d = d.sort_values('T'); a = d[d.gtc <= 0.3].head(1); b = d[d['T'] == 14]
        recs.append(dict(dev=dev, a=len(a), b=len(b), va=float((a.rate > 0.3).any()), vb=float((b.rate > 0.3).any()),
                         aa=float((a.adr > 0.3).any()), ab=float((b.adr > 0.3).any())))
    r = pd.DataFrame(recs); both = r[(r.a == 1) & (r.b == 1)]; only_b = r[(r.a == 0) & (r.b == 1)]
    rows.append(dict(dataset=ds, gran=g, episodes=len(r), gtc_certified=int(r.a.sum()), fixed14=int(r.b.sum()), both=len(both),
                     fixed14_viol_where_gtc_certified=both.vb.mean(), gtc_viol_same=both.va.mean(),
                     fixed14_viol_where_gtc_refused=only_b.vb.mean() if len(only_b) else np.nan, n_refused=len(only_b),
                     fixed14_violA_where_gtc_refused=only_b.ab.mean() if len(only_b) else np.nan))
pr = pd.DataFrame(rows); pr.to_csv(f'{out}/paired_gtc_fixed14.csv', index=False)
print('\n(3) fixed 14 days judged separately on the episodes GT-C certified and on those it refused (type-rate violations, target 0.3)')
print(pr.round(2).to_string(index=False))
