#!/usr/bin/env python3
"""Alert days under an allowlist that is fixed at enforcement and never updated (added in the audit of 24 Nov 2026, exploratory).
The primary metric counts a day as an alert day when a flow type appears that the device has never shown before: every new type
alerts once and is known afterwards. Here a day is an alert day when any flow type outside the list of the first T days appears,
so a new type alerts on every day on which it is used. Same stops as eval_all3.py: target 0.3, T >= 7, H further active days
inside the trace. The table also gives, per cell, the number of devices behind the stops, the number of devices with at least one
exceeding stop (first-seen counting) and the exact upper limit of a two-sided 95 percent interval for that share (Clopper-Pearson),
because the bootstrap interval collapses to a point when no stop exceeds the target.
Usage: fixed_list.py <inc_day.parquet> <res_dir> [H]"""
import sys, os, pandas as pd
from scipy.stats import beta
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import gtlib
inc, res = sys.argv[1:3]; H = int(sys.argv[3]) if len(sys.argv) > 3 else 14; EPS = 0.3
s = pd.read_parquet(f'{res}/scored.parquet'); s = s[(s['T'] >= 7) & (s[f'y{H}'] >= 0)].copy()
GR = [g for g in ('port', 'svc', 'net') if g in set(s.gran)]; s = s[s.gran.isin(GR)]
s['gtc'] = s.gt_u95 + (s.gt_pr - s['gt'])
stops = {}
for key, d in s.groupby(['dataset', 'site', 'device', 'gran', 'origin']):
    d = d.sort_values('T')
    st = {'GT-C': d[d.gtc <= EPS].head(1), 'quiet streak': d[d.streak_u95 <= EPS].head(1), 'fixed 14': d[d['T'] == 14]}
    stops[key] = {k: (int(v['T'].iloc[0]), int(v[f'alertdays{H}'].iloc[0])) for k, v in st.items() if len(v)}
rows = []
for gran in GR:
    for ds, site, dev, units, types, M, W in gtlib.load_matrices(inc, gran):
        K = M.shape[1]
        for o in range(0, max(1, K - 20), 21):
            Mo = M[:, o:]; Mo = Mo[Mo.any(axis=1)]
            for rule, (T, first_seen) in stops.get((ds, site, dev, gran, o), {}).items():
                outside = ~Mo[:, :T].any(axis=1)
                rows.append((ds, gran, rule, f'{site}/{dev}', first_seen, int(Mo[outside, T:T + H].any(axis=0).sum())))
r = pd.DataFrame(rows, columns=['dataset', 'gran', 'rule', 'dev', 'first_seen_days', 'fixed_list_days'])
r['v1'] = r.first_seen_days / H > EPS; r['v2'] = r.fixed_list_days / H > EPS
out = []
for (ds, g, rule), q in r.groupby(['dataset', 'gran', 'rule']):
    d = q.groupby('dev').v1.any(); n, x = len(d), int(d.sum())
    out.append(dict(dataset=ds, gran=g, rule=rule, stops=len(q), devices=n, exceed_first_seen=q.v1.mean(), exceed_fixed_list=q.v2.mean(),
                    mean_first_seen_days=q.first_seen_days.mean(), mean_fixed_list_days=q.fixed_list_days.mean(),
                    devices_exceeding=x, exact_upper_limit=1.0 if x == n else float(beta.ppf(0.975, x + 1, n - x))))
t = pd.DataFrame(out); t['gran'] = pd.Categorical(t.gran, GR); t = t.sort_values(['dataset', 'gran', 'rule'])
os.makedirs(f'{res}/tables', exist_ok=True); t.to_csv(f'{res}/tables/fixed_list_alert.csv', index=False)
pd.set_option('display.width', 250); print(t.round(3).to_string(index=False))
