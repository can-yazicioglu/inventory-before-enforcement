#!/usr/bin/env python3
"""Replication within one site: the same frozen analysis on two consecutive parts of one recording, side by side
(registered on 25 November 2026, ../docs/method.md, point 11 of that note). Part 2 is analysed as if it were a new recording.
On the public traces this is a trial of the procedure and exploratory. Target 0.3, the 14 active days after enforcement.

halves_table.csv    per dataset, level and rule (GT-C, quiet streak, fixed 14 days), for each part: episodes, share enforced,
                    median enforcement day, exceedance shares (alert-day rate = primary metric, rate of new flow types, list never
                    updated), devices and exact upper limit, and the calibration ratio of the part (per-device median and pooled).
                    diffA = alert-day exceedance of part 2 minus part 1 over the devices present in both parts, with a paired
                    cluster bootstrap interval. dev_both = number of those devices.
halves_devices.csv  per dataset and level: did GT-C enforce in the first learning episode of each part (two-by-two table over the
                    devices with a first episode in both parts), and the difference of the enforcement days where it did in both.
halves_ageing.csv   how a list ages: for every device that GT-C enforced in the first episode of part 1, the list of that day is
                    kept and judged on the active days of part 2 (all of them, and the first 14), in two countings: never updated
                    (a day counts if any flow type outside the list appears) and alert once (a day counts if a flow type appears
                    that the device has not shown since the start of part 1).
Usage: halves.py <part1 dir> <part2 dir> <out dir>     (each part dir holds inc_day.parquet and res/ as written by run_sens.sh)"""
import sys, os, numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import gtlib, reglib
P = sys.argv[1:3]; out = sys.argv[3]; EPS = 0.3; H = 14
RULES = ['GT-C', 'quiet streak', 'fixed 14']; GR_ALL = ['port', 'svc', 'net']
rng = np.random.default_rng(1125)


def load(p):
    s = pd.read_parquet(f'{p}/res/scored.parquet'); s = s[s.gran.isin(GR_ALL)].copy()
    s['gtc'] = s.gt_u95 + (s.gt_pr - s['gt']); s['dev'] = s.site + '/' + s.device
    e = s[(s['T'] >= reglib.T_MIN) & (s[f'y{H}'] >= 0)].copy(); e['rate'] = e[f'y{H}'] / H; e['adr'] = e[f'alertdays{H}'] / H
    stops = []
    for (ds, g, dev, o), d in e.groupby(['dataset', 'gran', 'dev', 'origin'], sort=False):
        d = d.sort_values('T')
        for rule, st in (('GT-C', d[d.gtc <= EPS].head(1)), ('quiet streak', d[d.streak_u95 <= EPS].head(1)), ('fixed 14', d[d['T'] == 14])):
            stops.append((ds, g, rule, dev, o, int(st['T'].iloc[0]) if len(st) else -1, float(st.adr.iloc[0] > EPS) if len(st) else np.nan))
    stops = pd.DataFrame(stops, columns=['dataset', 'gran', 'rule', 'dev', 'origin', 'T', 'va'])
    tab = pd.read_csv(f'{p}/res/tables/sequential_H{H}.csv'); tab = tab[(tab.eps == EPS) & tab.rule.isin(RULES) & tab.gran.isin(GR_ALL)]
    fx = pd.read_csv(f'{p}/res/tables/fixed_list_alert.csv'); cal = pd.read_csv(f'{p}/res/tables/calibration_explicit.csv')
    return dict(stops=stops, tab=tab, fx=fx, cal=cal, inc=f'{p}/inc_day.parquet')


A, B = load(P[0]), load(P[1])
# 1. side by side --------------------------------------------------------------------------------------------------------------
rows = []
for (ds, g, rule), q1 in A['stops'].groupby(['dataset', 'gran', 'rule'], sort=False):
    q2 = B['stops'][(B['stops'].dataset == ds) & (B['stops'].gran == g) & (B['stops'].rule == rule)]
    row = dict(dataset=ds, gran=g, rule=rule)
    for n, part in (('1', A), ('2', B)):
        t = part['tab'][(part['tab'].dataset == ds) & (part['tab'].gran == g) & (part['tab'].rule == rule)]
        f = part['fx'][(part['fx'].dataset == ds) & (part['fx'].gran == g) & (part['fx'].rule == rule)]
        c = part['cal'][(part['cal'].dataset == ds) & (part['cal'].gran == g)]
        if len(t):
            row.update({f'episodes{n}': int(t.episodes.iloc[0]), f'stopped{n}': t.stopped.iloc[0], f'med_T{n}': t.med_T.iloc[0],
                        f'violA{n}': t.violA.iloc[0], f'violA_lo{n}': t.violA_lo.iloc[0], f'violA_hi{n}': t.violA_hi.iloc[0], f'viol{n}': t.viol.iloc[0]})
        if len(f):
            row.update({f'strict{n}': f.exceed_fixed_list.iloc[0], f'devices{n}': int(f.devices.iloc[0]), f'upper{n}': f.exact_upper_limit.iloc[0]})
        if len(c):
            row.update({f'cal_dev_median{n}': c.dev_median.iloc[0], f'cal_pooled{n}': c.pooled.iloc[0]})
    devs = sorted(set(q1.dev) & set(q2.dev)); row['dev_both'] = len(devs)
    if len(devs) >= 3:
        a = q1[q1.dev.isin(devs) & (q1['T'] >= 0)].groupby('dev').va.agg(['sum', 'size']).reindex(devs).fillna(0).values
        b = q2[q2.dev.isin(devs) & (q2['T'] >= 0)].groupby('dev').va.agg(['sum', 'size']).reindex(devs).fillna(0).values
        share = lambda m: m[:, 0].sum() / m[:, 1].sum() if m[:, 1].sum() else np.nan
        idx = rng.integers(0, len(devs), (3000, len(devs)))
        d = b[idx, 0].sum(1) / np.maximum(b[idx, 1].sum(1), 1e-12) - a[idx, 0].sum(1) / np.maximum(a[idx, 1].sum(1), 1e-12)
        ok = (a[idx, 1].sum(1) > 0) & (b[idx, 1].sum(1) > 0)
        row.update(violA1_both=share(a), violA2_both=share(b), diffA=share(b) - share(a),
                   diffA_lo=np.quantile(d[ok], .025) if ok.any() else np.nan, diffA_hi=np.quantile(d[ok], .975) if ok.any() else np.nan)
    rows.append(row)
t = pd.DataFrame(rows); t['gran'] = pd.Categorical(t.gran, GR_ALL); t['rule'] = pd.Categorical(t.rule, RULES)
t = t.sort_values(['dataset', 'gran', 'rule']).reset_index(drop=True)
os.makedirs(out, exist_ok=True); t.to_csv(f'{out}/halves_table.csv', index=False)
pd.set_option('display.width', 250); pd.set_option('display.max_columns', 60)
print('1. the two parts side by side'); print(t.round(3).to_string(index=False))

# 2. per device: the first learning episode of each part -----------------------------------------------------------------------
rows = []
f1 = A['stops'][(A['stops'].rule == 'GT-C') & (A['stops'].origin == 0)]; f2 = B['stops'][(B['stops'].rule == 'GT-C') & (B['stops'].origin == 0)]
for (ds, g), q1 in f1.groupby(['dataset', 'gran'], sort=False):
    m = q1[['dev', 'T']].merge(f2[(f2.dataset == ds) & (f2.gran == g)][['dev', 'T']], on='dev', suffixes=('1', '2'))
    e1, e2 = m.T1 >= 0, m.T2 >= 0; both = m[e1 & e2]; d = (both.T2 - both.T1).values
    rows.append(dict(dataset=ds, gran=g, devices=len(m), both=int((e1 & e2).sum()), only_part1=int((e1 & ~e2).sum()), only_part2=int((~e1 & e2).sum()),
                     neither=int((~e1 & ~e2).sum()), agree=((e1 == e2).mean() if len(m) else np.nan),
                     day_diff_median=np.median(d) if len(d) else np.nan, day_diff_q25=np.quantile(d, .25) if len(d) else np.nan,
                     day_diff_q75=np.quantile(d, .75) if len(d) else np.nan))
dv = pd.DataFrame(rows); dv['gran'] = pd.Categorical(dv.gran, GR_ALL); dv = dv.sort_values(['dataset', 'gran']).reset_index(drop=True)
dv.to_csv(f'{out}/halves_devices.csv', index=False)
print('\n2. GT-C in the first learning episode of each part, per device'); print(dv.round(3).to_string(index=False))

# 3. how the list of part 1 ages over part 2 -----------------------------------------------------------------------------------
rows = []
grans = [g for g in GR_ALL if g in set(A['stops'].gran)]
for gran in grans:
    T1 = {(ds, dev): T for ds, dev, T in zip(f1[f1.gran == gran].dataset, f1[f1.gran == gran].dev, f1[f1.gran == gran]['T']) if T >= 0}
    m1 = {(ds, f'{site}/{dev}'): (types, M) for ds, site, dev, units, types, M, W in gtlib.load_matrices(A['inc'], gran)}
    for ds, site, dev, units, types2, M2, W2 in gtlib.load_matrices(B['inc'], gran, min_units=1):
        key = (ds, f'{site}/{dev}')
        if key not in T1 or key not in m1:
            continue
        types1, M1 = m1[key]; T = T1[key]
        on_list = set(types1[M1[:, :T].any(axis=1)]); known = set(types1[M1.any(axis=1)]) | on_list
        never = np.array([bool(set(types2[M2[:, j]]) - on_list) for j in range(M2.shape[1])])
        once = np.zeros(M2.shape[1], dtype=bool)
        for j in range(M2.shape[1]):
            new = set(types2[M2[:, j]]) - known; once[j] = bool(new); known |= new
        K2 = M2.shape[1]; h = min(H, K2)
        rows.append((ds, gran, key[1], T, len(on_list), K2, never.mean(), once.mean(), never[:h].mean(), once[:h].mean()))
ag = pd.DataFrame(rows, columns=['dataset', 'gran', 'dev', 'T1', 'list_size', 'days2', 'never_rate', 'once_rate', 'never_rate14', 'once_rate14'])
rows = []
for (ds, g), q in ag.groupby(['dataset', 'gran'], sort=False):
    rows.append(dict(dataset=ds, gran=g, devices=len(q), med_days2=q.days2.median(), never_rate_mean=q.never_rate.mean(), never_rate_median=q.never_rate.median(),
                     never_over_target=(q.never_rate > EPS).mean(), once_rate_mean=q.once_rate.mean(), once_rate_median=q.once_rate.median(),
                     once_over_target=(q.once_rate > EPS).mean(), never14_over_target=(q.never_rate14 > EPS).mean(),
                     once14_over_target=(q.once_rate14 > EPS).mean()))
a = pd.DataFrame(rows)
if len(a):
    a['gran'] = pd.Categorical(a.gran, GR_ALL); a = a.sort_values(['dataset', 'gran']).reset_index(drop=True)
a.to_csv(f'{out}/halves_ageing.csv', index=False)
print('\n3. the list that GT-C enforced in part 1, judged on the active days of part 2'); print(a.round(3).to_string(index=False))
