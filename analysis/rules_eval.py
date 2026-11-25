#!/usr/bin/env python3
"""Two analyses registered on 25 November 2026 (../docs/method.md, points 8 and 10 of the note of that date). Exploratory on the
public data. The frozen rule and the enforcement days of the primary analysis are not changed.

min_k.csv         Minimum of k days. For every enforcement of GT-C, the quiet streak and fixed 14 days at the target 0.3, the list
                  L_k holds the flow types seen on at least k of the first T days (k = 1, 2, 3). L_1 is the primary list.
time_uniform.csv  A bound that is valid at every look. GT-C next to the same rule with the levels of reglib.tu_alpha, at daily
                  and at weekly looks, for the targets 0.1, 0.3 and 1.0.

Columns: stopped = share of learning episodes enforced with H further active days inside the trace, med_T = median enforcement
day, exceed_types = share of enforcements whose rate of new flow types exceeds the target, exceed_once = the same for the
alert-day rate when every flow type outside the list alerts once (k = 1: the primary metric, with its cluster bootstrap interval),
exceed_never = the same when the list is never updated (k = 1: the strict count), list_share = median of |L_k| / |L_1|,
blocked_pct = flow records of the H days whose type is outside the list (median over enforcements and pooled), devices_exceeding
and exact_upper_limit = devices with at least one enforcement that exceeds (alert once) and the Clopper-Pearson limit for that
number of devices. time_uniform.csv adds, against GT-C on the same episodes: also_gtc = enforcements that GT-C enforces as well,
med_delay = median difference of the enforcement days on those.
Usage: rules_eval.py <inc_day.parquet> <res_dir> [H]"""
import sys, os, numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import gtlib, reglib
inc, res = sys.argv[1:3]; H = int(sys.argv[3]) if len(sys.argv) > 3 else 14
s = pd.read_parquet(f'{res}/scored.parquet'); s = s[(s['T'] >= reglib.T_MIN) & (s[f'y{H}'] >= 0)].copy()
GR = [g for g in ('port', 'svc', 'net') if g in set(s.gran)]; s = s[s.gran.isin(GR)]
drift = s.gt_pr - s['gt']                                   # the drift term of GT-C, unchanged
s['gtc'] = s.gt_u95 + drift
s['gtc_tu'] = reglib.tu_first_term(s.q1.values, s['T'].values) + drift
s['gtc_tu7'] = reglib.tu_first_term(s.q1.values, s['T'].values, weekly=True) + drift
EP = ['dataset', 'site', 'device', 'gran', 'origin']
PLAN = {'min_k': dict(eps=(0.3,), ks=(1, 2, 3), rules={'GT-C': 'gtc', 'quiet streak': 'streak_u95', 'fixed 14': None}),
        'time_uniform': dict(eps=(0.1, 0.3, 1.0), ks=(1,), rules={'GT-C': 'gtc', 'GT-C every look, daily': 'gtc_tu',
                                                                  'GT-C every look, weekly': 'gtc_tu7'})}
# enforcement day of every rule in every learning episode: stops[episode][(table, eps, rule)] = (T, alertdays, new types)
stops = {}; n_ep = {}
for key, d in s.groupby(EP, sort=False):
    d = d.sort_values('T'); n_ep[key[0], key[3]] = n_ep.get((key[0], key[3]), 0) + 1
    for table, plan in PLAN.items():
        for eps in plan['eps']:
            for rule, col in plan['rules'].items():
                st = d[d['T'] == 14] if col is None else d[d[col] <= eps].head(1)
                if len(st):
                    stops.setdefault(key, {})[table, eps, rule] = (int(st['T'].iloc[0]), int(st[f'alertdays{H}'].iloc[0]), int(st[f'y{H}'].iloc[0]))
rows = []
for gran in GR:
    for ds, site, dev, units, types, M, W in gtlib.load_matrices(inc, gran):
        K = M.shape[1]
        for o in range(0, max(1, K - 20), 21):               # the learning episodes of run_series3.py
            ep = stops.get((ds, site, dev, gran, o))
            if not ep:
                continue
            keep = M[:, o:].any(axis=1); Mo = M[keep][:, o:]; Wo = W[keep][:, o:]
            for (table, eps, rule), (T, alertdays, y) in ep.items():
                size1 = int(Mo[:, :T].any(axis=1).sum())
                for k in PLAN[table]['ks']:
                    r = reglib.list_outcomes(Mo, Wo, T, H, k)
                    if k == 1:                               # the list of the primary analysis: must agree with the stored series
                        assert r['once_days'] == alertdays and r['new_types'] == y and r['list_size'] == size1, (ds, dev, gran, o, rule)
                    rows.append((table, ds, gran, eps, rule, k, f'{site}/{dev}', o, T, size1, r['list_size'], r['once_days'], r['never_days'],
                                 r['new_types'], r['blocked'], r['total']))
r = pd.DataFrame(rows, columns=['table', 'dataset', 'gran', 'eps', 'rule', 'k', 'dev', 'origin', 'T', 'size1', 'size', 'once', 'never',
                                'new', 'blocked', 'total'])
rng = np.random.default_rng(25)
out = {t: [] for t in PLAN}
for (table, ds, g, eps, rule, k), q in r.groupby(['table', 'dataset', 'gran', 'eps', 'rule', 'k'], sort=False):
    v1 = q.once / H > eps; lo, hi = reglib.boot_share(rng, q.dev, v1)
    d = v1.groupby(q.dev).any(); n, x = len(d), int(d.sum())
    row = dict(dataset=ds, gran=g, eps=eps, rule=rule, k=k, episodes=n_ep[ds, g], stopped=len(q) / n_ep[ds, g], devices=n,
               med_T=q['T'].median(), exceed_types=(q.new / H > eps).mean(), exceed_once=v1.mean(), exceed_once_lo=lo, exceed_once_hi=hi,
               exceed_never=(q.never / H > eps).mean(), mean_once_days=q.once.mean(), mean_never_days=q.never.mean(),
               med_list_size=q['size'].median(), list_share=(q['size'] / q.size1.clip(lower=1)).median(),
               blocked_pct_med=100 * (q.blocked / q.total.clip(lower=1)).median(), blocked_pct_pooled=100 * q.blocked.sum() / max(q.total.sum(), 1),
               devices_exceeding=x, exact_upper_limit=reglib.exact_upper(x, n))
    if table == 'time_uniform':
        ref = r[(r.table == table) & (r.dataset == ds) & (r.gran == g) & (r.eps == eps) & (r.rule == 'GT-C')].set_index(['dev', 'origin'])['T']
        both = q.set_index(['dev', 'origin'])['T'].to_frame('t').join(ref.rename('ref'), how='inner')
        row.update(also_gtc=len(both), med_delay=(both.t - both.ref).median() if len(both) else np.nan)
    out[table].append(row)
# cells in which a rule enforces nothing still get a row
for table, plan in PLAN.items():
    have = {(x['dataset'], x['gran'], x['eps'], x['rule'], x['k']) for x in out[table]}
    for (ds, g), n in n_ep.items():
        for eps in plan['eps']:
            for rule in plan['rules']:
                for k in plan['ks']:
                    if (ds, g, eps, rule, k) not in have:
                        out[table].append(dict(dataset=ds, gran=g, eps=eps, rule=rule, k=k, episodes=n, stopped=0.0, devices=0))
os.makedirs(f'{res}/tables', exist_ok=True); pd.set_option('display.width', 250)
for table, plan in PLAN.items():
    t = pd.DataFrame(out[table]); t['gran'] = pd.Categorical(t.gran, GR); t['rule'] = pd.Categorical(t.rule, list(plan['rules']))
    t = t.sort_values(['dataset', 'gran', 'eps', 'rule', 'k']).reset_index(drop=True)
    t.to_csv(f'{res}/tables/{table}.csv', index=False)
    print(table); print(t.round(3).to_string(index=False))
print('first possible enforcement day without singletons (target: GT-C, every look daily, every look weekly):',
      {eps: (reglib.first_possible_day(eps), reglib.first_possible_day(eps, False), reglib.first_possible_day(eps, True)) for eps in (0.1, 0.3, 1.0)})
