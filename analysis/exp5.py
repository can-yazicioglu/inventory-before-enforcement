#!/usr/bin/env python3
"""Exp 5: fleet (product-level) learning across the 12 homes that run the same device models.
(a) coverage of a held-out home by an allowlist built from k other homes (types and flow records)
(b) Good-Turing with homes as sampling units: predicted vs actual number of types new to a held-out home
(c) residual new-type rate per device-day: solo learning vs fleet learning (all homes share one allowlist)
LAN peers are collapsed to 'lan' so that rules transfer between homes.
Usage: exp5.py <inc_day.parquet> <out_dir>"""
import sys, numpy as np, pandas as pd, duckdb
inc, out = sys.argv[1:3]
pd.set_option('display.width', 250)
rng = np.random.default_rng(5)
con = duckdb.connect()
df = con.execute(f"""SELECT site, device, day, gran,
    regexp_replace(ftype, '@(mac|dev|ip):.*$', '@lan') AS ftype, sum(n) AS n
    FROM read_parquet('{inc}') WHERE dataset = 'homes' AND gran IN ('port', 'net', 'host') GROUP BY ALL""").df()
A, B, C = [], [], []
for (gran, dev), g in df.groupby(['gran', 'device']):
    homes = sorted(g.site.unique())
    if len(homes) < 8: continue
    sets = {h: set(x.ftype) for h, x in g.groupby('site')}
    recs = {h: x.groupby('ftype').n.sum() for h, x in g.groupby('site')}
    for h in homes:
        others = [o for o in homes if o != h]
        for k in (1, 2, 3, 5, 8, len(others)):
            reps = 1 if k == len(others) else 20
            for _ in range(reps):
                sub = rng.choice(others, k, replace=False)
                allow = set().union(*[sets[o] for o in sub])
                cnt = {}
                for o in sub:
                    for t in sets[o]: cnt[t] = cnt.get(t, 0) + 1
                q1 = sum(v == 1 for v in cnt.values())
                new = sets[h] - allow
                r = recs[h]
                A.append(dict(gran=gran, device=dev, k=k, type_cov=1 - len(new) / len(sets[h]),
                              rec_cov=1 - r[r.index.isin(new)].sum() / r.sum(), pred_new=q1 / k, act_new=len(new)))
    # (c) solo vs fleet residual rate by calendar day
    g = g.sort_values('day')
    first_seen_fleet = g.groupby('ftype').day.min()
    for h, x in g.groupby('site'):
        d0 = x.day.min()
        fs_solo = x.groupby('ftype').day.min()
        days = np.sort(x.day.unique())
        ev = days[(days >= d0 + np.timedelta64(8, 'D'))][:-1]
        if len(ev) == 0: continue
        solo = fs_solo[fs_solo.isin(ev)].groupby(fs_solo).size().reindex(ev, fill_value=0)
        # fleet: a type is new to the fleet on day D only if no home saw it before D
        ff = first_seen_fleet.reindex(fs_solo.index)
        fleet_new = fs_solo[(fs_solo == ff) & fs_solo.isin(ev)]
        fleet = fleet_new.groupby(fleet_new).size().reindex(ev, fill_value=0)
        C.append(dict(gran=gran, device=dev, site=h, days=len(ev), solo=solo.sum() / len(ev), fleet=fleet.sum() / len(ev),
                      solo_alert=(solo > 0).mean(), fleet_alert=(fleet > 0).mean()))
a = pd.DataFrame(A); c = pd.DataFrame(C)
cov = a.groupby(['gran', 'k']).agg(type_cov_mean=('type_cov', 'mean'), type_cov_med=('type_cov', 'median'),
                                    rec_cov_med=('rec_cov', 'median'), rec_cov_p10=('rec_cov', lambda x: x.quantile(.1)),
                                    pred_new=('pred_new', 'mean'), act_new=('act_new', 'mean')).reset_index()
cov['gt_ratio'] = cov.act_new / cov.pred_new
cov.to_csv(f'{out}/fleet_coverage.csv', index=False)
print('(a,b) held-out home vs allowlist from k other homes; Good-Turing over homes: actual/predicted new types')
print(cov.round(3).to_string(index=False))
# products reaching 95% median flow-record coverage (MFOF-like) with k = 5 homes
m = a[a.k == 5].groupby(['gran', 'device']).rec_cov.median().reset_index()
print('\nproducts with median record coverage >= 0.95 at k=5:', m.groupby('gran').rec_cov.apply(lambda x: f'{(x >= .95).sum()}/{len(x)}').to_dict())
f = c.groupby('gran').agg(device_homes=('site', 'size'), solo=('solo', 'mean'), fleet=('fleet', 'mean'),
                          solo_alert=('solo_alert', 'mean'), fleet_alert=('fleet_alert', 'mean')).reset_index()
f['reduction'] = f.solo / f.fleet
f.to_csv(f'{out}/fleet_vs_solo.csv', index=False)
print('\n(c) new types per device-day after the first week: solo vs fleet allowlist'); print(f.round(3).to_string(index=False))

