#!/usr/bin/env python3
"""One table for the unit analyses registered on 25 November 2026: the primary analysis next to the same analysis without
partial recording days and on weekdays only (../docs/method.md, points 6 and 7 of that note). Target 0.3, the 14 active days
after enforcement, rules GT-C, quiet streak and fixed 14 days, levels port, svc and net. Only stored tables are read:
sequential_H14.csv (eval_all3.py), fixed_list_alert.csv (fixed_list.py) and days.csv (sens_units.py).
Columns: violA = exceedance share of the alert-day rate (primary metric) with its cluster bootstrap interval, viol = the same
for the rate of new flow types, strict = the same when the list is never updated, devices and exact_upper_limit as in
fixed_list.py, days_removed and device_days_removed against the primary analysis.
Usage: sens_table.py <data root>   (writes <data root>/out/sensitivity_units.csv)"""
import sys, os, pandas as pd
D = sys.argv[1]
RULES = ['GT-C', 'quiet streak', 'fixed 14']; GR = ['port', 'svc', 'net']
SRC = {'primary': [d for d in (f'{D}/v3/res_base', f'{D}/val/res', f'{D}/servtrace/res', f'{D}/deakin/res')
                   if os.path.exists(f'{d}/tables/fixed_list_alert.csv')], 'partial20': [f'{D}/sens/partial20/res'],
       'wd5': [f'{D}/sens/wd5/res'], 'wd6': [f'{D}/sens/wd6/res']}
rows = []
for variant, dirs in SRC.items():
    for d in dirs:
        seq = pd.read_csv(f'{d}/tables/sequential_H14.csv'); fx = pd.read_csv(f'{d}/tables/fixed_list_alert.csv')
        seq = seq[(seq.eps == 0.3) & seq.rule.isin(RULES) & seq.gran.isin(GR) & (seq.dataset != 'hvac')]
        t = seq[['dataset', 'gran', 'rule', 'episodes', 'stopped', 'med_T', 'violA', 'violA_lo', 'violA_hi', 'viol']].merge(
            fx[['dataset', 'gran', 'rule', 'stops', 'devices', 'exceed_first_seen', 'exceed_fixed_list', 'devices_exceeding', 'exact_upper_limit']],
            on=['dataset', 'gran', 'rule'], how='left')
        # the two scripts count the same stops: their alert-day exceedance must agree wherever a rule enforces at all
        chk = t.dropna(subset=['violA', 'exceed_first_seen'])
        assert ((chk.violA - chk.exceed_first_seen).abs() < 1e-12).all(), (variant, d)
        t = t.rename(columns={'exceed_fixed_list': 'strict'}).drop(columns=['exceed_first_seen'])
        t.insert(0, 'variant', variant); rows.append(t)
r = pd.concat(rows, ignore_index=True)
days = pd.concat([pd.read_csv(f'{D}/sens/{v}/days.csv') for v in ('partial20', 'wd5', 'wd6')], ignore_index=True)
base = days[days.variant == 'partial20'][['dataset', 'days_all', 'device_days_all']].assign(variant='primary', days_removed=0, device_days_removed=0) \
    .rename(columns={'days_all': 'days', 'device_days_all': 'device_days'})
days = pd.concat([base, days[['variant', 'dataset', 'days', 'device_days', 'days_removed', 'device_days_removed']]], ignore_index=True)
r = r.merge(days, on=['variant', 'dataset'], how='left')
r['variant'] = pd.Categorical(r.variant, list(SRC)); r['gran'] = pd.Categorical(r.gran, GR); r['rule'] = pd.Categorical(r.rule, RULES)
r = r.sort_values(['dataset', 'gran', 'rule', 'variant']).reset_index(drop=True)
os.makedirs(f'{D}/out', exist_ok=True); r.to_csv(f'{D}/out/sensitivity_units.csv', index=False)
pd.set_option('display.width', 250); pd.set_option('display.max_rows', 2000)
print(r[['dataset', 'gran', 'rule', 'variant', 'episodes', 'stopped', 'med_T', 'violA', 'violA_lo', 'violA_hi', 'viol', 'strict', 'devices',
         'exact_upper_limit', 'days_removed']].round(3).to_string(index=False))
