#!/usr/bin/env python3
"""Exp 4: device categories, certification time curves, participation-filter ablation.
Usage: exp4.py <res_dir> <res_keep_dir> <device_map.csv>"""
import sys, numpy as np, pandas as pd
import os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import scores
res, res_keep, dmap = sys.argv[1:4]
pd.set_option('display.width', 250)
UN = {'camera': ['BelkinCamera', 'CanaryCamera', 'NestDropCam', 'NetatmoWelcome', 'SamsungCamera', 'TPLinkCamera',
                 'WithingsBabyMonitor', 'RingDoorBell', 'AugustDoorBell'],
      'hub': ['SamsungSmartThings', 'PhilipsHue'], 'speaker/media': ['AmazonEcho', 'TribySpeaker', 'iHome', 'PixStarPhotoFrame', 'HelloBarbie'],
      'plug/bulb/sensor': ['BelkinWemoSwitch', 'BelkinWemoMotionSensor', 'TPLinkSmartPlug', 'LiFXBulb', 'NestProtect',
                           'NetatmoWeatherStation', 'AwairAirQuality'],
      'health': ['WithingsSleepSensor', 'WithingsSmartScale', 'BlipCareBPMeter'], 'printer': ['HPPrinter']}
HM = {'network camera': 'camera', 'hub': 'hub', 'smart speaker': 'speaker/media', 'media player': 'speaker/media', 'tablet': 'speaker/media',
      'electrical plug': 'plug/bulb/sensor', 'lightbulb': 'plug/bulb/sensor', 'sensor': 'plug/bulb/sensor', 'humidifier': 'plug/bulb/sensor',
      'remote controller': 'plug/bulb/sensor', 'robot cleaner': 'appliance', 'health care': 'health', 'printer': 'printer'}
m = pd.read_csv(dmap).drop_duplicates('name')
cat = {n: HM.get(c, 'appliance') for n, c in zip(m.name, m.category)}
cat.update({d: c for c, L in UN.items() for d in L})
s = pd.read_parquet(f'{res}/scored.parquet'); s = s[s.origin == 0].copy()
s['gtc'] = s.gt_u95 + (s.gt_pr - s['gt']); s['cat'] = s.device.map(cat).fillna('other'); s['dev'] = s.site + '/' + s.device
# (a) categories at T = 14
a = s[(s['T'] == 14) & s.gran.isin(['port', 'svc', 'net'])]
t = a.groupby(['gran', 'cat']).agg(devices=('dev', 'nunique'), types=('sobs', 'median'), gt_med=('gt', 'median'),
                                   cert03=('gtc', lambda x: (x <= 0.3).mean()), cert1=('gtc', lambda x: (x <= 1.0).mean()),
                                   real14=('y14', lambda x: (x[x >= 0] / 14).mean())).reset_index()
t.to_csv(f'{res}/tables/categories_T14.csv', index=False)
print('(a) by category at T=14 (both datasets pooled): median types, median GT rate, share certified, realised rate')
print(t.round(2).to_string(index=False))
# (b) certification time curves: share of devices certified by day T
rows = []
for (ds, g), q in s.groupby(['dataset', 'gran']):
    n = q.dev.nunique()
    for eps in (0.1, 0.3, 1.0):
        first = q[(q.gtc <= eps) & (q['T'] >= 7)].groupby('dev')['T'].min()
        last = q.groupby('dev')['T'].max(); first = first.reindex(last.index)
        ev = first.notna(); t = np.where(ev, first, last)                 # Kaplan-Meier: event = first certification, censored at trace end
        surv = 1.0
        for T in range(7, 121):
            at_risk = (t >= T).sum(); d = (ev & (t == T)).sum()
            if at_risk > 0: surv *= 1 - d / at_risk
            if T in (7, 10, 14, 21, 28, 42, 60, 90, 120) and at_risk >= 5:
                rows.append(dict(dataset=ds, gran=g, eps=eps, T=T, at_risk=int(at_risk), certified=1 - surv))
c = pd.DataFrame(rows); c.to_csv(f'{res}/tables/cert_curves.csv', index=False)
p = c[(c.eps == 0.3)].pivot_table(index=['dataset', 'gran'], columns='T', values='certified')
print('\n(b) share of devices certified (GT-C <= 0.3/day) by day T'); print(p.round(2).to_string())
p = c[(c.eps == 0.1)].pivot_table(index=['dataset', 'gran'], columns='T', values='certified')
print('\n    same for eps = 0.1/day'); print(p.loc[['unsw']].round(2).to_string())
# (c) ablation: without the participation filter
k = scores.add_scores(pd.read_parquet(f'{res_keep}/series.parquet')); k = k[k.origin == 0]
rows = []
for name, d in (('filtered', s), ('unfiltered', k)):
    d = d[(d['T'] == 14) & d.gran.isin(['port', 'svc'])]
    for (ds, g), q in d.groupby(['dataset', 'gran']):
        rows.append(dict(data=name, dataset=ds, gran=g, types_med=q.sobs.median(), types_mean=q.sobs.mean(), gt_mean=q['gt'].mean(),
                         real14=(q.y14[q.y14 >= 0] / 14).mean(), cert03=((q.gt_u95 + q.gt_pr - q['gt']) <= 0.3).mean()))
ab = pd.DataFrame(rows).sort_values(['dataset', 'gran', 'data']); ab.to_csv(f'{res}/tables/ablation_filter.csv', index=False)
print('\n(c) participation filter ablation at T=14'); print(ab.round(2).to_string(index=False))

