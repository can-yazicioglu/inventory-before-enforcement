#!/usr/bin/env python3
"""The exchangeability test as a stored table (recorded on 25 Nov 2026: before, exp1.py only printed it for the two base traces).
Per dataset, block length (1 = days, 7 = weeks) and level: devices tested, flow types first seen in the second half of the trace
(obs), their expected number under random halves (null), excess = obs / null, and sig05 = share of devices with p < 0.05.
The test is descriptive and not part of the rule. Aggregation as in exp1.py.
Usage: exch_table.py <out.csv> <res_dir>...     (each res_dir holds permtest.parquet, written by run_series3.py)"""
import sys, pandas as pd
G = ['proto', 'port', 'svc', 'svcx', 'dom', 'net', 'host']
p = pd.concat([pd.read_parquet(f'{d}/permtest.parquet') for d in sys.argv[2:]], ignore_index=True)
t = p.groupby(['dataset', 'block', 'gran']).agg(devices=('p', 'size'), obs=('obs', 'sum'), null=('null_mean', 'sum'),
                                               sig05=('p', lambda s: (s < 0.05).mean())).reset_index()
t['excess'] = t.obs / t.null
t['gran'] = pd.Categorical(t.gran, G); t = t.sort_values(['dataset', 'block', 'gran'])
t.to_csv(sys.argv[1], index=False)
pd.set_option('display.width', 250); pd.set_option('display.max_rows', 500); print(t.round(3).to_string(index=False))
