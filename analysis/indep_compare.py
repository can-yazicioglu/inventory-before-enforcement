#!/usr/bin/env python3
"""The stopping tables of the second program (indep.py: indep_seq_H14.csv) against the stored tables of the analysis
(eval_all3.py: tables/sequential_H14.csv), for every result directory given. The second program rounds its shares to four
decimals. Printed per directory: the rows that both tables hold and the largest absolute difference per column.
Exit status 1 if a row of the second program has no partner, if the number of learning episodes or the median enforcement day
differ, or if a share differs by more than the rounding (0.00005).
Usage: indep_compare.py <res_dir>..."""
import sys, pandas as pd
KEY = ['dataset', 'gran', 'eps', 'rule']; EXACT = ['episodes', 'med_T']; SHARES = ['stopped', 'viol', 'violA']
bad = False; out = []
for d in sys.argv[1:]:
    a = pd.read_csv(f'{d}/indep_seq_H14.csv'); b = pd.read_csv(f'{d}/tables/sequential_H14.csv')
    m = a.merge(b, on=KEY, suffixes=('_second', ''))
    row = dict(dir=d, rows_second=len(a), rows_both=len(m), datasets=','.join(sorted(set(m.dataset))), levels=','.join(sorted(set(m.gran))),
               rules=m.rule.nunique())
    for c in EXACT + SHARES:
        x, y = m[c + '_second'], m[c]
        both_missing = x.isna() & y.isna()                    # a rule that enforces nothing has no median day and no share
        diff = (x - y).abs().where(~both_missing, 0.0)
        row['max_diff_' + c] = diff.max()
        if diff.isna().any() or diff.max() > (1e-9 if c in EXACT else 5.0001e-5):
            bad = True
    if len(m) != len(a):
        bad = True
    out.append(row)
t = pd.DataFrame(out); pd.set_option('display.width', 250); pd.set_option('display.max_colwidth', 60)
print(t.to_string(index=False))
print('AGREE' if not bad else 'DIFFERENT')
sys.exit(1 if bad else 0)
