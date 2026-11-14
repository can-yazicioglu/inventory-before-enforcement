#!/usr/bin/env python3
"""Independent re-implementation of the frozen method (written from the method text in docs/method.md, not from gtlib/scores/eval_all).
Plain Python sets and loops, no incidence matrices, no pandas rolling.
Usage: indep.py <inc_day.parquet> <out_prefix> [H]"""
import sys, math, collections, statistics
import duckdb
from scipy.stats import chi2

inc, outp = sys.argv[1:3]; H = int(sys.argv[3]) if len(sys.argv) > 3 else 14
con = duckdb.connect()
rows = con.execute(f"SELECT dataset, site, device, gran, day, ftype FROM read_parquet('{inc}') "
                   f"WHERE gran IN ('port','svc','net') GROUP BY ALL").fetchall()
by = collections.defaultdict(lambda: collections.defaultdict(set))
for ds, site, dev, gran, day, ft in rows:
    by[(ds, gran, site, dev)][day].add(ft)

def episode(daysets):
    """daysets: list of sets (one per active day of the episode). Returns per-T records for T>=2."""
    K = len(daysets); count = collections.Counter(); out = {}
    errs = []                       # prediction errors e_t = N(t) - Q1(t-1)/(t-1), known after day t is observed
    q1_prev = None
    newc = []                       # number of new types on each day
    for i, s in enumerate(daysets):  # i = 0-based day index; after processing, T = i+1 days observed
        n_new = sum(1 for t in s if count[t] == 0)
        newc.append(n_new)
        if q1_prev is not None and i >= 2:           # prediction made after T=i days (T>=2) for day i
            errs.append(n_new - q1_prev / i)
        for t in s: count[t] += 1
        T = i + 1
        q1 = sum(1 for v in count.values() if v == 1)
        q1_prev = q1
        if T >= 2 and T < K:
            last = errs[-14:]
            corr = max(0.0, sum(last) / len(last)) if len(last) >= 3 else 0.0
            u95 = chi2.ppf(0.95, 2 * (q1 + 1)) / (2 * T)
            # days since the last day with a new type (quiet streak)
            j = max(k for k in range(T) if newc[k] > 0)
            out[T] = dict(q1=q1, gt=q1 / T, u95=u95, gtc=u95 + corr, gtpr=q1 / T + corr, streak=T - 1 - j)
    return out, newc

res = collections.defaultdict(list); cal = collections.defaultdict(list)
for (ds, gran, site, dev), dd in by.items():
    days = sorted(dd)[1:-1]
    if len(days) < 10: continue
    K = len(days)
    for o in range(0, max(1, K - 20), 21):
        sets = [dd[d] for d in days[o:]]
        Ko = len(sets)
        recs, newc = episode(sets)
        ok = [T for T in recs if T >= 7 and T + H <= Ko]
        if not ok: continue
        def outcome(T):
            fut = newc[T:T + H]
            return sum(fut) / H, sum(1 for x in fut if x > 0) / H
        ep = dict(dev=f'{site}/{dev}', origin=o)
        for eps in (0.1, 0.3, 1.0):
            for name, test in (('GT-C', lambda r: r['gtc'] <= eps), ('GT-UCB', lambda r: r['u95'] <= eps),
                               ('quiet streak', lambda r: 3.0 / max(r['streak'], 0.5) <= eps)):
                T = next((T for T in sorted(ok) if test(recs[T])), None)
                ep[(name, eps)] = (T, *outcome(T)) if T else None
            for F in (7, 14, 21, 28):
                ep[(f'fixed {F}', eps)] = (F, *outcome(F)) if F in ok else None
        res[(ds, gran)].append(ep)
        # calibration rows: next-day new types vs GT prediction, T >= 7, T+H <= Ko (same rows as the evaluation)
        for T in ok:
            cal[(ds, gran)].append((f'{site}/{dev}', o, newc[T], recs[T]['gt'], recs[T]['gtpr']))

import csv
with open(outp + f'_seq_H{H}.csv', 'w', newline='') as f:
    w = csv.writer(f); w.writerow(['dataset', 'gran', 'eps', 'rule', 'episodes', 'stopped', 'med_T', 'viol', 'violA'])
    for (ds, gran), eps_list in sorted(res.items()):
        for eps in (0.1, 0.3, 1.0):
            for rule in ('GT-UCB', 'GT-C', 'quiet streak', 'fixed 7', 'fixed 14', 'fixed 21', 'fixed 28'):
                st = [e[(rule, eps)] for e in eps_list if e[(rule, eps)]]
                n = len(eps_list)
                if st:
                    w.writerow([ds, gran, eps, rule, n, round(len(st) / n, 4), statistics.median(x[0] for x in st),
                                round(sum(x[1] > eps for x in st) / len(st), 4), round(sum(x[2] > eps for x in st) / len(st), 4)])
                else:
                    w.writerow([ds, gran, eps, rule, n, 0.0, '', '', ''])
with open(outp + f'_cal_H{H}.csv', 'w', newline='') as f:
    w = csv.writer(f); w.writerow(['dataset', 'gran', 'dev', 'origin', 'y1', 'gt', 'gtpr'])
    for (ds, gran), L in sorted(cal.items()):
        for r in L: w.writerow([ds, gran, *r])
print('done', {k: len(v) for k, v in res.items()})
