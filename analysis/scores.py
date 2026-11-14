"""Estimator scores and bounds on top of the series table.

GT_W(T) = R_W(T) / W : windowed Good-Turing. R_W = types seen exactly once in the whole history whose single
occurrence lies in the last W units. W = T gives the classical estimator Q1 / T.
PR correction: mean of the last `w_pr` prequential residuals N_t - GT(t-1), floored at zero.
"""
import numpy as np, pandas as pd
from scipy import stats
import sys
import os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import gtlib

KEY = ['dataset', 'site', 'device', 'gran', 'origin']


def _roll(s, col, fn, **kw):
    g = s.groupby(KEY, sort=False)[col]
    return getattr(g.shift(1).groupby([s[k] for k in KEY], sort=False), fn[0])(**fn[1]).agg(fn[2], **kw) \
        .reset_index(level=list(range(len(KEY))), drop=True)


def add_scores(s, w_pr=14, alpha=0.10):
    s = s.sort_values(KEY + ['T']).reset_index(drop=True)
    T = s['T'].values.astype(float)
    s['gt'] = s.q1 / T
    s['gt_u95'] = stats.chi2.ppf(0.95, 2 * (s.q1 + 1)) / (2 * T)
    s['chao'] = [gtlib.chao_ext(t, a, b, 1) for t, a, b in zip(s['T'], s.q1, s.q2)]
    for w in gtlib.WINDOWS:
        s[f'gt{w}'] = s[f'r{w}'] / s[f'w{w}']
        s[f'gt{w}_u95'] = stats.chi2.ppf(0.95, 2 * (s[f'r{w}'] + 1)) / (2 * s[f'w{w}'])
    s['streak_u95'] = 3.0 / np.maximum(s.streak, 0.5)
    for base in ('gt', 'gt14'):
        s['_res'] = np.where(s.y1 >= 0, s.y1 - s[base], np.nan)
        pr = _roll(s, '_res', ('rolling', dict(window=w_pr, min_periods=3), 'mean'))
        s[base + '_pr'] = s[base] + pr.clip(lower=0).fillna(0)
        s['_z'] = s['_res'] / np.sqrt(s[base] + 1.0)
        q = _roll(s, '_z', ('expanding', dict(min_periods=5), 'quantile'), q=1 - alpha)
        s[base + '_conf'] = s[base] + q.clip(lower=0) * np.sqrt(s[base] + 1.0)
    return s.drop(columns=['_res', '_z'])

