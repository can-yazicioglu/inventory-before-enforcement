"""Shared routines of the analyses registered on 25 November 2026 (see ../docs/method.md, note of that date).

Nothing here changes the frozen rule. The routines describe it further: a bound that is valid at every look
(point 10 of the note), allowlists built from flow types seen on at least k days (point 8), unit filters
(points 6, 7 and 11) and the exact upper limit that every stopping table reports (point 5)."""
import numpy as np
from scipy import stats

ALPHA = 0.05          # nominal level of the frozen bound
T_MIN = 7             # first day on which the frozen rule may enforce
PARTIAL_HOURS = 20.0  # a recording day that covers less than this is a partial recording day
PART_DAYS = 56        # replication within the site: part 1 is recording days 1 to 56, part 2 days 57 to 112
PART_MIN = 42         # part 2 is analysed on its own only with at least this many recording days


def tu_alpha(T, weekly=False):
    """Level spent at the look on day T by the bound that is valid at every look. The levels add up to ALPHA.
    Daily looks: ALPHA / (j (j + 1)) with j = T - 6, for T = 7, 8, ...
    Weekly looks: ALPHA / (j (j + 1)) with j = T / 7, for T = 7, 14, 21, ...  Other days are no looks (nan)."""
    T = np.asarray(T, dtype=float)
    if weekly:
        j = np.where((T >= T_MIN) & (T % 7 == 0), T / 7, np.nan)
    else:
        j = np.where(T >= T_MIN, T - (T_MIN - 1), np.nan)
    return ALPHA / (j * (j + 1))


def tu_first_term(q1, T, weekly=False):
    """First term of the bound at the level of tu_alpha: chi-square quantile(1 - alpha_T, 2 (Q1 + 1)) / (2 T).
    On a day that is no look the term is infinite, so the rule cannot enforce there."""
    q1 = np.asarray(q1, dtype=float); T = np.asarray(T, dtype=float)
    a = tu_alpha(T, weekly)
    out = np.full(np.broadcast(q1, T).shape, np.inf)
    ok = np.isfinite(a)
    out[ok] = stats.chi2.isf(np.broadcast_to(a, out.shape)[ok], 2 * (np.broadcast_to(q1, out.shape)[ok] + 1)) / \
        (2 * np.broadcast_to(T, out.shape)[ok])
    return out


def first_possible_day(eps, weekly=None, q1=0, t_max=2000):
    """First day on which a bound can be at most eps with q1 singletons and no drift term.
    weekly=None: the frozen GT-C bound (fixed 0.95 quantile). False or True: the bound that is valid at every look."""
    for T in range(T_MIN, t_max + 1):
        u = stats.chi2.ppf(1 - ALPHA, 2 * (q1 + 1)) / (2 * T) if weekly is None else float(tu_first_term(q1, T, weekly))
        if u <= eps:
            return T
    return None


def exact_upper(x, n, conf=0.95):
    """Upper end of the two-sided Clopper-Pearson interval for x of n."""
    if n == 0:
        return float('nan')
    return 1.0 if x >= n else float(stats.beta.ppf(1 - (1 - conf) / 2, x + 1, n - x))


def list_outcomes(Mo, Wo, T, H, k):
    """What happens in the H units after enforcement on day T under the list L_k: the flow types seen on at least k
    of the first T units. Mo[type, unit] is the incidence of one learning episode, Wo the record counts.
      list_size   : number of types on L_k
      once_days   : units with at least one type outside L_k that appears for the first time since enforcement
      never_days  : units with at least one type outside L_k (the list is never updated)
      new_types   : types outside L_k that appear in the H units
      blocked, total : flow records of the H units whose type is outside L_k, and all flow records of the H units"""
    cnt = Mo[:, :T].sum(axis=1)
    outside = cnt < k
    F = Mo[outside, T:T + H]
    used = F.any(axis=1)
    first = np.argmax(F[used], axis=1) if used.any() else np.zeros(0, dtype=int)
    return dict(list_size=int((~outside).sum()), once_days=int(len(np.unique(first))), never_days=int(F.any(axis=0).sum()),
                new_types=int(used.sum()), blocked=float(Wo[outside, T:T + H].sum()), total=float(Wo[:, T:T + H].sum()))


def boot_share(rng, dev, flag, B=1000):
    """Percentile interval of the share of flagged stops, by a cluster bootstrap over devices (as in eval_all3.boot)."""
    import pandas as pd
    a = pd.DataFrame({'dev': np.asarray(dev), 'v': np.asarray(flag, dtype=float), 'one': 1.0}).groupby('dev')[['v', 'one']].sum().values
    if len(a) < 3:
        return (np.nan, np.nan)
    idx = rng.integers(0, len(a), (B, len(a)))
    r = a[idx, 0].sum(axis=1) / np.maximum(a[idx, 1].sum(axis=1), 1e-12)
    return tuple(np.quantile(r, [.025, .975]))
