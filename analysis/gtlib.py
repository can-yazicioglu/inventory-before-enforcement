"""Core routines: incidence matrices, Good-Turing family estimators and realised outcomes."""
import numpy as np
import pandas as pd
import duckdb

WINDOWS = (7, 14, 28)
HORIZONS = (1, 7, 14, 30)


def load_matrices(path, gran, unit_col='day', min_units=10, where=''):
    """Yield (dataset, site, device, units, M, W): M[type, unit] incidence, W record counts.
    Units are the device's active units in time order, first and last (partial) dropped."""
    con = duckdb.connect()
    df = con.execute(f"""SELECT dataset, site, device, {unit_col} AS u, ftype, sum(n) AS n
                         FROM read_parquet('{path}') WHERE gran = '{gran}' {where} GROUP BY ALL""").df()
    for (ds, site, dev), g in df.groupby(['dataset', 'site', 'device'], sort=False):
        units = np.sort(g.u.unique())[1:-1]
        if len(units) < min_units:
            continue
        g = g[g.u.isin(units)]
        ux = pd.Index(units)
        types, tix = np.unique(g.ftype.values, return_inverse=True)
        M = np.zeros((len(types), len(units)), dtype=bool)
        W = np.zeros((len(types), len(units)), dtype=np.float64)
        di = ux.get_indexer(g.u.values)
        M[tix, di] = True
        W[tix, di] = g.n.values
        yield ds, site, dev, units, types, M, W


def chao_q0(T, q1, q2):
    if q1 == 0:
        return 0.0
    if q2 > 0:
        return (T - 1) / T * q1 * q1 / (2 * q2)
    return (T - 1) / T * q1 * (q1 - 1) / 2


def chao_ext(T, q1, q2, t):
    """Expected number of new types in the next t units (Chao et al. 2014, incidence data)."""
    q0 = chao_q0(T, q1, q2)
    if q0 <= 0:
        return 0.0
    return q0 * (1 - (1 - q1 / (T * q0 + q1)) ** t)


def series(M, W, t_min=2):
    """Per observation length T (units 0..T-1 observed): estimator inputs and realised outcomes."""
    S, K = M.shape
    cum = np.cumsum(M, axis=1)
    cumW = np.cumsum(W, axis=1)
    first = np.argmax(M, axis=1)
    tot = W.sum(axis=0)
    new_by_day = np.bincount(first, minlength=K)
    rows = []
    for T in range(t_min, K):
        c = cum[:, T - 1]
        seen = c > 0
        one = c == 1
        q1 = int(one.sum()); q2 = int((c == 2).sum())
        nz = np.nonzero(new_by_day[:T])[0]
        r = dict(T=T, K=K, sobs=int(seen.sum()), q1=q1, q2=q2, streak=int(T - 1 - nz[-1]),
                 wq1=float(cumW[one, T - 1].sum()), rec_obs=float(tot[:T].sum()))
        for w in WINDOWS:
            lo = max(0, T - w); ww = T - lo
            recent = (first >= lo) & (first < T)
            r[f'd{w}'] = recent.sum() / ww                 # recent discovery rate
            r[f'b{w}'] = int((recent & (c >= 2)).sum())    # recent births seen again
            r[f'r{w}'] = int((recent & one).sum())         # recent singletons
            r[f'w{w}'] = ww
        unseen = ~seen
        for h in HORIZONS:
            if T + h <= K:
                r[f'y{h}'] = int(new_by_day[T:T + h].sum())
                r[f'alertdays{h}'] = int((new_by_day[T:T + h] > 0).sum())
                r[f'blk{h}'] = float(W[unseen, T:T + h].sum())
                r[f'rec{h}'] = float(tot[T:T + h].sum())
            else:
                r[f'y{h}'] = -1; r[f'alertdays{h}'] = -1; r[f'blk{h}'] = np.nan; r[f'rec{h}'] = np.nan
        rows.append(r)
    return rows


def halves_perm_test(M, n_perm=300, rng=None, block=1):
    """Exchangeability test. Statistic: types first seen in the second half of the trace.
    Null: random halves (units, or blocks of `block` consecutive units, permuted)."""
    rng = rng or np.random.default_rng(0)
    S, K = M.shape
    nb = K // block
    if nb < 4:
        return None
    Mb = M[:, :nb * block].reshape(S, nb, block).any(axis=2) if block > 1 else M
    S2 = int(Mb.any(axis=1).sum())
    h = nb // 2
    obs = S2 - int(Mb[:, :h].any(axis=1).sum())
    null = np.empty(n_perm)
    for j in range(n_perm):
        idx = rng.permutation(nb)[:h]
        null[j] = S2 - Mb[:, idx].any(axis=1).sum()
    p = (1 + (null >= obs).sum()) / (n_perm + 1)
    return dict(obs=obs, null_mean=float(null.mean()), null_sd=float(null.std()), p=float(p), S=S2, nb=nb)

