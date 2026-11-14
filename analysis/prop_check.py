#!/usr/bin/env python3
"""Exact checks of the exchangeability identities by enumerating every ordering of arbitrary day-sets
(finite exchangeable sequences with any dependence between types).
P1: E[N(T+1)] = E[Q1(T+1)]/(T+1)            C1: E[Q1(T)]/T >= E[N(T+1)]
P2: P(alert on day T+1) = E[D(T+1)]/(T+1)   C2: E[D(T)]/T >= P(alert)      B: P(alert) <= E[(D(T)+1)/(T+1)]
CP: P(N(T+1) <= k-th smallest per-day singleton count among the first T days) >= k/(T+1)
N = new types on a day, Q1 = types seen on exactly one day, D = days carrying a type seen on no other day."""
import itertools, numpy as np
rng = np.random.default_rng(11)
w = dict(P1=0.0, C1=1e9, P2=0.0, C2=1e9, B=1e9, CP=1e9)
for trial in range(300):
    K = int(rng.integers(4, 8)); S = int(rng.integers(2, 20)); M = np.zeros((S, K), bool)
    for s in range(S):
        if rng.random() < 0.5: M[s, rng.integers(0, K)] = True
        else: M[s] = rng.random(K) < rng.beta(0.3, 1.5)
    if rng.random() < 0.5: M[:, rng.integers(0, K)] |= rng.random(S) < 0.6
    perms = list(itertools.permutations(range(K)))
    for T in range(2, K):
        N = []; q1n = []; q1t = []; al = []; d1 = []; dt = []; bd = []; ok = {k: [] for k in range(1, T + 1)}
        for p in perms:
            A = M[:, list(p)]; c = A[:, :T].sum(1); c1 = A[:, :T + 1].sum(1)
            n = int((A[:, T] & (c == 0)).sum()); N.append(n); al.append(n > 0)
            q1n.append((c1 == 1).sum() / (T + 1)); q1t.append((c == 1).sum() / T)
            u = [(A[:, j] & (c == 1)).sum() for j in range(T)]; u1 = [(A[:, j] & (c1 == 1)).sum() for j in range(T + 1)]
            d = sum(x > 0 for x in u); d1.append(sum(x > 0 for x in u1) / (T + 1)); dt.append(d / T); bd.append((d + 1) / (T + 1))
            sc = sorted(u)
            for k in range(1, T + 1): ok[k].append(n <= sc[k - 1])
        w['P1'] = max(w['P1'], abs(np.mean(N) - np.mean(q1n))); w['C1'] = min(w['C1'], np.mean(q1t) - np.mean(N))
        w['P2'] = max(w['P2'], abs(np.mean(al) - np.mean(d1))); w['C2'] = min(w['C2'], np.mean(dt) - np.mean(al))
        w['B'] = min(w['B'], np.mean(bd) - np.mean(al))
        for k in range(1, T + 1): w['CP'] = min(w['CP'], np.mean(ok[k]) - k / (T + 1))
print('largest identity error  P1:', w['P1'], ' P2:', w['P2'])
print('smallest slack (must be >= 0 up to rounding)  C1:', w['C1'], ' C2:', w['C2'], ' B:', w['B'], ' CP:', w['CP'])
