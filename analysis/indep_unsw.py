#!/usr/bin/env python3
"""Independent normalisation of UNSW-IoTraffic flows -> (device, local day, type) at port and svc level.
Written from the specification (dataset README and docs/method.md), pandas only. Compares with the pipeline's inc_day.parquet."""
import glob, os, re, collections, sys
import os; DATA = os.environ.get('IBE_DATA', 'data')
import pandas as pd, numpy as np, duckdb
F = DATA + '/unsw_raw/flows'
def scope(a):
    if a == '255.255.255.255' or a.endswith('.255'): return 'bcast'
    if (':' in a and a.lower().startswith('ff')) or re.match(r'^(22[4-9]|23\d)\.', a): return 'mcast'
    if a.startswith(('192.168.', '10.', '169.254.')) or re.match(r'^172\.(1[6-9]|2\d|3[01])\.', a) or a in ('0.0.0.0', '::', '0:0:0:0:0:0:0:0') \
       or a.lower().startswith(('fe80:', 'fc', 'fd')) and ':' in a: return 'lan'
    return 'wan'
frames = {}
for p in sorted(glob.glob(F + '/*.csv')):
    dev = re.match(r'(.+?)_+[0-9a-fA-F]{12}_flows\.csv$', os.path.basename(p)).group(1)
    d = pd.read_csv(p, dtype=str, usecols=['time', 'ethType', 'srcIp', 'dstIp', 'ipProto', 'srcPort', 'dstPort', 'srcPayloadSize', 'dstPayloadSize'])
    d = d[d.ethType.isin(['0x0800', '0x86dd']) & (d.srcIp != '*') & (d.dstIp != '*')].copy()
    t = pd.to_datetime(d.time, format='mixed')
    d = d[(t >= '2016-09-22') & (t < '2017-04-14')].copy(); t = t[d.index]
    d['day'] = t.dt.tz_localize('UTC').dt.tz_convert('Australia/Sydney').dt.date
    d['uday'] = t.dt.date
    d['ss'] = d.srcIp.map(scope); d['ds'] = d.dstIp.map(scope)
    frames[dev] = d
# device own address per UTC day: the local unicast non-gateway address that talks to non-local peers / gateway most
own = {}
for dev, d in frames.items():
    for (ud, v6), g in d.groupby(['uday', d.ethType == '0x86dd']):
        c = collections.Counter()
        for col, sc in (('srcIp', 'ss'), ('dstIp', 'ds')):
            x = g.loc[(g[sc] == 'lan') & (g[col] != '192.168.1.1') & ~g[col].isin(['0.0.0.0', '::', '0:0:0:0:0:0:0:0']), col]
            c.update(x.values)
        if c:
            own[(dev, ud, v6)] = c.most_common(1)[0][0]
ipdev = collections.defaultdict(dict)        # (uday) -> ip -> device
for (dev, ud, v6), ip in own.items(): ipdev[ud][ip] = dev
out = []
stats = collections.Counter()
for dev, d in frames.items():
    o = pd.Series([own.get((dev, u, v)) for u, v in zip(d.uday, d.ethType == '0x86dd')], index=d.index)
    unspec = d.srcIp.isin(['0.0.0.0', '::', '0:0:0:0:0:0:0:0'])
    is_src = (d.srcIp == o) | unspec
    is_dst = (d.dstIp == o) & ~is_src
    stats['unassigned'] += int((~is_src & ~is_dst).sum()); stats['all'] += len(d)
    d = d[is_src | is_dst].copy(); is_src = is_src[d.index]
    d['dev_port'] = np.where(is_src, d.srcPort, d.dstPort); d['peer_port'] = np.where(is_src, d.dstPort, d.srcPort)
    d['peer'] = np.where(is_src, d.dstIp, d.srcIp); d['psc'] = np.where(is_src, d.ds, d.ss)
    d['dev_pl'] = pd.to_numeric(pd.Series(np.where(is_src, d.srcPayloadSize, d.dstPayloadSize), index=d.index), errors='coerce').fillna(0)
    d['init'] = is_src.values
    d['proto'] = pd.to_numeric(d.ipProto, errors='coerce')
    d['dp'] = pd.to_numeric(d.dev_port, errors='coerce'); d['pp'] = pd.to_numeric(d.peer_port, errors='coerce')
    tu = d.proto.isin([6, 17]) & d.dp.notna() & d.pp.notna()
    a = d[d.proto.isin([6, 17]) & d.pp.notna()].groupby(['proto', 'pp']).dp.nunique()
    b = d[d.proto.isin([6, 17]) & d.dp.notna()].groupby(['proto', 'dp']).pp.nunique()
    av = pd.Series(list(zip(d.proto, d.pp))).map(a).fillna(0).values; bv = pd.Series(list(zip(d.proto, d.dp))).map(b).fillna(0).values
    role = np.full(len(d), 'na', dtype=object)
    pp, dp = d.pp.values, d.dp.values
    r = np.where(av > bv, 'out', np.where(bv > av, 'in',
        np.where((pp < 1024) & (dp >= 1024), 'out', np.where((dp < 1024) & (pp >= 1024), 'in',
        np.where(pp == dp, 'sym', np.where(d.init.values, 'out', 'in'))))))
    role[tu.values] = r[tu.values]
    d['role'] = role
    sp = np.where(d.role == 'in', d.dp, d.pp)
    d['sport'] = sp
    lanid = [('dev:' + ipdev[u][p]) if (s == 'lan' and p in ipdev[u]) else (('ip:' + p) if s == 'lan' else p) for u, p, s in zip(d.uday, d.peer, d.psc)]
    d['pid'] = lanid
    # participation filter
    key = ['day', 'proto', 'role', 'sport', 'pid']
    d['daypl'] = d.groupby(key, dropna=False).dev_pl.transform('sum')
    d = d[~((d.role == 'in') & (d.daypl == 0))]
    svc = np.where(d.role == 'na', d.proto.astype('Int64').astype(str),
                   d.proto.astype('Int64').astype(str) + '/' + d.role + '/' + np.where(d.sport >= 32768, 'hi', pd.Series(d.sport).astype('Int64').astype(str)))
    d['t_port'] = svc + '@' + d.psc
    d['t_svc'] = svc + '@' + np.where(d.psc == 'wan', 'wan', d.pid)
    for g in ('port', 'svc'):
        x = d.groupby(['day', 't_' + g]).size().reset_index(name='n'); x['device'] = dev; x['gran'] = g
        out.append(x.rename(columns={'t_' + g: 'ftype'}))
print(dict(stats))
I = pd.concat(out, ignore_index=True)
I['day'] = pd.to_datetime(I.day)
I.to_parquet(DATA + '/audit/indep_unsw_inc.parquet', index=False)
P = duckdb.connect().execute("SELECT device, day, gran, ftype, n FROM read_parquet('" + DATA + "/v3/inc_base/inc_day.parquet') WHERE dataset='unsw' AND gran IN ('port','svc')").df()
P['day'] = pd.to_datetime(P.day)
m = I.merge(P, on=['device', 'day', 'gran', 'ftype'], how='outer', suffixes=('_i', '_p'), indicator=True)
for g in ('port', 'svc'):
    q = m[m.gran == g]
    print(g, 'incidences: both', (q._merge == 'both').sum(), 'only indep', (q._merge == 'left_only').sum(), 'only pipeline', (q._merge == 'right_only').sum(),
          '| record-count mismatches among both:', int((q.n_i != q.n_p)[q._merge == 'both'].sum()))
    ti = set(zip(I[I.gran == g].device, I[I.gran == g].ftype)); tp = set(zip(P[P.gran == g].device, P[P.gran == g].ftype))
    print('   distinct (device,type): indep', len(ti), 'pipeline', len(tp), 'common', len(ti & tp))
d = m[m._merge != 'both']
print(d.groupby(['gran', 'device', '_merge'], observed=True).size().sort_values(ascending=False).head(20))
print(d.sort_values(['device','day']).head(40).to_string())
