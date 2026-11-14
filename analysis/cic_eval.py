#!/usr/bin/env python3
"""CICIoMT2024 Wi-Fi devices: (1) which benign states an allowlist learned from idle/active traffic misses,
(2) how much reconnaissance traffic each allowlist granularity lets through.
Usage: cic_eval.py <cic_dir> <out_dir>"""
import sys, re, numpy as np, pandas as pd
d, out = sys.argv[1:3]
pd.set_option('display.width', 250)
DEV = {'90:11:95:16:40:3b': 'Blink', '44:61:32:e8:88:2f': 'Ecobee', 'f4:b1:9c:c9:79:ff': 'M1T', 'fc:67:1f:e1:9e:58': 'Pager',
       'fc:67:1f:f7:cb:07': 'Owltron', '34:94:54:f0:db:f0': 'SenseU', '1c:90:ff:e6:e2:4b': 'Singcall'}
ATTACKER = ('192.168.137.48', '192.168.137.250')
F = pd.concat([pd.read_parquet(f'{d}/{n}.parquet') for n in ('power', 'inter', 'benign', 'recon')], ignore_index=True)
# device IP per file from frames the device itself sent
own = pd.concat([F.loc[F.mac_a.isin(DEV), ['file', 'mac_a', 'ip_a']].rename(columns={'mac_a': 'mac', 'ip_a': 'ip'})])
own = own[~own.ip.isin(['0.0.0.0', '::']) & ~own.ip.str.startswith('fe80')]
own = own.groupby(['file', 'ip', 'mac']).size().reset_index(name='c').sort_values('c', ascending=False).drop_duplicates(['file', 'ip'])
own['device'] = own.mac.map(DEV)
ipdev = {(f, ip): dv for f, ip, dv in zip(own.file, own.ip, own.device)}
# static fallback: device IP seen anywhere
anyip = own.sort_values('c', ascending=False).drop_duplicates('ip').set_index('ip').device.to_dict()

def scope(a):
    if a == '255.255.255.255' or a.endswith('.255'): return 'bcast'
    if a.startswith('ff') and ':' in a or re.match(r'^(22[4-9]|23\d)\.', a): return 'mcast'
    if a.startswith(('192.168.', '10.', '169.254.', 'fe80', 'fd', 'fc')) or re.match(r'^172\.(1[6-9]|2\d|3[01])\.', a) or a in ('0.0.0.0', '::'): return 'lan'
    return 'wan'

recs = []
for r in F.itertuples(index=False):
    for side in ('a', 'b'):
        ip = r.ip_a if side == 'a' else r.ip_b
        dv = ipdev.get((r.file, ip)) or (anyip.get(ip) if r.file.startswith('Recon') else None)
        if side == 'a' and dv is None and r.mac_a in DEV: dv = DEV[r.mac_a]
        if dv is None: continue
        peer = r.ip_b if side == 'a' else r.ip_a
        # server side: the SYN receiver if a SYN was seen; otherwise the well-known / non-ephemeral port; else the responder
        if r.proto == 6 and r.syn_a > 0: srv = 'b'
        elif r.proto in (6, 17) and (r.port_a < 1024) != (r.port_b < 1024): srv = 'a' if r.port_a < 1024 else 'b'
        elif r.proto in (6, 17) and (r.port_a < 32768) != (r.port_b < 32768): srv = 'a' if r.port_a < 32768 else 'b'
        else: srv = 'b'
        role = 'in' if srv == side else 'out'
        if r.proto in (6, 17):
            if r.port_a == r.port_b: role = 'sym'
            port = r.port_b if srv == 'b' else r.port_a
            svc = f'{r.proto}/{role}/{"hi" if port >= 32768 else port}'
        else:
            svc = str(r.proto)
        sc = scope(peer)
        dev_pl = r.pl_a if side == 'a' else r.pl_b
        net = re.sub(r'\.\d+$', '.0/24', peer) if sc == 'wan' and ':' not in peer else peer
        recs.append((r.file, dv, peer, sc, role, dev_pl,
                     f'{svc}@{peer}', f'{svc}@{net if sc == "wan" else peer}', f'{svc}@{"wan" if sc == "wan" else peer}', f'{svc}@{sc}'))
R = pd.DataFrame(recs, columns=['file', 'device', 'peer', 'scope', 'role', 'dev_pl', 'host', 'net', 'svc', 'port'])
R['answered'] = ~((R.role == 'in') & (R.dev_pl == 0))
def cond(f):
    if f.endswith('_Power.pcap'): return 'power'
    if '_LAN_' in f: return 'interaction'
    if f.startswith('Recon'): return f[:-9].lower()
    return f[:-5].lower()
R['cond'] = R.file.map(cond)
print('attacker hosts as peers in benign learning data:', R[R.peer.isin(ATTACKER) & ~R.cond.str.startswith('recon')].groupby(['cond','peer']).size().to_dict())
print('flows per condition and device'); print(R.pivot_table(index='cond', columns='device', values='peer', aggfunc='size', fill_value=0).to_string())
LV = ['host', 'net', 'svc', 'port']
rows = []
LEARN = {'idle': ['idle'], 'idle+active': ['idle', 'active'], 'idle+active+train': ['idle', 'active', 'benign_train']}
for lname, lc in LEARN.items():
    L = R[R.cond.isin(lc) & R.answered]
    for lv in LV:
        allow = {dv: set(g[lv]) for dv, g in L.groupby('device')}
        for tc in ('power', 'interaction', 'benign_test', 'active', 'benign_train'):
            if tc in lc: continue
            T = R[(R.cond == tc) & R.answered]
            for dv, g in T.groupby('device'):
                a = allow.get(dv, set()); new = ~g[lv].isin(a)
                rows.append(dict(learn=lname, level=lv, test=tc, device=dv, flows=len(g), blocked_flows=int(new.sum()),
                                 types=g[lv].nunique(), blocked_types=g.loc[new, lv].nunique(), rules=len(a)))
        # attack: reconnaissance flows from the attacker to the devices (no filter: every probe either matches a rule or not)
        A = R[R.cond.str.startswith('recon') & R.peer.isin(ATTACKER) & (R.role != 'out')]
        for (tc, dv), g in A.groupby(['cond', 'device']):
            a = allow.get(dv, set()); ok = g[lv].isin(a)
            rows.append(dict(learn=lname, level=lv, test=tc, device=dv, flows=len(g), blocked_flows=int((~ok).sum()),
                             types=g[lv].nunique(), blocked_types=g.loc[~ok, lv].nunique(), rules=len(a)))
E = pd.DataFrame(rows); E.to_csv(f'{out}/cic_eval.csv', index=False)
E['lvl'] = pd.Categorical(E.level, LV)
s = E.groupby(['learn', 'test', 'lvl'], observed=True).agg(devices=('device', 'nunique'), flows=('flows', 'sum'), blocked=('blocked_flows', 'sum'),
                                             types=('types', 'sum'), btypes=('blocked_types', 'sum')).reset_index()
s['flow_block_pct'] = 100 * s.blocked / s.flows; s['type_block_pct'] = 100 * s.btypes / s.types
p = s.pivot_table(index=['learn', 'test'], columns='lvl', values='flow_block_pct', observed=True)
print('\nblocked share of flows (%), by learning set, test condition and granularity'); print(p.round(1).to_string())
p = s[s.learn == 'idle+active+train'].pivot_table(index='test', columns='lvl', values='type_block_pct', observed=True)
print('\nblocked share of distinct rule types (%), learning = idle+active+train'); print(p.round(1).to_string())
print('\nrules per device (idle+active+train):'); print(E[(E.learn == 'idle+active+train')].groupby(['device', 'level']).rules.first().unstack()[LV].to_string())

