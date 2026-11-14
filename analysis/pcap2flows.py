#!/usr/bin/env python3
"""Reduce a pcap to bidirectional flow records (5-tuple, split after 120 s idle).
Output columns: file, t0, t1, mac_a, mac_b, ip_a, ip_b, proto, port_a, port_b, pkts_a, pkts_b, pl_a, pl_b, syn_a, synack_b, rst_b
Side a is the sender of the first packet of the flow (initiator).
Usage: pcap2flows.py <out.parquet> <pcap>..."""
import sys, os, socket, struct
import dpkt, pandas as pd

def mac(b): return ':'.join(f'{x:02x}' for x in b)

def run(path, rows):
    name = os.path.basename(path)
    flows = {}; n = 0; skipped = 0
    with open(path, 'rb') as f:
        pc = dpkt.pcap.Reader(f)
        if pc.datalink() != dpkt.pcap.DLT_EN10MB:
            print(name, 'unsupported linktype', pc.datalink()); return
        for ts, buf in pc:
            n += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                skipped += 1; continue
            ip = eth.data
            if isinstance(ip, dpkt.ip.IP):
                sa, da = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
            elif isinstance(ip, dpkt.ip6.IP6):
                sa, da = socket.inet_ntop(socket.AF_INET6, ip.src), socket.inet_ntop(socket.AF_INET6, ip.dst)
            else:
                skipped += 1; continue
            p = ip.p if isinstance(ip, dpkt.ip.IP) else ip.nxt
            l4 = ip.data; sp = dp = -1; pl = 0; syn = synack = rst = 0
            if isinstance(l4, dpkt.tcp.TCP):
                sp, dp, pl = l4.sport, l4.dport, len(l4.data)
                fl = l4.flags
                syn = int(fl & 0x02 and not fl & 0x10); synack = int(fl & 0x02 and fl & 0x10); rst = int(bool(fl & 0x04))
            elif isinstance(l4, dpkt.udp.UDP):
                sp, dp, pl = l4.sport, l4.dport, len(l4.data)
            else:
                pl = len(bytes(l4)) if not isinstance(l4, bytes) else len(l4)
            k = (sa, da, p, sp, dp); kr = (da, sa, p, dp, sp)
            fl_ = flows.get(k); rev = False
            if fl_ is None:
                fl_ = flows.get(kr); rev = fl_ is not None
            if fl_ is not None and ts - fl_[1] > 120:
                rows.append((name, *fl_[:2], *fl_[2])); flows.pop(kr if rev else k); fl_ = None; rev = False
            if fl_ is None:
                # [t0, t1, [mac_a, mac_b, ip_a, ip_b, proto, port_a, port_b, pkts_a, pkts_b, pl_a, pl_b, syn_a, synack_b, rst_b]]
                fl_ = [ts, ts, [mac(eth.src), mac(eth.dst), sa, da, p, sp, dp, 0, 0, 0, 0, 0, 0, 0]]
                flows[k] = fl_
            fl_[1] = ts; v = fl_[2]
            if rev:
                v[8] += 1; v[10] += pl; v[12] += synack; v[13] += rst
            else:
                v[7] += 1; v[9] += pl; v[11] += syn
    for fl_ in flows.values():
        rows.append((name, *fl_[:2], *fl_[2]))
    print(f'{name}: packets {n}, non-IP {skipped}, flows so far {len(rows)}', flush=True)

rows = []
for p in sys.argv[2:]:
    run(p, rows)
cols = ['file', 't0', 't1', 'mac_a', 'mac_b', 'ip_a', 'ip_b', 'proto', 'port_a', 'port_b', 'pkts_a', 'pkts_b', 'pl_a', 'pl_b',
        'syn_a', 'synack_b', 'rst_b']
pd.DataFrame(rows, columns=cols).to_parquet(sys.argv[1], index=False)

