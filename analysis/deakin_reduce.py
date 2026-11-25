#!/usr/bin/env python3
"""Reduce the Deakin IoT Traffic dataset (D-IoT, doi:10.26187/deakin.28013234, folder pcapIoT) to flow records, one output file
per daily capture. Runs on the machine that holds the archive. The zip is read member by member: nothing is unpacked to disk.
Standard library only.

Usage:
    python3 deakin_reduce.py <28013234.zip, or a folder of pcap files, or one pcap file> <out_dir> [workers]

Output: <out_dir>/<capture name>.csv.gz with one row per bidirectional flow and the columns
    t0, t1, mac_a, mac_b, ip_a, ip_b, proto, port_a, port_b, pkts_a, pkts_b, pl_a, pl_b, syn_a, synack_a, rst_a, syn_b, synack_b, rst_b
and <out_dir>/summary.csv with one row per capture (packets, packets that are not IP, flows, first and last timestamp, link type).
A capture whose output already exists is skipped, so an interrupted run can be started again.

Flow: bidirectional 5-tuple, split after a gap of 120 s, as in pcap2flows.py and hvac_reduce.py. Side a is the sender of the first
packet of the flow. Flows are closed at the end of every daily capture. Only packet headers are used: payload lengths come from
the IP and TCP/UDP headers. The captures use the Linux cooked header (link type 113), which holds the sender's MAC address only.
mac_a is the sender MAC of the first packet of side a, mac_b that of the first packet of side b (empty if b never sent a packet).
The folder pcapIoT holds only the packets that the IoT devices sent, so most flows have one side. The TCP flags are therefore
counted for both sides: a device that sends a SYN opened the connection, a device that sends a SYN-ACK answered one.
"""
import sys, os, io, csv, gzip, struct, socket, zipfile
from concurrent.futures import ProcessPoolExecutor

COLS = ['t0', 't1', 'mac_a', 'mac_b', 'ip_a', 'ip_b', 'proto', 'port_a', 'port_b', 'pkts_a', 'pkts_b', 'pl_a', 'pl_b',
        'syn_a', 'synack_a', 'rst_a', 'syn_b', 'synack_b', 'rst_b']
GAP = 120.0


def mac(b):
    return ':'.join(f'{x:02x}' for x in b)


def _rd(f, n):
    """Read exactly n bytes (completing short reads of a stream). Returns fewer only at the end."""
    b = f.read(n)
    while len(b) < n:
        c = f.read(n - len(b))
        if not c:
            break
        b += c
    return b


def packets(f):
    """Yield (ts, linktype, frame) from a classic pcap stream."""
    gh = _rd(f, 24)
    if len(gh) < 24:
        return
    magic = gh[:4]
    if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
        e = '<'
    elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
        e = '>'
    else:
        raise ValueError('not a classic pcap file, first bytes: ' + gh[:16].hex())
    nano = magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    link = struct.unpack(e + 'I', gh[20:24])[0] & 0x0fffffff
    hdr = struct.Struct(e + 'IIII'); div = 1e9 if nano else 1e6
    while True:
        h = _rd(f, 16)
        if len(h) < 16:
            return
        sec, frac, incl, _orig = hdr.unpack(h)
        data = _rd(f, incl)
        if len(data) < incl:
            return
        yield sec + frac / div, link, data


def parse(link, buf):
    """(sender MAC, ip_src, ip_dst, proto, sport, dport, payload, syn, synack, rst) or None if the frame is not IP."""
    if link == 113:                                 # Linux cooked, version 1
        if len(buf) < 16:
            return None
        ms = buf[6:12]; et = (buf[14] << 8) | buf[15]; off = 16
    elif link == 276:                               # Linux cooked, version 2
        if len(buf) < 20:
            return None
        ms = buf[12:18]; et = (buf[0] << 8) | buf[1]; off = 20
    elif link == 1:                                 # Ethernet
        if len(buf) < 14:
            return None
        ms = buf[6:12]; et = (buf[12] << 8) | buf[13]; off = 14
    else:
        return None
    while et in (0x8100, 0x88a8) and len(buf) >= off + 4:      # VLAN tags
        et = (buf[off + 2] << 8) | buf[off + 3]; off += 4
    if et == 0x0800:
        if len(buf) < off + 20 or buf[off] >> 4 != 4 or (buf[off] & 0x0f) < 5:
            return None                              # not an IPv4 header
        ihl = (buf[off] & 0x0f) * 4
        tot = (buf[off + 2] << 8) | buf[off + 3]
        p = buf[off + 9]
        sa = socket.inet_ntoa(buf[off + 12:off + 16]); da = socket.inet_ntoa(buf[off + 16:off + 20])
        if ((buf[off + 6] & 0x1f) << 8) | buf[off + 7]:        # later fragment of a fragmented packet: no ports
            return ms, sa, da, p, -1, -1, max(tot - ihl, 0), 0, 0, 0
        l4 = off + ihl; l4len = tot - ihl
    elif et == 0x86dd:
        if len(buf) < off + 40 or buf[off] >> 4 != 6:
            return None                              # not an IPv6 header
        l4len = (buf[off + 4] << 8) | buf[off + 5]; p = buf[off + 6]
        sa = socket.inet_ntop(socket.AF_INET6, buf[off + 8:off + 24]); da = socket.inet_ntop(socket.AF_INET6, buf[off + 24:off + 40])
        l4 = off + 40
    else:
        return None
    sp = dp = -1; pl = max(l4len, 0); syn = synack = rst = 0
    if p == 6 and len(buf) >= l4 + 14:
        sp = (buf[l4] << 8) | buf[l4 + 1]; dp = (buf[l4 + 2] << 8) | buf[l4 + 3]
        doff = (buf[l4 + 12] >> 4) * 4; fl = buf[l4 + 13]
        pl = max(l4len - doff, 0)
        syn = int(bool(fl & 0x02) and not fl & 0x10); synack = int(bool(fl & 0x02) and bool(fl & 0x10)); rst = int(bool(fl & 0x04))
    elif p == 17 and len(buf) >= l4 + 8:
        sp = (buf[l4] << 8) | buf[l4 + 1]; dp = (buf[l4 + 2] << 8) | buf[l4 + 3]
        pl = max(((buf[l4 + 4] << 8) | buf[l4 + 5]) - 8, 0)
    return ms, sa, da, p, sp, dp, pl, syn, synack, rst


def reduce_stream(f):
    """Flow rows of one capture, and its statistics."""
    flows = {}; rows = []; n = bad = 0; first = last = None; link = -1
    for ts, link, buf in packets(f):
        n += 1
        if first is None:
            first = ts
        last = ts
        r = parse(link, buf)
        if r is None:
            bad += 1; continue
        ms, sa, da, p, sp, dp, pl, syn, synack, rst = r
        k = (sa, da, p, sp, dp); kr = (da, sa, p, dp, sp)
        fl = flows.get(k); rev = False
        if fl is None:
            fl = flows.get(kr); rev = fl is not None
        if fl is not None and abs(ts - fl[1]) > GAP:
            rows.append(fl); flows.pop(kr if rev else k); fl = None; rev = False
        if fl is None:
            # 0 t0, 1 t1, 2 mac_a, 3 mac_b, 4 ip_a, 5 ip_b, 6 proto, 7 port_a, 8 port_b, 9 pkts_a, 10 pkts_b, 11 pl_a, 12 pl_b,
            # 13 syn_a, 14 synack_a, 15 rst_a, 16 syn_b, 17 synack_b, 18 rst_b
            fl = [ts, ts, mac(ms), '', sa, da, p, sp, dp, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            flows[k] = fl
        fl[1] = ts
        if rev:
            if not fl[3]:
                fl[3] = mac(ms)
            fl[10] += 1; fl[12] += pl; fl[16] += syn; fl[17] += synack; fl[18] += rst
        else:
            fl[9] += 1; fl[11] += pl; fl[13] += syn; fl[14] += synack; fl[15] += rst
    rows.extend(flows.values())
    rows.sort(key=lambda r: (r[0], r[4], r[5], r[6], r[7], r[8]))
    return rows, dict(packets=n, not_ip=bad, flows=len(rows), first_ts=first, last_ts=last, linktype=link)


def work(job):
    src, member, out_dir = job
    name = os.path.splitext(os.path.basename(member))[0]
    target = os.path.join(out_dir, name + '.csv.gz'); stat = target + '.stat'
    if os.path.exists(target) and os.path.exists(stat):
        return name, open(stat).read().strip(), True
    if zipfile.is_zipfile(src):
        zf = zipfile.ZipFile(src); raw = zf.open(member)
    else:
        raw = open(member, 'rb')
    with raw, io.BufferedReader(raw, buffer_size=1 << 22) as f:
        rows, st = reduce_stream(f)
    tmp = target + '.tmp'
    with gzip.open(tmp, 'wt', newline='', compresslevel=6) as o:
        w = csv.writer(o); w.writerow(COLS)
        for r in rows:
            w.writerow([f'{r[0]:.3f}', f'{r[1]:.3f}'] + r[2:])
    os.replace(tmp, target)
    line = ','.join(str(x) for x in (name, st['packets'], st['not_ip'], st['flows'], st['first_ts'], st['last_ts'], st['linktype'],
                                    os.path.getsize(target)))
    with open(stat, 'w') as o:
        o.write(line + '\n')
    return name, line, False


def main(src, out_dir, workers):
    os.makedirs(out_dir, exist_ok=True)
    if zipfile.is_zipfile(src):
        members = sorted(n for n in zipfile.ZipFile(src).namelist() if n.lower().endswith(('.pcap', '.cap')))
    elif os.path.isdir(src):
        members = sorted(os.path.join(r, n) for r, _, fs in os.walk(src) for n in fs if n.lower().endswith(('.pcap', '.cap')))
    else:
        members = [src]
    print(f'{len(members)} capture files, {workers} worker(s)', flush=True)
    lines = []; done = 0
    with ProcessPoolExecutor(max_workers=workers) as ex:
        for name, line, skipped in ex.map(work, [(src, m, out_dir) for m in members]):
            done += 1; lines.append(line)
            print(f'  {done}/{len(members)} {name}' + (' (already done)' if skipped else '') + f': {line.split(",")[1]} packets, {line.split(",")[3]} flows',
                  flush=True)
    with open(os.path.join(out_dir, 'summary.csv'), 'w') as o:
        o.write('file,packets,not_ip,flows,first_ts,last_ts,linktype,bytes\n')
        o.write('\n'.join(sorted(lines)) + '\n')
    for n in os.listdir(out_dir):
        if n.endswith('.stat'):
            os.remove(os.path.join(out_dir, n))
    tot = sum(int(x.split(',')[1]) for x in lines); fl = sum(int(x.split(',')[3]) for x in lines)
    size = sum(os.path.getsize(os.path.join(out_dir, n)) for n in os.listdir(out_dir))
    print(f'Done: {len(lines)} files, {tot:,} packets, {fl:,} flows, output {size / 1e6:.1f} MB in {out_dir}')


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else max(1, min(6, (os.cpu_count() or 2) - 2)))
