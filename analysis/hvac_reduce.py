#!/usr/bin/env python3
"""Reduce the HVAC control network traces (github.com/gkabasele/HVAC_Traces, hvac_traces.tar.gz) to flow records.

Usage (in the folder that holds hvac_traces.tar.gz):
    pip install pyarrow
    python hvac_reduce.py hvac_traces.tar.gz

Output: folder 'hvac_parts' (.bin parts of 19 MB and manifest_hvac.json, join.py rebuilds the file).
The archive is read as a stream, pcap by pcap. Only packet headers are used.
Flow: bidirectional 5-tuple, split after a gap of 120 s. Side a is the sender of the first packet of the flow.
Payload length is computed from the IP and TCP/UDP headers (the payload is truncated in the traces).
"""
import sys, os, io, json, gzip, struct, socket, tarfile, hashlib
import pyarrow as pa, pyarrow.parquet as pq

PART = 19_000_000
OUT = 'hvac_parts'
COLS = ['file', 't0', 't1', 'mac_a', 'mac_b', 'ip_a', 'ip_b', 'proto', 'port_a', 'port_b',
        'pkts_a', 'pkts_b', 'pl_a', 'pl_b', 'syn_a', 'synack_b', 'rst_b']


def mac(b):
    return ':'.join(f'{x:02x}' for x in b)


class _Pre:
    """Small wrapper that puts the bytes already read back in front."""
    def __init__(self, head, f): self.h, self.f = head, f
    def read(self, n=-1):
        if self.h:
            if n < 0 or n >= len(self.h):
                out, self.h = self.h, b''
                return out + (self.f.read() if n < 0 else self.f.read(n - len(out)))
            out, self.h = self.h[:n], self.h[n:]
            return out
        return self.f.read(n)


def _rd(f, n):
    """Read exactly n bytes (completing short reads of the stream). Returns fewer only at the end."""
    b = f.read(n)
    while len(b) < n:
        c = f.read(n - len(b))
        if not c: break
        b += c
    return b


def packets(f):
    """Yield (ts, linktype, frame). Classic pcap, pcapng and their gzip-compressed forms."""
    head = _rd(f, 4)
    if head[:2] == b'\x1f\x8b':                       # gzip even without the extension
        f = gzip.GzipFile(fileobj=_Pre(head, f)); head = _rd(f, 4)
    if head == b'\x0a\x0d\x0d\x0a':
        yield from _pcapng(_Pre(head, f)); return
    gh = head + _rd(f, 20)
    if len(gh) < 24:
        return
    magic = gh[:4]
    if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
        e = '<'
    elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
        e = '>'
    else:
        raise ValueError('taninmayan bicim, ilk baytlar: ' + gh[:16].hex())
    nano = magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    link = struct.unpack(e + 'I', gh[20:24])[0]
    hdr = struct.Struct(e + 'IIII')
    while True:
        h = _rd(f, 16)
        if len(h) < 16:
            return
        sec, frac, incl, _orig = hdr.unpack(h)
        data = _rd(f, incl)
        if len(data) < incl:
            return
        yield sec + frac / (1e9 if nano else 1e6), link, data


def _pcapng(f):
    e = '<'; ifaces = []                              # (linktype, time units per second)
    while True:
        h = _rd(f, 8)
        if len(h) < 8:
            return
        btype = struct.unpack(e + 'I', h[:4])[0]
        if btype == 0x0A0D0D0A:                       # section header: sets the byte order
            bom = _rd(f, 4)
            e = '<' if bom == b'\x4d\x3c\x2b\x1a' else '>'
            blen = struct.unpack(e + 'I', h[4:8])[0]
            _rd(f, blen - 12); ifaces = []
            continue
        blen = struct.unpack(e + 'I', h[4:8])[0]
        body = _rd(f, blen - 8)
        if len(body) < blen - 8:
            return
        body = body[:-4]
        if btype == 1:                                # interface description
            link = struct.unpack(e + 'H', body[:2])[0]; res = 1e6; o = 8
            while o + 4 <= len(body):
                code, ln = struct.unpack(e + 'HH', body[o:o + 4])
                if code == 0: break
                if code == 9 and ln >= 1:
                    v = body[o + 4]; res = float(2 ** (v & 0x7f)) if v & 0x80 else float(10 ** v)
                o += 4 + ((ln + 3) & ~3)
            ifaces.append((link, res))
        elif btype == 6 and len(body) >= 20:          # enhanced packet block
            iid, th, tl, cap, _orig = struct.unpack(e + 'IIIII', body[:20])
            link, res = ifaces[iid] if iid < len(ifaces) else (1, 1e6)
            yield ((th << 32) | tl) / res, link, body[20:20 + cap]
        elif btype == 3 and len(body) >= 4 and ifaces:  # simple packet block (no timestamp)
            yield 0.0, ifaces[0][0], body[4:]


def parse(link, buf):
    """(mac_src, mac_dst, ip_src, ip_dst, proto, sport, dport, payload, syn, synack, rst) or None"""
    ms = md = b'\0' * 6
    if link == 1:                                   # Ethernet
        if len(buf) < 14: return None
        md, ms = buf[0:6], buf[6:12]
        et = (buf[12] << 8) | buf[13]; off = 14
        while et in (0x8100, 0x88a8) and len(buf) >= off + 4:
            et = (buf[off + 2] << 8) | buf[off + 3]; off += 4
    elif link == 113:                               # Linux cooked
        if len(buf) < 16: return None
        ms = buf[6:12]; et = (buf[14] << 8) | buf[15]; off = 16
    elif link in (12, 101, 228, 229):               # raw IP
        if not buf: return None
        et = 0x0800 if buf[0] >> 4 == 4 else 0x86dd; off = 0
    else:
        return None
    if et == 0x0800:
        if len(buf) < off + 20: return None
        ihl = (buf[off] & 0x0f) * 4
        tot = (buf[off + 2] << 8) | buf[off + 3]
        p = buf[off + 9]
        if ((buf[off + 6] & 0x1f) << 8) | buf[off + 7]:    # later fragment of a fragmented packet: no ports
            return ms, md, socket.inet_ntoa(buf[off + 12:off + 16]), socket.inet_ntoa(buf[off + 16:off + 20]), p, -1, -1, max(tot - ihl, 0), 0, 0, 0
        sa = socket.inet_ntoa(buf[off + 12:off + 16]); da = socket.inet_ntoa(buf[off + 16:off + 20])
        l4 = off + ihl; l4len = tot - ihl
    elif et == 0x86dd:
        if len(buf) < off + 40: return None
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
    return ms, md, sa, da, p, sp, dp, pl, syn, synack, rst


def reduce_pcap(name, f, rows, flows, stats):
    for ts, link, buf in packets(f):
        stats[0] += 1
        r = parse(link, buf)
        if r is None:
            stats[1] += 1; continue
        ms, md, sa, da, p, sp, dp, pl, syn, synack, rst = r
        k = (sa, da, p, sp, dp); kr = (da, sa, p, dp, sp)
        fl = flows.get(k); rev = False
        if fl is None:
            fl = flows.get(kr); rev = fl is not None
        if fl is not None and abs(ts - fl[1]) > 120:
            rows.append((fl[14], fl[0], fl[1], *fl[2:14], fl[15], fl[16])); flows.pop(kr if rev else k); fl = None; rev = False
        if fl is None:
            # t0, t1, mac_a, mac_b, ip_a, ip_b, proto, port_a, port_b, pkts_a, pkts_b, pl_a, pl_b, syn_a, file, synack_b, rst_b
            fl = [ts, ts, mac(ms), mac(md), sa, da, p, sp, dp, 0, 0, 0, 0, 0, name, 0, 0]
            flows[k] = fl
        fl[1] = ts
        if rev:
            fl[10] += 1; fl[12] += pl; fl[15] += synack; fl[16] += rst
        else:
            fl[9] += 1; fl[11] += pl; fl[13] += syn


def members(path):
    """Yield (name, file object): a tar archive, a single pcap or a folder of pcaps."""
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for n in sorted(files):
                if '.pcap' in n.lower() or n.lower().endswith('.cap'):
                    p = os.path.join(root, n)
                    yield n, (gzip.open(p, 'rb') if n.endswith('.gz') else open(p, 'rb'))
    elif tarfile.is_tarfile(path):
        with tarfile.open(path, 'r|*') as tf:
            for m in tf:
                low = m.name.lower()
                if m.isfile() and ('.pcap' in low or low.endswith('.cap')):
                    f = tf.extractfile(m)
                    yield os.path.basename(m.name), (gzip.GzipFile(fileobj=f) if low.endswith('.gz') else f)
    else:
        yield os.path.basename(path), open(path, 'rb')


def main(paths, out_name='hvac_flows'):
    os.makedirs(OUT, exist_ok=True)
    rows = []; flows = {}; stats = [0, 0]; nfiles = 0; nskip = 0
    for path in paths:
        for name, f in members(path):
            try:
                reduce_pcap(name, f, rows, flows, stats)
            except Exception as e:
                nskip += 1
                if nskip <= 3: print('  skipped:', name, e)
            nfiles += 1
            if nfiles % 10 == 0:
                print(f'  {nfiles} files, {stats[0]:,} packets, {len(rows) + len(flows):,} flows', flush=True)
    for fl in flows.values():
        rows.append((fl[14], fl[0], fl[1], *fl[2:14], fl[15], fl[16]))
    if not rows:
        print(f'No packet could be read ({nfiles} files tried, {nskip} skipped).'); return
    t = pa.table({c: [r[i] for r in rows] for i, c in enumerate(COLS)})
    out_path = os.path.join(OUT, out_name + '.parquet')
    pq.write_table(t, out_path, compression='zstd', compression_level=9)
    size = os.path.getsize(out_path)
    print(f'{nfiles} files, {stats[0]:,} packets ({stats[1]:,} not IP), {len(rows):,} flows, output {size / 1e6:.1f} MB')
    h = hashlib.sha256(); parts = []
    with open(out_path, 'rb') as f:
        i = 0
        while True:
            chunk = f.read(PART)
            if not chunk: break
            i += 1; h.update(chunk)
            pn = f'{out_name}.parquet.part{i:03d}.bin'
            with open(os.path.join(OUT, pn), 'wb') as o: o.write(chunk)
            parts.append({'file': pn, 'bytes': len(chunk), 'sha256': hashlib.sha256(chunk).hexdigest()})
    os.remove(out_path)
    with open(os.path.join(OUT, 'manifest_hvac.json'), 'w') as f:
        json.dump({out_name + '.parquet': {'type': 'raw', 'bytes': size, 'sha256': h.hexdigest(), 'rows': len(rows), 'parts': parts}}, f, indent=1)
    print(f"Done. The files are in '{OUT}'.")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    main(sys.argv[1:])
