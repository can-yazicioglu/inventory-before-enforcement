# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
"""Small pcap helper for the end-to-end tests. Classic little-endian pcap files only.

  pcaptool.py info  <file.pcap>...             packets, duration, distinct source MAC addresses
  pcaptool.py merge <out.pcap> <in.pcap>...    concatenate captures that follow each other in time
  pcaptool.py dup   <out.pcap> <in.pcap>       write every packet twice (a mirror of both directions)
"""
import struct
import sys

MAGIC = b"\xd4\xc3\xb2\xa1"


def packets(path):
    with open(path, "rb") as f:
        head = f.read(24)
        if head[:4] != MAGIC:
            raise SystemExit(f"{path}: not a little-endian classic pcap file")
        yield head
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            caplen = struct.unpack("<I", h[8:12])[0]
            d = f.read(caplen)
            if len(d) < caplen:
                return
            yield h + d


def info(paths):
    for p in paths:
        it = packets(p)
        next(it)
        n, t0, t1, macs = 0, None, None, set()
        for pkt in it:
            sec, usec = struct.unpack("<II", pkt[:8])
            t1 = sec + usec / 1e6
            t0 = t1 if t0 is None else t0
            macs.add(pkt[22:28])
            n += 1
        print(f"{p}: packets {n}, seconds {0 if t0 is None else round(t1 - t0, 1)}, source MACs {len(macs)}")


def merge(out, paths, copies=1):
    n = 0
    with open(out, "wb") as o:
        for k, p in enumerate(paths):
            it = packets(p)
            head = next(it)
            if k == 0:
                o.write(head)
            for pkt in it:
                o.write(pkt * copies)
                n += copies
    print(f"{out}: packets {n}")


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "info":
        info(args)
    elif cmd == "merge":
        merge(args[0], args[1:])
    elif cmd == "dup":
        merge(args[0], args[1:2], copies=2)
    else:
        raise SystemExit(__doc__)
