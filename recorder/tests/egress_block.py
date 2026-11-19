#!/usr/bin/env python3
# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
"""Shows that a capture interface cannot transmit once the recorder's nftables rule is loaded.

A virtual cable is created, 20 raw Ethernet frames are sent into one end and counted at the other,
first without the rule, then with it, then with the rule loaded a second time (it must be safe to
load twice). The rule is the file that install.sh writes for that interface, not a copy of it.
Needs root, iproute2 and nftables. Usage: egress_block.py
"""
import os
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_installer import fake_install  # noqa: E402

A, B = "ibet0", "ibet1"


def sh(*cmd, check=True, text=None):
    return subprocess.run(cmd, check=check, input=text, text=True, capture_output=True)


def arrived(n=20):
    def rx():
        with open(f"/sys/class/net/{A}/statistics/rx_packets") as f:
            return int(f.read())
    before, sent = rx(), 0
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((B, 0))
    for _ in range(n):
        try:
            s.send(b"\xff" * 6 + b"\x02\x00\x00\x00\x00\x01" + b"\x88\xb5" + b"x" * 46)
            sent += 1
        except OSError:
            pass
    s.close()
    time.sleep(0.5)
    return sent, rx() - before


def main():
    with tempfile.TemporaryDirectory() as root:              # let the installer write its rule file
        r = fake_install(root, [B])
        if r.returncode:
            raise SystemExit("install.sh failed: " + r.stdout[-300:] + r.stderr[-300:])
        with open(os.path.join(root, "etc", "ibe", f"egress-{B}.nft"), encoding="utf-8") as f:
            rule = f.read()
    sh("ip", "link", "del", A, check=False)
    sh("ip", "link", "add", A, "type", "veth", "peer", "name", B)
    try:
        for i in (A, B):
            sh("sysctl", "-q", "-w", f"net.ipv6.conf.{i}.disable_ipv6=1", check=False)
            sh("ip", "link", "set", i, "up", "arp", "off")
        time.sleep(1)
        free = arrived()
        sh("nft", "-f", "-", text=rule)
        blocked = arrived()
        sh("nft", "-f", "-", text=rule)
        again = arrived()
        print(f"without the rule: {free[0]} of 20 frames accepted, {free[1]} arrived")
        print(f"with the rule:    {blocked[0]} of 20 frames accepted, {blocked[1]} arrived")
        print(f"rule loaded twice: {again[0]} of 20 frames accepted, {again[1]} arrived")
        ok = free[1] == 20 and blocked == (0, 0) and again == (0, 0)
        print("PASS" if ok else "FAIL")
        raise SystemExit(0 if ok else 1)
    finally:
        sh("nft", "delete", "table", "netdev", f"ibe_{B}", check=False)
        sh("ip", "link", "del", A, check=False)


if __name__ == "__main__":
    main()
