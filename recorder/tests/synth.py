# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
"""Hand-made capture files for tests: Ethernet, IPv4, IPv6, TCP, UDP, ICMP and a little DNS.

Checksums are left at zero. Zeek is run with -C, which ignores them, as the recorder does.
"""
import socket
import struct


def _mac(s):
    return bytes.fromhex(s.replace(":", ""))


def eth(src, dst, payload, etype=0x0800, vlan=None):
    if vlan is None:
        return _mac(dst) + _mac(src) + struct.pack("!H", etype) + payload
    return _mac(dst) + _mac(src) + struct.pack("!HHH", 0x8100, vlan, etype) + payload


def ip4(src, dst, proto, payload):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0x4000, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + payload


def ip6(src, dst, nxt, payload):
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), nxt, 64,
                       socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst)) + payload


def tcp(sp, dp, seq, ack, flags, data=b""):
    f = sum({"F": 1, "S": 2, "R": 4, "P": 8, "A": 16}[c] for c in flags)
    return struct.pack("!HHIIBBHHH", sp, dp, seq & 0xffffffff, ack & 0xffffffff, 5 << 4, f, 65535, 0, 0) + data


def udp(sp, dp, data=b""):
    return struct.pack("!HHHH", sp, dp, 8 + len(data), 0) + data


def icmp_echo(reply=False, ident=1, seq=1, data=b"ping"):
    return struct.pack("!BBHHH", 0 if reply else 8, 0, 0, ident, seq) + data


def arp(sender, target, reply=False):
    """ARP: the request of 'sender' for the MAC address of 'target', or the reply of 'sender' to 'target'."""
    return struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2 if reply else 1, _mac(sender.mac),
                       socket.inet_aton(sender.ip), _mac(target.mac) if reply else b"\0" * 6,
                       socket.inet_aton(target.ip))


def dns_name(name):
    return b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0"


def dns_query(ident, name):
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", 1, 1)


def dns_answer(ident, name, addr):
    return struct.pack("!HHHHHH", ident, 0x8180, 1, 1, 0, 0) + dns_name(name) + struct.pack("!HH", 1, 1) + \
        struct.pack("!HHHIH4s", 0xc00c, 1, 1, 300, 4, socket.inet_aton(addr))


class Host:
    def __init__(self, mac, ip):
        self.mac, self.ip = mac, ip


class Pcap:
    """Collects frames with their times and writes a classic pcap file (microsecond resolution)."""

    def __init__(self):
        self.frames = []

    def add(self, t, frame):
        self.frames.append((t, frame))

    def send(self, t, a, b, l4, proto, via=None, to_mac=None, vlan=None):
        """One packet from host a to host b. via: the router's MAC address on this segment, for a remote b.
        to_mac: explicit destination MAC address (multicast, broadcast)."""
        v6 = ":" in a.ip
        body = ip6(a.ip, b.ip, proto, l4) if v6 else ip4(a.ip, b.ip, proto, l4)
        self.add(t, eth(a.mac, to_mac or via or b.mac, body, 0x86dd if v6 else 0x0800, vlan))

    def arp(self, t, a, b, vlan=None):
        """a asks for the MAC address of b by broadcast and b answers, as before any first packet between them."""
        self.add(t, eth(a.mac, "ff:ff:ff:ff:ff:ff", arp(a, b), 0x0806, vlan))
        self.add(t + 0.0005, eth(b.mac, a.mac, arp(b, a, reply=True), 0x0806, vlan))

    def write(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for t, fr in sorted(self.frames, key=lambda x: x[0]):
                sec = int(t)
                f.write(struct.pack("<IIII", sec, int(round((t - sec) * 1e6)), len(fr), len(fr)) + fr)
        return len(self.frames)


class Tcp:
    """One TCP conversation between a client and a server, with correct sequence numbers."""

    def __init__(self, pcap, client, server, cport, sport, vlan=None):
        self.p, self.c, self.s, self.cp, self.sp, self.vlan = pcap, client, server, cport, sport, vlan
        self.cseq, self.sseq = 1000, 5000

    def _c(self, t, flags, data=b""):
        self.p.send(t, self.c, self.s, tcp(self.cp, self.sp, self.cseq, self.sseq, flags, data), 6, vlan=self.vlan)
        self.cseq += len(data) + (1 if "S" in flags or "F" in flags else 0)

    def _s(self, t, flags, data=b""):
        self.p.send(t, self.s, self.c, tcp(self.sp, self.cp, self.sseq, self.cseq, flags, data), 6, vlan=self.vlan)
        self.sseq += len(data) + (1 if "S" in flags or "F" in flags else 0)

    def handshake(self, t):
        self._c(t, "S")
        self._s(t + 0.001, "SA")
        self._c(t + 0.002, "A")
        return self

    def client_says(self, t, n=10):
        self._c(t, "PA", b"c" * n)
        self._s(t + 0.001, "A")
        return self

    def server_says(self, t, n=20):
        self._s(t, "PA", b"s" * n)
        self._c(t + 0.001, "A")
        return self

    def close(self, t):
        self._c(t, "FA")
        self._s(t + 0.001, "FA")
        self._c(t + 0.002, "A")
        return self

    def syn(self, t):
        self._c(t, "S")
        return self

    def server_probe(self, t):
        """A keep-alive probe of the server that nobody answers (the client is switched off)."""
        self._s(t, "A")
        return self

    def refused(self, t):
        self._c(t, "S")
        self.p.send(t + 0.001, self.s, self.c, tcp(self.sp, self.cp, 0, self.cseq, "RA"), 6)
        return self

    def stray_ack(self, t):
        self._c(t, "A")
        self.p.send(t + 0.001, self.s, self.c, tcp(self.sp, self.cp, self.sseq, 0, "R"), 6)
        return self
