#!/usr/bin/env python3
# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
"""Hand-made traffic with known answers, through the whole chain.

  hand-made capture -> Zeek (recorder script) -> anonymiser, hour by hour -> adapter -> incidence

Each case below is a situation that a connection log gets wrong unless it is handled on purpose.
The expected flow types of every device on every day are written down next to the case, and the
result must equal them exactly.

  long        a connection that stays open for 50 hours counts on each of its three days
  endless     a connection that is still open when the recording stops counts on each day too
  midstream   a connection that was open before the recording started, in which the server speaks
              first, is not mistaken for the server opening a connection to a client port
  idle        a connection that is silent for 20 minutes is still one connection with the right roles
  slow udp    an answer after 90 seconds belongs to the question, it is not a new flow of the server
  refused, stray, unanswered    the device that did not take part gets nothing
  midnight    a connection counts on every day on which it carried packets, however short it is,
              also when it ends between two hourly reports or is silent until just before midnight
  remote      remote hosts collapse to 'wan', the router is learned and is not a device
  ipv6, vlan, multicast, broadcast, icmp, port reuse
  dhcp        three devices that ask for an address within two minutes are three devices
  ping        a ping that runs for days counts on each day, whichever side has the higher address,
              and a ping that is not answered gives the silent device nothing
  answers     the unicast answer to a multicast question gives the asker nothing
  switched off    keep-alive probes to a device that is off do not make it active on that day
  routed      two devices in different VLANs that talk through a router keep their own names, the
              router is recognised although it leads to no outside network, and it has one name
  late        a flow that begins while the other device is switched off, and goes on after that
              device comes up on the next day, does not make the device active on the first day
  tunnels     a device that keeps a tunnel has the tunnel as its flow, and the addresses inside
              the tunnel do not become devices
  held        an answer that is the first packet after midnight counts on the day it was sent
              (a second capture, silent around midnight)
  flood       connection attempts that never got going are kept for a day up to a limit only

The same logs are then fed through two capture ports, and the capture is repeated with every frame
doubled (a switch that mirrors both directions): the flow types must not change.

Usage: scenarios.py --work DIR [--zeek /opt/zeek/bin/zeek]
Needs: zeek, duckdb, pyarrow.
"""
import argparse
import calendar
import datetime
import glob
import gzip
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
from zoneinfo import ZoneInfo

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "recorder"))
sys.path.insert(0, os.path.join(REPO, "analysis"))
sys.path.insert(0, HERE)
from ibe_recorder import core, pipeline  # noqa: E402
import synth  # noqa: E402

TZ = "Europe/Istanbul"
T0 = 1798538400                 # 2026-12-29 10:00 UTC, 13:00 in Istanbul
H = 3600
MIDNIGHT = T0 + 11 * H          # 00:00 on 30 December in Istanbul
END = T0 + 56 * H
GW = "02:00:00:00:00:fe"
C1 = synth.Host("02:00:00:00:00:0a", "192.168.1.10")
S1 = synth.Host("02:00:00:00:00:0b", "192.168.1.20")
D3 = synth.Host("02:00:00:00:00:0c", "192.168.1.30")
D4 = synth.Host("02:00:00:00:00:14", "192.168.1.41")
D5 = synth.Host("02:00:00:00:00:15", "192.168.1.42")
D6 = synth.Host("02:00:00:00:00:16", "192.168.1.43")
D7 = synth.Host("02:00:00:00:00:17", "192.168.1.44")          # switched off on the 29th
M = synth.Host("02:00:00:00:00:0d", "192.168.1.200")          # a monitoring host with the highest address
E1 = synth.Host("02:00:00:00:00:1a", "192.168.10.5")          # VLAN 10
E2 = synth.Host("02:00:00:00:00:1b", "192.168.20.5")          # VLAN 20
RX = "02:00:00:00:00:fd"                                      # routes between VLAN 10 and 20, leads nowhere else
RX10, RX20 = synth.Host(RX, "192.168.10.1"), synth.Host(RX, "192.168.20.1")
NAMES = {"C1": C1.mac, "S1": S1.mac, "D3": D3.mac, "D4": D4.mac, "D5": D5.mac, "D6": D6.mac, "D7": D7.mac, "M": M.mac,
         "E1": E1.mac, "E2": E2.mac, "GW": GW, "RX": RX}
SECRETS = ("192.168.", "52.1.", "8.8.8.8", "02:00:00", "020000", "fe80", "teamviewer", "224.0.0", "239.255",
           "192.88.", "52.9.", "10.99.", "2002:", "2a00:")


def routed(p, frames, vlan_of):
    """Add frames between two VLANs as a mirror of both VLANs delivers them: once on the way to the router
    and once on the way from it, with the router's MAC address on the routed side."""
    for t, fr in frames:
        dst, src, rest = fr[:6], fr[6:12], fr[12:]
        p.add(t, synth._mac(RX) + src + struct.pack("!HH", 0x8100, vlan_of[src]) + rest)
        p.add(t + 0.00005, dst + synth._mac(RX) + struct.pack("!HH", 0x8100, vlan_of[dst]) + rest)


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"  ({detail})" if detail else ""), flush=True)
    if not ok:
        raise SystemExit(1)


def build(path, double=False):
    """Write the capture and return {(device name, day of month, flow type)} expected at svc level."""
    p = synth.Pcap()
    want = set()

    def expect(dev, days, ftype):
        want.update((dev, d, ftype) for d in days)

    # long: opened at 13:00 on the 29th, data every half hour, closed at 15:01 on the 31st
    c = synth.Tcp(p, C1, S1, 40001, 8080).handshake(T0)
    for k in range(1, 101):
        c.client_says(T0 + k * 1800).server_says(T0 + k * 1800 + 1)
    c.close(T0 + 50 * H + 100)
    expect("C1", (29, 30, 31), "6/out/8080@dev:S1")
    expect("S1", (29, 30, 31), "6/in/8080@dev:C1")

    # endless: data every 20 minutes until 17:00 on the 31st, never closed
    c = synth.Tcp(p, C1, S1, 40002, 8090).handshake(T0 + 1)
    for k in range(1, 3 * 52 + 1):
        c.client_says(T0 + 1 + k * 1200)
    expect("C1", (29, 30, 31), "6/out/8090@dev:S1")
    expect("S1", (29, 30, 31), "6/in/8090@dev:C1")

    # midstream: no handshake, the server sends every 40 minutes until 19:00 on the 30th.
    # Three ordinary connections to the same service on the 29th show which port is the service.
    c = synth.Tcp(p, C1, S1, 2001, 8081)
    for k in range(0, 45):
        c.server_says(T0 + 5 + k * 2400)
    for i in range(3):
        synth.Tcp(p, C1, S1, 41000 + i, 8081).handshake(T0 + 20 + i).client_says(T0 + 21 + i).close(T0 + 22 + i)
    expect("C1", (29, 30), "6/out/8081@dev:S1")
    expect("S1", (29, 30), "6/in/8081@dev:C1")

    # idle: 20 minutes of silence, then the server speaks first
    synth.Tcp(p, C1, S1, 40004, 8083).handshake(T0 + 7).client_says(T0 + 7.1).server_says(T0 + 1207).close(T0 + 1300)
    expect("C1", (29,), "6/out/8083@dev:S1")
    expect("S1", (29,), "6/in/8083@dev:C1")

    # slow udp: the answer comes after 90 seconds
    p.send(T0 + 8, C1, S1, synth.udp(40005, 9999, b"question"), 17)
    p.send(T0 + 98, S1, C1, synth.udp(9999, 40005, b"answer"), 17)
    expect("C1", (29,), "17/out/9999@dev:S1")
    expect("S1", (29,), "17/in/9999@dev:C1")

    # refused, stray packet answered by a reset, unanswered: nothing for the other side
    synth.Tcp(p, C1, S1, 40006, 8084).refused(T0 + 9)
    synth.Tcp(p, C1, S1, 40007, 8085).stray_ack(T0 + 10)
    synth.Tcp(p, C1, D3, 40008, 8086).syn(T0 + 11)
    expect("C1", (29,), "6/out/8084@dev:S1")
    expect("C1", (29,), "6/out/8085@dev:S1")
    expect("C1", (29,), "6/out/8086@dev:D3")

    # remote: 20 hosts behind the router, one of them named by a DNS answer
    p.send(T0 + 12, C1, synth.Host(GW, "8.8.8.8"), synth.udp(40020, 53, synth.dns_query(7, "router7.teamviewer.com")), 17, via=GW)
    p.send(T0 + 12.05, synth.Host(GW, "8.8.8.8"), C1, synth.udp(53, 40020, synth.dns_answer(7, "router7.teamviewer.com", "52.1.0.3")), 17)
    for k in range(20):
        synth.Tcp(p, C1, synth.Host(GW, f"52.1.{k}.3"), 42000 + k, 443).handshake(T0 + 13 + k).client_says(T0 + 13.2 + k).close(T0 + 13.4 + k)
    expect("C1", (29,), "17/out/53@wan")
    expect("C1", (29,), "6/out/443@wan")

    # ipv6: the same two devices, known by their MAC addresses
    synth.Tcp(p, synth.Host(C1.mac, "fe80::a"), synth.Host(S1.mac, "fe80::b"), 40009, 5000) \
        .handshake(T0 + 40).client_says(T0 + 40.1).close(T0 + 40.2)
    expect("C1", (29,), "6/out/5000@dev:S1")
    expect("S1", (29,), "6/in/5000@dev:C1")

    # multicast and broadcast. The unicast answer to a multicast question is a flow of its own, opened by
    # the answering device towards a client port (ports from 32768 form one class)
    p.send(T0 + 41, C1, synth.Host("", "224.0.0.251"), synth.udp(5353, 5353, b"mdns"), 17, to_mac="01:00:5e:00:00:fb")
    p.send(T0 + 42, C1, synth.Host("", "239.255.255.250"), synth.udp(40010, 1900, b"M-SEARCH"), 17, to_mac="01:00:5e:7f:ff:fa")
    p.send(T0 + 42.5, D3, C1, synth.udp(1900, 40010, b"HTTP/1.1 200 OK"), 17)
    p.send(T0 + 43, C1, synth.Host("", "255.255.255.255"), synth.udp(68, 67, b"dhcp"), 17, to_mac="ff:ff:ff:ff:ff:ff")
    expect("C1", (29,), "17/out/5353@mcast:mdns")
    expect("C1", (29,), "17/out/1900@mcast:ssdp")
    expect("D3", (29,), "17/out/hi@dev:C1")
    expect("C1", (29,), "17/out/67@bcast")

    # vlan tag, icmp, the same ports used twice
    synth.Tcp(p, C1, S1, 40012, 9100, vlan=20).handshake(T0 + 44).client_says(T0 + 44.1).close(T0 + 44.2)
    p.send(T0 + 45, C1, S1, synth.icmp_echo(), 1)
    p.send(T0 + 45.01, S1, C1, synth.icmp_echo(reply=True), 1)
    for t in (T0 + 46, T0 + 646):
        synth.Tcp(p, C1, S1, 40011, 8087).handshake(t).client_says(t + 0.1).close(t + 1)
    expect("C1", (29,), "6/out/9100@dev:S1")
    expect("S1", (29,), "6/in/9100@dev:C1")
    expect("C1", (29,), "1@dev:S1")
    expect("S1", (29,), "1@dev:C1")
    expect("C1", (29,), "6/out/8087@dev:S1")
    expect("S1", (29,), "6/in/8087@dev:C1")

    # midnight: 30 seconds across it and two hours across it both count on both days
    synth.Tcp(p, C1, S1, 40013, 8088).handshake(MIDNIGHT - 10).client_says(MIDNIGHT + 10).close(MIDNIGHT + 20)
    c = synth.Tcp(p, C1, S1, 40014, 8089).handshake(MIDNIGHT - 1800)
    for k in range(1, 12):
        c.client_says(MIDNIGHT - 1800 + k * 600)
    c.close(MIDNIGHT + 5400)
    expect("C1", (29, 30), "6/out/8088@dev:S1")
    expect("S1", (29, 30), "6/in/8088@dev:C1")
    expect("C1", (29, 30), "6/out/8089@dev:S1")
    expect("S1", (29, 30), "6/in/8089@dev:C1")
    # opened at 20:30 on the 30th, data every ten minutes, closed at 00:25 on the 31st: between two reports
    c = synth.Tcp(p, C1, S1, 40015, 8101).handshake(MIDNIGHT + 20 * H + 1805)
    for k in range(1, 24):
        c.client_says(MIDNIGHT + 20 * H + 1805 + k * 600)
    c.close(MIDNIGHT + 24 * H + 1500)
    expect("C1", (30, 31), "6/out/8101@dev:S1")
    expect("S1", (30, 31), "6/in/8101@dev:C1")
    # opened at 23:45 on the 29th, then silent. One packet at 23:47 on the 30th and one at 00:05 on the 31st
    # (the same hour of the connection's life, on two days), closed at 10:00 on the 31st
    c = synth.Tcp(p, C1, S1, 40016, 8102).handshake(MIDNIGHT - 900).client_says(MIDNIGHT - 600)
    c.client_says(MIDNIGHT + 24 * H - 780).client_says(MIDNIGHT + 24 * H + 300)
    c.client_says(MIDNIGHT + 34 * H).close(MIDNIGHT + 34 * H + 5)
    expect("C1", (29, 30, 31), "6/out/8102@dev:S1")
    expect("S1", (29, 30, 31), "6/in/8102@dev:C1")

    # dhcp: three devices ask for an address within two minutes, with the same addresses and ports
    # (0.0.0.0:68 to 255.255.255.255:67). On the next day in another order.
    everyone = synth.Host("", "255.255.255.255")
    for day, order in ((0, (D4, D5, D6)), (1, (D6, D5, D4))):
        for k, dev in enumerate(order):
            for step in (0, 2):                                   # discover, then request
                p.send(T0 + 3000 + day * 86400 + k * 40 + step, synth.Host(dev.mac, "0.0.0.0"), everyone,
                       synth.udp(68, 67, b"dhcp"), 17, to_mac="ff:ff:ff:ff:ff:ff")
    for dev in ("D4", "D5", "D6"):
        expect(dev, (29, 30), "17/out/67@bcast")

    # ping: every 30 seconds from the 29th to noon on the 31st, from the host with the higher address
    t = T0 + 3200
    while t < MIDNIGHT + 36 * H:
        p.send(t, M, D3, synth.icmp_echo(seq=int(t) & 0xffff), 1)
        p.send(t + 0.01, D3, M, synth.icmp_echo(reply=True, seq=int(t) & 0xffff), 1)
        t += 30
    expect("M", (29, 30, 31), "1@dev:D3")
    expect("D3", (29, 30, 31), "1@dev:M")
    # a ping that is not answered: only the device that sent it has the type. A datagram to a closed port,
    # refused with an ICMP error message: the refusing device has no flow type, as after a TCP reset.
    p.send(T0 + 3300, M, D5, synth.icmp_echo(ident=9), 1)
    p.send(T0 + 3310, D6, D4, synth.udp(40050, 9, b"probe"), 17)
    p.send(T0 + 3310.01, D4, D6, struct.pack("!BBHI", 3, 3, 0, 0) + bytes(28), 1)       # port unreachable
    expect("M", (29,), "1@dev:D5")
    expect("D6", (29,), "17/out/9@dev:D4")

    # answers: a name question to a group address, answered from the service port to the asker's port.
    # The answering device serves that port. The asker sent nothing in that flow and gets nothing for it.
    p.send(T0 + 3400, C1, synth.Host("", "224.0.0.252"), synth.udp(40030, 5355, b"who is oct1"), 17, to_mac="01:00:5e:00:00:fc")
    p.send(T0 + 3400.02, D3, C1, synth.udp(5355, 40030, b"i am"), 17)
    expect("C1", (29,), "17/out/5355@mcast:llmnr")
    expect("D3", (29,), "17/in/5355@dev:C1")

    # switched off: D4 opens a connection at 15:00, works for half an hour and is cut off without closing.
    # The server probes at 00:30 on the 30th, nobody answers. D4 is not active on the 30th.
    c = synth.Tcp(p, D4, S1, 40040, 8110).handshake(T0 + 2 * H)
    for k in range(1, 4):
        c.client_says(T0 + 2 * H + k * 600)
    for k in range(8):
        c.server_probe(MIDNIGHT + 1800 + k * 75)
    expect("D4", (29,), "6/out/8110@dev:S1")
    expect("S1", (29, 30), "6/in/8110@dev:D4")

    # routed: E1 (VLAN 10) prints on E2 (VLAN 20) and E2 sends a scan to E1, through a router that leads to
    # no outside network and is not listed. Both VLANs are mirrored, so every frame is captured twice.
    # E1 also asks the router itself for the time. On the 30th E2 is off and E1 gets no answer.
    for t in (T0 + 2000, MIDNIGHT + 10 * H - 5):                  # the devices and the router ask for each other
        p.arp(t, E1, RX10, vlan=10)
        p.arp(t + 0.1, RX10, E1, vlan=10)
        p.arp(t + 0.2, E2, RX20, vlan=20)
        p.arp(t + 0.3, RX20, E2, vlan=20)
    lan = synth.Pcap()
    synth.Tcp(lan, E1, E2, 40060, 9100).handshake(T0 + 2010).client_says(T0 + 2010.1).close(T0 + 2010.2)
    synth.Tcp(lan, E2, E1, 40061, 445).handshake(T0 + 2070).client_says(T0 + 2070.1).close(T0 + 2070.2)
    synth.Tcp(lan, E1, E2, 40062, 9100).syn(MIDNIGHT + 10 * H)
    routed(p, lan.frames, {synth._mac(E1.mac): 10, synth._mac(E2.mac): 20})
    p.send(T0 + 2100, E1, RX10, synth.udp(40063, 123, b"time?"), 17, vlan=10)
    p.send(T0 + 2100.01, RX10, E1, synth.udp(123, 40063, b"time"), 17, vlan=10)
    expect("E1", (29, 30), "6/out/9100@dev:E2")
    expect("E2", (29,), "6/in/9100@dev:E1")
    expect("E2", (29,), "6/out/445@dev:E1")
    expect("E1", (29,), "6/in/445@dev:E2")
    expect("E1", (29,), "17/out/123@dev:RX")

    # late: D7 is switched off on the 29th and comes up at 10:00 on the 30th. Three flows towards it begin on
    # the 29th and never pause: a datagram every minute, a ping every 30 seconds, and a server that sends from
    # its service port (Zeek turns that record around, so D7 is its originator). D7 sent nothing on the 29th.
    up = MIDNIGHT + 10 * H
    t = T0 + 3500
    while t < MIDNIGHT + 12 * H:
        p.send(t, D5, D7, synth.udp(40070, 7000, b"hello"), 17)
        p.send(t + 3, S1, D7, synth.udp(443, 40071, b"here"), 17)
        for k in (0, 30):
            p.send(t + 7 + k, M, D7, synth.icmp_echo(ident=7, seq=int(t + k) & 0xffff), 1)
            if t >= up:
                p.send(t + 7.01 + k, D7, M, synth.icmp_echo(reply=True, ident=7, seq=int(t + k) & 0xffff), 1)
        if t >= up:
            p.send(t + 0.2, D7, D5, synth.udp(7000, 40070, b"ok"), 17)
            p.send(t + 3.2, D7, S1, synth.udp(40071, 443, b"ok"), 17)
        t += 60
    expect("D5", (29, 30), "17/out/7000@dev:D7")
    expect("D7", (30,), "17/in/7000@dev:D5")
    expect("M", (29, 30), "1@dev:D7")
    expect("D7", (30,), "1@dev:M")
    expect("S1", (29, 30), "17/in/443@dev:D7")
    expect("D7", (30,), "17/out/443@dev:S1")

    # tunnels: D5 reaches the IPv6 internet through a relay (IPv6 in IPv4, protocol 41), D6 keeps a GRE tunnel
    # (protocol 47) to a vendor. The flow of each device is the tunnel. What is inside it is not looked at.
    relay, vendor = synth.Host(GW, "192.88.99.1"), synth.Host(GW, "52.9.9.9")
    in_d, in_w = "2002:c0a8:12a::1", "2a00:1450:4001::5e"
    for k, (a, b, src, dst, l4) in enumerate((
            (D5, relay, in_d, in_w, synth.tcp(50000, 443, 1000, 0, "S")),
            (relay, D5, in_w, in_d, synth.tcp(443, 50000, 5000, 1001, "SA")),
            (D5, relay, in_d, in_w, synth.tcp(50000, 443, 1001, 5001, "A")),
            (D5, relay, in_d, in_w, synth.tcp(50000, 443, 1001, 5001, "PA", b"hello")),
            (relay, D5, in_w, in_d, synth.tcp(443, 50000, 5001, 1006, "A")))):
        p.send(T0 + 3700 + k * 0.01, a, b, synth.ip6(src, dst, 6, l4), 41, via=GW if a is D5 else None)
    gre = struct.pack("!HH", 0, 0x0800)
    for k in range(6):
        p.send(T0 + 3720 + k, D6, vendor, gre + synth.ip4("10.99.0.2", "10.99.0.1", 17, synth.udp(40000, 5000, b"data")), 47, via=GW)
        p.send(T0 + 3720.1 + k, vendor, D6, gre + synth.ip4("10.99.0.1", "10.99.0.2", 17, synth.udp(5000, 40000, b"data")), 47)
    # a tunnel inside UDP (VXLAN) is a UDP flow of the device
    vxlan = struct.pack("!II", 0x08000000, 42 << 8) + synth.eth("02:00:00:00:99:01", "02:00:00:00:99:02", synth.ip4(
        "10.99.1.2", "10.99.1.1", 17, synth.udp(40001, 5001, b"data")))
    for k in range(3):
        p.send(T0 + 3740 + k, D6, vendor, synth.udp(47000, 4789, vxlan), 17, via=GW)
    expect("D5", (29,), "41@wan")
    expect("D6", (29,), "47@wan")
    expect("D6", (29,), "17/out/4789@wan")

    # one last packet, hours later. The logs that Zeek writes when it stops are read as well.
    p.send(END, D3, S1, synth.udp(40099, 9998, b"end"), 17)
    expect("D3", (31,), "17/out/9998@dev:S1")
    if double:
        p.frames = [x for t, fr in p.frames for x in ((t, fr), (t + 0.00002, fr))]
    return p.write(path), want


def build_quiet(path, double=False):
    """A second capture in which nothing else happens around midnight. C1 opens a connection to S1 on the 29th
    and sends a request at noon and at 23:59:50 on the 30th. S1 answers at 00:00:01 on the 31st: the first
    packet the capture sees after midnight, and the first of S1 since the 29th. S1 sent nothing on the 30th."""
    p = synth.Pcap()
    c = synth.Tcp(p, C1, S1, 40001, 8080).handshake(T0)
    night = MIDNIGHT + 24 * H
    c._c(MIDNIGHT + 12 * H, "PA", b"c" * 10)
    c._c(night - 10, "PA", b"c" * 10)
    c._s(night + 1, "PA", b"s" * 20)
    c._c(night + 1.001, "A")
    c.close(night + 600)
    t = T0
    while t < END:                                  # other devices ask for each other all the time, except then
        if not night - 5 < t < night + 2:
            p.arp(t + 0.4, D5, D6)
        t += 20
    p.send(END + 30, D3, S1, synth.udp(40099, 9998, b"end"), 17)
    want = {("C1", d, "6/out/8080@dev:S1") for d in (29, 30, 31)} | {("S1", d, "6/in/8080@dev:C1") for d in (29, 31)}
    want.add(("D3", 31, "17/out/9998@dev:S1"))
    if double:
        p.frames = [x for t, fr in p.frames for x in ((t, fr), (t + 0.00002, fr))]
    return p.write(path), want


def flood(zeek, work, limit=20):
    """60 TCP flows that never get going: 30 connection attempts from made-up addresses that the server
    answers, and 30 stray acknowledgements. Returns how many of them Zeek ended within the hour (the rest is
    kept like any silent connection, until Zeek stops)."""
    p = synth.Pcap()
    for k in range(30):
        ghost = synth.Host(GW, f"52.7.{k}.9")
        p.send(T0 + 1 + k * 0.01, ghost, S1, synth.tcp(40000 + k, 8080, 1000, 0, "S"), 6)
        p.send(T0 + 1.001 + k * 0.01, S1, ghost, synth.tcp(8080, 40000 + k, 5000, 1001, "SA"), 6, via=GW)
        p.send(T0 + 2 + k * 0.01, C1, D3, synth.tcp(41000 + k, 8086, 1000, 1, "A"), 6)
    synth.Tcp(p, C1, S1, 40001, 8080).handshake(T0 + 3)                 # a real connection, silent afterwards
    for t in (T0 + 400, T0 + 800, T0 + 1200, T0 + H + 5):                  # the clock moves on
        p.arp(t, D5, D6)
    os.makedirs(work)
    p.write(os.path.join(work, "capture.pcap"))
    hours = run_zeek(zeek, os.path.join(work, "capture.pcap"), os.path.join(work, "zeek"), (f"IBE::max_one_sided={limit}",))
    ended = {hour: sum(1 for path in paths if os.path.basename(path).startswith("conn.") for _ in pipeline.read_log(path))
             for hour, paths in hours.items()}
    return ended.get(T0, 0), ended.get(T0 + 2 * H, 0)


def run_zeek(zeek, pcap, where, settings=()):
    os.makedirs(where)
    r = subprocess.run([zeek, "-b", "-C", "-r", os.path.abspath(pcap), os.path.join(REPO, "recorder", "zeek", "ibe.zeek"),
                        *settings], cwd=where, env=dict(os.environ, TZ="UTC"), capture_output=True, text=True)
    said = [x for x in r.stderr.splitlines() if x.strip() and "Overwriting packet analyzer mapping" not in x]
    check("Zeek runs without a message", r.returncode == 0 and not said, "\n".join(said)[:300])
    hours = {}
    for path in sorted(glob.glob(os.path.join(where, "*.log"))):
        m = re.fullmatch(r"([a-z_]+)\.(\d{4})-(\d\d)-(\d\d)-(\d\d)-\d\d-\d\d\.log", os.path.basename(path))
        if m:                                       # completed logs only, grouped by the hour they cover
            hour = calendar.timegm(tuple(int(x) for x in m.groups()[1:]) + (0, 0))
            hours.setdefault(hour, []).append(path)
    # What Zeek writes when it stops stays in logs with their open names. On the device the next start
    # completes them (leftover rotation). Here they are handed over as the last hour.
    last = max(hours)
    for path in sorted(glob.glob(os.path.join(where, "*.log"))):
        base = os.path.basename(path)
        if base in pipeline.ACTIVE:
            done = os.path.join(where, base[:-4] + ".at-stop.log")
            os.rename(path, done)
            hours.setdefault(last + H, []).append(done)
    stems = sorted({os.path.basename(p).split(".")[0] for ps in hours.values() for p in ps})
    check("Zeek writes only the expected logs", set(stems) <= set(pipeline.STEMS), str(stems))
    return hours


def record(work, hours, ifaces):
    """Feed the completed logs to the anonymiser one hour at a time, as the timer does on the device."""
    cfg = dict(pipeline.DEFAULTS, raw_dir=f"{work}/raw", data_dirs=[f"{work}/ssd", f"{work}/sd"], key_dir=f"{work}/key",
               state_dir=f"{work}/state", manage_services=False, interfaces=ifaces, sysfs_net=f"{work}/nosys",
               proc_swaps=f"{work}/noswaps", raise_errors=True, require_ram_disk=False, require_key_mount=False, rtc_epoch="")
    os.makedirs(cfg["key_dir"])
    with open(cfg["proc_swaps"], "w") as f:
        f.write("Filename Type Size Used Priority\n")
    pipeline.init_key(cfg["key_dir"])
    with open(os.path.join(cfg["key_dir"], "armed.json"), "w") as f:
        json.dump({"approval_ref": "scenario test"}, f)
    n_raw, st = 0, {}
    for hour in sorted(hours):
        for n, i in enumerate(ifaces):
            os.makedirs(os.path.join(cfg["raw_dir"], i), exist_ok=True)
            for path in hours[hour]:
                shutil.copy(path, os.path.join(cfg["raw_dir"], i))
                if os.path.basename(path).split(".")[0] in ("conn", "open_conn"):
                    n_raw += sum(1 for _ in pipeline.read_log(path))
        st = pipeline.run_once(cfg, now=hour + H + 420)
        check(f"hour {hour}: state", st["state"] == "ok" and not st["errors"], f"{st['state']} {st['errors']}") \
            if st["state"] != "ok" or st["errors"] else None
        left = [x for i in ifaces for x in os.listdir(os.path.join(cfg["raw_dir"], i))]
        if left:
            check("raw logs deleted after every run", False, str(left))
    return cfg, st, n_raw


def outputs(cfg):
    recs = []
    for p in sorted(glob.glob(os.path.join(cfg["data_dirs"][0], "anon-*.jsonl.gz"))):
        with gzip.open(p, "rt", encoding="utf-8") as f:
            recs += [json.loads(x) for x in f]
    return recs


def flow_types(work, cfg, role="init"):
    import duckdb
    import adapt_recorder
    out = os.path.join(work, "analysis-" + (role or "ports"))
    os.makedirs(os.path.join(out, "inc", "tmp"))
    norm = os.path.join(out, "norm.parquet")
    summary = adapt_recorder.convert(cfg["data_dirs"][0], norm, dataset="scenario", tz=TZ, hours="none")
    env = dict(os.environ, GT_INPUTS=f"{norm}|{TZ}")
    env.pop("GT_ROLE", None)
    if role:
        env["GT_ROLE"] = role
    r = subprocess.run([sys.executable, "-W", "ignore", os.path.join(REPO, "analysis", "incidence3.py"), "x", "x",
                        os.path.join(out, "inc")], env=env, capture_output=True, text=True)
    if r.returncode:
        print(r.stdout[-2000:], r.stderr[-2000:])
        raise SystemExit(1)
    rows = duckdb.connect().execute(f"""SELECT device, CAST(day AS VARCHAR), ftype
                                        FROM read_parquet('{out}/inc/inc_day.parquet') WHERE gran = 'svc'""").fetchall()
    pz = core.Pseudonymiser(pipeline.load_key(cfg["key_dir"]))
    name = {pz.device(mac): n for n, mac in NAMES.items()}

    def plain(text):
        for pseudonym, n in name.items():
            text = text.replace(pseudonym, n)
        return text
    return {(name.get(d, d), int(day[8:10]), plain(f)) for d, day, f in rows}, summary


def chain(zeek, work, double=False, ifaces=("eth1",), capture=None):
    os.makedirs(work)
    n_frames, want = (capture or build)(os.path.join(work, "capture.pcap"), double)
    hours = run_zeek(zeek, os.path.join(work, "capture.pcap"), os.path.join(work, "zeek"))
    cfg, st, n_raw = record(work, hours, list(ifaces))
    return cfg, st, n_raw, want, n_frames, len(hours)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zeek", default="/opt/zeek/bin/zeek")
    ap.add_argument("--work", required=True)
    a = ap.parse_args()
    if os.path.exists(a.work):
        raise SystemExit(f"{a.work} exists, give a new directory")
    t_start = time.time()

    cfg, st, n_raw, want, n_frames, n_hours = chain(a.zeek, os.path.join(a.work, "one"))
    recs = outputs(cfg)
    dropped = sum(st["records_dropped"].values())
    check("every raw record written or counted", st["records_out"] + dropped == n_raw and len(recs) == st["records_out"],
          f"{n_frames} frames, {n_hours} hourly runs, {n_raw} raw records, written {st['records_out']}, dropped {st['records_dropped']}")
    check("nothing dropped", dropped == 0, str(st["records_dropped"]))
    got, summary = flow_types(os.path.join(a.work, "one"), cfg)
    check("flow types of every device on every day are the expected ones", got == want,
          f"{len(got)} device-day-types, unexpected {sorted(got - want)}, missing {sorted(want - got)}")
    zone = ZoneInfo(TZ)
    days = sorted({datetime.datetime.fromtimestamp(r["ts"], zone).day for r in recs})
    check("three recording days", days == [29, 30, 31] and st["recording_days"] == 3, f"{days}, {st['recording_days']}")
    n_open = sum(1 for r in recs if r.get("open"))
    check("reports about open connections are written and marked", n_open == st["records_open"] and n_open > 100,
          f"{n_open} reports, {summary['no_handshake_rows']} rows without a handshake")
    # a connection is one record however long it lasts or however long it is silent
    finals = [r for r in recs if not r.get("open")]
    check("the 50 hour connection is one record with the right ends",
          [(r["hist"][:2], r["est"]) for r in finals if r["rp"] == 8080] == [("Sh", True)])
    check("the idle connection is one record", len([r for r in finals if r["rp"] == 8083]) == 1)
    check("the slow answer belongs to the question", [(r["rp"], r["est"]) for r in finals if 9999 in (r["op"], r["rp"])] == [(9999, True)])
    check("remote hosts are 'wan', one of them named by DNS",
          sorted({r["wc"] for r in recs if r["rs"] == "wan"}) == ["dns", "remote_access", "unknown"]
          and all(r["r"] == "wan" for r in recs if r["rs"] == "wan"),
          str(sorted({r.get("wc") for r in recs if r["rs"] == "wan"})))
    check("both routers are learned and are not devices", len(st["gateways"]) == 2 and not {"GW", "RX"} & {d for d, _, _ in got},
          f"{len(st['gateways'])} learned")
    check("devices in two VLANs keep their own names through the router", not [r for r in recs if r["ib"]],
          f"records with a side named by its address: {len([r for r in recs if r['ib']])}")
    check("the vlan tag is kept", {r["vlan"] for r in recs if r["op"] == 40012} == {20}
          and {r["vlan"] for r in recs if r["op"] == 40060} == {10})
    text = ""
    for d in cfg["data_dirs"]:
        for p in sorted(glob.glob(os.path.join(d, "*"))):
            with open(p, "rb") as f:
                raw = f.read()
            text += gzip.decompress(raw).decode() if p.endswith(".gz") else raw.decode()
    check("no address or name in the output", core.scan_text(text) is None and not [s for s in SECRETS if s in text],
          str(core.scan_text(text) or [s for s in SECRETS if s in text]))

    # roles decided by the port rules for every record (the registered sensitivity analysis): the only
    # difference here is that equal ports on both sides are called symmetric
    ports, _ = flow_types(os.path.join(a.work, "one"), cfg, role=None)
    differ = sorted(got ^ ports)
    check("port rules for every record give the same types, except equal ports", differ == [
        ("C1", 29, "17/out/5353@mcast:mdns"), ("C1", 29, "17/sym/5353@mcast:mdns")], str(differ))

    cfg2, st2, n_raw2, _, _, _ = chain(a.zeek, os.path.join(a.work, "two"), ifaces=("eth1", "eth2"))
    def strip(rs):
        return sorted(json.dumps({k: v for k, v in r.items() if k not in ("if", "o", "r")}, sort_keys=True) for r in rs)
    check("two capture ports give the records of one", strip(outputs(cfg2)) == strip(recs)
          and st2["records_dropped"]["duplicate"] == n_raw, f"duplicates removed {st2['records_dropped']['duplicate']}")
    got2, _ = flow_types(os.path.join(a.work, "two"), cfg2)
    check("two capture ports give the same flow types", got2 == want)

    # three switches, each mirrored to a port of its own: a conversation that crosses all of them is seen three times
    cfg5, st5, _, _, _, _ = chain(a.zeek, os.path.join(a.work, "three"), ifaces=("eth0", "eth1", "eth2"))
    check("three capture ports give the records of one", strip(outputs(cfg5)) == strip(recs)
          and st5["records_dropped"]["duplicate"] == 2 * n_raw, f"duplicates removed {st5['records_dropped']['duplicate']}")
    got5, _ = flow_types(os.path.join(a.work, "three"), cfg5)
    check("three capture ports give the same flow types", got5 == want)

    cfg3, st3, _, _, n3, _ = chain(a.zeek, os.path.join(a.work, "double"), double=True)
    got3, _ = flow_types(os.path.join(a.work, "double"), cfg3)
    recs3 = [r for r in outputs(cfg3) if not r.get("open")]
    check("every frame doubled (both directions mirrored): the same flow types", got3 == want,
          f"{n3} frames, unexpected {sorted(got3 - want)}, missing {sorted(want - got3)}")
    check("every frame doubled: packet counts double, which is why they are not used",
          sum(r["opk"] for r in recs3) == 2 * sum(r["opk"] for r in finals))
    for name, double in (("quiet", False), ("quiet-double", True)):
        cfg4, _, _, want4, _, _ = chain(a.zeek, os.path.join(a.work, name), double=double, capture=build_quiet)
        got4, _ = flow_types(os.path.join(a.work, name), cfg4)
        check("the answer that is the first packet after midnight counts on its own day" + (", frames doubled" if double else ""),
              got4 == want4, f"unexpected {sorted(got4 - want4)}, missing {sorted(want4 - got4)}")

    in_hour, at_stop = flood(a.zeek, os.path.join(a.work, "flood"))
    check("flows that never got going are kept for a day up to the limit, beyond it for five minutes",
          (in_hour, at_stop) == (40, 21), f"limit 20: {in_hour} of 60 ended within the hour, {at_stop} records at the stop")
    print(f"ALL PASS  {len(want)} device-day-types, {time.time() - t_start:.0f} s")


if __name__ == "__main__":
    main()
