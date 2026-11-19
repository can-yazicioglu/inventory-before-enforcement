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
  midnight    a short connection counts on the day it starts, a long one on both days
  remote      remote hosts collapse to 'wan', the router is learned and is not a device
  ipv6, vlan, multicast, broadcast, icmp, port reuse

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
SECRETS = ("192.168.1.", "52.1.", "8.8.8.8", "02:00:00", "020000", "fe80", "teamviewer", "224.0.0", "239.255")


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

    # midnight: 30 seconds across it count on the day they start, two hours across it count on both days
    synth.Tcp(p, C1, S1, 40013, 8088).handshake(MIDNIGHT - 10).client_says(MIDNIGHT + 10).close(MIDNIGHT + 20)
    c = synth.Tcp(p, C1, S1, 40014, 8089).handshake(MIDNIGHT - 1800)
    for k in range(1, 12):
        c.client_says(MIDNIGHT - 1800 + k * 600)
    c.close(MIDNIGHT + 5400)
    expect("C1", (29,), "6/out/8088@dev:S1")
    expect("S1", (29,), "6/in/8088@dev:C1")
    expect("C1", (29, 30), "6/out/8089@dev:S1")
    expect("S1", (29, 30), "6/in/8089@dev:C1")

    # one last packet, hours later, so that every earlier hour is complete
    p.send(END, D3, S1, synth.udp(40099, 9998, b"end"), 17)
    if double:
        p.frames = [x for t, fr in p.frames for x in ((t, fr), (t + 0.00002, fr))]
    return p.write(path), want


def run_zeek(zeek, pcap, where):
    os.makedirs(where)
    r = subprocess.run([zeek, "-b", "-C", "-r", os.path.abspath(pcap), os.path.join(REPO, "recorder", "zeek", "ibe.zeek")],
                       cwd=where, env=dict(os.environ, TZ="UTC"), capture_output=True, text=True)
    check("Zeek runs without a message", r.returncode == 0 and not r.stderr.strip(), r.stderr.strip()[:300])
    hours = {}
    for path in sorted(glob.glob(os.path.join(where, "*.log"))):
        m = re.fullmatch(r"([a-z_]+)\.(\d{4})-(\d\d)-(\d\d)-(\d\d)-\d\d-\d\d\.log", os.path.basename(path))
        if m:                                       # completed logs only, grouped by the hour they cover
            hour = calendar.timegm(tuple(int(x) for x in m.groups()[1:]) + (0, 0))
            hours.setdefault(hour, []).append(path)
    stems = sorted({os.path.basename(p).split(".")[0] for ps in hours.values() for p in ps})
    check("Zeek writes only the expected logs", set(stems) <= set(pipeline.STEMS), str(stems))
    return hours


def record(work, hours, ifaces):
    """Feed the completed logs to the anonymiser one hour at a time, as the timer does on the device."""
    cfg = dict(pipeline.DEFAULTS, raw_dir=f"{work}/raw", data_dirs=[f"{work}/ssd", f"{work}/sd"], key_dir=f"{work}/key",
               state_dir=f"{work}/state", manage_services=False, interfaces=ifaces, sysfs_net=f"{work}/nosys",
               proc_swaps=f"{work}/noswaps", raise_errors=True, require_ram_disk=False)
    os.makedirs(cfg["key_dir"])
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
    summary = adapt_recorder.convert(cfg["data_dirs"][0], norm, dataset="scenario", tz=TZ)
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
    name = {pz.device(h.mac): n for n, h in (("C1", C1), ("S1", S1), ("D3", D3))}
    name[pz.device(GW)] = "GW"

    def plain(text):
        for pseudonym, n in name.items():
            text = text.replace(pseudonym, n)
        return text
    return {(name.get(d, d), int(day[8:10]), plain(f)) for d, day, f in rows}, summary


def chain(zeek, work, double=False, ifaces=("eth1",)):
    os.makedirs(work)
    n_frames, want = build(os.path.join(work, "capture.pcap"), double)
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
    check("the router is learned and is not a device", len(st["gateways"]) == 1 and "GW" not in {d for d, _, _ in got})
    check("the vlan tag is kept", {r["vlan"] for r in recs if r["rp"] == 9100} == {20})
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

    cfg3, st3, _, _, n3, _ = chain(a.zeek, os.path.join(a.work, "double"), double=True)
    got3, _ = flow_types(os.path.join(a.work, "double"), cfg3)
    recs3 = [r for r in outputs(cfg3) if not r.get("open")]
    check("every frame doubled (both directions mirrored): the same flow types", got3 == want,
          f"{n3} frames, unexpected {sorted(got3 - want)}, missing {sorted(want - got3)}")
    check("every frame doubled: packet counts double, which is why they are not used",
          sum(r["opk"] for r in recs3) == 2 * sum(r["opk"] for r in finals))
    print(f"ALL PASS  {len(want)} device-day-types, {time.time() - t_start:.0f} s")


if __name__ == "__main__":
    main()
