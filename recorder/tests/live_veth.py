#!/usr/bin/env python3
# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
"""Live test of the recorder on virtual capture ports (needs root, zeek, tcpreplay, iproute2).

Two virtual cable pairs stand in for the two mirror ports. A capture file is replayed into both
while one Zeek process per port captures, exactly as on the device. The test then checks:

  1. packets seen by Zeek against packets sent, at each replay rate
  2. hourly rotation (here every 20 seconds), anonymisation, deletion of the raw logs
  3. a log left open by a killed capture is not lost: it is rotated when capture restarts
  4. pulling the key stops the recording and removes everything raw from memory

Usage: live_veth.py --pcap capture.pcap --work DIR [--zeek /opt/zeek/bin/zeek] [--rates 50,200,1000]
The numbers depend on the machine. They show that the chain works, not what a given board can do.
"""
import argparse
import glob
import gzip
import json
import os
import re
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "recorder"))
from ibe_recorder import core, pipeline  # noqa: E402

PAIRS = (("ibe0", "ibe1"), ("ibe2", "ibe3"))
ROTATE = "redef Log::default_rotation_interval = 20 secs; redef Stats::report_interval = 5 secs;"


def sh(*cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"  ({detail})" if detail else ""), flush=True)
    if not ok:
        raise SystemExit(1)


def links(up=True):
    for a, b in PAIRS:
        sh("ip", "link", "del", a, check=False)
        if up:
            sh("ip", "link", "add", a, "type", "veth", "peer", "name", b)
            for i in (a, b):
                sh("ip", "link", "set", i, "mtu", "65535")
                sh("ip", "link", "set", i, "up", "promisc", "on", "arp", "off")
                sh("ethtool", "-K", i, "rx", "off", "tx", "off", "sg", "off", "tso", "off", "gso", "off", "gro", "off",
                   check=False)


def start_zeek(zeek, raw, iface):
    d = os.path.join(raw, iface)
    os.makedirs(d, exist_ok=True)
    log = open(os.path.join(os.path.dirname(raw), f"zeek-{iface}.txt"), "a")
    return subprocess.Popen([zeek, "-b", "-C", "-i", iface, os.path.join(REPO, "recorder", "zeek", "ibe.zeek"), "-e", ROTATE],
                            cwd=d, stdout=log, stderr=log)


def replay(pcap, mbps):
    procs = [subprocess.Popen(["tcpreplay", "-i", a, f"--mbps={mbps}", pcap], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True) for a, _ in PAIRS]
    outs = [p.communicate()[0] for p in procs]
    sent, rate = [], []
    for o in outs:
        m = re.search(r"Actual: (\d+) packets .* sent in ([\d.]+) seconds", o)
        r = re.search(r"Rated: [\d.]+ Bps, ([\d.]+) Mbps, ([\d.]+) pps", o)
        f = re.search(r"Failed packets:\s+(\d+)", o)
        sent.append(int(m.group(1)) - (int(f.group(1)) if f else 0))
        rate.append((float(r.group(1)), float(r.group(2))))
    return sent, rate


def seen_by_zeek(raw, iface):
    """Packets Zeek reports as received on the wire, summed over all stats logs written so far."""
    recs = [r for p in glob.glob(os.path.join(raw, iface, "stats*.log")) for r in pipeline.read_log(p)]
    return sum(r.get("pkts_link", r.get("pkts_proc", 0)) for r in recs), sum(r.get("pkts_dropped", 0) for r in recs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zeek", default="/opt/zeek/bin/zeek")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--rates", default="50,200,1000")
    a = ap.parse_args()
    if os.path.exists(a.work):
        raise SystemExit(f"{a.work} exists, give a new directory")
    w = os.path.abspath(a.work)
    cfg = dict(pipeline.DEFAULTS, raw_dir=f"{w}/raw", data_dirs=[f"{w}/ssd", f"{w}/sd"], key_dir=f"{w}/key",
               state_dir=f"{w}/state", manage_services=False, interfaces=[b for _, b in PAIRS], wan_tokens=True)
    os.makedirs(cfg["key_dir"])
    pipeline.init_key(cfg["key_dir"])
    with open(os.path.join(cfg["key_dir"], "armed.json"), "w") as f:
        json.dump({"approval_ref": "live test"}, f)
    links()
    zeeks = {}
    try:
        for i in cfg["interfaces"]:
            zeeks[i] = start_zeek(a.zeek, cfg["raw_dir"], i)
        time.sleep(4)
        check("capture is allowed and both Zeek processes run",
              pipeline.preflight(cfg) is None and all(z.poll() is None for z in zeeks.values()))
        total_sent = [0, 0]
        for mbps in [int(x) for x in a.rates.split(",")]:
            before = [seen_by_zeek(cfg["raw_dir"], i) for i in cfg["interfaces"]]
            sent, rate = replay(os.path.abspath(a.pcap), mbps)
            time.sleep(12)                                  # two stats reports
            after = [seen_by_zeek(cfg["raw_dir"], i) for i in cfg["interfaces"]]
            for n in (0, 1):
                got, drop = after[n][0] - before[n][0], after[n][1] - before[n][1]
                total_sent[n] += sent[n]
                print(f"rate {mbps} Mbps asked, {rate[n][0]:.0f} Mbps and {rate[n][1]:.0f} packets per second reached, "
                      f"port {n}: sent {sent[n]}, seen {got} ({100 * got / max(sent[n], 1):.2f} percent), "
                      f"dropped by capture {drop}", flush=True)
        time.sleep(25)                                      # let the last logs rotate
        st = pipeline.run_once(cfg)
        check("anonymiser state", st["state"] == "ok", st["state"])
        check("records written and duplicates across the two ports removed",
              st["records_out"] > 0 and st["records_dropped"].get("duplicate", 0) > 0,
              f"written {st['records_out']}, dropped {st['records_dropped']}")
        left = sorted(n for i in cfg["interfaces"] for n in os.listdir(os.path.join(cfg["raw_dir"], i)) if n[0] != ".")
        check("only the open logs remain in memory", set(left) <= pipeline.ACTIVE, str(left))
        q = st["quality_last"]
        check("capture reports present for both ports", all(len(q[str(n)]["stats"]) > 0 for n in (0, 1)),
              f"packets by port {[q[str(n)]['pkts'] for n in (0, 1)]}, dropped {[q[str(n)]['dropped'] for n in (0, 1)]}")
        text = ""
        for p in glob.glob(os.path.join(cfg["data_dirs"][0], "*")):
            with open(p, "rb") as f:
                raw = f.read()
            text += gzip.decompress(raw).decode() if p.endswith(".gz") else raw.decode()
        check("output passes the leak scan", core.scan_text(text) is None)

        # 3. kill one capture hard in the middle of a log, restart it, nothing may be lost
        sent, _ = replay(os.path.abspath(a.pcap), 200)
        time.sleep(3)
        i = cfg["interfaces"][0]
        zeeks[i].send_signal(signal.SIGKILL)
        zeeks[i].wait()
        open_log = os.path.join(cfg["raw_dir"], i, "conn.log")
        n_open = sum(1 for _ in pipeline.read_log(open_log)) if os.path.exists(open_log) else 0
        zeeks[i] = start_zeek(a.zeek, cfg["raw_dir"], i)
        time.sleep(6)
        rot = [p for p in pipeline.rotated(cfg["raw_dir"], i, "conn")]
        n_rot = sum(1 for p in rot for _ in pipeline.read_log(p))
        check("log left open by a killed capture is rotated at restart, not overwritten",
              n_open > 0 and n_rot >= n_open, f"{n_open} records in the open log, {n_rot} in rotated logs after restart")
        before = st["records_out"]
        st = pipeline.run_once(cfg)
        check("those records are anonymised on the next run", st["records_out"] > before, f"{st['records_out'] - before} more")

        # 4. pull the key: recording stops and memory is emptied.
        # On the device the anonymiser stops the capture services itself. Here the test does it.
        os.rename(os.path.join(cfg["key_dir"], "hmac.key"), os.path.join(w, "pulled.key"))
        for z in zeeks.values():
            z.terminate()
            z.wait(timeout=20)
        st = pipeline.run_once(cfg)
        left = [n for i in cfg["interfaces"] for n in os.listdir(os.path.join(cfg["raw_dir"], i))]
        check("key removed: recording stops and nothing raw is kept", "key stick missing" in st["state"] and left == [],
              f"{st['state']}, files left {left}")
        check("capture would not be allowed to start again", pipeline.preflight(cfg) == "key stick missing")
        print("ALL PASS")
    finally:
        for z in zeeks.values():
            if z.poll() is None:
                z.terminate()
        for z in zeeks.values():
            try:
                z.wait(timeout=10)
            except subprocess.TimeoutExpired:
                z.kill()
        links(up=False)


if __name__ == "__main__":
    main()
