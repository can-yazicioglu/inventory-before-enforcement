#!/usr/bin/env python3
# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
"""How large an hourly batch can one run of the anonymiser take, and how much memory does it need?

The connection records of a capture are copied N times into one hour and anonymised in one run.
Prints records, seconds and peak memory. Run it on the device before shipping.

Usage: batch_size.py --pcap capture.pcap --work DIR [--copies 7,35,70] [--zeek /opt/zeek/bin/zeek]
"""
import argparse
import glob
import json
import os
import resource
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "recorder"))
from ibe_recorder import pipeline  # noqa: E402

NOW = 1798542000                # 2026-12-29 11:00 UTC


def one(zdir, work, copies):
    logs = {s: [r for p in sorted(glob.glob(os.path.join(zdir, s + "*.log"))) for r in pipeline.read_log(p)]
            for s in ("conn", "open_conn", "dns", "ssl")}
    cfg = dict(pipeline.DEFAULTS, raw_dir=f"{work}/raw", data_dirs=[f"{work}/ssd", f"{work}/sd"], key_dir=f"{work}/key",
               state_dir=f"{work}/state", manage_services=False, interfaces=["eth1"], sysfs_net=f"{work}/nosys",
               proc_swaps=f"{work}/noswaps", wan_tokens=True, raise_errors=True, require_ram_disk=False)
    os.makedirs(cfg["key_dir"])
    os.makedirs(os.path.join(cfg["raw_dir"], "eth1"))
    pipeline.init_key(cfg["key_dir"])
    with open(os.path.join(cfg["key_dir"], "armed.json"), "w") as f:
        json.dump({"approval_ref": "batch size test"}, f)
    t0 = min(r["ts"] for r in logs["conn"])
    span = max(r["ts"] for r in logs["conn"] + logs["open_conn"]) - t0
    for k in range(copies):                     # the whole capture squeezed into the hour before NOW, N times
        for stem in logs if k == 0 else ("conn", "open_conn"):
            with open(os.path.join(cfg["raw_dir"], "eth1", f"{stem}.c{k:03d}.log"), "w", encoding="utf-8") as f:
                for r in logs[stem]:
                    f.write(json.dumps(dict(r, ts=NOW - 3600 + (r["ts"] - t0) * 3500 / max(span, 1) + k * 0.001)) + "\n")
    raw_mb = sum(os.path.getsize(p) for p in glob.glob(os.path.join(cfg["raw_dir"], "eth1", "*"))) / 1e6
    del logs
    t = time.time()
    st = pipeline.run_once(cfg, now=NOW)
    sec = time.time() - t
    print(f"records {st['records_out']}, raw logs {raw_mb:.0f} MB, seconds {sec:.1f}, records per second "
          f"{st['records_out'] / sec:.0f}, peak memory {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1e6:.2f} GB, "
          f"state {st['state']}, dropped {st['records_dropped']}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zeek", default="/opt/zeek/bin/zeek")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--copies", default="7,35,70")
    ap.add_argument("--one", type=int, help=argparse.SUPPRESS)
    a = ap.parse_args()
    zdir = os.path.join(a.work, "zeek")
    if a.one:                                   # one size per process, so that peak memory is per size
        return one(zdir, os.path.join(a.work, f"copies{a.one}"), a.one)
    if os.path.exists(a.work):
        raise SystemExit(f"{a.work} exists, give a new directory")
    os.makedirs(zdir)
    subprocess.run([a.zeek, "-b", "-C", "-r", os.path.abspath(a.pcap), os.path.join(REPO, "recorder", "zeek", "ibe.zeek")],
                   cwd=zdir, check=True)
    for n in [int(x) for x in a.copies.split(",")]:
        subprocess.run([sys.executable, os.path.abspath(__file__), "--pcap", a.pcap, "--work", a.work, "--one", str(n)], check=True)


if __name__ == "__main__":
    main()
