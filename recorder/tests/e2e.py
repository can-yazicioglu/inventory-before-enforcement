#!/usr/bin/env python3
# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
"""End-to-end check of the whole chain on a real capture file.

  capture file -> Zeek (recorder script) -> anonymiser -> adapter -> incidence -> estimator and rule

The capture is replayed as N identical local days (time stamps shifted in the raw logs), once
through one capture port and once through two ports that both see every connection. Because the
days are identical, the answers are known in advance:

  1. no address, MAC address, name or key material appears in anything that leaves the site
  2. every raw record is either written or counted as dropped, and the raw logs are gone
  3. device pseudonyms match the MAC addresses one to one
  4. two capture ports give exactly the records of one capture port
  5. the flow types computed by the analysis equal an independent computation in plain Python
  6. no new flow type appears after the first day, so GT-C stops at T = 10 for epsilon 0.3 and
     at T = 7 for epsilon 1.0 on every device, with no alert day afterwards

Usage: e2e.py --zeek /opt/zeek/bin/zeek --pcap capture.pcap --work DIR [--days 30]
Needs: zeek, duckdb, pandas, numpy, scipy, pyarrow.
"""
import argparse
import datetime
import glob
import gzip
import json
import os
import re
import subprocess
import sys
from zoneinfo import ZoneInfo

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "recorder"))
from ibe_recorder import core, pipeline  # noqa: E402

TZ = "Europe/Istanbul"
STEMS = ("conn", "dns", "ssl", "stats", "capture_loss")


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"  ({detail})" if detail else ""), flush=True)
    if not ok:
        raise SystemExit(1)


def run_zeek(zeek, pcap, where):
    os.makedirs(where)
    subprocess.run([zeek, "-b", "-C", "-r", os.path.abspath(pcap), os.path.join(REPO, "recorder", "zeek", "ibe.zeek")],
                   cwd=where, check=True)
    logs = {s: [r for p in sorted(glob.glob(os.path.join(where, s + "*.log"))) for r in pipeline.read_log(p)]
            for s in STEMS}
    extra = sorted({os.path.basename(p).split(".")[0] for p in glob.glob(os.path.join(where, "*.log"))} - set(STEMS))
    check("Zeek writes only the five expected logs", not extra, f"extra: {extra}")
    return logs


def secrets_of(logs):
    """Every string of the raw logs that must never leave the site."""
    out = set()
    for r in logs["conn"]:
        out.update(str(r.get(k)) for k in ("id.orig_h", "id.resp_h", "orig_l2_addr", "resp_l2_addr") if r.get(k))
    for r in logs["dns"]:
        out.update(x for x in [r.get("query")] + list(r.get("answers") or []) if x and len(x) > 3)
    out.update(r["server_name"] for r in logs["ssl"] if r.get("server_name"))
    out |= {m.replace(":", "") for m in out if len(m) == 17 and m.count(":") == 5}
    return {s for s in out if len(s) >= 6}


def write_day(logs, raw, iface, shift, tag, jitter=0.0):
    d = os.path.join(raw, iface)
    os.makedirs(d, exist_ok=True)
    for stem, recs in logs.items():
        with open(os.path.join(d, f"{stem}.{tag}.log"), "w", encoding="utf-8") as f:
            for r in recs:
                f.write(json.dumps(dict(r, ts=r["ts"] + shift + jitter)) + "\n")


def record_side(work, logs, days, ifaces, shift0, tokens):
    cfg = dict(pipeline.DEFAULTS, raw_dir=f"{work}/raw", data_dirs=[f"{work}/ssd", f"{work}/sd"],
               key_dir=f"{work}/key", state_dir=f"{work}/state", manage_services=False, interfaces=ifaces,
               sysfs_net=f"{work}/nosys", wan_tokens=tokens, max_recording_days=days)
    os.makedirs(cfg["key_dir"])
    pipeline.init_key(cfg["key_dir"])
    with open(os.path.join(cfg["key_dir"], "armed.json"), "w") as f:
        json.dump({"approval_ref": "end-to-end test"}, f)
    t_end = max(r["ts"] for r in logs["conn"])
    st = {}
    for k in range(days):
        for n, i in enumerate(ifaces):
            write_day(logs, cfg["raw_dir"], i, shift0 + k * 86400, f"day{k:02d}", jitter=0.004 * n)
        st = pipeline.run_once(cfg, now=int(t_end + shift0 + k * 86400 + 600))
        if st["state"] != "ok":
            check(f"day {k}: recorder state", False, st["state"])
    return cfg, st


def outputs(cfg):
    recs = []
    for p in sorted(glob.glob(os.path.join(cfg["data_dirs"][0], "anon-*.jsonl.gz"))):
        with gzip.open(p, "rt", encoding="utf-8") as f:
            recs += [json.loads(x) for x in f]
    return recs


def reference_types(recs, gateways):
    """Flow types at svc level, computed independently of the adapter and of incidence3.py."""
    zone = ZoneInfo(TZ)
    rows, answered = [], set()
    for r in recs:
        proto = r["ipp"] if r["ipp"] > 0 else {"tcp": 6, "udp": 17, "icmp": 1}.get(r["proto"], 255)
        day = datetime.datetime.fromtimestamp(r["ts"], zone).date().isoformat()
        port = "hi" if r["rp"] >= 32768 else str(r["rp"])

        def peer(name, scope):
            if scope == "lan":
                return ("dev:" if name.startswith("d") else "ip:") + name
            return "wan" if scope == "wan" else name
        for dev, dscope, other, oscope, role in ((r["o"], r["os"], r["r"], r["rs"], "out"),
                                                 (r["r"], r["rs"], r["o"], r["os"], "in")):
            if dscope != "lan" or dev in gateways:
                continue
            label = peer(other, oscope)
            ftype = f"{proto}/{role}/{port}@{label}" if proto in (6, 17) else f"{proto}@{label}"
            host = (r.get("wh") or "wc_" + r["wc"]) if oscope == "wan" else label
            key = (dev, day, proto, role, r["rp"], host)
            if role == "in" and proto in (6, 17) and r["est"]:
                answered.add(key)
            rows.append((dev, day, ftype, role if proto in (6, 17) else "na", key))
    return {(dev, day, ftype) for dev, day, ftype, role, key in rows if role != "in" or key in answered}


def analyse(work, cfg, days):
    import duckdb
    import pandas as pd
    an, out = os.path.join(REPO, "analysis"), os.path.join(work, "analysis")
    os.makedirs(os.path.join(out, "inc", "tmp"))
    os.makedirs(os.path.join(out, "res"))
    norm = os.path.join(out, "norm.parquet")
    env = dict(os.environ, GT_ROLE="init", GT_INPUTS=f"{norm}|{TZ}", GT_GRANS="proto,port,svc,net,host")

    def py(*args):
        r = subprocess.run([sys.executable, "-W", "ignore"] + list(args), env=env, capture_output=True, text=True)
        if r.returncode:
            print(r.stdout[-3000:], r.stderr[-3000:])
            raise SystemExit(1)
        return r.stdout
    print(py(os.path.join(an, "adapt_recorder.py"), cfg["data_dirs"][0], norm, "--dataset", "e2e", "--tz", TZ,
             "--hours", "1-7=09:00-18:00").strip())
    py(os.path.join(an, "incidence3.py"), "x", "x", os.path.join(out, "inc"))
    inc = duckdb.connect().execute(f"""SELECT device, CAST(day AS VARCHAR) AS day, ftype
                                      FROM read_parquet('{out}/inc/inc_day.parquet') WHERE gran = 'svc'""").df()
    got = set(map(tuple, inc.values))
    gateways = set(json.load(open(os.path.join(cfg["data_dirs"][0], "status.json")))["gateways"])
    want = reference_types(outputs(cfg), gateways)
    check("flow types of the analysis equal the independent computation", got == want,
          f"{len(got)} device-day-types, only in analysis {len(got - want)}, only in reference {len(want - got)}")
    py(os.path.join(an, "run_series3.py"), os.path.join(out, "inc", "inc_day.parquet"), os.path.join(out, "res"))
    sys.path.insert(0, an)
    import scores
    s = scores.add_scores(pd.read_parquet(os.path.join(out, "res", "series.parquet")))
    s = s[s.origin == 0].copy()
    s["gtc"] = s.gt_u95 + (s.gt_pr - s["gt"])
    check("no new flow type after the first day at any level", int(s.y1.clip(lower=0).sum()) == 0 and int(s.q1.sum()) == 0)
    n_dev = s.groupby("gran").device.nunique().to_dict()
    for eps, t_want in ((0.3, 10), (1.0, 7)):
        stop = s[(s["T"] >= 7) & (s.gtc <= eps)].groupby(["gran", "device"])["T"].min()
        ok = (stop == t_want).all() and stop.groupby("gran").size().to_dict() == n_dev
        check(f"GT-C stops at T = {t_want} for epsilon {eps} on every device and level", ok,
              f"devices per level {n_dev}, stop days {sorted(set(stop))}")
    after = s[(s["T"] == 10)]
    check("no alert day in the 14 days after enforcement", int(after.alertdays14.sum()) == 0 and (after.alertdays14 >= 0).all())
    return n_dev


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zeek", default="/opt/zeek/bin/zeek")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--days", type=int, default=30)
    a = ap.parse_args()
    if os.path.exists(a.work):
        raise SystemExit(f"{a.work} exists, give a new directory")
    logs = run_zeek(a.zeek, a.pcap, os.path.join(a.work, "zeek"))
    n_raw = len(logs["conn"])
    t0, t1 = min(r["ts"] for r in logs["conn"]), max(r["ts"] for r in logs["conn"])
    check("capture fits in one local day", t1 - t0 < 23 * 3600, f"{n_raw} connection records over {(t1 - t0) / 3600:.1f} hours")
    start = datetime.datetime(2026, 12, 1, 0, 20, tzinfo=ZoneInfo(TZ)).timestamp()
    secrets = secrets_of(logs)

    one, st1 = record_side(os.path.join(a.work, "one"), logs, a.days, ["eth1"], start - t0, tokens=True)
    two, st2 = record_side(os.path.join(a.work, "two"), logs, a.days, ["eth1", "eth2"], start - t0, tokens=True)
    off, st3 = record_side(os.path.join(a.work, "notok"), logs, 2, ["eth1"], start - t0, tokens=False)

    for name, cfg, st, ports in (("one port", one, st1, 1), ("two ports", two, st2, 2)):
        dropped = sum(st["records_dropped"].values())
        check(f"{name}: every raw record written or counted",
              st["records_out"] + dropped == n_raw * a.days * ports, f"written {st['records_out']}, dropped {st['records_dropped']}")
        check(f"{name}: recording days", st["recording_days"] == a.days, str(st["recording_days"]))
        left = [p for i in cfg["interfaces"] for p in os.listdir(os.path.join(cfg["raw_dir"], i))]
        check(f"{name}: raw logs deleted", left == [], str(left[:3]))
    check("two ports: one duplicate removed per connection", st2["records_dropped"]["duplicate"] == n_raw * a.days)
    def strip(recs):          # the two runs use different keys, so compare everything except the pseudonyms
        return sorted(json.dumps({k: v for k, v in r.items() if k not in ("if", "o", "r", "wh", "wn", "wd")},
                                 sort_keys=True) for r in recs)
    r1, r2 = outputs(one), outputs(two)
    check("two ports give the records of one port", strip(r1) == strip(r2), f"{len(r1)} and {len(r2)} records")
    check("data directories are identical", outputs(dict(one, data_dirs=one["data_dirs"][::-1])) == r1)

    key = pipeline.load_key(one["key_dir"])
    pz, scope = core.Pseudonymiser(key), core.Scope()
    gw = {m for m, v in json.load(open(os.path.join(one["key_dir"], "gateways_seen.json"))).items() if len(v) >= 16}
    macs = set()
    for r in logs["conn"]:
        omac, rmac = r.get("orig_l2_addr") or "", r.get("resp_l2_addr") or ""
        so, sr = scope.of(r["id.orig_h"], omac, gw), scope.of(r["id.resp_h"], rmac, gw)
        if so in ("mcast", "bcast") or (so == "wan" and sr != "lan"):
            continue                                   # the recorder drops these records
        for side, mac in ((so, omac), (sr, rmac)):
            if side == "lan" and mac and not core.is_group_mac(mac) and core.norm_mac(mac) not in gw:
                macs.add(core.norm_mac(mac))
    seen = {x for r in r1 for x in (r["o"], r["r"]) if x.startswith("d") and len(x) == 11}
    check("device pseudonyms match MAC addresses one to one", seen == {pz.device(m) for m in macs},
          f"{len(seen)} pseudonyms, {len(macs)} MAC addresses, gateways learned {len(gw)}")

    # Search every output file for every raw string. The files are reduced to their distinct words first
    # (pseudonyms, labels and numbers repeat millions of times), which keeps the search exact and fast.
    n_files, words = 0, set()
    for cfg in (one, two, off):
        for d in cfg["data_dirs"]:
            for p in sorted(glob.glob(os.path.join(d, "*"))):
                with open(p, "rb") as f:
                    raw = f.read()
                text = gzip.decompress(raw).decode() if p.endswith(".gz") else raw.decode()
                n_files += 1
                if core.scan_text(text):
                    check("no address, name or key in the output", False, f"{os.path.basename(p)}: {core.scan_text(text)}")
                words.update(re.findall(r"[A-Za-z0-9_.:\-]+", text))
    hits = sorted({x for w in words for x in secrets if x in w} | {w for w in words if key.hex()[:20] in w})
    check("no address, name or key in the output", not hits,
          f"{n_files} files, {len(words)} distinct words, {len(secrets)} raw strings searched, hits {hits[:5]}")
    r3 = outputs(off)
    check("without permission for tokens, remote hosts carry a service type only",
          all("wh" not in r and "wn" not in r and "wd" not in r for r in r3) and any("wc" in r for r in r3),
          f"service types: {sorted({r['wc'] for r in r3 if 'wc' in r})}")
    stick = sorted(os.listdir(one["key_dir"]))
    check("files with real addresses stay on the key stick", "devices_observed.csv" in stick and "gateways_seen.json" in stick,
          str(stick))

    n_dev = analyse(a.work, one, a.days)
    print(f"ALL PASS  raw records per day {n_raw}, days {a.days}, devices per level {n_dev}")


if __name__ == "__main__":
    main()
