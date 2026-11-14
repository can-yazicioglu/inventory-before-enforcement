# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
"""Command line of the recorder. Run as: python3 -m ibe_recorder <command>."""
import argparse
import datetime
import hashlib
import json
import os
import shutil
import sys

from . import pipeline


def cmd_run(cfg, args):
    st = pipeline.run_once(cfg)
    print(st["state"], "| recording days:", st.get("recording_days", 0), "| records:", st.get("records_out", 0))


def cmd_status(cfg, args):
    path = os.path.join(cfg["state_dir"], "status.json")
    print(open(path, encoding="utf-8").read() if os.path.exists(path) else "no status yet")


def cmd_init_key(cfg, args):
    if os.path.exists(os.path.join(cfg["key_dir"], "hmac.key")):
        sys.exit("a key already exists on the key stick, refusing to overwrite it")
    os.makedirs(cfg["key_dir"], exist_ok=True)
    print("key written to", pipeline.init_key(cfg["key_dir"]))


def cmd_preflight(cfg, args):
    """Exit status 0 if capture may run now, 3 otherwise. Called by the capture service before it starts."""
    why = pipeline.preflight(cfg)
    if why:
        print("capture not allowed:", why)
        sys.exit(3)
    print("capture allowed")


def cmd_arm(cfg, args):
    """Recording may only start after ethics approval. The IT officer records the approval reference."""
    if pipeline.load_key(cfg["key_dir"]) is None:
        sys.exit("no key on the key stick: run init-key first")
    if os.path.exists(os.path.join(cfg["state_dir"], "STOP")):
        sys.exit("the recording limit was reached: use 'extend' with the site's written approval")
    with open(os.path.join(cfg["key_dir"], "armed.json"), "w", encoding="utf-8") as f:
        json.dump({"approval_ref": args.approval_ref, "armed_at": datetime.datetime.now().isoformat()}, f)
    print("armed. Capture starts when the ibe-zeek services are started.")


def cmd_disarm(cfg, args):
    p = os.path.join(cfg["key_dir"], "armed.json")
    if os.path.exists(p):
        os.remove(p)
    print("disarmed")


def cmd_extend(cfg, args):
    """Raise the limit after the site has approved an extension in writing."""
    cfg_path = args.config
    data = json.load(open(cfg_path, encoding="utf-8")) if os.path.exists(cfg_path) else {}
    data["max_recording_days"] = int(args.days)
    data.setdefault("extensions", []).append({"days": int(args.days), "approval_ref": args.approval_ref,
                                               "at": datetime.datetime.now().isoformat()})
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
    stop = os.path.join(cfg["state_dir"], "STOP")
    if os.path.exists(stop):
        os.remove(stop)
    print("limit is now", args.days, "recording days")


def cmd_export(cfg, args):
    """Copy the anonymised files to a folder (for example a USB stick) with a checksum list."""
    src = next((d for d in cfg["data_dirs"] if os.path.isdir(d)), None)
    if src is None:
        sys.exit("no data directory found")
    os.makedirs(args.dest, exist_ok=True)
    names = sorted(n for n in os.listdir(src)
                   if (n.startswith("anon-") and n.endswith(".gz")) or n in ("status.json", "devices.json", "coverage.jsonl"))
    with open(os.path.join(args.dest, "SHA256SUMS"), "w", encoding="ascii") as sums:
        for n in names:
            shutil.copy2(os.path.join(src, n), os.path.join(args.dest, n))
            with open(os.path.join(args.dest, n), "rb") as f:
                sums.write(f"{hashlib.sha256(f.read()).hexdigest()}  {n}\n")
    print(f"{len(names)} files copied to {args.dest}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ibe_recorder")
    ap.add_argument("--config", default="/etc/ibe/config.json")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run").set_defaults(fn=cmd_run)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("init-key").set_defaults(fn=cmd_init_key)
    a = sub.add_parser("arm")
    a.add_argument("--approval-ref", required=True, help="ethics approval date and number")
    a.set_defaults(fn=cmd_arm)
    sub.add_parser("disarm").set_defaults(fn=cmd_disarm)
    e = sub.add_parser("extend")
    e.add_argument("--days", required=True)
    e.add_argument("--approval-ref", required=True, help="reference of the site's written approval")
    e.set_defaults(fn=cmd_extend)
    sub.add_parser("preflight").set_defaults(fn=cmd_preflight)
    x = sub.add_parser("export")
    x.add_argument("--dest", required=True)
    x.set_defaults(fn=cmd_export)
    args = ap.parse_args(argv)
    args.fn(pipeline.load_config(args.config), args)


if __name__ == "__main__":
    main()
