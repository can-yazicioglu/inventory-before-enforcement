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
    try:
        st = pipeline.run_once(cfg)
    except Exception as e:
        # Last resort. Completed raw logs must not stay in RAM whatever went wrong. Only the kind of
        # error is printed: its text could quote raw data, and output goes to the system journal.
        try:
            pipeline.purge_raw(pipeline._usable(cfg))
        except Exception:
            pass
        print("run failed:", type(e).__name__)
        sys.exit(1)
    print(st["state"], "| recording days:", st.get("recording_days", 0), "| records:", st.get("records_out", 0))


def cmd_status(cfg, args):
    path = os.path.join(cfg["state_dir"], "status.json")
    if not os.path.exists(path):
        print("no status yet")
        return
    with open(path, encoding="utf-8") as f:
        print(f.read())


def cmd_init_key(cfg, args):
    if not pipeline.key_dir_ok(cfg):               # never create the key on the system disk
        sys.exit("the key stick is not plugged in (nothing is mounted at the key directory)")
    if os.path.exists(os.path.join(cfg["key_dir"], "hmac.key")):
        sys.exit("a key already exists on the key stick, refusing to overwrite it")
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
    if not pipeline.key_dir_ok(cfg):
        sys.exit("the key stick is not plugged in (nothing is mounted at the key directory)")
    if pipeline.load_key(cfg["key_dir"]) is None:
        sys.exit("no key on the key stick: run init-key first")
    if os.path.exists(os.path.join(cfg["state_dir"], "STOP")):
        sys.exit("the recording limit was reached: use 'extend' with the site's written approval")
    if len(args.approval_ref.strip()) < 3:
        sys.exit("the approval reference is too short: give its date and number")
    with open(os.path.join(cfg["key_dir"], "armed.json"), "w", encoding="utf-8") as f:
        json.dump({"approval_ref": args.approval_ref, "armed_at": datetime.datetime.now().isoformat()}, f)
    print("armed. Capture starts when the ibe-zeek services are started.")


def cmd_disarm(cfg, args):
    if not pipeline.key_dir_ok(cfg):               # the arm file is on the stick: without the stick nothing is disarmed
        sys.exit("the key stick is not plugged in: the arm file on it was not removed. Recording stops at the next "
                 "hourly run because the stick is missing, and starts again when the stick is put back")
    p = os.path.join(cfg["key_dir"], "armed.json")
    if os.path.exists(p):
        os.remove(p)
        print("disarmed. Capture stops at the next hourly run")
    else:
        print("there was no arm file on the key stick: not armed")


def cmd_extend(cfg, args):
    """Raise the limit after the site has approved an extension in writing."""
    cfg_path = args.config
    if cfg.get("config_unreadable"):               # never create a file that would put the built-in settings in force
        sys.exit(f"the configuration file {cfg_path} is missing or cannot be read: repair it first")
    with open(cfg_path, encoding="utf-8") as f:
        data = json.load(f)
    if int(args.days) < 1:
        sys.exit("the limit must be at least one day")
    if len(args.approval_ref.strip()) < 3:
        sys.exit("the approval reference is too short: give the date and number of the site's letter")
    data["max_recording_days"] = int(args.days)
    entry = {"days": int(args.days), "approval_ref": args.approval_ref, "at": datetime.datetime.now().isoformat()}
    if args.calendar_days is not None:
        if int(args.calendar_days) < 1:
            sys.exit("the calendar limit must be at least one day")
        data["max_calendar_days"] = entry["calendar_days"] = int(args.calendar_days)
    data.setdefault("extensions", []).append(entry)
    pipeline._write_atomic(os.path.abspath(cfg_path), json.dumps(data, indent=1).encode())   # never half a file
    stop = os.path.join(cfg["state_dir"], "STOP")
    if os.path.exists(stop):
        os.remove(stop)
    print("limit is now", args.days, "recording days")


def cmd_export(cfg, args):
    """Copy the data to a folder (for example a USB stick) with a checksum list.

    If an export key is configured the encrypted folder 'export' is copied, otherwise the anonymised files.
    """
    src = next((d for d in cfg["data_dirs"] if os.path.isdir(d)), None)
    if src is None:
        sys.exit("no data directory found")
    enc = os.path.join(os.path.dirname(src.rstrip("/")), "export")
    if cfg.get("export_recipient") and not os.path.isdir(enc):
        sys.exit("an export key is configured but nothing has been encrypted: check the key file, see status.json")
    if cfg.get("export_recipient") and os.path.isdir(enc):
        pipeline.encrypt_exports(cfg)
        src, names = enc, sorted(n for n in os.listdir(enc) if n.endswith(".gpg"))
    else:
        names = sorted(n for n in os.listdir(src)
                       if (n.startswith("anon-") and n.endswith(".gz")) or n in ("status.json", "devices.json", "coverage.jsonl"))
    os.makedirs(args.dest, exist_ok=True)
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
    e.add_argument("--days", required=True, help="new limit on the number of recording days")
    e.add_argument("--calendar-days", help="new limit on the days between the first and the last recording day")
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
