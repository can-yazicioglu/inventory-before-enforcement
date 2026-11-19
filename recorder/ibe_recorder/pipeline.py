# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
"""Hourly job: read rotated Zeek logs from RAM, anonymise, write, delete the raw logs.

Raw logs live only in a tmpfs directory. Only anonymised records are written to disk.
The HMAC key, the device table and every file that contains real addresses stay in key_dir,
which is a USB stick that remains at the site. Pulling the stick stops the recording.
"""
import csv
import datetime
import glob
import gzip
import hashlib
import hmac
import io
import ipaddress
import json
import math
import os
import re
import subprocess
import time
from zoneinfo import ZoneInfo

from . import core

VERSION = "0.6.0"
MIN_EPOCH = 1793491200          # 2026-11-01 UTC. A clock before this date was never set.
DEFAULTS = {
    "site": "A",
    "interfaces": ["eth1", "eth2"],
    "raw_dir": "/run/ibe/raw",
    "data_dirs": ["/mnt/ibe-data/anon", "/var/lib/ibe/anon"],
    "key_dir": "/mnt/ibe-key",
    "state_dir": "/var/lib/ibe",
    "local_nets": list(core.DEFAULT_LOCAL_NETS),
    "gateway_macs": [],
    "gateway_learn_threshold": 16,
    "gateway_forward_threshold": 2,
    "wan_tokens": False,
    "max_recording_days": 112,
    "max_calendar_days": 365,          # recording ends for good this many days after its first day
    "timezone": "Europe/Istanbul",
    "manage_services": True,
    "auto_init_key": False,
    "dedup_window_s": 2,
    "sysfs_net": "/sys/class/net",
    "proc_swaps": "/proc/swaps",
    "sysfs_block": "/sys/block",
    "proc_mounts": "/proc/mounts",
    "require_ram_disk": True,
    "require_key_mount": True,
    "rtc_epoch": "/sys/class/rtc/rtc0/since_epoch",
    "export_recipient": "",
    "led": "",
    "raise_errors": False,
}
MAX_DEVICES_SEEN = 20000                    # pseudonyms listed in status.json (17 bytes each)
STEMS = ("conn", "open_conn", "dns", "ssl", "capture_loss", "stats", "neigh")
ACTIVE = {s + ".log" for s in STEMS}        # the logs Zeek is still writing
LABEL_OK = re.compile(r"[A-Za-z0-9 _+/().\-]{0,40}")
# Brand and model are free text. On top of the address scan these shapes are refused: four groups of digits with
# any separator, eight digits in a row, twelve hexadecimal digits with or without separators (also in groups of
# four), a dot followed by a letter (a host or domain name). The name of a person or a room cannot be recognised
# by a pattern: the site reads devices.json before it hands the data over.
ADDRESS_LIKE = re.compile(r"(?:\d{1,3}[^0-9A-Za-z]){3}\d{1,3}|\d{8}|(?:[0-9A-Fa-f]{2}[^0-9A-Za-z]?){5}[0-9A-Fa-f]{2}"
                          r"|(?:[0-9A-Fa-f]{4}[^0-9A-Za-z]){2}[0-9A-Fa-f]{4}|\.[A-Za-z]")
SWITCH_OK = re.compile(r"[A-Za-z0-9]{0,3}")          # "a letter for the switch"
VOCAB = {
    "type": {"", "pc", "server", "vm", "ip_phone", "printer", "camera", "nvr", "storage", "medical_device",
             "medical_pc", "switch", "firewall", "access_point", "other"},
    "group": {"", "agentless", "general", "infrastructure"},
    "visibility": {"", "full", "partial"},
}
DEVICE_COLUMNS = ("mac", "ip", "type", "brand", "model", "group", "visibility", "switch")


def load_config(path=None):
    """Defaults, overridden by the file. A file that cannot be read as a JSON object is reported by
    config_problem, so that the recorder stops cleanly instead of failing half way."""
    cfg = dict(DEFAULTS)
    if path and not os.path.exists(path):
        cfg["config_unreadable"] = True     # a missing file must not mean: record with the built-in settings
    elif path:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("not an object")
            cfg.update(data)
        except (OSError, ValueError):
            cfg["config_unreadable"] = True
    return cfg


def read_log(path):
    """Zeek JSON log: one object per line. Malformed lines are skipped."""
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line.startswith("{"):
                try:
                    yield json.loads(line)
                except ValueError:
                    continue


def completed(cfg, stopped=False):
    """Every raw file that Zeek has finished, per capture port: [(port number, path)].

    A run reads exactly these files and deletes exactly these files. A log that Zeek completes while
    the run is busy is left for the next run instead of being deleted unread.
    stopped: capture has just been stopped, so the logs with the open names are complete as well.
    """
    return [(n, p) for n, i in enumerate(cfg["interfaces"])
            for p in sorted(glob.glob(os.path.join(cfg["raw_dir"], i, "*")))
            if os.path.isfile(p) and (stopped or os.path.basename(p) not in ACTIVE or _abandoned(p))]


def clock_step(st, now):
    """Seconds by which the system clock was moved since the last run, measured against the clock that
    cannot be set. 0 if that is not known (first run, or the device was restarted in between)."""
    mono, prev = time.monotonic(), st.get("clock_ref")
    st["clock_ref"] = [now, round(mono, 1)]
    if isinstance(prev, list) and len(prev) == 2 and all(isinstance(x, (int, float)) and not isinstance(x, bool)
                                                         and math.isfinite(x) for x in prev) and mono >= prev[1]:
        return (now - prev[0]) - (mono - prev[1])
    return 0.0


def _abandoned(path, after_s=7500):
    """An open log that has not been written for more than two rotation intervals. A running Zeek rotates
    every hour, so the capture process that wrote this file is gone and the file is complete."""
    try:
        return time.time() - os.path.getmtime(path) > after_s
    except OSError:
        return False


def of_kind(files, stem):
    """The completed logs of one kind: <stem>.<rotation time>.log."""
    return [(n, p) for n, p in files
            if os.path.basename(p).startswith(stem + ".") and p.endswith(".log")]


def _remove(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


ZEEK_FILE = re.compile(r"(?:\.shadow\.)?(?:%s)\..*" % "|".join(STEMS))


def stray_dirs(cfg):
    """Folders in the raw directory that hold Zeek logs and are not capture folders of the configuration:
    a capture process for a port that the configuration does not name. Nobody would read or delete its logs.

    Looked for only where the raw directory is a RAM disk. With a wrong path the folders found there are
    not the recorder's to touch.
    """
    if not isinstance(cfg.get("proc_mounts", ""), str) \
            or not on_ram_disk(cfg["raw_dir"], cfg.get("proc_mounts", "/proc/mounts")):
        return []
    try:
        found = [n for n in sorted(os.listdir(cfg["raw_dir"]))
                 if not n.startswith(".") and n not in cfg["interfaces"] and os.path.isdir(os.path.join(cfg["raw_dir"], n))]
    except OSError:
        return []
    return [n for n in found if _zeek_files(cfg, n)]


def _zeek_files(cfg, folder):
    """The files in a folder of the raw directory that have the name of a Zeek log. Nothing else in a folder
    that the configuration does not name is ever deleted."""
    try:
        return [os.path.join(cfg["raw_dir"], folder, n) for n in os.listdir(os.path.join(cfg["raw_dir"], folder))
                if ZEEK_FILE.fullmatch(n) and os.path.isfile(os.path.join(cfg["raw_dir"], folder, n))]
    except OSError:
        return []


def purge_raw(cfg, everything=False, only=None):
    """Delete raw logs from RAM: the files of one run (only), or everything when capture is stopped."""
    if only is not None:
        for _, p in only:
            _remove(p)
        return
    for i in cfg["interfaces"]:
        for p in glob.glob(os.path.join(cfg["raw_dir"], i, "*")):
            if os.path.isfile(p) and (everything or os.path.basename(p) not in ACTIVE):
                _remove(p)
        if everything:                     # Zeek's bookkeeping for the open logs goes with them
            for p in glob.glob(os.path.join(cfg["raw_dir"], i, ".shadow.*")):
                _remove(p)
    if everything:
        for i in stray_dirs(cfg):
            for p in _zeek_files(cfg, i):
                _remove(p)
        _remove(os.path.join(cfg["raw_dir"], "ip2dom.json"))


def load_key(key_dir):
    p = os.path.join(key_dir, "hmac.key")
    try:
        with open(p, encoding="ascii") as f:
            key = bytes.fromhex(f.read().strip())
    except (OSError, ValueError):
        return None
    return key if len(key) >= 32 and len(set(key)) >= 8 else None


def key_id(key):
    """Short fingerprint of the key. It tells whether two parts of a recording used the same key."""
    return hmac.new(key, b"ibe key id", hashlib.sha256).hexdigest()[:8]


def init_key(key_dir):
    """Create the key on the stick. It is generated on site and is never copied anywhere else."""
    path = os.path.join(key_dir, "hmac.key")
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="ascii") as f:
        f.write(core.new_key().hex() + "\n")
        f.flush()
        os.fsync(f.fileno())
    return path


def is_armed(key_dir):
    """Armed means: a file on the key stick names the ethics approval under which recording runs."""
    ref = _json_state(os.path.join(key_dir, "armed.json"), {})
    ref = ref.get("approval_ref") if isinstance(ref, dict) else None
    return isinstance(ref, str) and len(ref.strip()) >= 3


def config_problem(cfg):
    """Return None if the configuration can be used, else which entry is wrong."""
    if cfg.get("config_unreadable"):
        return "the file is missing or is not valid JSON"
    unknown = sorted(set(cfg) - set(DEFAULTS) - {"min_free_gb", "extensions"})
    if unknown:                            # a misspelt name would leave the built-in value in force
        # the name is typed by a person and this text goes into status.json: letters only, and only if it is short
        name = str(unknown[0])
        return "unknown entry " + (name if re.fullmatch(r"[a-z_]{1,30}", name) else f"number {sorted(cfg).index(unknown[0]) + 1}")
    for k in ("wan_tokens", "manage_services", "auto_init_key", "require_ram_disk", "require_key_mount", "raise_errors"):
        if not isinstance(cfg.get(k), bool):
            return k                       # "false" in quotes is a text, and a text counts as yes
    for k in ("gateway_learn_threshold", "gateway_forward_threshold", "dedup_window_s", "min_free_gb"):
        v = cfg.get(k, 2)
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not v >= 0:
            return k
    for k in ("export_recipient", "led", "sysfs_net", "proc_swaps", "sysfs_block", "proc_mounts", "rtc_epoch"):
        if not isinstance(cfg.get(k), str):
            return k
    for k in ("raw_dir", "key_dir", "state_dir", "site"):
        if not (isinstance(cfg.get(k), str) and cfg[k]):
            return k
    if not re.fullmatch(r"[A-Za-z0-9]{1,8}", cfg["site"]):
        return "site"
    try:
        ZoneInfo(cfg["timezone"])
    except Exception:                      # unknown name, empty name, wrong type
        return "timezone"
    for k in ("interfaces", "data_dirs"):
        if not _str_list(cfg.get(k)):
            return k
    # Everything below the raw log directory is deleted every hour. No other folder of the recorder may lie
    # in it, which is what a mistyped path (the folder above the key stick and the data disk) would amount to.
    raw = os.path.abspath(cfg["raw_dir"]).rstrip("/") + "/"
    for other in [cfg["key_dir"], cfg["state_dir"]] + cfg["data_dirs"]:
        if (os.path.abspath(other).rstrip("/") + "/").startswith(raw):
            return "raw_dir"
    for k in ("max_recording_days", "max_calendar_days"):
        days = cfg.get(k)
        if isinstance(days, bool) or not isinstance(days, int) or days < 1:
            return k
    try:
        core.Scope(cfg["local_nets"])
        [core.norm_mac(m) for m in cfg["gateway_macs"]]
        if core.nets_problem(cfg["local_nets"]):
            return "local_nets: " + core.nets_problem(cfg["local_nets"])
    except (ValueError, TypeError):
        return "local_nets or gateway_macs"
    return None


def _str_list(v):
    return isinstance(v, list) and bool(v) and all(isinstance(x, str) and x for x in v)


def _usable(cfg):
    """A broken configuration, repaired just enough to stop capture, empty the RAM and write the status."""
    cfg = dict(cfg)
    unreadable = cfg.pop("config_unreadable", False)
    for k in ("raw_dir", "key_dir", "state_dir", "site"):
        if not (isinstance(cfg.get(k), str) and cfg[k]) or (k == "site" and not re.fullmatch(r"[A-Za-z0-9]{1,8}", cfg[k])):
            cfg[k] = DEFAULTS[k]
    if unreadable or not _str_list(cfg.get("interfaces")):          # whatever capture directories exist are emptied
        try:
            found = sorted(n for n in os.listdir(cfg["raw_dir"]) if os.path.isdir(os.path.join(cfg["raw_dir"], n)))
        except OSError:
            found = []
        cfg["interfaces"] = found
    if not _str_list(cfg.get("data_dirs")):
        cfg.update(data_dirs=[os.path.join(cfg["state_dir"], "anon")], export_recipient="")
    for k in ("export_recipient", "led"):
        if not isinstance(cfg.get(k), str):
            cfg[k] = ""
    if isinstance(cfg.get("min_free_gb", 2), bool) or not isinstance(cfg.get("min_free_gb", 2), (int, float)):
        cfg.pop("min_free_gb", None)
    return cfg


def state_writable(state_dir):
    """The day count and the STOP mark live in this directory. If they cannot be saved the limit cannot be kept."""
    probe = os.path.join(state_dir, ".write-test")
    try:
        os.makedirs(state_dir, exist_ok=True)
        with open(probe, "wb") as f:
            f.write(b"x" * 4096)
            f.flush()
            os.fsync(f.fileno())
        os.remove(probe)
        return True
    except OSError:
        return False


def known_days(cfg, st):
    """Every recording day counted so far, from the state file and from every copy of the status (key stick,
    data directories). A state file that was lost, damaged or could not be updated cannot restart the count."""
    days = set()
    copies = [_json_state(os.path.join(d, "status.json"), {}) for d in [cfg["key_dir"]] + list(cfg["data_dirs"])]
    for src in [st] + copies:
        got = src.get("days") if isinstance(src, dict) else None
        if isinstance(got, list):
            days.update(x for x in got if isinstance(x, str) and _is_date(x))
    return sorted(days)


def _is_date(text):
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        return False
    try:
        datetime.date.fromisoformat(text)
        return True
    except ValueError:
        return False


def last_day_allowed(days, max_calendar_days):
    """The last date on which records may be written: the first recording day plus the permitted span."""
    first = datetime.date.fromisoformat(min(days))
    try:
        return (first + datetime.timedelta(days=max_calendar_days - 1)).isoformat()
    except OverflowError:
        return "9999-12-31"


def known_batches(cfg, st):
    """The number of hourly batches written so far, the largest value any copy of the status holds."""
    copies = [_json_state(os.path.join(d, "status.json"), {}) for d in [cfg["key_dir"]] + list(cfg["data_dirs"])]
    counts = [src.get("files") for src in [st] + copies if isinstance(src, dict)]
    return max([c for c in counts if isinstance(c, int) and not isinstance(c, bool) and c >= 0] + [0])


def on_stick(path, mounts="/proc/mounts"):
    """True if the path is itself the mount point of a real file system. The placeholder of an automount
    with no stick behind it, and a plain folder on the system disk, are not."""
    path, kind = os.path.realpath(path), None
    try:
        os.listdir(path)                    # a stick that is plugged in but idle is mounted by the first access
    except OSError:
        pass                                # no stick behind the automount point: the list below says so
    try:
        with open(mounts, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[1].replace("\\040", " ") == path:
                    kind = parts[2]                 # a later line is mounted on top of an earlier one
    except OSError:
        return False
    return kind is not None and kind != "autofs"


def key_dir_ok(cfg):
    return not cfg.get("require_key_mount", True) or on_stick(cfg["key_dir"], cfg.get("proc_mounts", "/proc/mounts"))


def clock_battery_ok(cfg):
    """False if the hardware clock itself reports a time before this software existed: its battery is
    empty or missing, and the system time after a power cut is only the last time that was saved."""
    if cfg.get("rtc_epoch", "") == "":
        return True                                 # switched off on purpose: a machine without a hardware clock
    try:
        with open(cfg["rtc_epoch"], encoding="ascii") as f:
            return int(f.read().strip()) >= MIN_EPOCH
    except (OSError, ValueError):
        return False                                # a hardware clock that cannot be read is no clock


def preflight(cfg, now=None):
    """Return None if capture may run, else the reason. Used before Zeek starts and every hour."""
    now = int(now or time.time())
    bad = config_problem(cfg)
    if bad:
        return "the configuration is wrong: " + bad
    if now < MIN_EPOCH or not clock_battery_ok(cfg):
        return "clock is not set"
    if cfg.get("require_ram_disk", True) and not on_ram_disk(cfg["raw_dir"], cfg.get("proc_mounts", "/proc/mounts")):
        return "the raw log directory is not in RAM"
    if disk_swap_on(cfg.get("proc_swaps", "/proc/swaps"), cfg.get("sysfs_block", "/sys/block")):
        return "swap to disk is on"        # raw logs live in RAM and must not be paged out to a disk
    if os.path.exists(os.path.join(cfg["state_dir"], "STOP")):
        return "recording limit reached"
    if not state_writable(cfg["state_dir"]):
        return "the state directory cannot be written"      # the day count could not be saved: no recording
    if not key_dir_ok(cfg) or load_key(cfg["key_dir"]) is None:
        return "key stick missing"
    if not is_armed(cfg["key_dir"]):
        return "not armed"
    return None


def _sane(r):
    """A record whose addresses, ports and time have the types Zeek writes. Anything else is dropped
    before it can upset the steps that compare records with each other."""
    def port(v):
        return v is None or (isinstance(v, int) and not isinstance(v, bool))
    return (isinstance(r.get("id.orig_h"), str) and isinstance(r.get("id.resp_h"), str)
            and all(r.get(k) is None or isinstance(r.get(k), str) for k in ("orig_l2_addr", "resp_l2_addr", "proto"))
            and port(r.get("id.orig_p")) and port(r.get("id.resp_p"))
            and isinstance(r.get("ts"), (int, float)) and not isinstance(r.get("ts"), bool))


def _device_mac(mac, gateways):
    try:
        return bool(mac) and not core.is_group_mac(mac) and core.norm_mac(mac) not in gateways
    except ValueError:
        return False


def dedup(records, window, gateways=frozenset()):
    """Drop the second copy of a connection that was captured on two mirror ports.

    The copy that names more endpoints by their own MAC address is kept, then the fuller one.
    """
    def weight(x):
        macs = sum(_device_mac(x.get(f), gateways) for f in ("orig_l2_addr", "resp_l2_addr"))
        return macs, core._int(x.get("orig_pkts")) + core._int(x.get("resp_pkts"))

    seen, out, dropped = {}, [], 0
    for iface, r in sorted(records, key=lambda x: _float(x[1].get("ts"))):
        # a request from the unspecified address (DHCP, duplicate address detection) has the same addresses and
        # ports whichever device sends it: there the sender's MAC address tells two devices from two copies
        # Flows without ports of two different IP protocols share the word 'unknown_transport' and the ports 0.
        ipp = r.get("ip_proto")
        k = (r.get("proto"), ipp if isinstance(ipp, int) else None, r.get("id.orig_h"), r.get("id.orig_p"),
             r.get("id.resp_h"), r.get("id.resp_p"), bool(r.get("_open")),
             str(r.get("orig_l2_addr") or "").lower() if r.get("id.orig_h") in ("0.0.0.0", "::") else None)
        ts = _float(r.get("ts"))
        j = seen.get(k)
        if j is not None and out[j][0] != iface and ts - _float(out[j][1].get("ts")) <= window:
            dropped += 1
            if weight(r) > weight(out[j][1]):
                out[j] = (iface, r)
            continue
        seen[k] = len(out)
        out.append((iface, r))
    return out, dropped


def _float(v):
    try:
        v = float(v)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return v if math.isfinite(v) else 0.0


def gateway_state(state):
    """The stored evidence about routers: {"nets": {mac: [networks]}, "fwd": {mac: [addresses]}}.
    Anything else in the file is ignored."""
    out = {"nets": {}, "fwd": {}}
    for kind in out:
        part = state.get(kind) if isinstance(state, dict) else None
        for mac, items in (part.items() if isinstance(part, dict) else ()):
            if isinstance(mac, str) and re.fullmatch(r"[0-9a-f]{12}", mac) and isinstance(items, list):
                out[kind][mac] = {x for x in items if isinstance(x, str)}
    return out


def learn_gateways(records, scope, state, threshold, neigh=None, fwd_threshold=2):
    """Two signs that a MAC address belongs to a router, not to a device.

    nets  it fronts addresses of many networks (/24, or /48 for IPv6) outside the site. Networks are counted,
          not addresses: a device that changes its own address stays in one network.
    fwd   it carries packets of local addresses that the neighbour protocol places at another MAC address,
          so it forwards between local networks. An address that the MAC address itself once answered for
          does not count (an address that moved from one device to another).
    Returns (state to store, set of MAC addresses learned as routers).
    """
    seen = gateway_state(state)
    nets, fwd = seen["nets"], seen["fwd"]
    for _, r in records:
        ts = _float(r.get("ts"))
        for ip_f, mac_f in (("id.orig_h", "orig_l2_addr"), ("id.resp_h", "resp_l2_addr")):
            ip, mac = r.get(ip_f), r.get(mac_f)
            try:
                if not ip or not mac or core.is_group_mac(mac):
                    continue
                a = core._ip(ip)
                if a.is_multicast or a.is_unspecified or str(a) == "255.255.255.255":
                    continue
                m = core.norm_mac(mac)
                if neigh is not None and neigh.at(ip, ts):
                    owner = neigh.live_at(ip, ts)
                    if owner and owner != m and not neigh.owned_by(str(a), m):
                        f = fwd.setdefault(m, set())
                        if len(f) <= fwd_threshold:
                            f.add(str(a))
                    continue                       # on the local link: not an address behind a router
                if scope.is_local_ip(ip):
                    continue
                n = nets.setdefault(m, set())
                if len(n) <= threshold:
                    n.add(core._net_of(ip))
            except ValueError:
                continue
    learned = {m for m, v in nets.items() if len(v) >= threshold} | {m for m, v in fwd.items() if len(v) >= fwd_threshold}
    return {k: {m: sorted(v) for m, v in part.items()} for k, part in seen.items()}, learned


def load_neighbours(path, sightings):
    """The neighbour table of the key stick, brought up to date with the sightings of this hour."""
    neigh = core.Neighbours(_json_state(path, {}))
    n = 0
    for r in sorted((r for r in sightings if isinstance(r, dict)), key=lambda r: _float(r.get("ts"))):
        n += neigh.see(r.get("ts"), r.get("ip"), r.get("mac"))
    return neigh, n


def build_ip2dom(dns_recs, ssl_recs, cache, now, scope=None, ttl=86400, cap=200000):
    """Remote address to name map from DNS answers and TLS server names. Kept in RAM, one day at most.

    Names of local addresses (the site's own host names) are never kept.
    """
    def put(ip, name):
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            return
        if isinstance(name, str) and 0 < len(name) <= 253 and not (scope and scope.is_local_ip(ip)):
            cache[ip] = [name, now]
    for r in dns_recs:
        answers = r.get("answers")
        for a in answers if isinstance(answers, list) else []:
            if isinstance(a, str):
                put(a, r.get("query"))
    for r in ssl_recs:
        if isinstance(r.get("id.resp_h"), str):
            put(r["id.resp_h"], r.get("server_name"))
    live = {k: v for k, v in cache.items() if isinstance(v, list) and len(v) == 2
            and isinstance(v[1], (int, float)) and now - v[1] <= ttl and isinstance(v[0], str) and v[0]
            and not (scope and scope.is_local_ip(k))}
    if len(live) > cap:
        live = dict(sorted(live.items(), key=lambda kv: -kv[1][1])[:cap])
    return live


def _read_device_rows(path, problems=None):
    """The rows of a device table. A row that does not fit the header keeps its addresses and loses its labels.
    A file that is not a table (a workbook saved under this name) ends the reading, it does not end the run."""
    if not os.path.exists(path):
        return []
    rows = []
    try:
        with open(path, encoding="utf-8-sig", errors="replace", newline="") as f:
            sample = f.read(2048)
            f.seek(0)
            delim = ";" if sample.count(";") > sample.count(",") else ","      # Excel in Turkish locale
            try:
                for n, row in enumerate(csv.DictReader(f, delimiter=delim), 2):
                    clean = {k.strip().lower(): v.strip() for k, v in row.items() if isinstance(k, str) and isinstance(v, str)}
                    if None in row:              # more cells than the header: which cell belongs where is unknown
                        clean = {k: v for k, v in clean.items() if k in ("mac", "ip")}
                        if problems is not None:
                            problems.append(f"line {n}: more cells than the header, labels of this line ignored")
                    rows.append(clean)
            except csv.Error:
                if problems is not None:
                    problems.append("the device table cannot be read as a table, the rest of it is ignored")
    except OSError:                          # a damaged stick, a folder under this name: the labels are lost, not the hour
        if problems is not None:
            problems.append("the device table cannot be opened or read, the rest of it is ignored")
    return rows


def load_devices(key_dir, pz):
    """IT officer's table. Returns {pseudonym: labels}. Unsafe label text is refused, not written."""
    out, problems = {}, []
    for n, row in enumerate(_read_device_rows(os.path.join(key_dir, "devices.csv"), problems), 2):
        labels = {}
        for c in DEVICE_COLUMNS[2:]:
            v = row.get(c, "")
            if not LABEL_OK.fullmatch(v) or core.scan_text(v) or ADDRESS_LIKE.search(v) \
                    or (c in VOCAB and v not in VOCAB[c]) or (c == "switch" and not SWITCH_OK.fullmatch(v)):
                problems.append(f"line {n}: column {c} refused")
                v = ""
            labels[c] = v
        if not any(labels.values()):
            continue
        try:
            if row.get("mac"):
                out[pz.device(row["mac"])] = labels
            elif row.get("ip"):
                out[pz.device_by_ip(row["ip"].split()[0])] = labels
        except ValueError:
            problems.append(f"line {n}: bad mac or ip")
    return out, problems


NOT_PRIVATE = "a network outside the private ranges can only be set in the configuration"


def update_observed(key_dir, records, scope, gateways, neigh=None):
    """Keep a list of the devices seen so far on the key stick, for the IT officer to label.

    The list holds real MAC and IP addresses. It is written to the key stick only and stays on site.
    Labels already given in devices.csv are carried over, so only new rows need filling in.
    """
    path = os.path.join(key_dir, "devices_observed.csv")
    seen, labels = {}, {}
    for src in (path, os.path.join(key_dir, "devices.csv")):
        for row in _read_device_rows(src):
            try:
                mac = core.norm_mac(row.get("mac", ""))
            except ValueError:
                continue
            seen.setdefault(mac, set()).update(row.get("ip", "").split()[:4])
            if any(row.get(c) for c in DEVICE_COLUMNS[2:]):
                labels[mac] = [row.get(c, "") for c in DEVICE_COLUMNS[2:]]
    for _, r in records:
        for ip_f, mac_f in (("id.orig_h", "orig_l2_addr"), ("id.resp_h", "resp_l2_addr")):
            ip, mac = r.get(ip_f), r.get(mac_f)
            try:
                if _device_mac(mac, gateways) and ip and (scope.is_local_ip(ip) or (
                        neigh is not None and neigh.at(ip, _float(r.get("ts"))) == core.norm_mac(mac))):
                    s = seen.setdefault(core.norm_mac(mac), set())
                    if len(s) < 4:
                        s.add(ip)
            except ValueError:
                continue
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(DEVICE_COLUMNS)
    n = 0
    for mac in sorted(seen):
        if mac not in gateways:
            pretty = ":".join(mac[i:i + 2] for i in range(0, 12, 2))
            w.writerow([pretty, " ".join(sorted(seen[mac]))] + labels.get(mac, [""] * 6))
            n += 1
    _write_atomic(path, buf.getvalue().encode())
    return n


def _write_atomic(path, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _json_state(path, default):
    try:
        with open(path, encoding="utf-8-sig") as f:      # Windows editors put a byte order mark in front
            return json.load(f)
    except (OSError, ValueError, RecursionError):        # RecursionError: brackets nested thousands deep
        return default


def _services(cfg, action, units=None):
    if cfg.get("manage_services"):
        if units is None:
            units = [f"ibe-zeek@{i}.service" for i in cfg["interfaces"]]
            if action == "stop":             # also a capture process that the configuration does not name
                units.append("ibe-zeek@*.service")
        for unit in units:
            try:
                subprocess.run(["systemctl", action, unit], check=False)
            except OSError:
                pass


def _stop(cfg, st, reason, permanent=False):
    """Stop capture and delete everything raw. A permanent stop survives reboots until 'extend'."""
    st["state"] = "stopped: " + reason
    if permanent:
        _write_atomic(os.path.join(cfg["state_dir"], "STOP"), reason.encode())
    _services(cfg, "stop")
    purge_raw(cfg, everything=True)


def capture_quality(files, ifaces):
    """Zeek's own view of the processed hour: loss estimate, packets seen, packets dropped."""
    out = {}
    for n, _ in enumerate(ifaces):
        loss = [_float(r.get("percent_lost")) for m, p in of_kind(files, "capture_loss") if m == n for r in read_log(p)]
        stats = [r for m, p in of_kind(files, "stats") if m == n for r in read_log(p)]
        # one report every five minutes while the capture runs: [time, packets seen since the last report].
        # A missing report or a report without packets marks a time when nothing was recorded.
        q = {"stats": sorted([int(_float(r.get("ts"))), core._int(r.get("pkts_proc"))] for r in stats),
             "pkts": sum(core._int(r.get("pkts_proc")) for r in stats),
             "dropped": sum(core._int(r.get("pkts_dropped")) for r in stats)}
        if loss:
            q.update(loss_n=len(loss), loss_mean=round(sum(loss) / len(loss), 4), loss_max=round(max(loss), 4))
        out[str(n)] = q
    return out


def link_health(cfg, prev):
    """Link state and received packet counters of the capture ports, read from the kernel."""
    cur, warn = {}, []
    for n, i in enumerate(cfg["interfaces"]):
        def rd(name):
            try:
                with open(os.path.join(cfg["sysfs_net"], i, name)) as f:
                    return int(f.read().strip())
            except (OSError, ValueError):
                return None
        carrier, rx = rd("carrier"), rd("statistics/rx_packets")
        cur[str(n)] = {"carrier": carrier, "rx_packets": rx}
        if carrier == 0:
            warn.append(f"no link on capture port {n}")
        old = (prev or {}).get(str(n), {}).get("rx_packets")
        if rx is not None and old is not None and rx == old:
            warn.append(f"no packets on capture port {n} since the last run")
    return cur, warn


def sync_dirs(dirs):
    """Copy anonymised files that one data directory has and another lacks (after an export or an outage)."""
    names = {d: {n for n in os.listdir(d) if n.startswith("anon-") and n.endswith(".gz")}
             for d in dirs if os.path.isdir(d)}
    copied = 0
    for src, have in names.items():
        for dst, there in names.items():
            for n in sorted(have - there):
                try:
                    with open(os.path.join(src, n), "rb") as f:
                        _write_atomic(os.path.join(dst, n), f.read())
                    there.add(n)
                    copied += 1
                except OSError:
                    break
    # the hourly coverage lines: every directory gets the union, so that a disk that was away for
    # some hours does not make those hours look like an outage
    cov = {}
    for d in names:
        try:
            with open(os.path.join(d, "coverage.jsonl"), encoding="ascii", errors="ignore") as f:
                cov[d] = [x for x in f.read().splitlines() if x.strip()]
        except OSError:
            cov[d] = []
    def when(line):
        try:
            t = json.loads(line).get("t", 0)
        except (ValueError, AttributeError, RecursionError):
            t = 0
        # a time that is not a number (a line edited by hand) must not stop the lines from being put in order
        return (t if isinstance(t, (int, float)) and not isinstance(t, bool) and t == t else 0), line
    union = sorted({x for lines in cov.values() for x in lines}, key=when)
    for d, lines in cov.items():
        if lines != union:
            try:
                _write_atomic(os.path.join(d, "coverage.jsonl"), ("\n".join(union) + "\n").encode("ascii"))
                copied += 1
            except OSError:
                pass
    return copied


def on_ram_disk(path, mounts="/proc/mounts"):
    """True if the path lies on a file system that exists in memory only (tmpfs or ramfs)."""
    path = os.path.realpath(path)
    best, kind = "", ""
    try:
        with open(mounts, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                point = parts[1].replace("\\040", " ")
                if (path == point or path.startswith(point.rstrip("/") + "/")) and len(point) >= len(best):
                    best, kind = point, parts[2]      # the longest mount point wins, a later line wins a tie
    except OSError:
        return False
    return kind in ("tmpfs", "ramfs")


def disk_swap_on(path="/proc/swaps", sysfs_block="/sys/block"):
    """True if memory can be written to a disk, which would let raw logs in RAM reach it.

    That is any active swap area except compressed swap in RAM (zram) that has no backing device.
    Raspberry Pi OS sets zram up with a backing file by default: idle pages are then moved to the disk.
    """
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            lines = f.read().splitlines()[1:]
    except OSError:
        return True                        # the list cannot be read: assume the worst
    for line in lines:
        if not line.split():
            continue
        dev = os.path.basename(line.split()[0])
        if not line.split()[0].startswith("/dev/zram"):
            return True
        try:
            with open(os.path.join(sysfs_block, dev, "backing_dev"), encoding="ascii", errors="replace") as f:
                if f.read().strip() not in ("", "none"):
                    return True
        except OSError:
            pass                           # this kernel cannot give zram a backing device
    return False


def encrypt_exports(cfg, only=None):
    """Encrypt the anonymised files for the researchers' public key into the folder 'export'.

    The folder sits next to the first data directory. Each file is encrypted once, the three small
    summary files are refreshed every run. Only the holder of the private key can read the result,
    so the folder can travel by any channel. Returns (files encrypted, error text or None).
    """
    key = cfg.get("export_recipient")
    src = cfg["data_dirs"][0]
    if not key or not os.path.isdir(src):
        return 0, None
    if not os.path.exists(key):
        return 0, "the export key file is missing, nothing is encrypted"
    dst = os.path.join(os.path.dirname(src.rstrip("/")), "export")
    home = os.path.join(cfg["raw_dir"], ".gnupg")
    os.makedirs(dst, exist_ok=True)
    os.makedirs(home, mode=0o700, exist_ok=True)
    fresh, n = ("status.json", "devices.json", "coverage.jsonl"), 0
    for name in sorted(os.listdir(src)):
        if only is not None and name not in only:
            continue
        if not (name in fresh or (name.startswith("anon-") and name.endswith(".gz"))):
            continue
        out = os.path.join(dst, name + ".gpg")
        if os.path.exists(out) and name not in fresh:
            continue
        try:
            r = subprocess.run(["gpg", "--batch", "--yes", "--no-options", "--homedir", home, "--trust-model", "always",
                                "--recipient-file", key, "--output", out + ".tmp", "--encrypt", os.path.join(src, name)],
                               capture_output=True, text=True)
        except OSError as e:
            return n, f"gpg cannot be run: {e.strerror}"
        if r.returncode:
            return n, "gpg refused the key or the file"
        os.replace(out + ".tmp", out)
        n += 1
    return n, None


def set_led(cfg, state):
    """Best effort health light: heartbeat while recording, solid when ready, fast blink when stopped."""
    led = cfg.get("led")
    if not led or not os.path.isdir(led):
        return
    mode = "heartbeat" if state == "ok" else "default-on" if state.startswith("ready") else "timer"
    try:
        with open(os.path.join(led, "trigger"), "w") as f:
            f.write(mode)
        if mode == "timer":
            for name in ("delay_on", "delay_off"):
                with open(os.path.join(led, name), "w") as f:
                    f.write("120")
    except OSError:
        pass


def run_once(cfg, now=None):
    """Process every completed (rotated) raw log. Returns the status dictionary."""
    now = int(now or time.time())
    problem = config_problem(cfg)
    if problem:
        cfg = _usable(cfg)                 # enough to stop capture, empty the RAM and say why
    status_path = os.path.join(cfg["state_dir"], "status.json")
    st = _json_state(status_path, {})
    if not isinstance(st, dict):
        st = {}
    for k, v in (("days", []), ("records_out", 0), ("records_dropped", {}), ("errors", []), ("files", 0)):
        st.setdefault(k, v)
    st["days"] = known_days(cfg, st)
    st["files"] = known_batches(cfg, st)
    last = st.get("last_run", 0)
    st.update(version=VERSION, site=cfg["site"], state="ok", warnings=[])
    # addresses of the site's own routers and networks are given on the key stick, so they stay on site
    site = _json_state(os.path.join(cfg["key_dir"], "site.json"), None)
    if not isinstance(site, dict) and os.path.exists(os.path.join(cfg["key_dir"], "site.json")):
        st["warnings"].append("site.json on the key stick cannot be read and is ignored")
    for k in ("gateway_macs", "local_nets"):
        v = site.get(k) if isinstance(site, dict) else None
        if isinstance(v, list) and v and all(isinstance(x, str) for x in v):
            try:
                [core.norm_mac(x) for x in v] if k == "gateway_macs" else core.Scope(v)
                if k == "local_nets" and (core.nets_problem(v) or core.public_nets(v)):
                    # A host in a local network is named by a token of its address. For addresses outside the
                    # private ranges that needs the site's written permission, which the stick cannot give:
                    # such a network can only be set in the configuration. (A public address that devices use
                    # on the local link is recognised by itself, through the neighbour table.)
                    raise ValueError(NOT_PRIVATE)
                cfg = dict(cfg, **{k: v})
            except ValueError as e:
                st["warnings"].append(f"site.json: {k} ignored, " + (NOT_PRIVATE if str(e) == NOT_PRIVATE else "bad value"))
    if not config_problem(cfg) and core.public_nets(cfg["local_nets"]):
        st["warnings"].append(f"{core.public_nets(cfg['local_nets'])} of the local networks in the configuration are public "
                              "address space: hosts in them are named by tokens")

    if cfg.get("auto_init_key") and os.path.ismount(cfg["key_dir"]) and key_dir_ok(cfg) \
            and not os.path.exists(os.path.join(cfg["key_dir"], "hmac.key")):
        try:                               # an automount point without a stick behind it fails here
            init_key(cfg["key_dir"])
        except OSError:
            pass
    if now + 3600 < last:          # recorded, not fatal: stopping for good would lose more than it saves
        st["clock_jumps"] = st.get("clock_jumps", []) + [{"t": now, "back_s": last - now}]
        st["warnings"].append("the clock went backwards, check the clock battery")
    st["last_run"] = now
    step = clock_step(st, now)
    why = "the configuration is wrong: " + problem if problem else preflight(cfg, now)
    if why == "not armed":
        _services(cfg, "stop")
        purge_raw(cfg, everything=True)
        st["state"] = "ready, not recording (not armed)"
        if os.path.exists(os.path.join(cfg["key_dir"], "armed.json")):
            st["warnings"].append("armed.json is on the key stick but holds no usable approval reference")
        return _finish(cfg, st, status_path)
    if why:
        _stop(cfg, st, why)
        return _finish(cfg, st, status_path)

    stray = stray_dirs(cfg)
    if stray:          # a capture process the configuration does not name: nobody would read or delete its logs
        _services(cfg, "stop", [f"ibe-zeek@{i}.service" for i in stray])
        for i in stray:
            for p in _zeek_files(cfg, i):
                _remove(p)
        st["warnings"].append("a capture directory that is not in the configuration was stopped and emptied")
    # Zeek rotates its logs when its own clock reaches the next full hour, and that clock never goes back.
    # After a step back it would hold its logs open, and raw data in RAM, until the system clock has caught
    # up. So capture is stopped here (a stopped Zeek has written everything out) and started again below.
    restart = step < -60 and bool(cfg.get("manage_services"))
    if restart:
        _services(cfg, "stop")
        st["warnings"].append("the clock was set back: capture was restarted so that its logs are completed again")
    files = completed(cfg, stopped=restart)
    n_written, quality = 0, {}
    try:
        n_written, quality = _process(cfg, st, now, files)
    except Exception as e:                 # whatever goes wrong, the raw logs of this hour must still go
        if cfg.get("raise_errors"):
            raise
        tb = e.__traceback__
        while tb.tb_next:
            tb = tb.tb_next
        # the type and the place only: the text of an error could quote raw data
        where = f"{type(e).__name__} at {os.path.basename(tb.tb_frame.f_code.co_filename)}:{tb.tb_lineno}"
        st["errors"].append({"t": now, "e": "run failed, the hour was not written: " + where})
        st["warnings"].append("the last run failed: " + where)
    finally:
        # raw logs are deleted whether or not the batch was written: nothing raw may outlive its run
        purge_raw(cfg, only=files)
        if restart:                        # Zeek's notes about the open logs that were just read and deleted
            for i in cfg["interfaces"]:
                for p in glob.glob(os.path.join(cfg["raw_dir"], i, ".shadow.*")):
                    _remove(p)

    links, warn = link_health(cfg, st.get("links"))
    st["links"] = links
    st["warnings"] += warn
    if any(q.get("loss_max", 0) > 1 for q in quality.values()):
        st["warnings"].append("capture loss above 1 percent in the last hour")
    if any(q.get("dropped", 0) > 0 for q in quality.values()):
        st["warnings"].append("packets dropped by the capture in the last hour")
    st["quality_last"] = quality
    coverage = json.dumps({"t": now, "records": n_written, "q": quality, "links": links,
                           "clock_back_s": max(0, last - now) if now + 3600 < last else 0,
                           "key": st.get("key_id", "")},
                          separators=(",", ":"), sort_keys=True)
    for d in cfg["data_dirs"]:
        try:
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "coverage.jsonl"), "a", encoding="ascii") as f:
                f.write(coverage + "\n")
        except OSError:
            st["warnings"].append("a data directory is not writable")
    try:
        sync_dirs(cfg["data_dirs"])
    except (OSError, ValueError):          # a damaged file on the data disk must not fail the run
        st["warnings"].append("the data directories could not be compared")
    st["recording_days"] = len(st["days"])
    tz = ZoneInfo(cfg["timezone"])
    today = datetime.datetime.fromtimestamp(now, tz).date().isoformat()
    # Three limits. The number of days on which records were written. The number of hourly batches written,
    # which a clock that stands still or is set back cannot stretch. And the calendar: days without recording
    # move the end, but never further than max_calendar_days after the first day.
    over_days = st["recording_days"] >= cfg["max_recording_days"] and today != max(st["days"])
    over_hours = st["files"] >= cfg["max_recording_days"] * 25
    over_span = bool(st["days"]) and today > last_day_allowed(st["days"], cfg["max_calendar_days"])
    if st["state"] == "ok" and (over_days or over_hours):
        _stop(cfg, st, f"limit of {cfg['max_recording_days']} recording days reached", permanent=True)
    elif st["state"] == "ok" and over_span:
        _stop(cfg, st, f"limit of {cfg['max_calendar_days']} days since the first recording day reached",
              permanent=True)
    elif st["state"] == "ok":
        _services(cfg, "start")          # no effect when already running, restarts capture after a pause
    st["errors"] = st["errors"][-50:]
    return _finish(cfg, st, status_path)


def _process(cfg, st, now, files):
    """Anonymise the completed logs in 'files' and write the batch. Returns (records written, quality)."""
    key = load_key(cfg["key_dir"])
    pz, scope = core.Pseudonymiser(key), core.Scope(cfg["local_nets"])
    kid = key_id(key)
    if st.get("key_id") not in (None, kid):
        st["key_changes"] = st.get("key_changes", []) + [{"t": now, "from": st["key_id"], "to": kid}]
    if st.get("key_changes"):
        st["warnings"].append("the key on the stick was replaced during the recording: "
                              "pseudonyms before and after do not match")
    st["key_id"] = kid
    here = os.path.dirname(os.path.abspath(__file__))
    psl = core.PublicSuffix(os.path.join(here, "public_suffix_list.dat"))
    def rule_lines(path):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                return f.read().splitlines()
        except OSError:                    # missing, or not readable: no rules from this file
            return []
    builtin = rule_lines(os.path.join(here, "service_rules.csv"))
    cat = core.Categoriser(builtin)
    try:
        # a category is a word that leaves the site: the stick may assign domains to the built-in words only
        cat.rules.update(core.Categoriser(rule_lines(os.path.join(cfg["key_dir"], "service_rules.csv"))).rules)
    except ValueError:
        st["warnings"].append("service_rules.csv on the key stick ignored: a line has a category "
                              "that is not one of the built-in ones")
    raw, max_days, max_span = cfg["raw_dir"], cfg["max_recording_days"], cfg["max_calendar_days"]
    tz = ZoneInfo(cfg["timezone"])

    dropped = st["records_dropped"]
    conn = []
    for stem in ("conn", "open_conn"):                # open_conn: hourly reports about connections still open
        for n, p in of_kind(files, stem):
            for r in read_log(p):
                if not _sane(r):
                    dropped["malformed"] = dropped.get("malformed", 0) + 1
                    continue
                r.pop("_open", None)
                if stem == "open_conn":
                    r["_open"] = True
                conn.append((n, r))
    quality = capture_quality(files, cfg["interfaces"])
    n_written = 0
    cache_path = os.path.join(raw, "ip2dom.json")            # RAM only
    cache = _json_state(cache_path, {})
    ip2dom = build_ip2dom((r for _, p in of_kind(files, "dns") for r in read_log(p)),
                          (r for _, p in of_kind(files, "ssl") for r in read_log(p)),
                          cache if isinstance(cache, dict) else {}, now, scope)
    _write_atomic(cache_path, json.dumps(ip2dom).encode())   # also in an hour without connections: names expire
    neigh_path = os.path.join(cfg["key_dir"], "neighbours.json")    # holds real addresses, stays on site
    neigh, n_seen = load_neighbours(neigh_path, (r for _, p in of_kind(files, "neigh") for r in read_log(p)))
    st["neighbours"] = len(neigh.table)
    odd = sum(1 for ip in neigh.table if not scope.is_local_ip(ip))
    if odd:
        # Such a site has networks of its own that the list does not know. A host of the site in another of
        # them, behind a router, is written as a remote host ('wan') and cannot be told apart later.
        st["warnings"].append(f"{odd} addresses on the local link are outside the local networks: if the site has more "
                              "networks of that kind, they must be listed in the configuration (local_nets), or its "
                              "hosts behind a router are recorded as remote hosts")
    if n_seen:
        try:
            _write_atomic(neigh_path, json.dumps(neigh.dump(now)).encode())
        except OSError as e:
            st["errors"].append({"t": now, "e": f"cannot write to key stick: {e.strerror}"})
    if not conn:
        return 0, quality
    names = {k: v[0] for k, v in ip2dom.items()}
    gw_path = os.path.join(cfg["key_dir"], "gateways_seen.json")   # holds real addresses, stays on site
    gw_state, learned = learn_gateways(conn, scope, _json_state(gw_path, {}), cfg["gateway_learn_threshold"],
                                       neigh, cfg["gateway_forward_threshold"])
    gateways = learned | {core.norm_mac(m) for m in cfg["gateway_macs"]}
    conn, n_dup = dedup(conn, cfg["dedup_window_s"], gateways)
    dropped["duplicate"] = dropped.get("duplicate", 0) + n_dup

    labels, problems = load_devices(cfg["key_dir"], pz)
    categories = set(cat.rules.values()) | set(core.PORT_CATEGORY.values()) | {"other", "unknown"}
    unclassified, lines, days, devs, n_open = {}, [], set(st["days"]), set(), 0
    for iface, r in conn:
        rec, why = core.transform(r, pz, scope, gateways, cfg["wan_tokens"], names, psl, cat, iface,
                                  bool(r.get("_open")), neigh)
        if rec is not None and not MIN_EPOCH <= rec["ts"] <= now + 86400:
            rec, why = None, "bad_time"            # stamped by a clock that was not set
        if rec is not None and core.leak_check(rec, categories):
            rec, why = None, "leak_check"
        if rec is not None:
            day = datetime.datetime.fromtimestamp(rec["ts"], tz).date().isoformat()
            if day not in days and (len(days) >= max_days or (days and day > last_day_allowed(days, max_span))):
                rec, why = None, "over_limit"
            else:
                days.add(day)
        if rec is None:
            dropped[why] = dropped.get(why, 0) + 1
            continue
        lines.append(json.dumps(rec, separators=(",", ":"), sort_keys=True))
        n_open += "open" in rec
        if rec.get("wc") in ("other", "unknown"):
            dev = rec["o"] if rec["os"] == "lan" else rec["r"]
            if labels.get(dev, {}).get("group") == "agentless":
                reg = psl.registrable(names.get(r["id.resp_h"] if rec["rs"] == "wan" else r["id.orig_h"]))
                if reg:
                    unclassified[reg] = unclassified.get(reg, 0) + 1
        # a device counts as seen once it has sent a packet. An address that was only tried (a sweep through
        # the router) would otherwise stay in this list, and in every copy of the status, for good.
        devs.update(x for x, sent in ((rec["o"], rec["opk"] > 0), (rec["r"], rec["rpk"] > 0))
                    if sent and x[0] in "di" and len(x) == 11)
    text = "\n".join(lines) + "\n"
    problem = core.scan_text(text)
    if problem:
        st["errors"].append({"t": now, "e": "batch refused by leak scan: " + problem})
        dropped["leak_scan"] = dropped.get("leak_scan", 0) + len(lines)
    elif lines:
        blob = gzip.compress(text.encode(), 6, mtime=0)
        name = f"anon-{cfg['site']}-{now}-{hashlib.sha256(blob).hexdigest()[:8]}.jsonl.gz"
        # The batch is counted before it is written. A run that dies after writing it (power cut, time limit,
        # an error further down) would otherwise leave a batch and a day that no limit knows of.
        try:
            _write_atomic(os.path.join(cfg["state_dir"], "status.json"),
                          json.dumps(dict(st, files=st["files"] + 1, days=sorted(days)), indent=1, sort_keys=True).encode())
        except OSError:
            pass                           # _finish stops capture if the state cannot be written
        written = 0
        for n, d in enumerate(cfg["data_dirs"]):
            try:
                _write_atomic(os.path.join(d, name), blob)
                written += 1
            except OSError as e:
                st["errors"].append({"t": now, "e": f"cannot write to data directory {n}: {e.strerror}"})
        if written == 0:
            _stop(cfg, st, "no writable data directory")
            dropped["not_written"] = dropped.get("not_written", 0) + len(lines)
        else:
            n_written = len(lines)
            st["records_out"] += n_written
            st["records_open"] = st.get("records_open", 0) + n_open
            st["files"] += 1
            st["days"] = sorted(days)
    # files for the IT officer. They hold real addresses and names and stay on the key stick.
    try:
        _write_atomic(gw_path, json.dumps(gw_state).encode())
        update_observed(cfg["key_dir"], conn, scope, gateways, neigh)
        if unclassified:
            up = os.path.join(cfg["key_dir"], "unclassified_domains.json")
            old = _json_state(up, {})
            old = old if isinstance(old, dict) else {}
            for k, v in unclassified.items():
                old[k] = core._int(old.get(k)) + v
            _write_atomic(up, json.dumps(old, indent=1, sort_keys=True).encode())
    except OSError as e:
        st["errors"].append({"t": now, "e": f"cannot write to key stick: {e.strerror}"})
    seen = sorted(set(st.get("devices_seen", [])) | devs)
    if len(seen) > MAX_DEVICES_SEEN:           # a flood of made-up senders: the count is kept, the list is not
        st["warnings"].append("more devices than the status can list, the list is cut")
        seen = seen[:MAX_DEVICES_SEEN]
    st.update(devices_seen=seen, devices_labelled=len([d for d in seen if d in labels]),
              devices_in_table=len(labels), device_table_problems=problems[:20],
              gateways=sorted(pz.device(m) for m in gateways))
    for d in cfg["data_dirs"]:
        try:
            _write_atomic(os.path.join(d, "devices.json"), json.dumps(labels, sort_keys=True).encode())
        except OSError:
            pass
    return n_written, quality


def _finish(cfg, st, status_path):
    try:
        usage = os.statvfs(cfg["data_dirs"][0])
        st["data_free_gb"] = round(usage.f_bavail * usage.f_frsize / 1e9, 2)
    except OSError:
        st["data_free_gb"] = None
    if st["data_free_gb"] is not None and st["data_free_gb"] < cfg.get("min_free_gb", 2):
        st.setdefault("warnings", []).append("the data disk is almost full")
    st["rtc_present"] = os.path.exists("/sys/class/rtc/rtc0")
    try:
        done, err = encrypt_exports(cfg)
        st["export_encrypted"] = st.get("export_encrypted", 0) + done
        if err:
            st.setdefault("warnings", []).append("export encryption failed: " + err)
    except OSError as e:
        st.setdefault("warnings", []).append(f"export encryption failed: {e.strerror}")
    try:
        # the device's own state (day count, counters) stays on the device and is always written in full
        _write_atomic(status_path, json.dumps(st, indent=1, sort_keys=True).encode())
    except OSError:
        # the day count cannot be saved, so the limit could not be kept: no recording until it can
        st["state"] = "stopped: the state directory cannot be written"
        _services(cfg, "stop")
        purge_raw(cfg, everything=True)
    blob = json.dumps(st, indent=1, sort_keys=True).encode()
    if core.scan_text(blob.decode()):          # the copies of the status leave the site
        blob = json.dumps({"version": VERSION, "state": "status withheld by leak scan",
                           "last_run": st.get("last_run"), "days": st.get("days")}).encode()
    targets = [os.path.join(d, "status.json") for d in cfg["data_dirs"]]
    if key_dir_ok(cfg) and os.path.exists(os.path.join(cfg["key_dir"], "hmac.key")):       # the stick is plugged in
        targets.append(os.path.join(cfg["key_dir"], "status.json"))
    for p in targets:
        try:
            _write_atomic(p, blob)
        except OSError:
            pass
    try:
        encrypt_exports(cfg, only=("status.json",))        # the copy in 'export' shows the status just written
    except OSError:
        pass
    failed = any(w.startswith("the last run failed") for w in st.get("warnings", []))
    set_led(cfg, "failed" if failed and st["state"] == "ok" else st["state"])
    return st
