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
import io
import ipaddress
import json
import os
import re
import subprocess
import time
from zoneinfo import ZoneInfo

from . import core

VERSION = "0.2.0"
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
    "wan_tokens": False,
    "max_recording_days": 112,
    "timezone": "Europe/Istanbul",
    "manage_services": True,
    "auto_init_key": False,
    "dedup_window_s": 2,
    "sysfs_net": "/sys/class/net",
    "led": "",
}
ACTIVE = {"conn.log", "dns.log", "ssl.log", "capture_loss.log", "stats.log"}
LABEL_OK = re.compile(r"[A-Za-z0-9 _+/().\-]{0,40}")
VOCAB = {
    "type": {"", "pc", "server", "vm", "ip_phone", "printer", "camera", "nvr", "storage", "medical_device",
             "medical_pc", "switch", "firewall", "access_point", "other"},
    "group": {"", "agentless", "general", "infrastructure"},
    "visibility": {"", "full", "partial"},
}
DEVICE_COLUMNS = ("mac", "ip", "type", "brand", "model", "group", "visibility", "switch")


def load_config(path=None):
    cfg = dict(DEFAULTS)
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            cfg.update(json.load(f))
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


def rotated(raw_dir, iface, stem):
    return sorted(p for p in glob.glob(os.path.join(raw_dir, iface, stem + "*.log"))
                  if os.path.basename(p) not in ACTIVE)


def purge_raw(cfg, everything=False):
    """Delete raw logs from RAM. Completed logs always, the open ones too when capture is stopped."""
    for i in cfg["interfaces"]:
        for p in glob.glob(os.path.join(cfg["raw_dir"], i, "*")):
            if os.path.isfile(p) and (everything or os.path.basename(p) not in ACTIVE):
                os.remove(p)
        if everything:                     # Zeek's bookkeeping for the open logs goes with them
            for p in glob.glob(os.path.join(cfg["raw_dir"], i, ".shadow.*")):
                os.remove(p)
    if everything:
        cache = os.path.join(cfg["raw_dir"], "ip2dom.json")
        if os.path.exists(cache):
            os.remove(cache)


def load_key(key_dir):
    p = os.path.join(key_dir, "hmac.key")
    try:
        with open(p, encoding="ascii") as f:
            key = bytes.fromhex(f.read().strip())
    except (OSError, ValueError):
        return None
    return key if len(key) >= 32 else None


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


def preflight(cfg, now=None):
    """Return None if capture may run, else the reason. Used before Zeek starts and every hour."""
    now = int(now or time.time())
    if now < MIN_EPOCH:
        return "clock is not set"
    if os.path.exists(os.path.join(cfg["state_dir"], "STOP")):
        return "recording limit reached"
    if load_key(cfg["key_dir"]) is None:
        return "key stick missing"
    if not is_armed(cfg["key_dir"]):
        return "not armed"
    return None


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
        k = (r.get("proto"), r.get("id.orig_h"), r.get("id.orig_p"), r.get("id.resp_h"), r.get("id.resp_p"))
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
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def learn_gateways(records, scope, state, threshold):
    """A MAC address that fronts many non-local IP addresses is a router, not a device."""
    seen = {m: set(v) for m, v in state.items()}
    for _, r in records:
        for ip_f, mac_f in (("id.orig_h", "orig_l2_addr"), ("id.resp_h", "resp_l2_addr")):
            ip, mac = r.get(ip_f), r.get(mac_f)
            try:
                if not ip or not mac or core.is_group_mac(mac) or scope.is_local_ip(ip) \
                        or core._ip(ip).is_multicast:
                    continue
                s = seen.setdefault(core.norm_mac(mac), set())
                if len(s) <= threshold:
                    s.add(ip)
            except ValueError:
                continue
    return {m: sorted(v) for m, v in seen.items()}, {m for m, v in seen.items() if len(v) >= threshold}


def build_ip2dom(dns_recs, ssl_recs, cache, now, ttl=86400, cap=200000):
    """Address to name map from DNS answers and TLS server names. Kept in RAM, for one day at most."""
    for r in dns_recs:
        q = r.get("query")
        for a in r.get("answers") or []:
            try:
                cache[str(ipaddress.ip_address(a))] = [q, now]
            except ValueError:
                continue
    for r in ssl_recs:
        if r.get("server_name") and r.get("id.resp_h"):
            cache[r["id.resp_h"]] = [r["server_name"], now]
    live = {k: v for k, v in cache.items() if now - v[1] <= ttl and v[0]}
    if len(live) > cap:
        live = dict(sorted(live.items(), key=lambda kv: -kv[1][1])[:cap])
    return live


def _read_device_rows(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as f:
        sample = f.read(2048)
        f.seek(0)
        delim = ";" if sample.count(";") > sample.count(",") else ","      # Excel in Turkish locale
        return [{(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
                for row in csv.DictReader(f, delimiter=delim)]


def load_devices(key_dir, pz):
    """IT officer's table. Returns {pseudonym: labels}. Unsafe label text is refused, not written."""
    out, problems = {}, []
    for n, row in enumerate(_read_device_rows(os.path.join(key_dir, "devices.csv")), 2):
        labels = {}
        for c in DEVICE_COLUMNS[2:]:
            v = row.get(c, "")
            if not LABEL_OK.fullmatch(v) or core.scan_text(v) or (c in VOCAB and v not in VOCAB[c]):
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


def update_observed(key_dir, records, scope, gateways):
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
                if _device_mac(mac, gateways) and ip and scope.is_local_ip(ip):
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
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _services(cfg, action):
    if cfg.get("manage_services"):
        for unit in [f"ibe-zeek@{i}.service" for i in cfg["interfaces"]]:
            subprocess.run(["systemctl", action, unit], check=False)


def _stop(cfg, st, reason, permanent=False):
    """Stop capture and delete everything raw. A permanent stop survives reboots until 'extend'."""
    st["state"] = "stopped: " + reason
    if permanent:
        _write_atomic(os.path.join(cfg["state_dir"], "STOP"), reason.encode())
    _services(cfg, "stop")
    purge_raw(cfg, everything=True)


def capture_quality(raw_dir, ifaces):
    """Zeek's own view of the processed hour: loss estimate, packets seen, packets dropped."""
    out = {}
    for n, i in enumerate(ifaces):
        loss = [_float(r.get("percent_lost")) for p in rotated(raw_dir, i, "capture_loss") for r in read_log(p)]
        stats = [r for p in rotated(raw_dir, i, "stats") for r in read_log(p)]
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
    return copied


def disk_swap_on(path="/proc/swaps"):
    """True if a swap area on a disk is active. Compressed swap in RAM (zram) is not a disk."""
    try:
        with open(path, encoding="ascii") as f:
            return any(line.split() and not line.startswith("/dev/zram") for line in f.read().splitlines()[1:])
    except OSError:
        return False


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
    status_path = os.path.join(cfg["state_dir"], "status.json")
    st = _json_state(status_path, {})
    for k, v in (("days", []), ("records_out", 0), ("records_dropped", {}), ("errors", []), ("files", 0)):
        st.setdefault(k, v)
    last = st.get("last_run", 0)
    st.update(version=VERSION, site=cfg["site"], state="ok", warnings=[])
    # addresses of the site's own routers and networks are given on the key stick, so they stay on site
    site = _json_state(os.path.join(cfg["key_dir"], "site.json"), {})
    for k in ("gateway_macs", "local_nets"):
        v = site.get(k) if isinstance(site, dict) else None
        if isinstance(v, list) and v and all(isinstance(x, str) for x in v):
            try:
                [core.norm_mac(x) for x in v] if k == "gateway_macs" else core.Scope(v)
                cfg = dict(cfg, **{k: v})
            except ValueError:
                st["warnings"].append(f"site.json: {k} ignored, bad value")

    if cfg.get("auto_init_key") and os.path.ismount(cfg["key_dir"]) \
            and not os.path.exists(os.path.join(cfg["key_dir"], "hmac.key")):
        init_key(cfg["key_dir"])
    if now + 3600 < last:          # recorded, not fatal: stopping for good would lose more than it saves
        st["clock_jumps"] = st.get("clock_jumps", []) + [{"t": now, "back_s": last - now}]
        st["warnings"].append("the clock went backwards, check the clock battery")
    st["last_run"] = now
    why = preflight(cfg, now)
    if why == "not armed":
        _services(cfg, "stop")
        purge_raw(cfg, everything=True)
        st["state"] = "ready, not recording (not armed)"
        return _finish(cfg, st, status_path)
    if why:
        _stop(cfg, st, why)
        return _finish(cfg, st, status_path)

    pz, scope = core.Pseudonymiser(load_key(cfg["key_dir"])), core.Scope(cfg["local_nets"])
    here = os.path.dirname(os.path.abspath(__file__))
    psl = core.PublicSuffix(os.path.join(here, "public_suffix_list.dat"))
    def rule_lines(path):
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    builtin = rule_lines(os.path.join(here, "service_rules.csv"))
    try:
        cat = core.Categoriser(builtin + rule_lines(os.path.join(cfg["key_dir"], "service_rules.csv")))
    except ValueError as e:
        st["warnings"].append(f"site service rules ignored: {e}")
        cat = core.Categoriser(builtin)
    raw, ifaces, max_days = cfg["raw_dir"], cfg["interfaces"], cfg["max_recording_days"]
    tz = ZoneInfo(cfg["timezone"])

    files = {s: [(n, p) for n, i in enumerate(ifaces) for p in rotated(raw, i, s)] for s in ("conn", "dns", "ssl")}
    conn = [(n, r) for n, p in files["conn"] for r in read_log(p)]
    quality = capture_quality(raw, ifaces)
    n_written = 0
    if conn:
        cache_path = os.path.join(raw, "ip2dom.json")            # RAM only
        ip2dom = build_ip2dom((r for _, p in files["dns"] for r in read_log(p)),
                              (r for _, p in files["ssl"] for r in read_log(p)), _json_state(cache_path, {}), now)
        _write_atomic(cache_path, json.dumps(ip2dom).encode())
        names = {k: v[0] for k, v in ip2dom.items()}
        gw_path = os.path.join(cfg["key_dir"], "gateways_seen.json")   # holds real addresses, stays on site
        gw_state, learned = learn_gateways(conn, scope, _json_state(gw_path, {}), cfg["gateway_learn_threshold"])
        gateways = learned | {core.norm_mac(m) for m in cfg["gateway_macs"]}
        conn, n_dup = dedup(conn, cfg["dedup_window_s"], gateways)
        dropped = st["records_dropped"]
        dropped["duplicate"] = dropped.get("duplicate", 0) + n_dup

        labels, problems = load_devices(cfg["key_dir"], pz)
        unclassified, lines, days, devs = {}, [], set(st["days"]), set()
        for iface, r in conn:
            rec, why = core.transform(r, pz, scope, gateways, cfg["wan_tokens"], names, psl, cat, iface)
            if rec is not None and core.leak_check(rec):
                rec, why = None, "leak_check"
            if rec is not None:
                day = datetime.datetime.fromtimestamp(rec["ts"], tz).date().isoformat()
                if day not in days and len(days) >= max_days:
                    rec, why = None, "over_limit"
                else:
                    days.add(day)
            if rec is None:
                dropped[why] = dropped.get(why, 0) + 1
                continue
            lines.append(json.dumps(rec, separators=(",", ":"), sort_keys=True))
            if rec.get("wc") in ("other", "unknown"):
                dev = rec["o"] if rec["os"] == "lan" else rec["r"]
                if labels.get(dev, {}).get("group") == "agentless":
                    reg = psl.registrable(names.get(r["id.resp_h"] if rec["rs"] == "wan" else r["id.orig_h"]))
                    if reg:
                        unclassified[reg] = unclassified.get(reg, 0) + 1
            devs.update(x for x in (rec["o"], rec["r"]) if x[0] in "di" and len(x) == 11)
        text = "\n".join(lines) + "\n"
        problem = core.scan_text(text)
        if problem:
            st["errors"].append({"t": now, "e": "batch refused by leak scan: " + problem})
        elif lines:
            blob = gzip.compress(text.encode(), 6, mtime=0)
            name = f"anon-{cfg['site']}-{now}-{hashlib.sha256(blob).hexdigest()[:8]}.jsonl.gz"
            written = 0
            for n, d in enumerate(cfg["data_dirs"]):
                try:
                    _write_atomic(os.path.join(d, name), blob)
                    written += 1
                except OSError as e:
                    st["errors"].append({"t": now, "e": f"cannot write to data directory {n}: {e.strerror}"})
            if written == 0:
                _stop(cfg, st, "no writable data directory")
            else:
                n_written = len(lines)
                st["records_out"] += n_written
                st["files"] += 1
                st["days"] = sorted(days)
        # files for the IT officer. They hold real addresses and names and stay on the key stick.
        try:
            _write_atomic(gw_path, json.dumps(gw_state).encode())
            update_observed(cfg["key_dir"], conn, scope, gateways)
            if unclassified:
                up = os.path.join(cfg["key_dir"], "unclassified_domains.json")
                old = _json_state(up, {})
                for k, v in unclassified.items():
                    old[k] = old.get(k, 0) + v
                _write_atomic(up, json.dumps(old, indent=1, sort_keys=True).encode())
        except OSError as e:
            st["errors"].append({"t": now, "e": f"cannot write to key stick: {e.strerror}"})
        seen = sorted(set(st.get("devices_seen", [])) | devs)
        st.update(devices_seen=seen, devices_labelled=len([d for d in seen if d in labels]),
                  devices_in_table=len(labels), device_table_problems=problems[:20],
                  gateways=sorted(pz.device(m) for m in gateways))
        for d in cfg["data_dirs"]:
            try:
                _write_atomic(os.path.join(d, "devices.json"), json.dumps(labels, sort_keys=True).encode())
            except OSError:
                pass
    # raw logs are deleted whether or not the batch was written: nothing raw may outlive the hour
    purge_raw(cfg)

    links, warn = link_health(cfg, st.get("links"))
    st["links"] = links
    st["warnings"] += warn
    if any(q.get("loss_max", 0) > 1 for q in quality.values()):
        st["warnings"].append("capture loss above 1 percent in the last hour")
    if any(q.get("dropped", 0) > 0 for q in quality.values()):
        st["warnings"].append("packets dropped by the capture in the last hour")
    st["quality_last"] = quality
    coverage = json.dumps({"t": now, "records": n_written, "q": quality, "links": links,
                           "clock_back_s": max(0, last - now) if now + 3600 < last else 0},
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
    except OSError:
        pass
    st["recording_days"] = len(st["days"])
    today = datetime.datetime.fromtimestamp(now, tz).date().isoformat()
    if st["state"] == "ok" and st["recording_days"] >= max_days and today not in st["days"]:
        _stop(cfg, st, f"limit of {max_days} recording days reached", permanent=True)
    elif st["state"] == "ok":
        _services(cfg, "start")          # no effect when already running, restarts capture after a pause
    st["errors"] = st["errors"][-50:]
    return _finish(cfg, st, status_path)


def _finish(cfg, st, status_path):
    try:
        usage = os.statvfs(cfg["data_dirs"][0])
        st["data_free_gb"] = round(usage.f_bavail * usage.f_frsize / 1e9, 2)
    except OSError:
        st["data_free_gb"] = None
    if st["data_free_gb"] is not None and st["data_free_gb"] < cfg.get("min_free_gb", 2):
        st.setdefault("warnings", []).append("the data disk is almost full")
    st["rtc_present"] = os.path.exists("/sys/class/rtc/rtc0")
    if disk_swap_on():
        st.setdefault("warnings", []).append("disk swap is on: raw logs in memory could reach the disk")
    blob = json.dumps(st, indent=1, sort_keys=True).encode()
    if core.scan_text(blob.decode()):          # the status file leaves the site too
        blob = json.dumps({"version": VERSION, "state": "status withheld by leak scan",
                           "last_run": st.get("last_run")}).encode()
    targets = [status_path] + [os.path.join(d, "status.json") for d in cfg["data_dirs"]]
    if os.path.exists(os.path.join(cfg["key_dir"], "hmac.key")):       # the stick is plugged in
        targets.append(os.path.join(cfg["key_dir"], "status.json"))
    for p in targets:
        try:
            _write_atomic(p, blob)
        except OSError:
            pass
    set_led(cfg, st["state"])
    return st
