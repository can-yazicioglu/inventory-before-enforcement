#!/usr/bin/env python3
# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
"""Adapter: anonymised recorder output (recorder/) into the common schema (see normalize3.py).

One output row per (connection record, local endpoint). The recorder names local devices by
pseudonym and never names remote hosts, so:
  device     pseudonym of the local endpoint
  dev_init   True for the side that opened the connection (role is taken from this: GT_ROLE=init)
  dev_pl     bytes the device sent. For the answering side it is at least 1 when the connection was
             established, 0 otherwise, which is the participation filter for connection logs
  peer_id    LAN: 'dev:<pseudonym>' (identity by MAC) or 'ip:<pseudonym>' (identity by address)
             WAN: one-way host token when the site allows it, else 'wc_<service type>'
  peer_addr  WAN: '<network token>.0', so that the /24 rule of incidence3.py yields the network token
Two kinds of record need care:
  handshake not seen   a TCP record without the opening SYN and without the answering SYN-ACK was
             picked up in the middle of a conversation (capture start, a restart, a long silence).
             Who opened it is unknown, so dev_init is NULL and incidence3.py decides the role with
             the rules it uses for flow exports. Such a record counts for a device only if the
             device sent a packet in it other than a reset.
  open       an hourly report about a connection that is still open. It marks the flow as present
             at that time. Its bytes are not added (the final record carries the totals).
Days on which the recorder was down for more than an hour inside working hours are dropped.

Usage:
  adapt_recorder.py <export_dir> <out.parquet> [--dataset NAME] [--tz Europe/Istanbul]
                    [--hours "1-5=08:00-17:00,6=08:00-13:30"] [--group agentless] [--visibility full]
Then:
  GT_ROLE=init GT_INPUTS="<out.parquet>|<tz>" python3 incidence3.py x x <inc_dir>
"""
import argparse
import datetime
import glob
import json
import os
from zoneinfo import ZoneInfo

REPORT_S = 300          # the recorder writes one capture report every five minutes
SLACK_S = 5             # report times are whole seconds and the timer is not exact
COLUMNS = {"ts": "BIGINT", "proto": "VARCHAR", "ipp": "INTEGER", "op": "INTEGER", "rp": "INTEGER", "os": "VARCHAR",
           "rs": "VARCHAR", "o": "VARCHAR", "r": "VARCHAR", "ob": "BIGINT", "rb": "BIGINT", "est": "BOOLEAN",
           "wc": "VARCHAR", "wh": "VARCHAR", "wn": "VARCHAR", "wd": "VARCHAR", "hist": "VARCHAR", "opk": "BIGINT",
           "open": "BOOLEAN"}
OPEN = "coalesce(open, false)"
# handshake not seen: neither the originator's SYN (S) nor the responder's SYN-ACK (h) is in the history
UNKNOWN = "(proto = 'tcp' AND NOT regexp_matches(coalesce(hist, ''), '[Sh]'))"
# the originator sent something other than a reset: in the reported hour, or anywhere in a finished record
O_PART = f"(CASE WHEN {OPEN} THEN opk > 0 ELSE regexp_matches(coalesce(hist, ''), '[ADFH]') END)"


def parse_hours(spec):
    """'1-5=08:00-17:00,6=08:00-13:30' -> {isoweekday: (start_minute, end_minute)}."""
    out = {}
    for part in filter(None, (spec or "").split(",")):
        days, span = part.split("=")
        lo, _, hi = days.partition("-")
        a, b = span.split("-")
        mins = [int(x[:2]) * 60 + int(x[3:5]) for x in (a, b)]
        for d in range(int(lo), int(hi or lo) + 1):
            out[d] = (mins[0], mins[1])
    return out


def _merge(intervals):
    out = []
    for lo, hi in sorted(intervals):
        if out and lo <= out[-1][1]:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return out


def _intersect(a, b):
    out, i, j = [], 0, 0
    while i < len(a) and j < len(b):
        lo, hi = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        if lo < hi:
            out.append([lo, hi])
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return out


def outage_days(coverage_lines, tz, hours, limit_s=3600):
    """Local days on which capture was down for more than limit_s inside working hours.

    Every capture report covers the five minutes before it, and counts only if packets were seen.
    The site is recorded at a moment only if every capture port is. Days from the first to the
    last report are judged (the first and the last day are partial anyway).
    Returns (sorted list of days, {day: seconds down}).
    """
    zone = ZoneInfo(tz)
    per_port = {}
    for line in coverage_lines:
        for port, v in line.get("q", {}).items():
            per_port.setdefault(port, [])
            per_port[port] += [[int(t) - REPORT_S - SLACK_S, int(t)] for t, pkts in v.get("stats", []) if pkts > 0]
    if not per_port or not hours or not any(per_port.values()):
        return [], {}
    covered = None
    for iv in per_port.values():
        covered = _merge(iv) if covered is None else _intersect(covered, _merge(iv))
    ends = [hi for iv in per_port.values() for _, hi in iv]
    day = datetime.datetime.fromtimestamp(min(ends), zone).date()
    last = datetime.datetime.fromtimestamp(max(ends), zone).date()
    down = {}
    while day <= last:
        span = hours.get(day.isoweekday())
        if span:
            midnight = datetime.datetime.combine(day, datetime.time(0), zone)
            ws = int((midnight + datetime.timedelta(minutes=span[0])).timestamp())
            we = int((midnight + datetime.timedelta(minutes=span[1])).timestamp())
            seen = sum(min(hi, we) - max(lo, ws) for lo, hi in covered if lo < we and hi > ws)
            if we - ws - seen > 0:
                down[day.isoformat()] = we - ws - seen
        day += datetime.timedelta(days=1)
    return sorted(d for d, sec in down.items() if sec > limit_s), down


def convert(src, out, dataset="siteA", tz="Europe/Istanbul", hours="", group="", visibility=""):
    """Write the normalised rows of the export folder 'src' to the parquet file 'out'. Returns a summary."""
    import duckdb

    def load(name, default):
        try:
            with open(os.path.join(src, name), encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return default
    status, labels = load("status.json", {}), load("devices.json", {})
    site = str(status.get("site", "A"))
    gateways = set(status.get("gateways", []))
    cov = []
    if os.path.exists(os.path.join(src, "coverage.jsonl")):
        with open(os.path.join(src, "coverage.jsonl"), encoding="utf-8") as f:
            cov = [json.loads(x) for x in f if x.strip()]
    dropped, down = outage_days(cov, tz, parse_hours(hours))
    keys = sorted({str(c["key"]) for c in cov if isinstance(c, dict) and c.get("key")})
    keep = None
    if group or visibility:
        keep = sorted(d for d, v in labels.items() if (not group or v.get("group") == group)
                      and (not visibility or v.get("visibility") == visibility))

    files = sorted(glob.glob(os.path.join(src, "anon-*.jsonl.gz")))
    if not files:
        raise SystemExit(f"no anon-*.jsonl.gz files in {src}")
    con = duckdb.connect()
    con.execute("SET threads TO 2")
    con.execute("SET memory_limit='5GB'")
    cols = "{" + ", ".join(f"'{k}': '{v}'" for k, v in COLUMNS.items()) + "}"
    con.execute(f"CREATE TABLE r AS SELECT * FROM read_json({files}, format='newline_delimited', columns={cols})")
    def table(name, kind, values):
        con.execute(f"CREATE TABLE {name}(d {kind})")
        if values:
            con.executemany(f"INSERT INTO {name} VALUES (?)", [[v] for v in values])
    table("gw", "VARCHAR", sorted(gateways))
    table("bad_day", "DATE", dropped)
    proto = "CASE WHEN ipp > 0 THEN ipp WHEN proto = 'tcp' THEN 6 WHEN proto = 'udp' THEN 17 WHEN proto = 'icmp' THEN 1 ELSE 255 END"
    ported = "proto IN ('tcp', 'udp')"

    def side(dev, dev_scope, peer, peer_scope, dev_port, peer_port, init, dev_pl, took_part):
        return f"""
        SELECT '{dataset}' AS dataset, '{site}' AS site, {dev} AS device, make_timestamp(ts * 1000000) AS ts,
               {proto} AS proto,
               CASE WHEN {ported} THEN {dev_port} END AS dev_port, CASE WHEN {ported} THEN {peer_port} END AS peer_port,
               {peer_scope} AS peer_scope,
               CASE WHEN {peer_scope} = 'wan' THEN coalesce(wn || '.0', 'wc_' || wc) ELSE {peer} END AS peer_addr,
               CASE WHEN {peer_scope} = 'lan' THEN (CASE WHEN {peer} LIKE 'd%' THEN 'dev:' ELSE 'ip:' END) || {peer}
                    WHEN {peer_scope} = 'wan' THEN coalesce(wh, 'wc_' || wc) ELSE {peer} END AS peer_id,
               CASE WHEN {UNKNOWN} THEN NULL ELSE {init} END AS dev_init, nullif(wd, '') AS domain,
               CASE WHEN {OPEN} THEN 0 ELSE ob + rb END AS n_bytes, CAST({dev_pl} AS BIGINT) AS dev_pl,
               {OPEN} AS is_open, {UNKNOWN} AS no_handshake
        FROM r WHERE {dev_scope} = 'lan' AND {dev} NOT IN (SELECT d FROM gw) AND (NOT {UNKNOWN} OR {took_part})"""
    q = side("o", "os", "r", "rs", "op", "rp", "true", f"CASE WHEN {UNKNOWN} THEN greatest(ob, 1) ELSE ob END", O_PART) \
        + " UNION ALL " + \
        side("r", "rs", "o", "os", "rp", "op", "false", "CASE WHEN est THEN greatest(rb, 1) ELSE 0 END", "est")
    where = f"WHERE CAST(timezone('{tz}', timezone('UTC', ts)) AS DATE) NOT IN (SELECT d FROM bad_day)"
    if keep is not None:
        table("keep", "VARCHAR", keep)
        where += " AND device IN (SELECT d FROM keep)"
    con.execute(f"COPY (SELECT * FROM ({q}) {where}) TO '{out}' (FORMAT parquet, COMPRESSION zstd)")
    n_in = con.execute("SELECT count(*) FROM r").fetchone()[0]
    s = con.execute(f"""SELECT count(*), count(DISTINCT device), min(ts), max(ts),
                        coalesce(sum((peer_scope = 'wan')::int), 0), coalesce(sum((peer_scope = 'lan')::int), 0),
                        coalesce(sum((dev_init = false AND dev_pl = 0)::int), 0),
                        coalesce(sum(is_open::int), 0), coalesce(sum(no_handshake::int), 0)
                        FROM read_parquet('{out}')""").fetchone()
    return {"records_in": n_in, "rows": s[0], "devices": s[1], "first": s[2], "last": s[3], "peer_wan": s[4],
            "peer_lan": s[5], "unanswered_inbound": s[6], "open_rows": s[7], "no_handshake_rows": s[8],
            "gateways": len(gateways), "device_filter": None if keep is None else len(keep),
            "gap_days": len(down), "dropped_days": dropped, "keys": keys}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("src")
    ap.add_argument("out")
    ap.add_argument("--dataset", default="siteA")
    ap.add_argument("--tz", default="Europe/Istanbul")
    ap.add_argument("--hours", default="", help='working hours, for example "1-5=08:00-17:00,6=08:00-13:30"')
    ap.add_argument("--group", default="", help="keep only devices labelled with this group")
    ap.add_argument("--visibility", default="", help="keep only devices labelled with this visibility")
    a = ap.parse_args()
    s = convert(a.src, a.out, a.dataset, a.tz, a.hours, a.group, a.visibility)
    print(f"records in {s['records_in']}, rows out {s['rows']}, devices {s['devices']}, "
          f"{str(s['first'])[:16]} .. {str(s['last'])[:16]} UTC")
    print(f"peer wan {s['peer_wan']}, peer lan {s['peer_lan']}, unanswered inbound {s['unanswered_inbound']}")
    print(f"reports about open connections {s['open_rows']}, rows without a handshake {s['no_handshake_rows']}")
    print(f"gateways excluded {s['gateways']}, device filter {'none' if s['device_filter'] is None else s['device_filter']}")
    print(f"days with capture gaps in working hours {s['gap_days']}, dropped (more than one hour) "
          f"{len(s['dropped_days'])}: {s['dropped_days']}")
    if len(s["keys"]) > 1:
        print(f"WARNING: the key stick was replaced during the recording ({len(s['keys'])} keys). Pseudonyms made with "
              "different keys do not match: the same device appears as several devices.")
    print(f'next: GT_ROLE=init GT_INPUTS="{a.out}|{a.tz}" python3 incidence3.py x x <inc_dir>')


if __name__ == "__main__":
    main()
