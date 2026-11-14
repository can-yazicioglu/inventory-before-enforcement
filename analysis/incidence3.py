#!/usr/bin/env python3
"""Per-device flow-type incidence (v2).

Flow type = one allowlist rule: transport / role / service port @ peer label.
Role and service port:
  1. port fan-out over the device's whole trace (a service port pairs with many counterpart ports)
  2. tie: the side with a port below 1024 is the server
  3. still tied: equal ports -> 'sym', else the recorded initiator if known, else the lower port
  service ports >= 32768 are bucketed as 'hi' (Linux ephemeral and IANA dynamic ranges)
  ICMP/ICMPv6/IGMP and port-less protocols are one service per peer.
  With GT_ROLE=init the role is the recorded initiator (connection logs such as Zeek, where the initiator is known).
Peer label by granularity:
  host  : exact peer (WAN IP, LAN identity, multicast/broadcast address)
  net   : WAN /24 (IPv4) or /48 (IPv6), LAN identity
  dom   : WAN registered domain when known (TLS SNI / HTTP Host) else /24, LAN identity  [UNSW only]
  svc   : any WAN host, LAN identity
  port  : peer scope only (wan / lan / mcast / bcast)
  proto : peer scope only, service port dropped
Inbound services on which the device sent no payload to the peer that day are dropped (participation filter).
Sampling units: local calendar day (all granularities) and local hour (svc, port, net).

Usage: incidence2.py <unsw.parquet> <homes_dir> <out_dir>
"""
import sys
import duckdb

unsw, homes, out = sys.argv[1:4]
import os
FILTER = os.environ.get('GT_FILTER', 'in')      # in: drop unanswered inbound | strict: also drop unanswered non-initiated outbound | keep
ROLE = os.environ.get('GT_ROLE', 'fanout')      # fanout: learned from port fan-out | static: fixed online rule | init: recorded initiator (connection logs)
TZ = os.environ.get('GT_TZ', 'local')           # local calendar day | utc
KEEP_UNANSWERED = FILTER == 'keep'
con = duckdb.connect()
con.execute("SET threads TO 2"); con.execute("SET memory_limit='5GB'")
con.execute("SET preserve_insertion_order=false"); con.execute(f"SET temp_directory='{out}/tmp'")
TZ_UNSW = "timezone('Australia/Sydney', timezone('UTC', ts))" if TZ == 'local' else 'ts'
TZ_HOMES = "timezone('Asia/Tokyo', timezone('UTC', ts))" if TZ == 'local' else 'ts'
COLS = "dataset, site, device, proto, peer_addr, peer_id, peer_scope, domain, dev_port, peer_port, dev_init, n_bytes, dev_pl"
INPUTS = os.environ.get('GT_INPUTS')            # optional: "path|IANA timezone;path|timezone" replaces the two default inputs
if INPUTS:
    srcs = [x.split('|') for x in INPUTS.split(';')]
else:
    srcs = [[unsw, 'Australia/Sydney'], [f'{homes}/home*.parquet', 'Asia/Tokyo']]
sel = []
for path, tz in srcs:
    t = f"timezone('{tz}', timezone('UTC', ts))" if TZ == 'local' else 'ts'
    sel.append(f"SELECT {COLS}, date_trunc('hour', {t}) AS hr FROM read_parquet('{path}')")
con.execute("CREATE TABLE f AS " + " UNION ALL ".join(sel))
print('records', con.execute("SELECT count(*) FROM f").fetchone()[0], flush=True)
# ROLE = 'prefix': fan-out is learned from each device's first 7 days only and then frozen (no hindsight)
con.execute("CREATE TABLE d0 AS SELECT site, device, min(hr) AS h0 FROM f GROUP BY ALL")
PFX = "AND hr < h0 + INTERVAL 7 DAY" if ROLE == 'prefix' else ''
con.execute(f"""CREATE TABLE fa AS SELECT site, device, proto, peer_port, count(DISTINCT dev_port) AS a
               FROM f JOIN d0 USING (site, device) WHERE proto IN (6, 17) AND peer_port IS NOT NULL {PFX} GROUP BY ALL""")
con.execute(f"""CREATE TABLE fb AS SELECT site, device, proto, dev_port, count(DISTINCT peer_port) AS b
               FROM f JOIN d0 USING (site, device) WHERE proto IN (6, 17) AND dev_port IS NOT NULL {PFX} GROUP BY ALL""")
con.execute(f"""
CREATE TABLE g AS
SELECT f.dataset, f.site, f.device, f.hr, f.proto, f.peer_addr, f.peer_id, f.peer_scope, f.domain, f.n_bytes, f.dev_init, f.dev_pl,
  CASE
    WHEN f.proto NOT IN (6, 17) OR f.peer_port IS NULL OR f.dev_port IS NULL THEN 'na'
    WHEN '{ROLE}' = 'static' AND f.peer_port = f.dev_port THEN 'sym'
    WHEN '{ROLE}' = 'static' AND f.peer_port < 1024 AND f.dev_port >= 1024 THEN 'out'
    WHEN '{ROLE}' = 'static' AND f.dev_port < 1024 AND f.peer_port >= 1024 THEN 'in'
    WHEN '{ROLE}' = 'static' AND f.peer_port < 32768 AND f.dev_port >= 32768 THEN 'out'
    WHEN '{ROLE}' = 'static' AND f.dev_port < 32768 AND f.peer_port >= 32768 THEN 'in'
    WHEN '{ROLE}' = 'static' AND f.dev_init IS NOT NULL THEN CASE WHEN f.dev_init THEN 'out' ELSE 'in' END
    WHEN '{ROLE}' = 'static' THEN CASE WHEN f.peer_port < f.dev_port THEN 'out' ELSE 'in' END
    WHEN '{ROLE}' = 'init' AND f.dev_init IS NOT NULL THEN CASE WHEN f.dev_init THEN 'out' ELSE 'in' END
    WHEN coalesce(fa.a, 0) > coalesce(fb.b, 0) THEN 'out'
    WHEN coalesce(fb.b, 0) > coalesce(fa.a, 0) THEN 'in'
    WHEN f.peer_port < 1024 AND f.dev_port >= 1024 THEN 'out'
    WHEN f.dev_port < 1024 AND f.peer_port >= 1024 THEN 'in'
    WHEN f.peer_port = f.dev_port THEN 'sym'
    WHEN f.dev_init IS NOT NULL THEN CASE WHEN f.dev_init THEN 'out' ELSE 'in' END
    WHEN f.peer_port < f.dev_port THEN 'out' ELSE 'in' END AS role,
  f.peer_port, f.dev_port
FROM f LEFT JOIN fa USING (site, device, proto, peer_port) LEFT JOIN fb USING (site, device, proto, dev_port)
""")
con.execute("DROP TABLE f")
# Device-participation filter: an inbound service counts on a day only if the device sent payload on it
# to that peer that day.
# Unanswered or refused inbound probes (scans, floods) are not device behaviour and must not be learned.
con.execute("""CREATE TABLE g2 AS SELECT *,
                 sum(coalesce(dev_pl, 0)) OVER w AS day_pl, bool_or(coalesce(dev_init, false)) OVER w AS day_init
               FROM g WINDOW w AS (PARTITION BY site, device, CAST(hr AS DATE), proto, role,
                                   CASE WHEN role = 'in' THEN dev_port ELSE peer_port END, peer_id)""")
con.execute("DROP TABLE g"); con.execute("ALTER TABLE g2 RENAME TO g")
d = con.execute("""SELECT dataset, count(*) n, sum((role = 'in')::int) inbound,
                    sum((role = 'in' AND day_pl = 0)::int) unanswered FROM g GROUP BY 1 ORDER BY 1""").df()
print('participation filter:\n', d.to_string(), flush=True)
if KEEP_UNANSWERED:
    print('keeping unanswered inbound records (ablation)')
else:
    con.execute("DELETE FROM g WHERE role = 'in' AND day_pl = 0")
    if FILTER == 'strict':
        n = con.execute("SELECT count(*) FROM g WHERE role IN ('out', 'sym') AND day_pl = 0 AND NOT day_init").fetchone()[0]
        print('strict filter: dropping', n, 'outbound records without device payload or initiation', flush=True)
        con.execute("DELETE FROM g WHERE role IN ('out', 'sym') AND day_pl = 0 AND NOT day_init")
v = con.execute("""SELECT dataset, role, dev_init, count(*) n FROM g WHERE role IN ('in','out') AND dev_init IS NOT NULL
                   GROUP BY ALL ORDER BY 1, 2, 3""").df()
print('role vs recorded initiator:\n', v.to_string(), flush=True)
con.execute("""
CREATE TABLE h AS
SELECT dataset, site, device, hr, CAST(hr AS DATE) AS day, n_bytes, peer_scope,
  CASE WHEN role = 'na' THEN CAST(proto AS VARCHAR)
       ELSE proto || '/' || role || '/' ||
            CASE WHEN (CASE WHEN role = 'in' THEN dev_port ELSE peer_port END) >= 32768 THEN 'hi'
                 ELSE CAST(CASE WHEN role = 'in' THEN dev_port ELSE peer_port END AS VARCHAR) END END AS svc,
  CASE WHEN role = 'na' THEN CAST(proto AS VARCHAR) ELSE proto || '/' || role END AS svc0,
  peer_id,
  CASE WHEN peer_scope = 'wan' AND peer_addr LIKE '%:%' THEN
         array_to_string(list_slice(string_split(peer_addr, ':'), 1, 3), ':') || '::/48'
       WHEN peer_scope = 'wan' THEN regexp_replace(peer_addr, '\\.[0-9]+$', '.0/24')
       ELSE peer_id END AS peer_net,
  domain
FROM g""")
con.execute("DROP TABLE g")
LEVELS = {
    'host': "svc || '@' || peer_id",
    'net': "svc || '@' || peer_net",
    'dom': "svc || '@' || CASE WHEN peer_scope = 'wan' THEN coalesce(domain, peer_net) ELSE peer_id END",
    'svc': "svc || '@' || CASE WHEN peer_scope = 'wan' THEN 'wan' ELSE peer_id END",
    'port': "svc || '@' || peer_scope",
    # sensitivity only (GT_EXTRA=1): LAN hosts that are not catalogued devices collapse to one class and IPv6
    # solicited-node multicast groups collapse to their /104, so that address churn (DHCP leases of unmanaged
    # hosts, IPv6 temporary addresses) cannot create new types
    'svcx': "svc || '@' || CASE WHEN peer_scope = 'wan' THEN 'wan' WHEN peer_scope = 'lan' AND peer_id NOT LIKE 'dev:%' THEN 'lan' "
            "WHEN peer_id LIKE 'ff02:0:0:0:0:1:ff%' THEN 'ff02::1:ff00:0/104' ELSE peer_id END",
    'proto': "svc0 || '@' || peer_scope",
}
parts = []
for g, expr in LEVELS.items():
    where = "WHERE dataset = 'unsw'" if g == 'dom' else ''
    if g == 'dom' and INPUTS: continue
    if g == 'svcx' and not os.environ.get('GT_EXTRA'): continue
    parts.append(f"SELECT dataset, site, device, day, '{g}' AS gran, {expr} AS ftype, count(*) AS n, sum(n_bytes) AS b "
                 f"FROM h {where} GROUP BY ALL")
con.execute(f"COPY ({' UNION ALL '.join(parts)}) TO '{out}/inc_day.parquet' (FORMAT parquet, COMPRESSION zstd)")
for g in ('svc', 'port', 'net'):
    con.execute(f"""COPY (SELECT dataset, site, device, hr, '{g}' AS gran, {LEVELS[g]} AS ftype, count(*) AS n
                    FROM h GROUP BY ALL) TO '{out}/inc_hour_{g}.parquet' (FORMAT parquet, COMPRESSION zstd)""")
s = con.execute(f"""SELECT dataset, gran, count(DISTINCT site || device) AS devices,
       count(DISTINCT site || device || ftype) AS types, count(*) AS incidences, sum(n) AS records
       FROM read_parquet('{out}/inc_day.parquet') GROUP BY ALL ORDER BY 1, 2""").df()
print(s.to_string())

