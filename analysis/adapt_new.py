#!/usr/bin/env python3
"""Adapters: UNSW 2025 flow files and the HVAC control-network flows into the common schema (see normalize2.py).
Usage: adapt_new.py <unsw25_dir> <hvac_flows.parquet> <out_dir>"""
import sys, duckdb
u, h, out = sys.argv[1:4]
con = duckdb.connect(); con.execute("SET threads TO 2"); con.execute("SET memory_limit='5GB'")
SCOPE = """CASE WHEN {a} = '255.255.255.255' OR {a} LIKE '%.255' THEN 'bcast'
  WHEN regexp_matches({a}, '^(22[4-9]|23[0-9])\\.') THEN 'mcast'
  WHEN {a} LIKE '192.168.%' OR {a} LIKE '10.%' OR regexp_matches({a}, '^172\\.(1[6-9]|2[0-9]|3[01])\\.') OR {a} LIKE '169.254.%'
       OR {a} = '0.0.0.0' THEN 'lan' ELSE 'wan' END"""
# UNSW 2025. Payload bytes are not available: DevBytes10 = bytes the device sent within the first 10 packets.
# Participation proxy: UDP any device bytes, TCP more than two bare control segments (132 bytes).
# Recording days (correction of 24 Nov 2026): the archives hold one file per local day (SrcFile, 'YY-MM-DD.parquet'), and every
# file runs up to two minutes past local midnight. Where the next day was not recorded, those two minutes used to appear as a
# day of their own (3 of 88 days in v1, 33 of 273 in v2). A record now never falls on a later local day than its file.
DAY_END = """timezone('UTC', timezone('Australia/Sydney',
             CAST(strptime('20' || substr(SrcFile, 1, 8), '%Y-%m-%d') AS TIMESTAMP) + INTERVAL 86399 SECOND))"""
for v in ('v1', 'v2'):
    con.execute(f"""COPY (
      SELECT 'unsw25{v}' AS dataset, '{v}' AS site, Device AS device,
             LEAST(make_timestamp(CAST(FirstSeen AS BIGINT)), {DAY_END}) AS ts, Proto AS proto,
             DevPort AS dev_port, RemPort AS peer_port, {SCOPE.format(a='RemIP')} AS peer_scope, RemIP AS peer_addr,
             CASE WHEN {SCOPE.format(a='RemIP')} = 'lan' THEN 'ip:' || RemIP ELSE RemIP END AS peer_id,
             (FirstDir = 1) AS dev_init, CAST(NULL AS VARCHAR) AS domain, TotalFlowSize AS n_bytes,
             CAST(CASE WHEN Proto = 6 AND DevBytes10 <= 132 THEN 0 ELSE DevBytes10 END AS BIGINT) AS dev_pl
      FROM read_parquet('{u}/DATA2025{v}_flows.parquet') WHERE RemIP <> '' AND Proto IN (1, 2, 6, 17)
    ) TO '{out}/unsw25{v}.parquet' (FORMAT parquet, COMPRESSION zstd)""")
    print(v, con.execute(f"SELECT count(*), count(DISTINCT device), min(ts), max(ts) FROM read_parquet('{out}/unsw25{v}.parquet')").fetchone())
# HVAC: monitored hosts are the internal Crypto-PAn prefix 252.103.0.0/16 (README table). One record per internal endpoint.
HS = """CASE WHEN {a} = '206.120.97.255' THEN 'bcast' WHEN {a} = '208.103.225.198' THEN 'mcast'
        WHEN {a} LIKE '252.103.%' THEN 'lan' ELSE 'wan' END"""
con.execute(f"""COPY (
  SELECT 'hvac' AS dataset, 'hvac' AS site, ip_a AS device, make_timestamp(CAST(t0 * 1e6 AS BIGINT)) AS ts, proto,
         CASE WHEN port_a < 0 THEN NULL ELSE port_a END AS dev_port, CASE WHEN port_b < 0 THEN NULL ELSE port_b END AS peer_port,
         {HS.format(a='ip_b')} AS peer_scope, ip_b AS peer_addr,
         CASE WHEN {HS.format(a='ip_b')} = 'lan' THEN 'ip:' || ip_b ELSE ip_b END AS peer_id,
         true AS dev_init, CAST(NULL AS VARCHAR) AS domain, pl_a + pl_b AS n_bytes, pl_a AS dev_pl
  FROM read_parquet('{h}') WHERE ip_a LIKE '252.103.%'
  UNION ALL
  SELECT 'hvac', 'hvac', ip_b, make_timestamp(CAST(t0 * 1e6 AS BIGINT)), proto,
         CASE WHEN port_b < 0 THEN NULL ELSE port_b END, CASE WHEN port_a < 0 THEN NULL ELSE port_a END,
         {HS.format(a='ip_a')}, ip_a, CASE WHEN {HS.format(a='ip_a')} = 'lan' THEN 'ip:' || ip_a ELSE ip_a END,
         false, CAST(NULL AS VARCHAR), pl_a + pl_b, pl_b
  FROM read_parquet('{h}') WHERE ip_b LIKE '252.103.%'
) TO '{out}/hvac.parquet' (FORMAT parquet, COMPRESSION zstd)""")
print('hvac', con.execute(f"SELECT count(*), count(DISTINCT device), min(ts), max(ts) FROM read_parquet('{out}/hvac.parquet')").fetchone())

