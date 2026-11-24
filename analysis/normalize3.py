#!/usr/bin/env python3
"""Normalize public flow datasets into one schema (v2, 12 Nov 2026 fix).

Fix (12 Nov 2026): in the 12-home data the out*/in* counters are relative to the record's `device` MAC
(out = sent by that device), not to the record's source address. dev_pl now follows that convention.
Before the fix, payload sent by the remote side was read as device payload on remote-initiated records.

One output row per (flow record, monitored endpoint). Columns:
  dataset, site, device, ts (UTC), proto, dev_port, peer_port,
  peer_scope  (wan | lan | mcast | bcast)
  peer_addr   (IP address of the peer)
  peer_id     (stable peer identity: WAN = IP, LAN = 'dev:<name>' for catalogued devices,
               'mac:<mac>' (homes) or 'ip:<addr>' (unsw) for other LAN hosts, mcast/bcast = address)
  dev_init    (True if the monitored device is the flow initiator, NULL if unknown)
  domain      (registered domain from TLS SNI / HTTP Host, UNSW only, else NULL)
  n_bytes, dev_pl (payload bytes sent by the monitored device in this record)

Usage:
  normalize2.py unsw  <flows_dir> <protocol_params_dir> <out.parquet>
  normalize2.py homes <all.zip> <devices.xlsx> <out_dir> <tmp_dir>
"""
import sys, os, zipfile
import duckdb
import pandas as pd

SCOPE = """
CASE
  WHEN {a} = '255.255.255.255' OR {a} LIKE '%.255' THEN 'bcast'
  WHEN {a} LIKE 'ff%:%' OR regexp_matches({a}, '^(22[4-9]|23[0-9])\\.') THEN 'mcast'
  WHEN {a} LIKE 'fe80:%' OR {a} LIKE '192.168.%' OR {a} LIKE '10.%'
       OR regexp_matches({a}, '^172\\.(1[6-9]|2[0-9]|3[01])\\.') OR {a} LIKE '169.254.%'
       OR {a} LIKE 'fc%:%' OR {a} LIKE 'fd%:%' OR {a} IN ('0.0.0.0', '::', '0:0:0:0:0:0:0:0') THEN 'lan'
  ELSE 'wan' END
"""


def sni_from_ext(hexs):
    """Extract server_name from a hex string of TLS ClientHello extensions."""
    try:
        b = bytes.fromhex(hexs)
    except Exception:
        return None
    i = 0
    while i + 4 <= len(b):
        t = int.from_bytes(b[i:i + 2], 'big'); l = int.from_bytes(b[i + 2:i + 4], 'big')
        if t == 0 and l >= 5:
            nl = int.from_bytes(b[i + 7:i + 9], 'big')
            try:
                return b[i + 9:i + 9 + nl].decode('ascii').lower()
            except Exception:
                return None
        i += 4 + l
    return None


def unsw(flows_dir, params_dir, out):
    import tldextract
    ext = tldextract.TLDExtract(suffix_list_urls=(), cache_dir='/tmp/tldx')
    con = duckdb.connect()
    con.execute("SET threads TO 2"); con.execute("SET memory_limit='5GB'")
    con.execute(f"""
    CREATE TABLE f AS
    SELECT regexp_extract(filename, '([^/]+?)_+[0-9a-fA-F]{{12}}_flows\\.csv$', 1) AS device,
           CAST(time AS TIMESTAMP) AS ts, ethType, srcIp, dstIp, TRY_CAST(ipProto AS INTEGER) AS proto,
           TRY_CAST(srcPort AS INTEGER) AS srcPort, TRY_CAST(dstPort AS INTEGER) AS dstPort,
           TRY_CAST(srcPayloadSize AS BIGINT) + TRY_CAST(dstPayloadSize AS BIGINT) AS n_bytes,
           TRY_CAST(srcPayloadSize AS BIGINT) AS spl, TRY_CAST(dstPayloadSize AS BIGINT) AS dpl,
           row_number() OVER () AS rid
    FROM read_csv('{flows_dir}/*.csv', filename=true, all_varchar=true, header=true)
    WHERE ethType IN ('0x0800', '0x86dd') AND srcIp <> '*' AND dstIp <> '*'
    """)
    n_all = con.execute("SELECT count(*) FROM f").fetchone()[0]
    con.execute("DELETE FROM f WHERE ts < '2016-09-22' OR ts >= '2017-04-14'")
    con.execute("ALTER TABLE f ADD COLUMN day DATE"); con.execute("UPDATE f SET day = CAST(ts AS DATE)")
    # device address per (device, day, ip version) by greedy cover
    con.execute("""
    CREATE TABLE addr AS
    WITH a AS (SELECT device, day, ethType, rid, srcIp AS ip FROM f UNION ALL
               SELECT device, day, ethType, rid, dstIp FROM f)
    SELECT device, day, ethType, ip, count(DISTINCT rid) AS c FROM a
    WHERE ip NOT IN ('192.168.1.1', '255.255.255.255', '0.0.0.0', '::', '0:0:0:0:0:0:0:0')
      AND ip NOT LIKE '%.255' AND ip NOT LIKE 'ff%:%' AND NOT regexp_matches(ip, '^(22[4-9]|23[0-9])\\.')
      AND (ip LIKE '192.168.%' OR ip LIKE '%:%')
    GROUP BY ALL""")
    addr = con.execute("SELECT * FROM addr").df()
    flows = con.execute("SELECT rid, device, day, ethType, srcIp, dstIp FROM f").df()
    unspec = ('0.0.0.0', '::', '0:0:0:0:0:0:0:0')
    pre = flows[flows.srcIp.isin(unspec)]
    flows = flows.drop(pre.index)
    addr_g = {k: v for k, v in addr.groupby(['device', 'day', 'ethType'], sort=False)}
    assign = {}; own = []
    for (dev, day, et), g in flows.groupby(['device', 'day', 'ethType'], sort=False):
        cand = addr_g.get((dev, day, et))
        if cand is None:
            continue
        # ties are broken by the address, so that the result does not depend on the order in which the database returns rows
        remaining = g; order = cand.sort_values(['c', 'ip'], ascending=[False, True]).ip.tolist(); chosen = []
        while len(remaining) and order:
            best, best_c = None, 0
            for ip in order[:20]:
                c = int(((remaining.srcIp == ip) | (remaining.dstIp == ip)).sum())
                if c > best_c:
                    best, best_c = ip, c
            if best is None or (best_c < max(1, 0.5 * len(remaining)) and chosen):
                break
            chosen.append(best); order.remove(best)
            hit = (remaining.srcIp == best) | (remaining.dstIp == best)
            for rid, s in zip(remaining.rid[hit], remaining.srcIp[hit]):
                assign[rid] = (best, s == best)
            own.append((dev, day, best, int(hit.sum())))
            remaining = remaining[~hit]
    for rid, s in zip(pre.rid, pre.srcIp):
        assign[rid] = (s, True)
    a = pd.DataFrame([(k, v[0], v[1]) for k, v in assign.items()], columns=['rid', 'dev_addr', 'dev_is_src'])
    con.register('a', a)
    # (day, ip) -> device name, for resolving LAN peers that are other monitored devices.
    # Keep the dominant owner of each address per day.
    o = pd.DataFrame(own, columns=['device', 'day', 'ip', 'c']).sort_values(['c', 'device'], ascending=[False, True])
    o = o.drop_duplicates(['day', 'ip'])
    con.register('own', o)
    # domain labels from TLS SNI and HTTP Host, per (device, peer ip)
    dom_rows = []
    for d in sorted(os.listdir(params_dir)):
        dev = d.rsplit('_', 1)[0].rstrip('_')
        p = os.path.join(params_dir, d, 'request', 'tlsattributes.csv')
        if os.path.exists(p):
            t = con.execute(f"""SELECT dstIp, "client-hello-extensions" AS e, count(*) c
                                FROM read_csv('{p}', all_varchar=true, header=true) GROUP BY ALL""").df()
            for ip, e, c in zip(t.dstIp, t.e, t.c):
                s = sni_from_ext(e) if isinstance(e, str) else None
                if s:
                    dom_rows.append((dev, ip, s, c))
        p = os.path.join(params_dir, d, 'request', 'httpattributes.csv')
        if os.path.exists(p):
            t = con.execute(f"""SELECT dstIp, lower(host) AS h, count(*) c
                                FROM read_csv('{p}', all_varchar=true, header=true) WHERE host IS NOT NULL
                                GROUP BY ALL""").df()
            for ip, h, c in zip(t.dstIp, t.h, t.c):
                h = h.split(':')[0].strip()
                if h and not h.replace('.', '').isdigit():
                    dom_rows.append((dev, ip, h, c))
    dm = pd.DataFrame(dom_rows, columns=['device', 'ip', 'host', 'c'])
    dm['domain'] = [ext(h).top_domain_under_public_suffix or None for h in dm.host]
    dm = dm.dropna(subset=['domain']).groupby(['device', 'ip', 'domain'], as_index=False).c.sum()
    dm = dm.sort_values(['c', 'domain'], ascending=[False, True]).drop_duplicates(['device', 'ip'])
    con.register('dm', dm)
    con.execute(f"""
    CREATE TABLE o1 AS
    SELECT 'unsw' AS dataset, 'unsw' AS site, f.device, f.ts, f.day, f.proto,
           CASE WHEN a.dev_is_src THEN f.srcPort ELSE f.dstPort END AS dev_port,
           CASE WHEN a.dev_is_src THEN f.dstPort ELSE f.srcPort END AS peer_port,
           CASE WHEN a.dev_is_src THEN f.dstIp ELSE f.srcIp END AS peer_addr,
           a.dev_is_src AS dev_init, f.n_bytes, CASE WHEN a.dev_is_src THEN f.spl ELSE f.dpl END AS dev_pl
    FROM f JOIN a USING (rid)""")
    con.execute(f"""
    COPY (
      SELECT o1.dataset, o1.site, o1.device, o1.ts, o1.proto, o1.dev_port, o1.peer_port,
             {SCOPE.format(a='o1.peer_addr')} AS peer_scope, o1.peer_addr,
             CASE WHEN {SCOPE.format(a='o1.peer_addr')} = 'lan' THEN
                    CASE WHEN own.device IS NOT NULL THEN 'dev:' || own.device ELSE 'ip:' || o1.peer_addr END
                  ELSE o1.peer_addr END AS peer_id,
             o1.dev_init, dm.domain, o1.n_bytes, o1.dev_pl
      FROM o1 LEFT JOIN own ON own.day = o1.day AND own.ip = o1.peer_addr
              LEFT JOIN dm ON dm.device = o1.device AND dm.ip = o1.peer_addr
    ) TO '{out}' (FORMAT parquet, COMPRESSION zstd)""")
    s = con.execute(f"""SELECT count(*) n, sum((peer_scope='wan')::int) wan,
        sum((peer_scope='wan' AND domain IS NOT NULL)::int) wan_dom,
        sum((peer_id LIKE 'dev:%')::int) lan_dev, sum((peer_id LIKE 'ip:%')::int) lan_ip
        FROM read_parquet('{out}')""").fetchone()
    print(f"unsw: ip flows {n_all}, out {s[0]}, wan {s[1]}, wan with domain {s[2]} ({s[2]/s[1]:.3f}), "
          f"lan peer=device {s[3]}, lan peer=other {s[4]}, domain map entries {len(dm)}")


def homes(zip_path, devices_xlsx, out_dir, tmp_dir):
    os.makedirs(out_dir, exist_ok=True); os.makedirs(tmp_dir, exist_ok=True)
    dev = pd.read_excel(devices_xlsx, sheet_name=0)
    home_cols = [c for c in dev.columns if c.startswith('home')]
    m = dev.melt(id_vars=['manufacturer', 'category', 'model', 'name'], value_vars=home_cols,
                 var_name='home', value_name='mac').dropna()
    m['mac'] = m.mac.str.lower().str.strip(); m['home'] = m.home.str.replace('home0', 'home')
    dup = m.duplicated(['home', 'name'], keep=False)          # two different products share the name 'humidifier'
    m.loc[dup, 'name'] = m.manufacturer[dup] + '-' + m.name[dup]
    m.to_csv(os.path.join(out_dir, 'device_map.csv'), index=False)
    con = duckdb.connect(); con.execute("SET threads TO 2"); con.execute("SET memory_limit='4GB'")
    con.register('dmap', m)
    zf = zipfile.ZipFile(zip_path)
    for name in sorted(zf.namelist(), key=lambda s: int(s[4:-4])):
        site = name[:-4]; out = os.path.join(out_dir, f'{site}.parquet')
        tmp = os.path.join(tmp_dir, name); zf.extract(name, tmp_dir)
        con.execute(f"""
        CREATE OR REPLACE TABLE f AS
        SELECT CAST(start AS TIMESTAMP) AS ts, lower(srcMac) AS smac, lower(destMac) AS dmac, srcIP, destIP,
               TRY_CAST(ipProto AS INTEGER) AS proto, TRY_CAST(srcPort AS INTEGER) AS sport,
               TRY_CAST(destPort AS INTEGER) AS dport,
               TRY_CAST(outByteCount AS BIGINT) + TRY_CAST(inByteCount AS BIGINT) AS n_bytes,
               TRY_CAST(outDataByteCount AS BIGINT) AS opl, TRY_CAST(inDataByteCount AS BIGINT) AS ipl,
               lower(device) AS dmac_label, deviceInitiated
        FROM read_csv('{tmp}', all_varchar=true, header=true)""")
        con.execute(f"CREATE OR REPLACE TABLE dm AS SELECT mac, name FROM dmap WHERE home = '{site}'")
        # one record per monitored endpoint (source side and destination side)
        con.execute(f"""
        CREATE OR REPLACE TABLE o AS
        SELECT 'homes' AS dataset, '{site}' AS site, d.name AS device, f.ts, f.proto,
               f.sport AS dev_port, f.dport AS peer_port, f.destIP AS peer_addr, f.dmac AS peer_mac,
               CASE WHEN f.dmac_label = f.smac THEN (f.deviceInitiated = '1') ELSE NULL END AS dev_init, f.n_bytes,
               CASE WHEN f.dmac_label = f.dmac THEN f.ipl ELSE f.opl END AS dev_pl
        FROM f JOIN dm d ON d.mac = f.smac
        UNION ALL
        SELECT 'homes', '{site}', d.name, f.ts, f.proto, f.dport, f.sport, f.srcIP, f.smac,
               CASE WHEN f.dmac_label = f.dmac THEN (f.deviceInitiated = '1') ELSE NULL END, f.n_bytes,
               CASE WHEN f.dmac_label = f.dmac THEN f.opl ELSE f.ipl END
        FROM f JOIN dm d ON d.mac = f.dmac""")
        con.execute(f"""
        COPY (
          SELECT o.dataset, o.site, o.device, o.ts, o.proto, o.dev_port, o.peer_port,
                 {SCOPE.format(a='o.peer_addr')} AS peer_scope, o.peer_addr,
                 CASE WHEN {SCOPE.format(a='o.peer_addr')} = 'lan' THEN
                        CASE WHEN p.name IS NOT NULL THEN 'dev:' || p.name ELSE 'mac:' || o.peer_mac END
                      ELSE o.peer_addr END AS peer_id,
                 o.dev_init, CAST(NULL AS VARCHAR) AS domain, o.n_bytes, o.dev_pl
          FROM o LEFT JOIN dm p ON p.mac = o.peer_mac
        ) TO '{out}' (FORMAT parquet, COMPRESSION zstd)""")
        s = con.execute(f"""SELECT count(*), count(DISTINCT device), min(ts), max(ts),
            sum((peer_id LIKE 'dev:%')::int), sum((peer_id LIKE 'mac:%')::int) FROM read_parquet('{out}')""").fetchone()
        n_all = con.execute("SELECT count(*) FROM f").fetchone()[0]
        os.remove(tmp)
        print(f"{site}: csv rows {n_all}, records {s[0]}, devices {s[1]}, {str(s[2])[:10]}..{str(s[3])[:10]}, "
              f"lan peer=device {s[4]}, lan peer=other {s[5]}", flush=True)


if __name__ == '__main__':
    if sys.argv[1] == 'unsw':
        unsw(*sys.argv[2:5])
    else:
        homes(*sys.argv[2:6])

