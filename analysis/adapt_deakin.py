#!/usr/bin/env python3
"""Adapter: Deakin IoT Traffic (D-IoT, Pasquini et al., doi:10.26187/deakin.28013234, CC BY 4.0) into the common schema
(see normalize3.py). Input: the flow records that deakin_reduce.py writes from the folder pcapIoT, and macAddresses.csv of
the dataset (24 IoT devices). One output row per flow record and monitored device.

What the data allow:
- The folder pcapIoT holds only the packets that the IoT devices sent (the captures use the Linux cooked header, which names
  the sender only). The flow types of a device are therefore built from what the device itself sent. The participation filter
  needs nothing more: it asks whether the device sent data to the peer.
- Initiator: known for TCP when the device sent a SYN (it opened the connection) or a SYN-ACK (it answered one). Unknown
  otherwise, also for UDP, where the port rules of incidence3.py decide.
- Device identity is the MAC address. Several devices share a product name, so the device label is the name and the last
  two bytes of the MAC address.
- LAN peer identity: the device label if the peer address belongs to a monitored device on that local day, else the IP address
  (as in the UNSW traces).
- Local days are Australia/Melbourne. The daily files ignore the two daylight saving changes inside the recording, so the day
  is taken from the packet timestamps (UTC) and not from the file names.
Usage: adapt_deakin.py <dir with *.csv.gz> <macAddresses.csv> <out.parquet>"""
import sys, os, re, csv, duckdb
flows, macs, outp = sys.argv[1:4]
TZ = 'Australia/Melbourne'
SCOPE = """CASE
  WHEN {a} = '255.255.255.255' OR {a} LIKE '%.255' THEN 'bcast'
  WHEN {a} LIKE 'ff%:%' OR regexp_matches({a}, '^(22[4-9]|23[0-9])\\.') THEN 'mcast'
  WHEN {a} LIKE 'fe80:%' OR {a} LIKE '192.168.%' OR {a} LIKE '10.%'
       OR regexp_matches({a}, '^172\\.(1[6-9]|2[0-9]|3[01])\\.') OR {a} LIKE '169.254.%'
       OR {a} LIKE 'fc%:%' OR {a} LIKE 'fd%:%' OR {a} IN ('0.0.0.0', '::') THEN 'lan'
  ELSE 'wan' END"""
con = duckdb.connect(); con.execute("SET threads TO 2"); con.execute("SET memory_limit='5GB'")
with open(macs, newline='', encoding='utf-8-sig') as f:
    dev = [(r['MAC Address'].strip().lower(), r['Device Name'].strip()) for r in csv.DictReader(f)]
label = {m: re.sub(r'[^A-Za-z0-9]+', '-', n).strip('-') + '_' + m.replace(':', '')[-4:] for m, n in dev}
assert len(set(label.values())) == len(dev), 'device labels are not unique'
con.execute("CREATE TABLE dev (mac VARCHAR, device VARCHAR, name VARCHAR)")
con.executemany("INSERT INTO dev VALUES (?, ?, ?)", [(m, label[m], n) for m, n in dev])
con.execute(f"""CREATE TABLE f AS SELECT * FROM read_csv('{flows}/*.csv.gz', header=true, filename=true,
    columns={{'t0': 'DOUBLE', 't1': 'DOUBLE', 'mac_a': 'VARCHAR', 'mac_b': 'VARCHAR', 'ip_a': 'VARCHAR', 'ip_b': 'VARCHAR', 'proto': 'INTEGER',
              'port_a': 'INTEGER', 'port_b': 'INTEGER', 'pkts_a': 'BIGINT', 'pkts_b': 'BIGINT', 'pl_a': 'BIGINT', 'pl_b': 'BIGINT',
              'syn_a': 'INTEGER', 'synack_a': 'INTEGER', 'rst_a': 'INTEGER', 'syn_b': 'INTEGER', 'synack_b': 'INTEGER', 'rst_b': 'INTEGER'}})""")
con.execute("UPDATE f SET mac_b = NULL WHERE mac_b = ''")
n_all = con.execute("SELECT count(*) FROM f").fetchone()[0]
# one row per flow record and monitored side
SIDE = """SELECT d.device, make_timestamp(CAST(f.t0 * 1e6 AS BIGINT)) AS ts, f.proto,
                 CASE WHEN f.port_{x} < 0 THEN NULL ELSE f.port_{x} END AS dev_port, CASE WHEN f.port_{y} < 0 THEN NULL ELSE f.port_{y} END AS peer_port,
                 f.ip_{x} AS dev_addr, f.ip_{y} AS peer_addr,
                 CASE WHEN f.proto = 6 AND f.syn_{x} > 0 THEN true WHEN f.proto = 6 AND f.synack_{x} > 0 THEN false ELSE NULL END AS dev_init,
                 f.pl_a + f.pl_b AS n_bytes, f.pl_{x} AS dev_pl
          FROM f JOIN dev d ON f.mac_{x} = d.mac WHERE f.pkts_{x} > 0"""
con.execute(f"CREATE TABLE o AS {SIDE.format(x='a', y='b')} UNION ALL {SIDE.format(x='b', y='a')}")
con.execute("ALTER TABLE o ADD COLUMN day DATE"); con.execute(f"UPDATE o SET day = CAST(timezone('{TZ}', timezone('UTC', ts)) AS DATE)")
# the address of a monitored device on a local day: the device that sent most records from it
con.execute("""CREATE TABLE own AS SELECT day, ip, device FROM (
                 SELECT day, ip, device, row_number() OVER (PARTITION BY day, ip ORDER BY c DESC, device) AS r
                 FROM (SELECT day, dev_addr AS ip, device, count(*) AS c FROM o WHERE dev_addr NOT IN ('0.0.0.0', '::') GROUP BY ALL)) WHERE r = 1""")
con.execute(f"""COPY (
  SELECT 'deakin' AS dataset, 'deakin' AS site, o.device, o.ts, o.proto, o.dev_port, o.peer_port,
         {SCOPE.format(a='o.peer_addr')} AS peer_scope, o.peer_addr,
         CASE WHEN {SCOPE.format(a='o.peer_addr')} = 'lan' THEN
                CASE WHEN own.device IS NOT NULL THEN 'dev:' || own.device ELSE 'ip:' || o.peer_addr END
              ELSE o.peer_addr END AS peer_id,
         o.dev_init, CAST(NULL AS VARCHAR) AS domain, o.n_bytes, o.dev_pl
  FROM o LEFT JOIN own ON own.day = o.day AND own.ip = o.peer_addr
) TO '{outp}' (FORMAT parquet, COMPRESSION zstd)""")
con.execute(f"COPY (SELECT mac, device, name FROM dev ORDER BY device) TO '{os.path.splitext(outp)[0]}_devices.csv' (HEADER)")
s = con.execute(f"""SELECT count(*) AS records, count(DISTINCT device) AS devices, min(ts) AS first, max(ts) AS last,
                           count(DISTINCT CAST(timezone('{TZ}', timezone('UTC', ts)) AS DATE)) AS local_days,
                           sum((peer_scope = 'lan' AND peer_id LIKE 'dev:%')::int) AS lan_peer_device,
                           sum((peer_scope = 'lan' AND peer_id LIKE 'ip:%')::int) AS lan_peer_other,
                           sum((dev_init IS NULL)::int) AS initiator_unknown
                    FROM read_parquet('{outp}')""").df()
print(f'flow records read: {n_all}'); print(s.to_string(index=False))
print(con.execute(f"""SELECT device, count(*) AS records, count(DISTINCT CAST(timezone('{TZ}', timezone('UTC', ts)) AS DATE)) AS days,
                             CAST(min(ts) AS DATE) AS first, CAST(max(ts) AS DATE) AS last
                      FROM read_parquet('{outp}') GROUP BY 1 ORDER BY 1""").df().to_string(index=False))
