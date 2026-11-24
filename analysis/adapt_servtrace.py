#!/usr/bin/env python3
"""IoT-ServTrace (Azizi, Okui, Nakahara, Kubota and Habibi Gharakheili, IFIP Networking 2026) -> incidence table, port level only.
Source: https://github.com/shay-fi/IoT-ServTrace (MIT licence). One JSON-lines file per device type, each record holding
flowEndTimestamp (UTC), protocol (TCP or UDP) and portNumber. There is no remote address, no direction and no payload size, so only
the port level can be built: transport / out / service port @ wan, with ports of 32768 and above as one class. The participation
filter cannot be applied and is not needed: the records are flows of the device towards services outside the home network.
Local days are Asia/Tokyo (KDDI Research laboratory). Use of the result: a long-horizon check of the stopping rule at the port level.
Usage: adapt_servtrace.py <dir with IoT-ServTrace-2019 and IoT-ServTrace-2022> <out_dir>"""
import sys, os, duckdb
raw, out = sys.argv[1:3]
os.makedirs(out, exist_ok=True)
con = duckdb.connect(); con.execute("SET threads TO 2"); con.execute("SET memory_limit='5GB'"); con.execute(f"SET temp_directory='{out}/tmp'")
q = []
for year in ('2019', '2022'):
    q.append(f"""SELECT 'servtrace{year[2:]}' AS dataset, '{year}' AS site, regexp_extract(filename, '([^/]+)\\.json$', 1) AS device,
                        CAST(timezone('Asia/Tokyo', timezone('UTC', CAST(flowEndTimestamp AS TIMESTAMP))) AS DATE) AS day, 'port' AS gran,
                        CASE protocol WHEN 'TCP' THEN '6' WHEN 'UDP' THEN '17' ELSE protocol END || '/out/' ||
                        CASE WHEN portNumber >= 32768 THEN 'hi' ELSE CAST(portNumber AS VARCHAR) END || '@wan' AS ftype
                 FROM read_json('{raw}/IoT-ServTrace-{year}/*.json', format='newline_delimited', filename=true,
                                columns={{'flowEndTimestamp': 'VARCHAR', 'protocol': 'VARCHAR', 'portNumber': 'BIGINT'}})""")
con.execute("COPY (SELECT dataset, site, device, day, gran, ftype, count(*) AS n, CAST(0 AS DOUBLE) AS b FROM (" + " UNION ALL ".join(q) +
            f") GROUP BY ALL) TO '{out}/inc_day.parquet' (FORMAT PARQUET)")
print(con.execute(f"""SELECT dataset, count(DISTINCT device) AS devices, min(day) AS first_day, max(day) AS last_day, sum(n) AS flows,
                             count(*) AS incidences, count(DISTINCT ftype) AS types FROM read_parquet('{out}/inc_day.parquet') GROUP BY ALL ORDER BY 1""").df().to_string(index=False))
