#!/usr/bin/env python3
"""Coverage of every capture on every local day (registered on 25 November 2026, ../docs/method.md, point 6 of that note).
The public traces have no record of when the capture was down. The coverage of a local day is the time between the first and
the last flow record of any device of the capture on that day. A day that covers less than 20 hours is a partial recording day.
A capture is a (dataset, site) pair of the common schema: a trace, and in the 12-home data a home.

Sources are given as  kind|path|time zone :
  norm|<parquet file or glob in the common schema>|<IANA zone>     normalised records (column ts in UTC)
  servtrace|<dir with IoT-ServTrace-2019 and IoT-ServTrace-2022>|<IANA zone>   the JSON files of IoT-ServTrace
Output: dataset, site, day, first, last, hours, records, partial.
Usage: coverage.py <out.csv> <source>..."""
import sys, os, duckdb
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import reglib
outp = sys.argv[1]
con = duckdb.connect(); con.execute("SET threads TO 2"); con.execute("SET memory_limit='4GB'")
parts = []
for spec in sys.argv[2:]:
    kind, path, tz = spec.split('|')
    if kind == 'norm':
        parts.append(f"SELECT dataset, site, timezone('{tz}', timezone('UTC', ts)) AS l FROM read_parquet('{path}')")
    elif kind == 'servtrace':
        for year in ('2019', '2022'):
            parts.append(f"""SELECT 'servtrace{year[2:]}' AS dataset, '{year}' AS site,
                                    timezone('{tz}', timezone('UTC', CAST(flowEndTimestamp AS TIMESTAMP))) AS l
                             FROM read_json('{path}/IoT-ServTrace-{year}/*.json', format='newline_delimited',
                                            columns={{'flowEndTimestamp': 'VARCHAR', 'protocol': 'VARCHAR', 'portNumber': 'BIGINT'}})""")
    else:
        sys.exit(f'unknown source kind: {kind}')
c = con.execute(f"""SELECT dataset, site, CAST(l AS DATE) AS day, min(l) AS first, max(l) AS last,
                           date_diff('second', min(l), max(l)) / 3600.0 AS hours, count(*) AS records
                    FROM ({' UNION ALL '.join(parts)}) GROUP BY ALL ORDER BY dataset, site, day""").df()
c['partial'] = c.hours < reglib.PARTIAL_HOURS
c.to_csv(outp, index=False)
g = c.groupby(['dataset', 'site']).agg(recording_days=('day', 'size'), partial_days=('partial', 'sum'), first_day=('day', 'min'),
                                       last_day=('day', 'max'), median_hours=('hours', 'median')).reset_index()
g['calendar_days'] = [(b - a).days + 1 for a, b in zip(g.first_day, g.last_day)]
print(g.to_string(index=False))
