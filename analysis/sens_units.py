#!/usr/bin/env python3
"""Incidence tables for the unit analyses registered on 25 November 2026 (../docs/method.md, points 6, 7 and 11 of that note).
Each variant only removes days from the incidence table. The frozen procedure then runs unchanged on what remains
(run_sens.sh): it drops the first and the last remaining active day of every device, T counts retained days, and the horizon
is the next 14 retained active days.

  partial20  days on which the capture covers less than 20 hours are removed for every device of the capture (coverage.py)
  wd5        only local days from Monday to Friday
  wd6        only local days from Monday to Saturday
  part1      recording days 1 to 56 of a capture, counted from its first local day with records
  part2      recording days 57 to 112
The two parts are the trial of the replication within the site. They are built only for captures with at least 98 days
with records (56 + 42). Traces whose unit is not the day (HVAC, 7 days) are left out of every variant.
Usage: sens_units.py <coverage.csv> <out_dir> <inc_day.parquet>..."""
import sys, os, duckdb
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import reglib
cov, out = sys.argv[1:3]; incs = sys.argv[3:]
SKIP = "('hvac')"
con = duckdb.connect(); con.execute("SET threads TO 2"); con.execute("SET memory_limit='4GB'")
con.execute(f"CREATE TABLE cov AS SELECT dataset, CAST(site AS VARCHAR) AS site, CAST(day AS DATE) AS day, hours FROM read_csv('{cov}', header=true)")
con.execute("""CREATE TABLE cap AS SELECT dataset, site, min(day) AS d0, count(*) AS n_days FROM cov GROUP BY ALL""")
src = ' UNION ALL '.join(f"SELECT dataset, CAST(site AS VARCHAR) AS site, device, CAST(day AS DATE) AS day, gran, ftype, n, b FROM read_parquet('{p}')"
                         for p in incs)
con.execute(f"CREATE TABLE inc AS SELECT * FROM ({src}) WHERE dataset NOT IN {SKIP}")
missing = con.execute("SELECT count(*) FROM (SELECT DISTINCT dataset, site, day FROM inc) LEFT JOIN cov USING (dataset, site, day) WHERE hours IS NULL").fetchone()[0]
if missing:
    sys.exit(f'{missing} capture-days of the incidence tables have no coverage row')
VARIANTS = {
    'partial20': f"SELECT i.* FROM inc i JOIN cov c USING (dataset, site, day) WHERE c.hours >= {reglib.PARTIAL_HOURS}",
    'wd5': "SELECT * FROM inc WHERE isodow(day) BETWEEN 1 AND 5",
    'wd6': "SELECT * FROM inc WHERE isodow(day) BETWEEN 1 AND 6",
    'part1': f"""SELECT i.* FROM inc i JOIN cap USING (dataset, site)
                 WHERE n_days >= {reglib.PART_DAYS + reglib.PART_MIN} AND date_diff('day', d0, day) < {reglib.PART_DAYS}""",
    'part2': f"""SELECT i.* FROM inc i JOIN cap USING (dataset, site)
                 WHERE n_days >= {reglib.PART_DAYS + reglib.PART_MIN} AND date_diff('day', d0, day) BETWEEN {reglib.PART_DAYS} AND {2 * reglib.PART_DAYS - 1}""",
}
base = con.execute("SELECT dataset, count(DISTINCT site || '/' || day) AS days, count(DISTINCT site || '/' || device || '/' || day) AS device_days FROM inc GROUP BY 1 ORDER BY 1").df()
print('all days\n', base.to_string(index=False))
for name, q in VARIANTS.items():
    os.makedirs(f'{out}/{name}', exist_ok=True)
    con.execute(f"COPY ({q}) TO '{out}/{name}/inc_day.parquet' (FORMAT parquet, COMPRESSION zstd)")
    t = con.execute(f"""SELECT dataset, count(DISTINCT site || '/' || day) AS days, count(DISTINCT site || '/' || device || '/' || day) AS device_days
                        FROM read_parquet('{out}/{name}/inc_day.parquet') GROUP BY 1 ORDER BY 1""").df()
    t = base.merge(t, on='dataset', how='left', suffixes=('_all', '')).fillna(0)
    t['days_removed'] = t.days_all - t.days; t['device_days_removed'] = t.device_days_all - t.device_days
    t.insert(0, 'variant', name); t.to_csv(f'{out}/{name}/days.csv', index=False)
    print(name, '\n', t.to_string(index=False), flush=True)
