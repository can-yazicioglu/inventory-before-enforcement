#!/usr/bin/env python3
"""Descriptive numbers quoted in the text that no other script prints: size and continuity of the traces, what the participation
filter removes, recording gaps, the role variant that learns from the first seven days only, late flow types by kind of peer,
recording days of the validation data, and partial recording days.
Reads the normalised data, the incidence tables and the scored series under $IBE_DATA. Usage: facts.py"""
import os, duckdb, pandas as pd
R = os.environ.get('IBE_DATA', 'data'); con = duckdb.connect(); con.execute("SET threads TO 2")
q = lambda s: con.execute(s).df()
pd.set_option('display.width', 250)
U, H = f"read_parquet('{R}/v2/unsw.parquet')", f"read_parquet('{R}/v3/homes/home*.parquet')"
SYD = "timezone('Australia/Sydney', timezone('UTC', ts))"

print('1. UNSW 2016 trace')
print(q(f"""SELECT count(*) AS records, count(DISTINCT device) AS devices, count(DISTINCT CAST({SYD} AS DATE)) AS recording_days,
            datediff('day', min(CAST({SYD} AS DATE)), max(CAST({SYD} AS DATE))) + 1 AS calendar_days FROM {U}""").to_string(index=False))
a = q(f"""SELECT device, count(DISTINCT CAST({SYD} AS DATE)) AS active,
          datediff('day', min(CAST({SYD} AS DATE)), max(CAST({SYD} AS DATE))) + 1 AS own_span FROM {U} GROUP BY ALL""")
print(f'   median device: {a.active.median():.0f} active days, active on {(a.active / a.own_span).median():.3f} of the calendar days between its first and last record')

print('2. 12 homes')
print(q(f"SELECT count(*) AS records, count(DISTINCT site) AS homes, count(DISTINCT site || '/' || device) AS devices, count(DISTINCT device) AS models FROM {H}").to_string(index=False))
d = q(f"SELECT site, datediff('day', min(CAST(ts AS DATE)), max(CAST(ts AS DATE))) + 1 AS days FROM {H} GROUP BY ALL").days
print(f'   calendar days per home: min {d.min()}, median {d.median():.0f}, max {d.max()}')

print('3. participation filter: port-level rule types (device, type) with and without the filter')
for ds in ('homes', 'unsw'):
    n = [q(f"SELECT count(*) AS n FROM (SELECT DISTINCT site, device, ftype FROM read_parquet('{R}/v3/inc_{v}/inc_day.parquet') WHERE dataset='{ds}' AND gran='port')").n[0] for v in ('keep', 'base')]
    print(f'   {ds}: without filter {n[0]}, with filter {n[1]}, share removed {(n[0] - n[1]) / n[0]:.3f}')

print('4. recording gaps in the UNSW 2016 trace (first learning episode, T >= 7, next-day outcome known)')
s = pd.read_parquet(f'{R}/v3/res_base/scored.parquet'); s = s[(s.dataset == 'unsw') & (s.origin == 0) & (s['T'] >= 7) & s.gran.isin(['port', 'svc', 'net'])]
for g, x in s[s.y1 >= 0].groupby('gran'):
    a, b = x[x.gap > 1], x[x.gap == 1]
    print(f'   {g}: days that follow a gap are {len(a) / len(x):.3f} of the days and carry {a.y1.sum() / x.y1.sum():.3f} of the new types. '
          f'Realised / predicted after a gap {a.y1.sum() / a["gt"].sum():.2f}, on consecutive days {b.y1.sum() / b["gt"].sum():.2f}')
e = s[(s.y14 >= 0) & (s.gran == 'svc')]
print(f'   rows whose next 14 active days span more than 21 calendar days: {(e.span14 > 21).mean():.3f}')

print('5. role learned from the first 7 days only (prefix variant): distinct flow types per device, svc level')
for ds in ('unsw', 'homes'):
    a = q(f"SELECT site, device, count(DISTINCT ftype) AS whole_trace FROM read_parquet('{R}/v3/inc_base/inc_day.parquet') WHERE dataset='{ds}' AND gran='svc' GROUP BY ALL")
    b = q(f"SELECT site, device, count(DISTINCT ftype) AS first_week FROM read_parquet('{R}/v3/inc_prefix/inc_day.parquet') WHERE dataset='{ds}' AND gran='svc' GROUP BY ALL")
    m = a.merge(b, on=['site', 'device']); m['factor'] = (m.first_week / m.whole_trace).round(1)
    print(m.sort_values('factor', ascending=False).head(5).to_string(index=False))

print('6. UNSW 2016, svc level: flow types first seen after the first 8 active days of their device, by kind of peer')
print(q(f"""WITH d AS (SELECT device, day, dense_rank() OVER (PARTITION BY device ORDER BY day) AS k
                       FROM (SELECT DISTINCT device, day FROM read_parquet('{R}/v3/inc_base/inc_day.parquet') WHERE dataset='unsw' AND gran='svc')),
     f AS (SELECT i.device, ftype, min(k) AS first_k FROM read_parquet('{R}/v3/inc_base/inc_day.parquet') i JOIN d USING (device, day)
           WHERE dataset='unsw' AND gran='svc' GROUP BY ALL)
SELECT CASE WHEN ftype LIKE '%@ip:%' THEN 'LAN host known by its IP address' WHEN ftype LIKE '%@dev:%' THEN 'LAN device of the catalogue'
            WHEN ftype LIKE '%@wan' THEN 'any WAN host' WHEN ftype LIKE '%.255' THEN 'broadcast address'
            WHEN regexp_matches(ftype, '@(22[4-9]|23[0-9])\\.') OR ftype ILIKE '%@ff%:%' THEN 'multicast address' ELSE 'other' END AS peer,
       count(*) AS types FROM f WHERE first_k > 8 GROUP BY ALL ORDER BY types DESC""").to_string(index=False))

print('7. validation data: recording days')
for v in ('v1', 'v2'):
    p = f"read_parquet('{R}/orig/DATA2025{v}_flows.parquet')"
    print(f'   unsw25{v}:', q(f"SELECT count(*) AS flows, count(DISTINCT Device) AS devices, count(DISTINCT SrcFile) AS day_files, min(SrcFile) AS first_file, max(SrcFile) AS last_file FROM {p}").to_dict('records')[0],
          '| days in the incidence table:', q(f"SELECT count(DISTINCT day) AS n FROM read_parquet('{R}/val/inc/inc_day.parquet') WHERE dataset='unsw25{v}' AND gran='svc'").n[0])
print('   device with most svc types:', q(f"SELECT dataset, device, count(DISTINCT ftype) AS svc_types FROM read_parquet('{R}/val/inc/inc_day.parquet') WHERE gran='svc' GROUP BY ALL ORDER BY svc_types DESC LIMIT 2").values.tolist())
print('   hvac:', q(f"SELECT count(*) AS flows, CAST(sum(pkts_a) + sum(pkts_b) AS BIGINT) AS packets FROM read_parquet('{R}/orig/hvac_flows.parquet')").to_dict('records')[0],
      q(f"SELECT count(DISTINCT device) AS internal_nodes, min(ts) AS first, max(ts) AS last FROM read_parquet('{R}/val/norm/hvac.parquet')").astype(str).to_dict('records')[0])

print('8. partial recording days: local days on which the first and the last record of the whole capture lie less than 20 hours apart')
for name, src, tz in (('unsw', U, 'Australia/Sydney'), ('unsw25v1', f"read_parquet('{R}/val/norm/unsw25v1.parquet')", 'Australia/Sydney'),
                      ('unsw25v2', f"read_parquet('{R}/val/norm/unsw25v2.parquet')", 'Australia/Sydney')):
    L = f"timezone('{tz}', timezone('UTC', ts))"
    c = q(f"SELECT CAST({L} AS DATE) AS d, date_diff('second', min({L}), max({L})) / 3600.0 AS h FROM {src} GROUP BY ALL")
    print(f'   {name}: {len(c)} recording days, {int((c.h < 20).sum())} cover less than 20 hours, {int((c.h < 1).sum())} less than 1 hour')
