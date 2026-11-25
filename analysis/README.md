# Analysis

The frozen method (`../docs/method.md`) as code. Python 3 with duckdb, pandas, numpy, scipy and pyarrow.

| Step | Script | What it does |
|---|---|---|
| 1 | `join.py` | rebuilds the original data files from parts and verifies SHA-256 |
| 2 | `normalize3.py`, `adapt_new.py`, `adapt_recorder.py` | bring every source into one schema: one row per flow record and monitored device |
| 3 | `incidence3.py` | flow types per device and day at six levels of detail, role assignment, participation filter |
| 4 | `run_series3.py`, `gtlib.py` | for every device and observation length T: Q1, Q2, new types on the following days, exchangeability test |
| 5 | `scores.py` | Good-Turing estimate, upper bound, drift correction (GT-C) |
| 6 | `eval_all3.py`, `extra.py`, `alertday.py`, `matched.py`, `capture_len.py`, `hvac_cal.py` | calibration, the stopping rules, alert-day metric, cluster bootstrap, how long a capture must be |
| describe | `facts.py`, `exp1.py`, `exp4.py`, `exp5.py`, `exp6.py` | the descriptive numbers of the text, exchangeability test, device categories, fleet learning, sampling unit |
| other data | `pcap2flows.py`, `cic_eval.py`, `adapt_servtrace.py`, `deakin_reduce.py`, `adapt_deakin.py` | CICIoMT2024 (device states, reconnaissance), IoT-ServTrace (port level only), Deakin D-IoT (packets sent by the devices only) |
| registered on 25 Nov 2026 | `rules_eval.py`, `coverage.py`, `sens_units.py`, `sens_table.py`, `halves.py`, `reglib.py` | allowlists from flow types seen on at least k days, a bound that is valid at every look, the analysis without partial recording days and on weekdays only, the replication within one recording |
| check | `verify.py`, `indep.py`, `indep_unsw.py`, `prop_check.py` | brute-force recount of the inputs, a second program for the stopping tables (see below), exact check of the propositions |

Run order and time zones are recorded in `run_prep.sh`, `run_v3.sh`, `run_final_base.sh`, `run_val.sh` and `run_extra.sh`, in
this order. `run_cic.sh`, `run_servtrace.sh` and `run_deakin.sh` are independent of them. `run_sens.sh` comes last: it runs the
analyses registered on 25 November 2026 on all traces. Every number quoted in the text comes from a table or a log that one of
these scripts writes.

The second program (`indep.py`) recomputes the enforcement days and the two exceedance shares of GT-C, of the chi-square limit
alone, of the quiet streak and of the fixed windows for the 14-day horizon at the port, svc and net levels. It uses sets and
loops instead of matrices, starts from the same table of flow types per device and day and follows the same conventions. It
checks the computation of the rule and of the outcomes, not the preparation of the data. The preparation of the UNSW 2016 data
was repeated separately (`indep_unsw.py`). Intervals, calibration, the certification curves and the other tables were not
recomputed independently.
Paths come from the environment variable `IBE_DATA` (default `data/`).

## Clinical sites

```bash
python3 adapt_recorder.py <export_dir> site.parquet --tz Europe/Istanbul \
        --hours "1-5=08:00-17:00,6=08:00-13:30" --group agentless --visibility full
GT_ROLE=init GT_INPUTS="site.parquet|Europe/Istanbul" GT_GRANS=proto,port,svc,net,host \
        python3 incidence3.py x x inc/
python3 run_series3.py inc/inc_day.parquet res/
```

`GT_ROLE=init` takes the role from the side that opened the connection, which connection logs
record and flow exports do not. `--hours` gives the working hours used by the outage rule. It has
no default: `--hours none` switches the rule off on purpose, and the output then says so.

Four kinds of recorder record are treated specially by `adapt_recorder.py` (see the notes of
19 November 2026 in `../docs/method.md`):

- Opener not seen. A TCP record without the opening SYN and without the answering SYN-ACK was picked up in the middle of a conversation. A UDP record that Zeek turned around (`^` in the history) began with a packet from a service port. Who opened these is unknown, so the role is decided by the port rules that `incidence3.py` uses for flow exports, and the record counts for a device only if the device sent a packet in it (TCP: other than a reset).
- An hourly report about a connection that is still open (`"open":true`) marks the flow type as present at that time, for each side that sent a packet in that hour. Its bytes are not added.
- A protocol without ports has no roles, so the participation filter of `incidence3.py` cannot work on it. Its record counts for the answering side only if that side sent a packet. An ICMP error message gives its sender no flow type: it is the refusal of a packet of somebody else, as a reset is for TCP.
- A finished record that ends in a later clock hour than it began counts only for its opener, at the start. It covers the whole life of the connection, so which side sent on which day is taken from the hourly reports.

Registered sensitivity analysis: the same command without `GT_ROLE=init` decides every role by the
port rules.

## Tests

`tests/test_adapt_recorder.py` covers the outage rule. `tests/test_recorder_rows.py` runs small sets of
recorder records through the adapter and `incidence3.py` and checks the flow types that come out
(handshake seen and not seen, refusals, hourly reports, turned-around UDP, protocols without ports, long
connections whose other side is switched off on the first day).
The complete chain from a capture file to
the stopping rule is checked by `../recorder/tests/e2e.py` and `../recorder/tests/scenarios.py`.
