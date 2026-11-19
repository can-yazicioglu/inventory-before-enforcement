# Analysis

The frozen method (`../docs/method.md`) as code. Python 3 with duckdb, pandas, numpy, scipy and pyarrow.

| Step | Script | What it does |
|---|---|---|
| 1 | `join.py` | rebuilds the original data files from parts and verifies SHA-256 |
| 2 | `normalize3.py`, `adapt_new.py`, `adapt_recorder.py` | bring every source into one schema: one row per flow record and monitored device |
| 3 | `incidence3.py` | flow types per device and day at six levels of detail, role assignment, participation filter |
| 4 | `run_series3.py`, `gtlib.py` | for every device and observation length T: Q1, Q2, new types on the following days, exchangeability test |
| 5 | `scores.py` | Good-Turing estimate, upper bound, drift correction (GT-C) |
| 6 | `eval_all3.py`, `extra.py`, `alertday.py`, `matched.py` | calibration, the stopping rules, alert-day metric, cluster bootstrap |
| check | `verify.py`, `indep.py`, `indep_unsw.py`, `prop_check.py` | brute-force recount of the inputs, a second implementation written from the method text, exact check of the propositions |

Run order and time zones are recorded in `run_v3.sh`, `run_final_base.sh` and `run_val.sh`.
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
record and flow exports do not. `--hours` gives the working hours used by the outage rule.

Two kinds of recorder record are treated specially by `adapt_recorder.py` (see the note of
19 November 2026 in `../docs/method.md`):

- A TCP record without the opening SYN and without the answering SYN-ACK was picked up in the middle of a conversation. Who opened it is unknown, so its role is decided by the port rules that `incidence3.py` uses for flow exports, and it counts for a device only if the device sent a packet in it other than a reset.
- An hourly report about a connection that is still open (`"open":true`) marks the flow type as present at that time. Its bytes are not added.

Registered sensitivity analysis: the same command without `GT_ROLE=init` decides every role by the
port rules.

## Tests

`tests/test_adapt_recorder.py` covers the outage rule. `tests/test_recorder_rows.py` runs small sets of
recorder records through the adapter and `incidence3.py` and checks the flow types that come out
(handshake seen and not seen, refusals, hourly reports). The complete chain from a capture file to
the stopping rule is checked by `../recorder/tests/e2e.py` and `../recorder/tests/scenarios.py`.
