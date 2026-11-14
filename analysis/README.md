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

## Tests

`tests/test_adapt_recorder.py` covers the outage rule. The complete chain from a capture file to the
stopping rule is checked by `../recorder/tests/e2e.py`.
