# Stored result tables

`public/` holds the result tables (CSV) of the public-data runs, copied from the data root by
`analysis/collect_tables.sh` after all run scripts. The folder names are those of the data root:

| Folder | Written by | Content |
|---|---|---|
| `v3/res_base` | `run_v3.sh`, `run_final_base.sh`, `run_extra.sh`, `run_sens.sh` | 12 homes and UNSW 2016, primary analysis |
| `v3/res_keep`, `res_prefix`, `res_strict`, `res_utc` | `run_v3.sh` | the same traces with one preparation choice changed |
| `val/res`, `val/res_hvac_6h` | `run_val.sh`, `run_extra.sh`, `run_sens.sh` | UNSW 2025 (two archives), HVAC trace |
| `servtrace/res` | `run_servtrace.sh`, `run_sens.sh` | IoT-ServTrace, port level only |
| `deakin` | `run_deakin.sh`, `run_sens.sh` | Deakin D-IoT. `summary.csv` is the output of `deakin_reduce.py` (packets per daily file) |
| `cic/out` | `run_cic.sh` | CICIoMT2024 |
| `out` | `run_extra.sh`, `run_sens.sh` | tables over several traces |
| `sens` | `run_sens.sh` | coverage per capture, and the stopping tables without partial recording days, on weekdays only and for the two parts of a recording |

The tables are generated. They are not edited by hand. After a change of the analysis code the full run is repeated,
the tables are collected again, and `git diff` shows every number that moved. Floating-point sums can differ in the last
binary digit between two runs, because the database does not return rows in a fixed order.

The method note (`docs/method.md`) says which analyses are registered and which are exploratory. All tables here come
from public data. Tables of the clinical site are not stored in this repository.
