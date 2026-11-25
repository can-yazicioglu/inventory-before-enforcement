#!/bin/bash
# Copies the stored result tables (CSV) of the public-data runs from $IBE_DATA into ../paper/tables/public and keeps the folder
# names of the data root. Raw data, intermediate files (parquet) and logs are not copied. Run after all run scripts.
# The tables are the record behind every number of the public-data results. They are generated: do not edit them by hand.
D=${IBE_DATA:-data}; A=$(cd "$(dirname "$0")" && pwd); T=$A/../paper/tables/public; mkdir -p $T
cd $D || exit 1
for f in out/*.csv cic/out/*.csv \
         v3/res_base/*.csv v3/res_base/tables/*.csv v3/res_keep/tables/*.csv v3/res_prefix/tables/*.csv v3/res_strict/tables/*.csv \
         v3/res_utc/tables/*.csv val/res/*.csv val/res/tables/*.csv val/res_hvac_6h/tables/*.csv \
         servtrace/res/*.csv servtrace/res/tables/*.csv deakin/summary.csv deakin/res/*.csv deakin/res/tables/*.csv \
         sens/coverage_summary.csv sens/*/days.csv sens/*/res/tables/*.csv; do
  [ -f "$f" ] || continue
  case $f in */indep_cal_H14.csv) continue;; esac          # one row per device and day: an intermediate file
  mkdir -p "$T/$(dirname $f)" && cp "$f" "$T/$f"
done
( cd $T && find . -name '*.csv' | sort | xargs wc -c | tail -1 )
echo TABLESDONE
