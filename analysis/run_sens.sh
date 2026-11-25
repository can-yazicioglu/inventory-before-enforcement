#!/bin/bash
# Step 6: the analyses registered on 25 Nov 2026 (../docs/method.md, points 6 to 11 of the note of that date).
# Run after run_v3.sh, run_final_base.sh, run_val.sh, run_extra.sh, run_servtrace.sh and, if that trace is there, run_deakin.sh.
# Exploratory on the public data.
D=${IBE_DATA:-data}; A=$(cd "$(dirname "$0")" && pwd); S=$D/sens; mkdir -p $S $D/out
DK=""; DKC=""                                   # Deakin D-IoT takes part if it was prepared
if [ -s $D/deakin/inc/inc_day.parquet ]; then DK="$D/deakin/inc/inc_day.parquet"; DKC="norm|$D/deakin/norm/deakin.parquet|Australia/Melbourne"; fi
# (1) minimum of k days, and the bound that is valid at every look, on the enforcements of the primary analysis
python3 -I -W ignore $A/rules_eval.py $D/v3/inc_base/inc_day.parquet $D/v3/res_base > $D/v3/res_base/rules_eval.log 2>&1 || echo FAIL rules_eval base
python3 -I -W ignore $A/rules_eval.py $D/val/inc/inc_day.parquet $D/val/res > $D/val/res/rules_eval.log 2>&1 || echo FAIL rules_eval val
python3 -I -W ignore $A/rules_eval.py $D/servtrace/inc/inc_day.parquet $D/servtrace/res > $D/servtrace/res/rules_eval.log 2>&1 || echo FAIL rules_eval servtrace
[ -n "$DK" ] && { python3 -I -W ignore $A/rules_eval.py $DK $D/deakin/res > $D/deakin/res/rules_eval.log 2>&1 || echo FAIL rules_eval deakin; }
# (2) coverage of every capture on every local day
python3 -I $A/coverage.py $S/coverage.csv "norm|$D/v2/unsw.parquet|Australia/Sydney" "norm|$D/v3/homes/home*.parquet|Asia/Tokyo" \
  "norm|$D/val/norm/unsw25v1.parquet|Australia/Sydney" "norm|$D/val/norm/unsw25v2.parquet|Australia/Sydney" \
  "servtrace|$D/servtrace/raw|Asia/Tokyo" $DKC > $S/coverage.log 2>&1 || { echo FAIL coverage; exit 1; }
# (3) the variants of the incidence table (partial recording days removed, weekdays only, the two parts of a recording),
#     then the frozen chain on each of them, unchanged
python3 -I $A/sens_units.py $S/coverage.csv $S $D/v3/inc_base/inc_day.parquet $D/val/inc/inc_day.parquet $D/servtrace/inc/inc_day.parquet $DK \
  > $S/units.log 2>&1 || { echo FAIL sens_units; exit 1; }
for v in partial20 wd5 wd6 part1 part2; do
  R=$S/$v/res; mkdir -p $R
  GT_GRANS=port,svc,net python3 -I $A/run_series3.py $S/$v/inc_day.parquet $R > $R/series.log 2>&1 || { echo FAIL series $v; continue; }
  python3 -I -W ignore -c "
import sys, pandas as pd
sys.path.insert(0,'$A'); import scores
scores.add_scores(pd.read_parquet('$R/series.parquet')).to_parquet('$R/scored.parquet', index=False)" || { echo FAIL score $v; continue; }
  python3 -I -W ignore $A/eval_all3.py $R 14 7 > $R/eval14.log 2>&1 || echo FAIL eval $v
  # calibration without partial recording days and of each part (the same three variants that the pattern part* selected)
  case $v in partial20|part1|part2) python3 -I -W ignore $A/extra.py $R 14 > $R/extra.log 2>&1 || echo FAIL extra $v;; esac
  python3 -I -W ignore $A/fixed_list.py $S/$v/inc_day.parquet $R > $R/fixed_list.log 2>&1 || echo FAIL fixed_list $v
  echo "done $v $(date +%H:%M)"
done
python3 -I -W ignore $A/sens_table.py $D > $D/out/sens_table.log 2>&1 || echo FAIL sens_table
python3 -I -W ignore $A/halves.py $S/part1 $S/part2 $D/out > $D/out/halves.log 2>&1 || echo FAIL halves
# (4) a check that reads stored tables only: the stopping tables of the second program against those of the analysis
python3 -I $A/indep_compare.py $D/v3/res_base $D/val/res $D/servtrace/res ${DK:+$D/deakin/res} > $D/out/indep_compare.log 2>&1 || echo FAIL indep_compare
echo SENSDONE
