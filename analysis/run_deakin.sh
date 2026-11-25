#!/bin/bash
# Deakin D-IoT with the frozen method (added on 25 Nov 2026, ../docs/method.md, point 13 of the note of that date).
# The flow records that deakin_reduce.py writes lie under $IBE_DATA/deakin/flows (*.csv.gz), the dataset's macAddresses.csv
# under $IBE_DATA/deakin/csv/CSVs.
S=${IBE_DATA:-data}/deakin; A=$(cd "$(dirname "$0")" && pwd); mkdir -p $S/norm $S/inc/tmp $S/res
python3 -I $A/adapt_deakin.py $S/flows $S/csv/CSVs/macAddresses.csv $S/norm/deakin.parquet > $S/adapt.log 2>&1 || { echo FAIL adapt; exit 1; }
export GT_INPUTS="$S/norm/deakin.parquet|Australia/Melbourne"
GT_EXTRA=1 python3 -I $A/incidence3.py x x $S/inc > $S/inc/log.txt 2>&1 || { echo FAIL inc; exit 1; }
GT_GRANS=proto,port,svc,svcx,net,host python3 -I $A/run_series3.py $S/inc/inc_day.parquet $S/res > $S/res/series.log 2>&1 || { echo FAIL series; exit 1; }
python3 -I -W ignore -c "
import sys, pandas as pd
sys.path.insert(0,'$A'); import scores
scores.add_scores(pd.read_parquet('$S/res/series.parquet')).to_parquet('$S/res/scored.parquet', index=False)" || { echo FAIL score; exit 1; }
python3 -I -W ignore $A/eval_all3.py $S/res 7 7 > $S/res/eval7.log 2>&1
python3 -I -W ignore $A/eval_all3.py $S/res 30 7 > $S/res/eval30.log 2>&1
python3 -I -W ignore $A/eval_all3.py $S/res 14 7 > $S/res/eval14.log 2>&1
python3 -I -W ignore $A/extra.py $S/res 14 > $S/res/extra.log 2>&1
python3 -I -W ignore $A/alertday.py $S/inc/inc_day.parquet $S/res/tables/alertday.csv > $S/res/alertday.log 2>&1
python3 -I -W ignore $A/matched.py $S/res/matched_streak.csv $S/res/scored.parquet > $S/res/matched.log 2>&1
python3 -I -W ignore $A/capture_len.py $S/res/capture_length.csv $S/res/scored.parquet > $S/res/capture_len.log 2>&1
python3 -I $A/indep.py $S/inc/inc_day.parquet $S/res/indep 14 > $S/res/indep.log 2>&1
python3 -I -W ignore $A/fixed_list.py $S/inc/inc_day.parquet $S/res > $S/res/fixed_list.log 2>&1
python3 -I -W ignore $A/exch_table.py $S/res/exchangeability.csv $S/res > $S/res/exch_table.log 2>&1
rm -rf $S/inc/tmp
echo DEAKINDONE
