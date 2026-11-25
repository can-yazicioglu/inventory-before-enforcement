#!/bin/bash
# Step 5: everything that run_v3.sh, run_final_base.sh and run_val.sh do not start, with the exact invocations
# (recorded in the audit of 24 Nov 2026). Run after those three.
D=${IBE_DATA:-data}; A=$(cd "$(dirname "$0")" && pwd); D3=$D/v3; DV=$D/val
mkdir -p $D/out $D/audit
python3 -I -W ignore $A/eval_all3.py $D3/res_base 7 7 > $D3/res_base/eval7.log 2>&1 || echo FAIL eval7 base
python3 -I -W ignore $A/eval_all3.py $DV/res 7 7 > $DV/res/eval7.log 2>&1 || echo FAIL eval7 val
python3 -I -W ignore $A/alertday.py $DV/inc/inc_day.parquet $DV/res/tables/alertday.csv > $DV/res/alertday.log 2>&1 || echo FAIL alertday val
python3 -I -W ignore $A/matched.py $D/out/matched_streak.csv $D3/res_base/scored.parquet $DV/res/scored.parquet > $D/out/matched.log 2>&1 || echo FAIL matched
python3 -I -W ignore $A/capture_len.py $D/out/capture_length.csv $D3/res_base/scored.parquet $DV/res/scored.parquet > $D/out/capture_len.log 2>&1 || echo FAIL capture_len
python3 -I -W ignore $A/eval_all3.py $DV/res_hvac_6h 14 7 > $DV/res_hvac_6h/eval14.log 2>&1 || echo FAIL eval hvac
python3 -I -W ignore $A/hvac_cal.py $DV $D/out/hvac_calibration_explicit.csv > $D/out/hvac_cal.log 2>&1 || echo FAIL hvac_cal
python3 -I -W ignore $A/facts.py > $D/out/facts.log 2>&1 || echo FAIL facts
python3 -I -W ignore $A/exch_table.py $D/out/exchangeability.csv $D3/res_base $DV/res > $D/out/exch_table.log 2>&1 || echo FAIL exch_table
python3 -I -W ignore $A/fixed_list.py $D3/inc_base/inc_day.parquet $D3/res_base > $D3/res_base/fixed_list.log 2>&1 || echo FAIL fixed_list base
python3 -I -W ignore $A/fixed_list.py $DV/inc/inc_day.parquet $DV/res > $DV/res/fixed_list.log 2>&1 || echo FAIL fixed_list val
python3 -I $A/prop_check.py > $D/out/prop_check.log 2>&1 || echo FAIL prop_check
python3 -I -W ignore $A/verify.py $D3/inc_base/inc_day.parquet $D3/res_base/series.parquet > $D/out/verify.log 2>&1 || echo FAIL verify
python3 -I $A/indep.py $DV/inc/inc_day.parquet $DV/res/indep 14 > $DV/res/indep.log 2>&1 || echo FAIL indep val
python3 -I -W ignore $A/indep_unsw.py > $D/out/indep_unsw.log 2>&1 || echo FAIL indep_unsw
echo EXTRADONE
