#!/bin/bash
# validation datasets (UNSW 2025 v1/v2, HVAC) with the frozen method
D=${IBE_DATA:-data}/val; A=$(cd "$(dirname "$0")" && pwd); O=${IBE_DATA:-data}/orig
mkdir -p $D/norm $D/inc/tmp $D/res
python3 -I $A/adapt_new.py $O $O/hvac_flows.parquet $D/norm > $D/adapt.log 2>&1 || { echo FAIL adapt; exit 1; }
export GT_INPUTS="$D/norm/unsw25v1.parquet|Australia/Sydney;$D/norm/unsw25v2.parquet|Australia/Sydney;$D/norm/hvac.parquet|Europe/Brussels"
GT_EXTRA=1 python3 -I $A/incidence3.py x x $D/inc > $D/inc/log.txt 2>&1 || { echo FAIL inc; exit 1; }
GT_GRANS=proto,port,svc,svcx,net,host python3 -I $A/run_series3.py $D/inc/inc_day.parquet $D/res > $D/res/series.log 2>&1 || { echo FAIL series; exit 1; }
python3 -I -W ignore -c "
import sys, pandas as pd
sys.path.insert(0,'$A'); import scores
scores.add_scores(pd.read_parquet('$D/res/series.parquet')).to_parquet('$D/res/scored.parquet', index=False)"
python3 -I -W ignore $A/eval_all3.py $D/res 14 7 > $D/res/eval14.log 2>&1
python3 -I -W ignore $A/extra.py $D/res 14 > $D/res/extra.log 2>&1
python3 -I -W ignore $A/run_hvac.py $D/inc $D > $D/hvac.log 2>&1
rm -rf $D/inc/tmp
echo VALDONE
