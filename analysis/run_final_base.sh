#!/bin/bash
D=${IBE_DATA:-data}/v3; A=$(cd "$(dirname "$0")" && pwd); U=${IBE_DATA:-data}/v2/unsw.parquet
rm -rf $D/inc_base $D/res_base; mkdir -p $D/inc_base/tmp $D/res_base
GT_FILTER=in GT_EXTRA=1 python3 -I $A/incidence3.py $U $D/homes $D/inc_base > $D/inc_base/log.txt 2>&1 || exit 1
GT_GRANS=proto,port,svc,svcx,dom,net,host python3 -I $A/run_series3.py $D/inc_base/inc_day.parquet $D/res_base > $D/res_base/series.log 2>&1 || exit 1
python3 -I -W ignore -c "
import sys, pandas as pd
sys.path.insert(0,'$A'); import scores
scores.add_scores(pd.read_parquet('$D/res_base/series.parquet')).to_parquet('$D/res_base/scored.parquet', index=False)"
python3 -I -W ignore $A/eval_all3.py $D/res_base 30 7 > $D/res_base/eval30.log 2>&1
python3 -I -W ignore $A/eval_all3.py $D/res_base 14 7 > $D/res_base/eval14.log 2>&1
python3 -I -W ignore $A/exp1.py $D/res_base 7 > $D/res_base/exp1.log 2>&1
python3 -I -W ignore $A/exp4.py $D/res_base $D/res_keep $D/homes/device_map.csv > $D/res_base/exp4.log 2>&1
python3 -I -W ignore $A/exp5.py $D/inc_base/inc_day.parquet $D/res_base/tables > $D/res_base/exp5.log 2>&1
python3 -I -W ignore $A/exp6.py $D/inc_base $D/res_base/tables > $D/res_base/exp6.log 2>&1
python3 -I -W ignore $A/extra.py $D/res_base 14 > $D/res_base/extra.log 2>&1
python3 -I -W ignore $A/alertday.py $D/inc_base/inc_day.parquet $D/res_base/tables/alertday.csv > $D/res_base/alertday.log 2>&1
python3 -I $A/indep.py $D/inc_base/inc_day.parquet $D/res_base/indep 14 > $D/res_base/indep.log 2>&1
rm -rf $D/inc_base/tmp; echo FINALBASEDONE
