#!/bin/bash
# full re-run on the corrected 12-home normalisation (v3). Usage: run_v3.sh
D=${IBE_DATA:-data}/v3; A=$(cd "$(dirname "$0")" && pwd)
U=${IBE_DATA:-data}/v2/unsw.parquet      # UNSW 2016 normalisation is unchanged
run() {  # name, env...
  name=$1; shift
  mkdir -p $D/inc_$name/tmp $D/res_$name
  env "$@" python3 -I $A/incidence3.py $U $D/homes $D/inc_$name > $D/inc_$name/log.txt 2>&1 || { echo "FAIL inc $name"; return; }
  env "$@" python3 -I $A/run_series3.py $D/inc_$name/inc_day.parquet $D/res_$name > $D/res_$name/series.log 2>&1 || { echo "FAIL series $name"; return; }
  python3 -I -W ignore -c "
import sys, pandas as pd
sys.path.insert(0,'$A'); import scores
scores.add_scores(pd.read_parquet('$D/res_$name/series.parquet')).to_parquet('$D/res_$name/scored.parquet', index=False)" || { echo "FAIL score $name"; return; }
  python3 -I -W ignore $A/eval_all3.py $D/res_$name 14 7 > $D/res_$name/eval14.log 2>&1
  rm -rf $D/inc_$name/tmp
  echo "done $name $(date +%H:%M)"
}
run base GT_FILTER=in GT_EXTRA=1 GT_GRANS=proto,port,svc,svcx,dom,net,host
cp -r $D/res_base/tables $D/res_base/tables_h14
python3 -I -W ignore $A/eval_all3.py $D/res_base 30 7 > $D/res_base/eval30.log 2>&1
run keep GT_FILTER=keep GT_GRANS=port,svc,net
run prefix GT_ROLE=prefix GT_GRANS=port,svc,net
run strict GT_FILTER=strict GT_GRANS=port,svc,net
run utc GT_TZ=utc GT_GRANS=port,svc,net
echo ALLDONE
