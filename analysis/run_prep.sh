#!/bin/bash
# Steps 1 to 3: rebuild the source files from their uploaded parts, unpack them and bring the two base traces into the
# common schema (recorded on 25 Nov 2026: before, these invocations were only described in words).
# Usage: run_prep.sh <manifest_dir> <dir with parts>...
# Afterwards: run_v3.sh, run_final_base.sh, run_val.sh, run_extra.sh, run_sens.sh, and independently run_cic.sh and run_servtrace.sh.
D=${IBE_DATA:-data}; A=$(cd "$(dirname "$0")" && pwd); M=$1; shift
mkdir -p $D/orig $D/unsw_raw $D/proto_raw $D/v2 $D/v3/homes $D/tmp_homes $D/cic/pcap
# ActiveBroker.pcap is not used by any analysis, so join.py may report it as missing.
python3 -I $A/join.py $M $D/orig "$@" > $D/join.log 2>&1
for f in all.zip doi_10_5061_dryad_w0vt4b94b__v20250829.zip protocols.zip devices.xlsx DATA2025v1_flows.parquet DATA2025v2_flows.parquet hvac_flows.parquet; do
  [ -s $D/orig/$f ] || { echo "FAIL join: $f"; exit 1; }
done
# UNSW 2016: the flow files and, from the protocol attributes, only what carries TLS SNI and HTTP Host
unzip -o -q $D/orig/doi_10_5061_dryad_w0vt4b94b__v20250829.zip flows.zip -d $D/unsw_raw || { echo FAIL unzip dryad; exit 1; }
unzip -o -q $D/unsw_raw/flows.zip -d $D/unsw_raw || { echo FAIL unzip flows; exit 1; }
unzip -o -q $D/orig/protocols.zip 'protocols/parameters/*/request/tlsattributes.csv' 'protocols/parameters/*/request/httpattributes.csv' -d $D/proto_raw \
  || { echo FAIL unzip protocols; exit 1; }
python3 -I $A/normalize3.py unsw $D/unsw_raw/flows $D/proto_raw/protocols/parameters $D/v2/unsw.parquet > $D/v2/normalize_unsw.log 2>&1 || { echo FAIL unsw; exit 1; }
python3 -I $A/normalize3.py homes $D/orig/all.zip $D/orig/devices.xlsx $D/v3/homes $D/tmp_homes > $D/v3/normalize_homes.log 2>&1 || { echo FAIL homes; exit 1; }
# CICIoMT2024: run_cic.sh expects the captures under cic/pcap with their original names
for f in $D/orig/*.pcap; do ln -sf $(cd $D/orig && pwd)/$(basename $f) $D/cic/pcap/$(basename $f); done
rm -f $D/cic/pcap/ActiveBroker.pcap
echo PREPDONE
