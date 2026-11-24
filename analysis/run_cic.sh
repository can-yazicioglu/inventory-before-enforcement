#!/bin/bash
# CICIoMT2024: packet captures to flow records, then the evaluation of device states and reconnaissance.
# The captures lie under $IBE_DATA/cic/pcap with their original names (Idle.pcap, Active.pcap, Benign_train.pcap, Benign_test.pcap,
# seven *_Power.pcap, sixteen *_LAN_*.pcap, four Recon-*_test.pcap). cic_eval.py tells the conditions apart by these names.
D=${IBE_DATA:-data}/cic; A=$(cd "$(dirname "$0")" && pwd); mkdir -p $D/out
python3 -I $A/pcap2flows.py $D/power.parquet $D/pcap/*_Power.pcap > $D/out/power.log 2>&1 || { echo FAIL power; exit 1; }
python3 -I $A/pcap2flows.py $D/recon.parquet $D/pcap/Recon-*.pcap > $D/out/recon.log 2>&1 || { echo FAIL recon; exit 1; }
python3 -I $A/pcap2flows.py $D/inter.parquet $D/pcap/*_LAN_*.pcap > $D/out/inter.log 2>&1 || { echo FAIL inter; exit 1; }
python3 -I $A/pcap2flows.py $D/benign.parquet $D/pcap/Idle.pcap $D/pcap/Active.pcap $D/pcap/Benign_train.pcap $D/pcap/Benign_test.pcap > $D/out/benign.log 2>&1 || { echo FAIL benign; exit 1; }
python3 -I -W ignore $A/cic_eval.py $D $D/out > $D/out/cic_eval.log 2>&1 || { echo FAIL cic_eval; exit 1; }
echo CICDONE
