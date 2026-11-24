#!/usr/bin/env bash
# Copyright 2026 Can Yazicioglu
# SPDX-License-Identifier: Apache-2.0
#
# The whole test run, from the top, in one go.
#
# It is repeated after the last change of the code, however small. Every number it prints is then compared
# with the number of the version before, and the work is not finished while a difference is unexplained.
#
#   1 lint            pyflakes, shellcheck, bash -n
#   2 unit tests      recorder and analysis side, on every Python given
#   3 scenarios.py    a capture made by hand with the answers written down beforehand
#   4 egress_block.py nothing leaves through a capture port
#   5 live_veth.py    two virtual capture ports, live Zeek, replay
#   6 e2e.py          a real benign capture as 30 identical days, through the analysis to the stopping rule
#   7 e2e.py          the same with a real scan
#   8 batch_size.py   memory and speed of the hourly job
#
# Usage: sudo recorder/tests/final.sh --benign benign.pcap --scan scan.pcap --work NEW_DIR
#             [--zeek /opt/zeek/bin/zeek] [--python python3] [--pythons "python3.11 python3.12 python3.13"]
#
# Needs root (virtual ports and the packet filter), zeek, tcpreplay, iproute2, nftables, gpg, shellcheck,
# and for every Python: pyflakes, duckdb, pandas, numpy, scipy, pyarrow. The captures are not in the
# repository (docs/data.md). Steps 3 to 8 run with --python, steps 1 and 2 with every one of --pythons.
# The output of each step is kept in NEW_DIR/logs. The run goes on after a failed step and says so at the end.
set -u

ZEEK=/opt/zeek/bin/zeek
PY=python3
PYTHONS="python3.11 python3.12 python3.13"
BENIGN="" SCAN="" WORK=""
while [ $# -gt 0 ]; do
    case "$1" in
        --benign) BENIGN=$2 ;;
        --scan) SCAN=$2 ;;
        --work) WORK=$2 ;;
        --zeek) ZEEK=$2 ;;
        --python) PY=$2 ;;
        --pythons) PYTHONS=$2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift 2 || { echo "an argument needs a value" >&2; exit 2; }
done
if [ -z "$BENIGN" ] || [ -z "$SCAN" ] || [ -z "$WORK" ]; then
    echo "usage: final.sh --benign benign.pcap --scan scan.pcap --work NEW_DIR [--zeek PATH] [--python PY] [--pythons \"PY PY\"]" >&2
    exit 2
fi
for f in "$BENIGN" "$SCAN" "$ZEEK"; do
    [ -e "$f" ] || { echo "not found: $f" >&2; exit 2; }
done
[ -e "$WORK" ] && { echo "$WORK exists, give a new directory" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "needs root (virtual capture ports, packet filter)" >&2; exit 2; }

BENIGN=$(readlink -f "$BENIGN") SCAN=$(readlink -f "$SCAN")
mkdir -p "$WORK/logs"
WORK=$(readlink -f "$WORK")
REPO=$(cd "$(dirname "$0")/../.." && pwd)
T=$REPO/recorder/tests
cd "$REPO" || exit 2

SUMMARY=()
FAILED=0
step() {    # step NAME COMMAND...: run, keep the output, note the result
    local name=$1 log rc t0=$SECONDS
    shift
    log=$WORK/logs/$name.log
    echo "==== $name"
    "$@" > "$log" 2>&1
    rc=$?
    tail -n 60 "$log"
    if [ $rc -eq 0 ]; then
        SUMMARY+=("PASS  $name  ($((SECONDS - t0)) s)")
    else
        SUMMARY+=("FAIL  $name  (exit $rc, see $log)")
        FAILED=1
    fi
}

lint() {
    local p rc=0
    for p in $PYTHONS; do
        "$p" -m pyflakes recorder analysis/adapt_recorder.py analysis/tests || rc=1
    done
    shellcheck recorder/install.sh recorder/tests/final.sh || rc=1
    bash -n recorder/install.sh || rc=1
    return $rc
}

{
    echo "commit $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)$(git -C "$REPO" diff --quiet HEAD 2>/dev/null || echo ' with uncommitted changes')"
    echo "recorder $(sed -n 's/^VERSION = "\(.*\)"/\1/p' recorder/ibe_recorder/pipeline.py)"
    "$ZEEK" --version
    for p in $PYTHONS $PY; do "$p" --version; done
    echo "cores $(nproc), memory $(awk '/MemTotal/ {printf "%.1f GB", $2 / 1048576}' /proc/meminfo)"
    sha256sum "$BENIGN" "$SCAN"
} 2>&1 | tee "$WORK/logs/00_versions.log"

step 01_lint lint
for p in $PYTHONS; do
    step "02_unit_recorder_$p" "$p" -W error -m unittest discover -s recorder/tests -p 'test_*.py'
    step "02_unit_analysis_$p" "$p" -W error -m unittest discover -s analysis/tests -p 'test_*.py'
done
step 03_scenarios "$PY" "$T/scenarios.py" --zeek "$ZEEK" --work "$WORK/scenarios"
step 04_egress_block "$PY" "$T/egress_block.py"
step 05_live "$PY" "$T/live_veth.py" --zeek "$ZEEK" --pcap "$BENIGN" --work "$WORK/live"
step 06_e2e_benign "$PY" "$T/e2e.py" --zeek "$ZEEK" --pcap "$BENIGN" --work "$WORK/e2e_benign"
step 07_e2e_scan "$PY" "$T/e2e.py" --zeek "$ZEEK" --pcap "$SCAN" --work "$WORK/e2e_scan"
step 08_batch_size "$PY" "$T/batch_size.py" --zeek "$ZEEK" --pcap "$BENIGN" --work "$WORK/batch"

echo
echo "==== summary"
printf '%s\n' "${SUMMARY[@]}" | tee "$WORK/logs/99_summary.log"
if [ $FAILED -ne 0 ]; then
    echo "NOT FINISHED: at least one step failed"
    exit 1
fi
echo "ALL STEPS PASSED. Now compare every number with the version before."
