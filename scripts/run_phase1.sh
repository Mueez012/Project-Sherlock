#!/usr/bin/env bash
# Phase 1 end-to-end: build -> verify (hard gate) -> package -> checksum check -> audit of all 62 numbers.
set -euo pipefail
RAW=$(realpath "${1:-./raw}")
WORK=$(realpath -m "${2:-./phase1_out}")
PY=${PYTHON:-python3}
mkdir -p "$WORK"
$PY -m threatmamba.data.build_threatmamba_base --raw "$RAW" --out "$WORK/base" | tee "$WORK/build.log"
$PY -m threatmamba.data.verify_base --base "$WORK/base" --contrib "$RAW/TTP_Group_Contribution.csv" | tee "$WORK/verify.log"
$PY -m threatmamba.data.make_handoff --base "$WORK/base" --out "$WORK/handoff"
( cd "$WORK/handoff" && $PY -c "import json,hashlib,sys;m=json.load(open('manifest.json'));bad=[f for f,h in m['sha256'].items() if hashlib.sha256(open(f,'rb').read()).hexdigest()!=h];print('checksums OK' if not bad else bad);sys.exit(bool(bad))" )
$PY -m threatmamba.data.audit_numbers --raw "$RAW" --handoff "$WORK/handoff" | tee "$WORK/audit.log"
