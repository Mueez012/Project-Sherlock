#!/bin/bash
# GPU job chain (each step resumable; re-running this script continues):
#   1. fine-tuned SecureBERT on split seeds 1 and 2 (finetune_v2_seed_<s>)
#   2. a second fine-tuned model per split with another model seed, for 2-model
#      ensembles (finetune_v2b_seed_<s>: model seed 10+s, split seed s)
#   3. the frozen-encoder single-change queue
cd "$(dirname "$0")/.."
finished() { python -c "import json,sys; s=json.load(open('runs/$1/summary.json')); sys.exit(0 if s['stop_reason']!='in_progress' else 1)" 2>/dev/null; }
running() {    # is a python process training run $1 right now? (asks Windows)
  powershell -NoProfile -Command "if (Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object { \$_.CommandLine -like '*--run-name $1 *' -or \$_.CommandLine -like '*--run-name $1' }) { exit 0 } else { exit 1 }"
}

finetune() {   # name model_seed split_seed
  local name=$1
  finished $name && return
  while running $name; do sleep 30; done      # already started by an earlier chain
  finished $name && return
  local resume=""; [ -f "$HOME/ttp_cache/finetune_state/$name/last.pt" ] && resume="--resume"
  PYTHONUNBUFFERED=1 python -W ignore -m ttp_extraction.training.train_finetune \
    --csv ThreatMAMBA-main/CTI2TTPs.csv --seed $2 --split-seed $3 --run-name $name $resume \
    >> reports/logs/$name.log 2>&1
}

for s in 1 2; do finetune finetune_v2_seed_$s $s $s; done
for s in 0 1 2; do finetune finetune_v2b_seed_$s $((10 + s)) $s; done
python -m ttp_extraction.training.queue --jobs configs/single_change_jobs.txt --parallel 1
