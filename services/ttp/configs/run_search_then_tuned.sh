#!/bin/bash
# Overnight follow-up (resumable), run after the frozen single-change queue:
#   1. Optuna search on split seed 0 (validation only)  -> configs/tuned.json
#   2. --preset tuned on split seeds 0, 1, 2
#   3. final report with the tuned family added (one test evaluation)
cd "$(dirname "$0")/.."
# (the frozen queue has already finished when this is started)

python -W ignore -m ttp_extraction.training.search --trials 20 --max-epochs 60 >> reports/logs/search.log 2>&1
python -m ttp_extraction.training.search --report >> reports/logs/search.log 2>&1

cat > configs/tuned_jobs.txt <<'EOF'
# Tuned frozen preset (configs/tuned.json, from the Optuna search), split seeds 0/1/2.
tuned_seed_0  --preset tuned --seed 0
tuned_seed_1  --preset tuned --seed 1
tuned_seed_2  --preset tuned --seed 2
EOF
python -m ttp_extraction.training.queue --jobs configs/tuned_jobs.txt --parallel 1

python - <<'EOF'
import json
p = "configs/final_families.json"
f = json.load(open(p))
f["tuned_preset_frozen"] = ["tuned_seed_0", "tuned_seed_1", "tuned_seed_2"]
json.dump(f, open(p, "w"), indent=2)
EOF
python -W ignore -m ttp_extraction.evaluation.final_report --families configs/final_families.json \
  --out reports/final_results_with_tuned.json >> reports/logs/final_report.log 2>&1
echo "overnight chain done"
