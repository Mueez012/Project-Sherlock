#!/usr/bin/env bash
# Download the public ThreatMAMBA raw files at a pinned commit and verify them. Raw data is never committed.
set -euo pipefail
DEST=${1:-./raw}
COMMIT=504fc92f18cb939cc6dc4776c2887f147e69691c   # MuscleFish/ThreatMAMBA main, verified 11 Oct 2026
BASE="https://raw.githubusercontent.com/MuscleFish/ThreatMAMBA/$COMMIT"
mkdir -p "$DEST"
for f in CTI2TTPs.csv CTI2Attacker.csv TTP_Group_Contribution.csv; do
  [ -s "$DEST/$f" ] || curl -fsSL --retry 3 -o "$DEST/$f" "$BASE/$f"
done
( cd "$DEST" && sha256sum -c - <<'SUMS'
4df8ac94a0f4a8008a30d6e6afd8cee2a7f617d46c1a7c621c054d280a1cce90  CTI2TTPs.csv
1f596c71c6ea7f7cacde748adf1ba47e314cc85e84e094ea2b342fa1ceeea483  CTI2Attacker.csv
0b0a66efe0d293480dd6c27192f02bb521101888b2ad7a688a4ffacff271c5d4  TTP_Group_Contribution.csv
SUMS
)
