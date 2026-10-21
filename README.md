# ThreatMAMBA

[![ci](https://github.com/Mueez012/Project-Sherlock/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/Mueez012/Project-Sherlock/actions/workflows/ci.yml)

Reproduction of *ThreatMAMBA: Achieving High-Robustness Cyber Threat Attribution During the Evolution of Attacks*
(IEEE TIFS 2026). Paste a CTI report into the web interface and get its ATT&CK techniques, its indicators of
compromise and, once the classifier is trained, the likely threat actor.

| Module | Folder | Owner | Status |
|---|---|---|---|
| Datasets (cleaned D1 and D2) | `datasets/` | graph lead | committed, checked in CI |
| IOC extraction + IOCHunter | `src/threatmamba/ioc/`, `src/threatmamba/clients/ioc.py` | IOC teammate | regex stub; client for the IOC-hunter service ready |
| TTP Extractor | `src/threatmamba/ttp/` | TTP teammate | keyword baseline in place |
| CSKG construction | `src/threatmamba/cskg/` | graph lead | next |
| Attribution (GAT + MAMBA) | `src/threatmamba/attribution/` | team | after CSKG |
| API (the hub) + test page | `src/threatmamba/api/`, `src/threatmamba/web/` | team | working |
| Website | `frontend/` | graph lead | working: one call to the hub, results and indicators |

Modules talk to each other only through the models in `src/threatmamba/contracts.py`.

## Run it

You need [uv](https://docs.astral.sh/uv/) for development and Docker for the container.

```bash
uv sync                                            # .venv with every dependency from uv.lock
uv run pre-commit install                          # local checks on commit and push
uv run uvicorn threatmamba.api.main:app --reload   # http://localhost:8000
uv run pytest                                      # unit tests
```

The website (Node 22) talks only to the hub. Its hub address is `API_ORIGIN` (default `http://127.0.0.1:8000`);
on a machine where port 8000 is taken, run the hub with `--port 8080` and put `API_ORIGIN=http://127.0.0.1:8080`
in `frontend/.env.local`.

```bash
cd frontend
npm ci                                             # dependencies from package-lock.json
npm run dev                                        # http://localhost:3000
npm run lint && npm test && npm run contrast       # what the CI web job runs, plus npm run build
```

### The datasets

The cleaned datasets are committed and are the source of truth; nothing rebuilds them.

```
datasets/
├── d1_model_ready/   train.csv, valid.csv, test.csv, labels.json   (sentences, 14 tactics + 189 techniques)
├── d2_model_ready/   train.jsonl, valid.jsonl, test.jsonl, groups.json   (reports, 25 groups)
├── scripts/          clean_d1.py, clean_d2.py: how they were made from the paper's raw CSVs
└── SHA256SUMS        checksums of every file above
```

Check them (CI runs the same command):

```bash
uv run python -m threatmamba.data.verify_datasets datasets
```

To change a dataset on purpose, commit the new files and `SHA256SUMS` together:
`cd datasets && sha256sum d1_model_ready/* d2_model_ready/* > SHA256SUMS`.

### The container

There are two containers. `app` is the hub: the root `Dockerfile` builds it in two stages, the first installing
the locked dependencies with uv, the second copying only the result into a slim Python image that runs as a non-root
user and reports its health at `/health`. `web` is the website: `frontend/Dockerfile` builds the Next.js app in
standalone mode on `node:22-slim`, with the hub's address (`http://app:8000`) fixed at build time.

```bash
docker compose up -d --build                                           # website http://localhost:3000, hub :8000
TM_PORT=8080 docker compose up -d --build                              # if port 8000 is taken on this machine
TM_IMAGE=ghcr.io/<owner>/threatmamba:latest docker compose up -d app   # run a published hub release
docker compose down
```

## Set up GitHub (once)

The repository settings (default branch, branch rules, environments, collaborators, Actions permissions) are
Terraform in `infra/github/`; everything else is files in this repo. Order matters:

1. Push a first commit to `develop`, `QA` and `main` (no workflows yet, so nothing runs).
2. Push this code to `develop`; wait for the `ci` run to go green.
3. `cd infra/github && cp team.tfvars.example team.tfvars` (fill it in), then
   `export GITHUB_TOKEN=$(gh auth token) && terraform init && terraform apply -var-file=team.tfvars`.
4. Set the GHCR package visibility to Public once.
5. From then on, every change goes through a PR.

The Terraform adopts the existing repo through an `import` block. Keep `terraform.tfstate` (git-ignored) on
your machine; if it is lost, `terraform apply` simply imports the repo again.

## How the team works

Every task, three steps:

```bash
git switch develop && git pull                      # 1. start from the latest code
# 2. write code (and, ideally, a test in tests/unit/)
bash scripts/ship.sh "feat(ioc): what you did"      # 3. send it
```

`ship.sh` commits, pushes, opens a pull request into `develop` and sets it to merge by itself once CI is green.
No approval is needed for `develop`. If CI fails you get an email: fix the problem and run step 3 again.
Messages start with `feat:`, `fix:`, `test:`, `docs:` or `chore:` (a scope like `feat(ttp):` is optional).

Promotions (`develop` -> `QA` -> `main`) and releases are done by the repo owner and need one teammate's approval.
To release, bump `VERSION` on `develop` before promoting to `main`.

## What the pipeline does

| Stage | develop | QA | main |
|---|---|---|---|
| Lint: ruff, ruff security rules (Bandit), formatting, hadolint, actionlint | yes | yes | yes |
| Unit and contract tests, 40% coverage gate | fast | fast + slow | fast + slow |
| Datasets: checksums, shapes, labels, splits, sentence splitting | yes | yes | yes |
| SAST: CodeQL | yes | yes | yes |
| Trivy: dependencies, secrets, Dockerfile misconfiguration | yes | yes | yes |
| Container: build, Trivy image scan, start with health check, system tests | yes | yes | yes |
| Delivery to GHCR (Deployments tab: develop, qa, release) | `develop` | `qa` | `vX.Y.Z`, `latest` |
| GitHub Release with run instructions | | | yes |

All jobs feed one check, `ci-passed`, which the branch rules require. PRs run everything except delivery.

## Adding your module

Implement the protocol in your module's `base.py` (`IOCExtractor`, `HuntingSource`, `TTPExtractor`), keep the
baseline as the stub-mode fallback, and add tests under `tests/unit/`. To keep CI green:

- No network in unit tests. IOCHunter's external services sit behind `HuntingSource`; record real responses once
  (for example with `pytest-recording`) and replay them in tests. No API keys in CI.
- No model downloads in CI. Use a small fake encoder in tests and mark long tests `@pytest.mark.slow` (they run
  on QA and main only).
- When torch is needed, use the CPU-only index commented in `pyproject.toml`, and keep a pure-PyTorch path for
  Mamba (the official kernels need CUDA).
- Never commit raw data, checkpoints or keys. Checkpoints go in GitHub Release assets, listed in `models/manifest.json`.
  The cleaned datasets in `datasets/` are the one exception; change them only together with `datasets/SHA256SUMS`.
