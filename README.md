# ThreatMAMBA

[![ci](https://github.com/Mueez012/Project-Sherlock/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/Mueez012/Project-Sherlock/actions/workflows/ci.yml)

Reproduction of *ThreatMAMBA: Achieving High-Robustness Cyber Threat Attribution During the Evolution of Attacks*
(IEEE TIFS 2026). Paste a CTI report into the web interface and get its ATT&CK techniques, its indicators of
compromise and, once the classifier is trained, the likely threat actor.

| Module | Folder | Owner | Status |
|---|---|---|---|
| Datasets (cleaned D1 and D2) | `datasets/` | graph lead | committed, checked in CI |
| IOC extraction + IOCHunter | `src/threatmamba/ioc/`, `src/threatmamba/clients/ioc.py` | IOC teammate | regex stub; client for the IOC-hunter service ready |
| TTP Extractor | `src/threatmamba/ttp/`, `src/threatmamba/clients/ttp.py`, `services/ttp/` | TTP teammate | keyword stub; the trained model runs in the `ttp` container |
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

### How a report is read

A report comes in as pasted text (`POST /api/analyze`) or as a file (`POST /api/analyze/file`, up to 20 MB): PDF,
DOCX, HTML, Markdown, TXT or a STIX 2.1 bundle. `src/threatmamba/documents.py` turns a file into text with one
paragraph per line (wrapped PDF lines joined, page headers and footers removed, pages remembered); a PDF without a
text layer is refused, as there is no OCR. For a STIX bundle, the ATT&CK ids it declares are never shown to the model.

`src/threatmamba/text.py` then cuts the text once, the paper's single "sentence cutting" step. Each line is a
paragraph (a wrapped sentence is joined back); NLTK punkt, pinned with its English data stored in the repo, splits
paragraphs into sentences, never inside an indicator. Only real sentences become the timeline: headings, label lines,
indicator lists and pieces under four words are left out. TTP extraction runs on the timeline sentences. IOC
extraction reads the whole report, and an indicator found outside a sentence (for example in an indicator list)
belongs to the nearest sentence before it. Every answer lists each sentence's position in the text, and its page
for a PDF.

### The datasets

The cleaned datasets are committed and are the source of truth; nothing rebuilds them. D2's `sentences` are exactly
what the splitter above produces, and CI checks it.

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
`cd datasets && sha256sum d1_model_ready/* d2_model_ready/* > SHA256SUMS`. After a change to the splitter, re-cut
D2's sentences first (nothing else in D2 changes): `uv run python datasets/scripts/resplit_d2.py`.

### Model files

Trained models are too big for git, so they are attached to a GitHub Release and listed in `models/manifest.json`
(name, download URL, SHA-256). docker compose downloads them by itself (see below). To run the TTP service outside
Docker, download them into `models/` with:

```bash
uv run python scripts/fetch_models.py
```

It skips files that are already present and correct, and stops with an error if a download's SHA-256 does not
match the manifest. Add an entry to the manifest whenever a new model is released.

### The container

There are four containers. `app` is the hub: the root `Dockerfile` builds it in two stages, the first installing
the locked dependencies with uv, the second copying only the result into a slim Python image that runs as a non-root
user and reports its health at `/health`. `web` is the website: `frontend/Dockerfile` builds the Next.js app in
standalone mode on `node:22-slim`, with the hub's address (`http://app:8000`) fixed at build time.

`ttp` builds the trained TTP model service from `services/ttp/Dockerfile` and runs it on CPU, so the stack runs on
any machine with Docker. The model bundle is not in the image: on the first start the one-shot `models` service
downloads it from the GitHub Release (about 1.4 GB, SHA-256 checked) into the `ttp-models` volume and exits, and
`ttp` starts after it; later starts reuse the volume. On a machine with an NVIDIA GPU and the NVIDIA Container
Toolkit, add `-f docker-compose.gpu.yml` (below) for the same model on the GPU, which is faster on long reports. The
hub calls it at `http://ttp:8001` when `TM_TTP_MODE=real` (set in `.env`; the compose default is stub, which is what
CI runs). Like `ioc`, the hub does not wait for it: until it is healthy, `/health` reports it as down and real-mode
analyses answer 503.

`ioc` builds IOC Hunter from `services/ioc/Dockerfile`, including its extraction dependencies and Chromium for
provider lookups. The hub calls it at `http://ioc:8002` when `TM_IOC_MODE=real` (set in `.env`; the compose default
is stub, which is what CI runs). The hub does not wait for `ioc`: until it is healthy, `/health` reports it as down
and real-mode analyses answer 503. The website waits for the hub. Saved investigations and lookup evidence are
stored in the persistent `ioc-data` volume. Optional `OTX_API_KEY` and `VT_API_KEY` values are passed at runtime.

Saved IOC investigations (pick an IOC and a lookup method by hand, run it, grow the IOC graph, resume, export) are
served by IOC-hunter and reached through the hub at `/api/investigations`; the hub forwards each request unchanged.
The reference is `services/ioc/docs/api/`. IOC-hunter's terminal workflow uses the same saved investigations when
run inside the container, for example `docker compose exec ioc ioc-hunter runs`. On the website's result page,
"Investigate these indicators" starts an investigation from the analysed text and opens it in place (graph,
lookups, evidence, finish, JSON download); `/investigations` lists and reopens saved ones. A lookup can take minutes,
so the hub waits up to `TM_IOC_INVESTIGATION_TIMEOUT_S` (default 600 s) on these routes.

Settings (modes, ports, the emails-and-CVEs switch) live in `.env`: copy `.env.example` to `.env` and edit it;
compose reads it automatically and git ignores it.

```bash
docker compose up -d --build                                           # website http://localhost:3000, hub :8000
docker compose -f docker-compose.yml -f docker-compose.gpu.yml up -d --build   # same, TTP on an NVIDIA GPU
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
5. From then on, `develop` takes direct pushes; `QA` and `main` take pull requests.

The Terraform adopts the existing repo through an `import` block. Keep `terraform.tfstate` (git-ignored) on
your machine; if it is lost, `terraform apply` simply imports the repo again.

## How the team works

Every task, three steps:

```bash
git switch develop && git pull                      # 1. start from the latest code
# 2. write code (and, ideally, a test in tests/unit/)
git add -A && git commit -m "feat(ioc): what you did" && git push   # 3. send it
```

`develop` takes direct pushes, so there is no pull request. The commit hooks check formatting, lint and the message,
and the push hook runs the fast unit tests. CI then runs on `develop`; if it fails you get an email: fix the problem
and push again. Messages start with `feat:`, `fix:`, `test:`, `docs:` or `chore:` (a scope like `feat(ttp):` is
optional).

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
