# ThreatMAMBA

Reproduction of *ThreatMAMBA: Achieving High-Robustness Cyber Threat Attribution During the Evolution of Attacks*
(IEEE TIFS 2026). Paste a CTI report into the web interface and get its ATT&CK techniques, its indicators of
compromise and, once the classifier is trained, the likely threat actor.

| Module | Folder | Owner | Status |
|---|---|---|---|
| Phase 1 data preparation | `src/threatmamba/data/` | graph lead | done, verified in CI on the real data |
| IOC extraction + IOCHunter | `src/threatmamba/ioc/` | IOC teammate | regex baseline in place |
| TTP Extractor | `src/threatmamba/ttp/` | TTP teammate | keyword baseline in place |
| CSKG construction | `src/threatmamba/cskg/` | graph lead | next |
| Attribution (GAT + MAMBA) | `src/threatmamba/attribution/` | team | after CSKG |
| API + live interface | `src/threatmamba/api/`, `src/threatmamba/web/` | team | working |

Modules talk to each other only through the models in `src/threatmamba/contracts.py`.

## Run it

You need [uv](https://docs.astral.sh/uv/) for development and Docker for the container.

```bash
uv sync                                            # .venv with every dependency from uv.lock
uv run pre-commit install                          # local checks on commit and push
uv run uvicorn threatmamba.api.main:app --reload   # http://localhost:8000
uv run pytest                                      # unit tests
```

Phase 1 on the real data (downloads the public raw files at a pinned commit and checks their hashes):

```bash
bash scripts/fetch_raw.sh raw
PYTHON="uv run python" bash scripts/run_phase1.sh raw phase1_out
```

### The container

There is one container: the FastAPI service, which also serves the web page. The `Dockerfile` builds it in two
stages. The first installs the locked dependencies with uv; the second copies only the result into a slim Python
image that runs as a non-root user and reports its health at `/health`. `docker-compose.yml` runs it.

```bash
docker compose up --build                                          # build and run on http://localhost:8000
TM_IMAGE=ghcr.io/<owner>/threatmamba:latest docker compose up -d   # run a published release
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

```
feat/ioc-*, feat/ttp-*, feat/cskg-*  --PR-->  develop  --PR-->  QA  --PR-->  main  ->  release vX.Y.Z
```

- Branch from `develop` as `feat/<module>-<what>` and open a PR into `develop`. One teammate approves, and
  `ci-passed` must be green. Commit messages follow conventional commits (`feat:`, `fix:`, `test:`, `docs:`).
- To promote, open a PR `develop` -> `QA`, then `QA` -> `main`. `promotion-guard` rejects any other path.
- To release, bump `VERSION` on `develop` before promoting to `main`. A version that already exists is refused.

## What the pipeline does

| Stage | develop | QA | main |
|---|---|---|---|
| Lint: ruff, ruff security rules (Bandit), formatting, hadolint, actionlint | yes | yes | yes |
| Unit and contract tests, 60% coverage gate | fast | fast + slow | fast + slow |
| Phase 1 on the real data: build, 18 checks, checksums, 62-number audit | yes | yes | yes |
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
- Never commit data, checkpoints or keys. Checkpoints go in GitHub Release assets, listed in `models/manifest.json`.
