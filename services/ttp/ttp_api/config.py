"""API settings. Every field can be set with an environment variable TTP_API_<NAME>,
e.g. TTP_API_MAX_UPLOAD_MB=50 or TTP_API_CORS_ORIGINS='["http://localhost:3000"]'."""
from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TTP_API_", env_file=".env", extra="ignore")

    bundle_dir: Path = ROOT / "models" / "ttp-v2"   # final model: 2-model fine-tuned ensemble
    catalog_path: Path = ROOT / "data" / "attack" / "catalog-v14.json"
    device: str = "cpu"                       # TTP_API_DEVICE=cuda when the GPU is not busy training
    torch_threads: int | None = None          # None = all CPU cores
    batch_size: int = 32
    load_model: bool = True                   # tests inject a fake predictor instead

    max_upload_mb: float = 20.0
    max_text_chars: int = 2_000_000
    max_sentences: int = 3000
    queue_limit: int = 10                     # queued + running jobs before 429
    job_timeout_s: float = 600.0
    keep_jobs: int = 200                      # oldest finished jobs are dropped after this
    job_store: Literal["memory", "sqlite"] = "sqlite"     # survives restarts; "memory" for tests
    sqlite_path: Path = ROOT / "reports" / "api_jobs.sqlite3"
    tmp_dir: Path | None = None               # None = system temp folder
    cors_origins: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    @property
    def max_upload_bytes(self) -> int:
        return int(self.max_upload_mb * 1024 * 1024)
