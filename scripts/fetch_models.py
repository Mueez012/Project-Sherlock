"""Download the model files listed in models/manifest.json into models/, checking each file's SHA-256.

    uv run python scripts/fetch_models.py          (Windows, macOS, Linux)

Model files are too big for git (GitHub refuses files over 100 MB), so they live on a GitHub Release. Each
manifest entry names one file:

    {"name": "ttp-v3.zip",
     "url": "https://github.com/Mueez012/Project-Sherlock/releases/download/models-v3/ttp-v3.zip",
     "sha256": "<64 hex characters>",
     "unzip": true}

A file already present with the right SHA-256 is skipped. A download whose SHA-256 differs is deleted and the
script exits with an error. With "unzip": true the zip is extracted into models/ after it checks out; a marker file
(<name>.unzipped) records a finished extraction, so an interrupted one is redone on the next run.

docker compose runs this script in its one-shot `models` service, into a Docker volume (--models /models
--manifest <the repo's manifest>), so the ttp container finds its bundle without any manual step.
"""

import argparse
import hashlib
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALLOWED_SCHEMES = ("https://", "file:")  # file: only for tests
READ_TIMEOUT_S = 60  # a stalled connection fails after this long instead of hanging; a slow one keeps going
PROGRESS_EVERY = 100 * 1024 * 1024


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def unzip(target: Path, digest: str, models: Path) -> None:
    marker = target.with_name(target.name + ".unzipped")
    if marker.is_file() and marker.read_text(encoding="utf-8").strip() == digest:
        return
    print(f"unzip   {target.name}", flush=True)
    with zipfile.ZipFile(target) as archive:
        archive.extractall(models)
    marker.write_text(digest + "\n", encoding="utf-8")


def fetch(entry: dict, models: Path) -> str:
    target = models / entry["name"]
    if target.is_file() and sha256(target) == entry["sha256"]:
        if entry.get("unzip"):
            unzip(target, entry["sha256"], models)
        return f"ok      {entry['name']} (already here)"
    if not entry["url"].startswith(ALLOWED_SCHEMES):
        raise ValueError(f"{entry['name']}: only https URLs are allowed")
    part = target.with_name(target.name + ".part")
    print(f"download {entry['name']} from {entry['url']}", flush=True)
    done = 0
    with urllib.request.urlopen(entry["url"], timeout=READ_TIMEOUT_S) as response, open(part, "wb") as out:  # noqa: S310 (scheme checked)
        total = int(response.headers.get("Content-Length") or 0)
        while block := response.read(1 << 20):
            out.write(block)
            if (done + len(block)) // PROGRESS_EVERY > done // PROGRESS_EVERY:
                print(f"         {(done + len(block)) >> 20} MB of {total >> 20 or '?'} MB", flush=True)
            done += len(block)
    digest = sha256(part)
    if digest != entry["sha256"]:
        part.unlink()
        raise ValueError(f"{entry['name']}: SHA-256 is {digest}, the manifest says {entry['sha256']}")
    part.replace(target)
    if entry.get("unzip"):
        unzip(target, digest, models)
    return f"fetched {entry['name']}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--models", type=Path, default=ROOT / "models", help="the models/ folder (default: the repo's)")
    ap.add_argument("--manifest", type=Path, help="the manifest (default: manifest.json in the models folder)")
    a = ap.parse_args(argv)
    manifest = json.loads((a.manifest or a.models / "manifest.json").read_text(encoding="utf-8"))
    if not manifest["files"]:
        print("models/manifest.json lists no files yet")
        return 0
    try:
        for entry in manifest["files"]:
            print(fetch(entry, a.models), flush=True)
    except (OSError, ValueError) as e:
        print(f"FAILED  {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
