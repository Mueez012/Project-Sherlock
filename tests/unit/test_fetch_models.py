"""scripts/fetch_models.py against local files (file: URLs), so no network is used."""

import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "fetch_models.py"
spec = importlib.util.spec_from_file_location("fetch_models", SCRIPT)
fetch_models = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch_models)


def _setup(tmp_path, *, good_hash=True):
    release = tmp_path / "release"
    release.mkdir()
    zipped = release / "ttp-v3.zip"
    with zipfile.ZipFile(zipped, "w") as z:
        z.writestr("ttp-v3/config.json", "{}")
    digest = hashlib.sha256(zipped.read_bytes()).hexdigest() if good_hash else "0" * 64
    models = tmp_path / "models"
    models.mkdir()
    entry = {"name": "ttp-v3.zip", "url": zipped.as_uri(), "sha256": digest, "unzip": True}
    (models / "manifest.json").write_text(json.dumps({"files": [entry]}))
    return models


def test_downloads_checks_and_unzips(tmp_path, capsys):
    models = _setup(tmp_path)
    assert fetch_models.main(["--models", str(models)]) == 0
    assert (models / "ttp-v3" / "config.json").is_file()
    assert fetch_models.main(["--models", str(models)]) == 0
    assert "already here" in capsys.readouterr().out


def test_a_wrong_checksum_fails_and_leaves_nothing(tmp_path, capsys):
    models = _setup(tmp_path, good_hash=False)
    assert fetch_models.main(["--models", str(models)]) == 1
    assert "SHA-256 is" in capsys.readouterr().err
    assert not (models / "ttp-v3.zip").exists()
    assert not (models / "ttp-v3.zip.part").exists()


def test_an_empty_manifest_is_fine(tmp_path, capsys):
    (tmp_path / "manifest.json").write_text(json.dumps({"files": []}))
    assert fetch_models.main(["--models", str(tmp_path)]) == 0
    assert "lists no files yet" in capsys.readouterr().out
