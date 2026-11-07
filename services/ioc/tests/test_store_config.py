"""All entry points resolve the same application collection."""
from pathlib import Path

from ioc_hunter.config import PROJECT_DIRECTORY, resolve_store_directory


def test_default_and_environment_precedence(tmp_path, monkeypatch):
    monkeypatch.delenv("IOC_HUNTER_STORE", raising=False)
    assert resolve_store_directory() == PROJECT_DIRECTORY / "output" / "investigations"
    monkeypatch.setenv("IOC_HUNTER_STORE", str(tmp_path / "configured"))
    assert resolve_store_directory() == tmp_path / "configured"
    assert resolve_store_directory(tmp_path / "explicit") == tmp_path / "explicit"


def test_relative_environment_uses_service_root_but_explicit_uses_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("IOC_HUNTER_STORE", "output/custom")
    assert resolve_store_directory() == (PROJECT_DIRECTORY / "output" / "custom").resolve()
    assert resolve_store_directory(Path("explicit")) == tmp_path / "explicit"
