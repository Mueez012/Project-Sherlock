"""Offline identity adapters and ownership, independent of HTTP and workflow."""

import traceback

import pytest

from ioc_hunter.access import (
    AccessDenied,
    AccessError,
    AuthenticationNotConfigured,
    AuthenticationRequired,
    require_owner,
    resolve_actor,
    resolve_bearer,
    trusted_cli_actor,
)


@pytest.fixture(autouse=True)
def isolated_access_environment(monkeypatch):
    for name in ("IOC_HUNTER_LOCAL_ACTOR", "IOC_HUNTER_ACTOR_ID"):
        monkeypatch.delenv(name, raising=False)


def test_http_identity_is_unconfigured_by_default_even_with_claimed_actor(monkeypatch):
    monkeypatch.setenv("IOC_HUNTER_ACTOR_ID", "claimed-owner")
    for header in (None, "Bearer claimed-owner"):
        with pytest.raises(AuthenticationNotConfigured) as caught:
            resolve_actor(header)
        assert caught.value.status_code == 503
        assert isinstance(caught.value, AccessError)


def test_local_http_mode_requires_deliberate_configuration_and_no_authorization(monkeypatch):
    monkeypatch.setenv("IOC_HUNTER_LOCAL_ACTOR", "development-owner")
    assert resolve_actor() == "development-owner"
    for header in ("", "Bearer development-owner", "Basic unexpected"):
        with pytest.raises(AuthenticationRequired) as caught:
            resolve_actor(header)
        assert caught.value.status_code == 401


@pytest.mark.parametrize("actor", ["", " ", " actor", "actor\n"])
def test_invalid_local_actor_does_not_enable_http_access(actor, monkeypatch):
    monkeypatch.setenv("IOC_HUNTER_LOCAL_ACTOR", actor)
    with pytest.raises(AuthenticationNotConfigured):
        resolve_actor()


def test_local_actor_is_read_from_runtime_environment(monkeypatch):
    monkeypatch.setenv("IOC_HUNTER_LOCAL_ACTOR", "development-before")
    assert resolve_actor() == "development-before"
    monkeypatch.setenv("IOC_HUNTER_LOCAL_ACTOR", "development-after")
    assert resolve_actor() == "development-after"
    monkeypatch.delenv("IOC_HUNTER_LOCAL_ACTOR")
    with pytest.raises(AuthenticationNotConfigured):
        resolve_actor()


def test_injected_provider_receives_credentials_and_supplies_verified_actor(monkeypatch):
    monkeypatch.setenv("IOC_HUNTER_LOCAL_ACTOR", "development-owner")

    class FakeIdentityProvider:
        def __init__(self):
            self.headers = []

        def resolve(self, authorization):
            self.headers.append(authorization)
            return "externally-verified-owner"

    provider = FakeIdentityProvider()
    assert resolve_actor("Bearer synthetic-provider-credential", provider=provider) == "externally-verified-owner"
    assert provider.headers == ["Bearer synthetic-provider-credential"]


def test_callable_adapter_and_compatibility_alias_delegate_to_provider():
    received = []

    def provider(authorization):
        received.append(authorization)
        return "verified-owner"

    assert resolve_actor(None, provider=provider) == "verified-owner"
    assert resolve_bearer("Bearer synthetic", provider=provider) == "verified-owner"
    assert received == [None, "Bearer synthetic"]


@pytest.mark.parametrize("actor", [None, "", " ", " actor", "actor\n", 7])
def test_unverified_provider_result_is_rejected_without_local_fallback(actor, monkeypatch):
    monkeypatch.setenv("IOC_HUNTER_LOCAL_ACTOR", "development-owner")
    with pytest.raises(AuthenticationRequired):
        resolve_actor(provider=lambda authorization: actor)


def test_provider_access_failures_propagate_without_local_fallback(monkeypatch):
    monkeypatch.setenv("IOC_HUNTER_LOCAL_ACTOR", "development-owner")

    def provider(authorization):
        raise AuthenticationRequired()

    with pytest.raises(AuthenticationRequired):
        resolve_actor(provider=provider)


def test_unexpected_provider_failure_is_generic_and_does_not_expose_credentials(monkeypatch):
    monkeypatch.setenv("IOC_HUNTER_LOCAL_ACTOR", "development-owner")

    def provider(authorization):
        raise RuntimeError("synthetic-private-provider-detail")

    with pytest.raises(AuthenticationNotConfigured) as caught:
        resolve_actor("Bearer synthetic-credential", provider=provider)
    assert caught.value.status_code == 503
    rendered = "".join(traceback.format_exception(caught.value))
    assert "synthetic-private-provider-detail" not in rendered
    assert "synthetic-credential" not in str(caught.value)


def test_invalid_provider_configuration_fails_closed():
    with pytest.raises(AuthenticationNotConfigured):
        resolve_actor(provider=object())


def test_trusted_cli_actor_is_separate_and_retains_legacy_local_identity(monkeypatch):
    assert trusted_cli_actor() == "local"
    monkeypatch.setenv("IOC_HUNTER_LOCAL_ACTOR", "http-development-owner")
    assert trusted_cli_actor() == "local"
    monkeypatch.setenv("IOC_HUNTER_ACTOR_ID", "terminal-owner")
    assert trusted_cli_actor() == "terminal-owner"
    monkeypatch.setenv("IOC_HUNTER_ACTOR_ID", " ")
    with pytest.raises(ValueError):
        trusted_cli_actor()


@pytest.mark.parametrize("actor,owner", [
    ("alice", "bob"), ("Alice", "alice"), ("", ""), (None, None),
    (" owner", " owner"), ("a\n", "a\n"),
])
def test_ownership_requires_valid_exact_principal(actor, owner):
    with pytest.raises(AccessDenied) as caught:
        require_owner(actor, owner)
    assert caught.value.status_code == 403


def test_matching_owner_is_authorized_without_credentials_in_ownership_layer():
    assert require_owner("analyst-a", "analyst-a") is None

