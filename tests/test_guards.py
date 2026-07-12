"""Guardrails: protected LB + protected policy are refused before any network call.
Dummy XC env lets XC() construct (no HTTP happens — the guard raises first)."""
import pytest

from vpcopilot import apply


def _env(monkeypatch):
    monkeypatch.setenv("XC_API_URL", "https://xc.example/api")
    monkeypatch.setenv("XC_API_TOKEN", "dummy")
    monkeypatch.setenv("XC_NAMESPACE", "test-ns")


def test_protected_lb_refused(monkeypatch):
    _env(monkeypatch)
    with pytest.raises(RuntimeError, match="protected LB"):
        apply.apply_service_policy("nimbus-www", "some-policy", "http://x", dry_run=False)


def test_malicious_user_protected_lb_refused(monkeypatch):
    _env(monkeypatch)
    with pytest.raises(RuntimeError, match="protected LB"):
        apply.apply_malicious_user("nimbus-www", dry_run=False)


def test_protected_policy_refused(monkeypatch, tmp_path):
    _env(monkeypatch)
    art = tmp_path / "sp.json"
    art.write_text('{"metadata":{"name":"nimbus-bizlogic-policy"},"spec":{"algo":"FIRST_MATCH"}}')
    with pytest.raises(RuntimeError, match="protected policy"):
        apply.apply_from_scan(str(art), "some-other-lb", "http://x", allow_protected=True)
