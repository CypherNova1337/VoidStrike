"""Tests for the scope guard — the primary safety control."""

import pytest

from voidstrike.authorization import (
    AuthorizationError,
    Engagement,
    ScopeGuard,
    ScopeViolation,
)


def _guard(**kw):
    eng = Engagement(name="t", in_scope=kw.pop("in_scope", ["*.example.com"]),
                     out_of_scope=kw.pop("out_of_scope", []), **kw)
    g = ScopeGuard(eng, resolve_dns=False)
    g.grant_consent("tester")
    return g


def test_requires_consent():
    g = ScopeGuard(Engagement(name="t", in_scope=["example.com"]), resolve_dns=False)
    with pytest.raises(AuthorizationError):
        g.check("http://example.com/")


def test_in_scope_allowed():
    g = _guard()
    assert g.check("https://app.example.com/x") == "app.example.com"


def test_out_of_scope_rejected():
    g = _guard(in_scope=["*.example.com"], out_of_scope=["secret.example.com"])
    with pytest.raises(ScopeViolation):
        g.check("https://secret.example.com/")


def test_not_in_scope_rejected():
    g = _guard(in_scope=["example.com"])
    with pytest.raises(ScopeViolation):
        g.check("https://not-example.org/")


def test_empty_scope_rejected():
    g = _guard(in_scope=[])
    with pytest.raises(ScopeViolation):
        g.check("https://anything.com/")


def test_hard_blocklist():
    g = _guard(in_scope=["*.gov"])
    with pytest.raises(ScopeViolation):
        g.check("https://irs.gov/")


def test_expiry():
    eng = Engagement(name="t", in_scope=["example.com"], expires_at=1.0)
    g = ScopeGuard(eng, resolve_dns=False)
    g.grant_consent()
    with pytest.raises(AuthorizationError):
        g.check("https://example.com/")


def test_audit_log_records_decisions():
    g = _guard()
    g.check("https://app.example.com/")
    events = [d["event"] for d in g.audit_log]
    assert "consent" in events and "scope-check" in events
