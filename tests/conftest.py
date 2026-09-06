"""Test-session environment.

`app` runs its DB setup at import time, so the database path must be decided
before any test imports it. Every session gets a fresh temporary SQLite file;
the developer's real history.db — and their real Postgres, if DATABASE_URL is
set in the shell — are never touched by the suite.

Shared network stubs (G2): every fetcher we own goes through
``recon.retrieval.fetch`` on an SSRF-guarded ``recon.safeweb`` client, so a
network-free test needs two things — the guard's resolver answering a public
address (``public_dns``) and a client whose transport is an
``httpx.MockTransport`` (``mock_client``). Tests import ``mock_client`` from
here (``from conftest import mock_client``).
"""

import os
import tempfile

import httpx
import pytest

_TMP = tempfile.mkdtemp(prefix="sherlock-web-tests-")
os.environ["SHERLOCK_DB_PATH"] = os.path.join(_TMP, "history.db")
os.environ.pop("DATABASE_URL", None)          # never the developer's Postgres
os.environ.pop("APP_PASSWORD", None)          # never a Basic-auth gate in tests
os.environ["SHERLOCK_SITES_SOURCE"] = "bundled"   # deterministic, offline
os.environ["RECON_MAX_CONCURRENT_INVESTIGATIONS"] = "1"   # makes "queued" testable
# TestClient sends "Host: testserver"; the loopback-only allow-list must admit it.
os.environ["APP_ALLOWED_HOSTS"] = "localhost,127.0.0.1,::1,testserver"


@pytest.fixture
def public_dns(monkeypatch):
    """Hostnames resolve to a public address so the SSRF guard passes offline."""
    from recon import safeweb

    async def fake_resolve(host, port):
        return ["93.184.216.34"]
    monkeypatch.setattr(safeweb, "_resolve", fake_resolve)


def _real_async_client():
    """The unpatched ``safeweb.async_client``, captured once at import so a
    factory built by :func:`mock_client` never calls a patched attribute (every
    ``recon.*`` module shares the one ``safeweb`` module object, so patching
    ``enrich.safeweb.async_client`` patches it for all of them)."""
    from recon import safeweb
    return safeweb.async_client


_REAL_ASYNC_CLIENT = _real_async_client()


def mock_client(handler, calls=None):
    """A ``safeweb.async_client``-compatible factory whose transport is
    ``httpx.MockTransport(handler)``. Every request is appended to ``calls``
    when given. Use with ``monkeypatch.setattr(<module>.safeweb,
    "async_client", mock_client(handler, calls))`` and the ``public_dns``
    fixture. Note the patch is process-wide (one ``safeweb`` module), so one
    handler serves every fetcher for the duration of the test."""

    def counting(request):
        if calls is not None:
            calls.append(request)
        return handler(request)

    def factory(**kw):
        kw.pop("transport", None)
        return _REAL_ASYNC_CLIENT(transport=httpx.MockTransport(counting), **kw)
    return factory
