"""Test-session environment.

`app` runs its DB setup at import time, so the database path must be decided
before any test imports it. Every session gets a fresh temporary SQLite file;
the developer's real history.db — and their real Postgres, if DATABASE_URL is
set in the shell — are never touched by the suite.
"""

import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="sherlock-web-tests-")
os.environ["SHERLOCK_DB_PATH"] = os.path.join(_TMP, "history.db")
os.environ.pop("DATABASE_URL", None)          # never the developer's Postgres
os.environ.pop("APP_PASSWORD", None)          # never a Basic-auth gate in tests
os.environ["SHERLOCK_SITES_SOURCE"] = "bundled"   # deterministic, offline
os.environ["RECON_MAX_CONCURRENT_INVESTIGATIONS"] = "1"   # makes "queued" testable
# TestClient sends "Host: testserver"; the loopback-only allow-list must admit it.
os.environ["APP_ALLOWED_HOSTS"] = "localhost,127.0.0.1,::1,testserver"
