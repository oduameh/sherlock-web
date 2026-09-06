"""scripts/lockcheck.py: the locks must cover requirements*.txt (D-3)."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("lockcheck", ROOT / "scripts" / "lockcheck.py")
lockcheck = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lockcheck)


def test_canonical_names():
    assert lockcheck.canonical("Sherlock_Project") == "sherlock-project"
    assert lockcheck.canonical("psycopg.binary") == "psycopg-binary"


def test_parse_requirements_reads_names_extras_pins_and_skips_includes():
    text = """
    # comment
    -r requirements.txt
    fastapi>=0.110
    psycopg[binary]>=3.1
    httpx==0.28.1   # pinned
    Pillow == 12.3.0
    scrapling[fetchers]>=0.4.14,<0.5
    """
    assert lockcheck.parse_requirements(text) == {
        "fastapi": None, "psycopg": None, "httpx": "0.28.1", "pillow": "12.3.0",
        "scrapling": None,
    }


def test_parse_lock_reads_pins_only():
    text = """
    anyio==4.9.0 \\
        --hash=sha256:abc
        # via httpx
    # pip==26.2.1 (unsafe)
    Fast-API==0.141.1 \\
    """
    assert lockcheck.parse_lock(text) == {"anyio": "4.9.0", "fast-api": "0.141.1"}


def test_drift_reports_missing_and_mismatched_pins():
    req = {"fastapi": None, "httpx": "0.28.1", "pillow": "12.3.0"}
    lock = {"fastapi": "0.141.1", "httpx": "0.27.0"}
    assert lockcheck.drift(req, lock, lock_name="L") == [
        "L: httpx is pinned to 0.28.1 but locked at 0.27.0",
        "L: pillow is required but not locked",
    ]
    assert lockcheck.drift(req, {**lock, "httpx": "0.28.1", "pillow": "12.3.0"}) == []


def test_check_flags_a_missing_lock(tmp_path):
    (tmp_path / "requirements.txt").write_text("httpx==0.28.1\n")
    problems = lockcheck.check(tmp_path)
    assert "requirements.lock: missing" in problems
    assert "requirements-ci.lock: missing" in problems


def test_the_repository_locks_cover_its_requirements():
    assert lockcheck.check(ROOT) == []


@pytest.mark.parametrize("lock", ["requirements.lock", "requirements-ci.lock"])
def test_every_lock_line_is_hashed(lock):
    """A pin without a hash makes pip refuse the whole file under
    --require-hashes; catch it here rather than in CI."""
    text = (ROOT / lock).read_text()
    pins = lockcheck.parse_lock(text)
    assert len(pins) > 50
    for line in text.splitlines():
        if lockcheck._PIN.match(line.strip()):
            assert line.rstrip().endswith("\\"), line     # continued by a --hash line
    assert text.count("--hash=sha256:") >= len(pins)
