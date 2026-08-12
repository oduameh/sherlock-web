import pytest

from recon.validate import is_probably_email


@pytest.mark.parametrize("value", [
    "user@example.com",
    "first.last@sub.domain.co.uk",
    "user+tag@gmail.com",
    "a_b-c@example.io",
])
def test_accepts_valid_emails(value):
    assert is_probably_email(value) is True


@pytest.mark.parametrize("value", [
    "",
    "   ",
    "notanemail",
    "missing@tld",
    "@example.com",
    "user@",
    "user@@example.com",
    "user@.com",
    "user..name@example.com",
    "user@example.c",
    "spaces in@example.com",
])
def test_rejects_invalid_emails(value):
    assert is_probably_email(value) is False


def test_rejects_overlong_email():
    assert is_probably_email("a" * 250 + "@example.com") is False
