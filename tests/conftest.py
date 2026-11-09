"""Shared fixtures for the ``.msg`` conversion tests."""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from unittest.mock import patch

import pytest


@pytest.fixture(params=["not_installed", "fails"])
def no_msgconvert(request: pytest.FixtureRequest) -> Iterator[None]:
    """Make ``msgconvert`` unusable: absent, or installed but failing."""
    error: Exception = (
        FileNotFoundError()
        if request.param == "not_installed"
        else subprocess.CalledProcessError(1, "msgconvert")
    )
    with patch("mailsuite.utils.subprocess.check_call", side_effect=error):
        yield
