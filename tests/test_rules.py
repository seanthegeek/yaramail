"""Run the bundled YARA rules against the sample corpus.

Each `.eml` under ``tests/samples/<category>/`` should produce a verdict that
matches its parent directory name when scanned with the rules in ``tests/``.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from mailsuite.utils import parse_email

from yaramail import MailScanner

RULES_DIR = Path(__file__).parent
SAMPLES_DIR = RULES_DIR / "samples"


def _collect_samples() -> list[tuple[str, Path]]:
    samples = []
    for eml in SAMPLES_DIR.rglob("*.eml"):
        category = eml.parent.name
        samples.append((category, eml))
    return samples


def _load_implicit_safe_domains(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line for line in path.read_text().strip().splitlines() if line]


@pytest.fixture(scope="module")
def scanner() -> MailScanner:
    return MailScanner(
        header_rules=str(RULES_DIR / "header.yar"),
        body_rules=str(RULES_DIR / "body.yar"),
        header_body_rules=str(RULES_DIR / "header_body.yar"),
        attachment_rules=str(RULES_DIR / "attachment.yar"),
        implicit_safe_domains=_load_implicit_safe_domains(
            RULES_DIR / "implicit_safe_domains.txt"
        ),
        passwords=str(RULES_DIR / "passwords.txt"),
        use_authentication_results_original=True,
    )


@pytest.mark.parametrize(
    ("expected_verdict", "sample"),
    _collect_samples(),
    ids=lambda value: value.name if isinstance(value, Path) else value,
)
def test_sample_verdict(
    scanner: MailScanner, expected_verdict: str, sample: Path
) -> None:
    parsed = parse_email(sample.read_text())
    results = scanner.scan_email(parsed)
    assert results["verdict"] == expected_verdict
