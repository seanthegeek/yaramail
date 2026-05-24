"""Tests for the ``yaramail`` CLI entry point."""

from __future__ import annotations

import json
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "tests"
SAMPLES = RULES_DIR / "samples"


def _invoke(
    *args: str,
    stdin: str | None = None,
    capsys: pytest.CaptureFixture[str] | None = None,
) -> tuple[int, str, str]:
    """Run the CLI in-process so coverage is recorded."""
    from yaramail._cli import _main

    argv = ["yaramail", *args]
    exit_code = 0
    with patch.object(sys, "argv", argv):
        if stdin is not None:
            with patch("yaramail._cli.stdin", StringIO(stdin)):
                try:
                    _main()
                except SystemExit as exc:
                    exit_code = int(exc.code or 0)
        else:
            try:
                _main()
            except SystemExit as exc:
                exit_code = int(exc.code or 0)
    assert capsys is not None
    out, err = capsys.readouterr()
    return exit_code, out, err


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    from yaramail import __version__

    # argparse's --version prints to stdout and exits 0
    code, out, _ = _invoke("--version", "dummy", capsys=capsys)
    assert code == 0
    assert __version__ in out


def test_scan_single_file_emits_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = SAMPLES / "safe" / "workday.eml"
    output = tmp_path / "result.json"
    code, _, _ = _invoke(
        str(sample),
        "--rules",
        str(RULES_DIR),
        "--output",
        str(output),
        "-o",
        capsys=capsys,
    )
    assert code == 0
    data = json.loads(output.read_text())
    assert str(sample) in data


def test_scan_glob_with_no_matches_exits_nonzero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _, _ = _invoke(str(tmp_path / "does-not-exist-*.eml"), capsys=capsys)
    assert code != 0


def test_test_mode_runs_all_samples(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = _invoke(
        "-t",
        "-o",
        str(SAMPLES),
        "--rules",
        str(RULES_DIR),
        capsys=capsys,
    )
    data = json.loads(out)
    assert data["total"] == data["passed"] + data["failed"]
    assert code == data["failed"]


def test_test_mode_rejects_non_directory(capsys: pytest.CaptureFixture[str]) -> None:
    sample = SAMPLES / "safe" / "workday.eml"
    code, _, _ = _invoke("-t", str(sample), "--rules", str(RULES_DIR), capsys=capsys)
    assert code != 0


@pytest.mark.parametrize(
    "missing_arg",
    [
        "--header-rules",
        "--body-rules",
        "--header-body-rules",
        "--attachment-rules",
        "--passwords",
        "--implicit-safe-domains",
    ],
)
def test_missing_rule_files_are_skipped_with_warning(
    missing_arg: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sample = SAMPLES / "safe" / "workday.eml"
    output = tmp_path / "out.json"
    code, _, err = _invoke(
        str(sample),
        "--rules",
        str(RULES_DIR),
        missing_arg,
        "definitely-not-a-real-file.txt",
        "--output",
        str(output),
        "-o",
        capsys=capsys,
    )
    assert code == 0
    assert "does not exist" in err


def test_scan_stdin(capsys: pytest.CaptureFixture[str]) -> None:
    sample = (SAMPLES / "safe" / "workday.eml").read_text()
    code, out, _ = _invoke(
        "-", "--rules", str(RULES_DIR), "-o", stdin=sample, capsys=capsys
    )
    assert code == 0
    data = json.loads(out)
    assert "verdict" in data


def test_scan_stdin_verbose(capsys: pytest.CaptureFixture[str]) -> None:
    sample = (SAMPLES / "safe" / "workday.eml").read_text()
    code, out, _ = _invoke(
        "-", "-v", "--rules", str(RULES_DIR), "-o", stdin=sample, capsys=capsys
    )
    assert code == 0
    data = json.loads(out)
    # Verbose includes the parsed email envelope, not just the yaramail block.
    assert "yaramail" in data
    assert "headers" in data or "subject" in data


def test_scan_verbose_with_single_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = SAMPLES / "safe" / "workday.eml"
    output = tmp_path / "out.json"
    code, _, _ = _invoke(
        str(sample),
        "-v",
        "--rules",
        str(RULES_DIR),
        "--output",
        str(output),
        "-o",
        capsys=capsys,
    )
    assert code == 0
    data = json.loads(output.read_text())
    payload = data[str(sample)]
    assert "yaramail" in payload


def test_scan_test_mode_verbose(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = _invoke(
        "-t",
        "-v",
        "-o",
        str(SAMPLES),
        "--rules",
        str(RULES_DIR),
        capsys=capsys,
    )
    data = json.loads(out)
    assert "total" in data
    assert code == data["failed"]


def test_scan_missing_file_logs_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Glob to an existing file plus a non-existent literal — argparse uses
    # the glob match, so we need a path that exists at glob time but fails to
    # open. Easier: create a directory matched by the glob.
    (tmp_path / "ghost.eml").write_text("garbage that is not parsable\n")
    code, _, err = _invoke(
        str(tmp_path / "ghost.eml"),
        "--rules",
        str(RULES_DIR),
        "-o",
        capsys=capsys,
    )
    # Output may be empty (exits -1) — we just want the error path exercised.
    assert "Failed to" in err or code != 0


def test_scan_corrupt_stdin_logs_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, _, err = _invoke(
        "-",
        "--rules",
        str(RULES_DIR),
        "-o",
        stdin="\x00\x00not an email\x00",
        capsys=capsys,
    )
    # The CLI logs and continues, returning -1 if no output was produced.
    assert "Failed to" in err or code != 0


def test_raw_headers_flag_strips_headers_string(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = SAMPLES / "safe" / "workday.eml"
    output = tmp_path / "out.json"
    code, _, _ = _invoke(
        str(sample),
        "-v",
        "-r",
        "--rules",
        str(RULES_DIR),
        "--output",
        str(output),
        "-o",
        capsys=capsys,
    )
    assert code == 0
    payload = json.loads(output.read_text())[str(sample)]
    # With raw headers requested, headers_string is dropped from the verbose
    # output and raw_headers is retained.
    assert "headers_string" not in payload
    assert "raw_headers" in payload


def test_raw_body_flag_strips_body_markdown(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = SAMPLES / "safe" / "workday.eml"
    output = tmp_path / "out.json"
    code, _, _ = _invoke(
        str(sample),
        "-v",
        "-b",
        "--rules",
        str(RULES_DIR),
        "--output",
        str(output),
        "-o",
        capsys=capsys,
    )
    assert code == 0
    payload = json.loads(output.read_text())[str(sample)]
    assert "body_markdown" not in payload
    assert "raw_body" in payload


def test_test_mode_reports_failures(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A sample whose verdict doesn't match its directory name is reported."""
    corpus = tmp_path / "corpus"
    misclassified = corpus / "phishing"
    misclassified.mkdir(parents=True)
    # Workday sample's natural verdict is "safe" (with the bundled rules);
    # placing it under phishing/ guarantees a verdict mismatch.
    (misclassified / "workday.eml").write_bytes(
        (SAMPLES / "safe" / "workday.eml").read_bytes()
    )
    # Non-.eml siblings should be skipped over.
    (misclassified / "README.txt").write_text("ignored")
    code, out, _ = _invoke(
        "-t",
        "-o",
        str(corpus),
        "--rules",
        str(RULES_DIR),
        capsys=capsys,
    )
    data = json.loads(out)
    assert data["failed"] == 1
    assert data["total"] == 1
    assert data["test_failures"][0]["expected"] == "phishing"
    assert code == 1


def test_test_mode_aborts_on_unparseable_sample(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """In test mode, a sample that can't be parsed is logged and aborts with 1."""
    corpus = tmp_path / "corpus"
    category = corpus / "safe"
    category.mkdir(parents=True)
    (category / "broken.eml").write_text("\x00\x00 not a parseable email\x00")
    code, _, err = _invoke(
        "-t",
        "-o",
        str(corpus),
        "--rules",
        str(RULES_DIR),
        capsys=capsys,
    )
    assert code == 1
    assert "broken.eml" in err


def test_unreadable_implicit_safe_domains_logs_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    for name in ("header.yar", "body.yar", "header_body.yar", "attachment.yar"):
        (rules / name).write_text("")
    # implicit_safe_domains points at a *directory*, which trips open() with
    # an IsADirectoryError → handler logs the failure but continues.
    domains_path = rules / "implicit_safe_domains.txt"
    domains_path.mkdir()
    sample = SAMPLES / "safe" / "workday.eml"
    output = tmp_path / "out.json"
    code, _, err = _invoke(
        str(sample),
        "--rules",
        str(rules),
        "--output",
        str(output),
        capsys=capsys,
    )
    assert code == 0
    assert "Error reading" in err


def test_output_to_unwritable_path_logs_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A --output path that can't be opened for writing is logged, not raised."""
    sample = SAMPLES / "safe" / "workday.eml"
    # A directory can't be opened with open(..., "w").
    output_dir = tmp_path / "out-is-a-dir"
    output_dir.mkdir()
    code, _, err = _invoke(
        str(sample),
        "--rules",
        str(RULES_DIR),
        "--output",
        str(output_dir),
        "-o",
        capsys=capsys,
    )
    assert "Error writing" in err


def test_invalid_rules_exits_nonzero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad_rules = tmp_path / "rules"
    bad_rules.mkdir()
    (bad_rules / "header.yar").write_text("this is not valid YARA")
    sample = SAMPLES / "safe" / "workday.eml"
    code, _, err = _invoke(str(sample), "--rules", str(bad_rules), capsys=capsys)
    assert code != 0
    assert "Failed to parse YARA rules" in err
