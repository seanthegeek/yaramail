"""Unit tests for module-level helpers in :mod:`yaramail`."""

from __future__ import annotations

from io import StringIO
from pathlib import Path

from typing import Any, cast

import pytest
import yara

from yaramail import (
    _carve_passwords,
    _compile_rules,
    _deduplicate_list,
    _input_to_str_list,
    _is_pdf,
    _is_zip,
    _match_to_dict,
    _pdf_to_markdown,
)

RULES_DIR = Path(__file__).parent


class TestIsPdf:
    def test_matches_pdf_magic(self) -> None:
        assert _is_pdf(b"%PDF-1.7\n...") is True

    def test_rejects_other_bytes(self) -> None:
        assert _is_pdf(b"PK\x03\x04not-a-pdf") is False

    def test_rejects_empty(self) -> None:
        assert _is_pdf(b"") is False

    def test_returns_false_on_type_error(self) -> None:
        # str.startswith(bytes) raises TypeError; helper should swallow it.
        assert _is_pdf("not bytes") is False  # pyright: ignore[reportArgumentType]


class TestIsZip:
    def test_matches_zip_magic(self) -> None:
        assert _is_zip(b"\x50\x4b\x03\x04rest") is True

    def test_rejects_other_bytes(self) -> None:
        assert _is_zip(b"%PDF-1.7") is False

    def test_returns_false_on_type_error(self) -> None:
        assert _is_zip("not bytes") is False  # pyright: ignore[reportArgumentType]


class TestPdfToMarkdown:
    def test_rejects_non_pdf(self) -> None:
        with pytest.raises(ValueError, match="Not a PDF"):
            _pdf_to_markdown(b"not a pdf")


class TestInputToStrList:
    def test_none(self) -> None:
        assert _input_to_str_list(None) == []

    def test_list(self) -> None:
        assert _input_to_str_list(["a", "b"]) == ["a", "b"]

    def test_string_io(self) -> None:
        assert _input_to_str_list(StringIO("a\nb\n")) == ["a", "b"]

    def test_path(self, tmp_path: Path) -> None:
        f = tmp_path / "lines.txt"
        f.write_text("one\ntwo\n")
        assert _input_to_str_list(str(f)) == ["one", "two"]

    def test_string_that_is_not_a_path(self) -> None:
        # Non-existent string paths fall through to an empty list.
        assert _input_to_str_list("/does/not/exist/abc.txt") == []


class TestCompileRules:
    def test_passes_through_compiled_rules(self) -> None:
        compiled = yara.compile(source="rule r { condition: true }")
        assert _compile_rules(compiled) is compiled

    def test_from_file_path(self) -> None:
        rules = _compile_rules(str(RULES_DIR / "header.yar"))
        assert isinstance(rules, yara.Rules)

    def test_from_directory(self, tmp_path: Path) -> None:
        (tmp_path / "a.yar").write_text("rule a { condition: true }")
        (tmp_path / "b.yar").write_text("rule b { condition: false }")
        (tmp_path / "nested").mkdir()  # subdirectories should be skipped
        (tmp_path / "nested" / "ignored.yar").write_text("not parsed")
        rules = _compile_rules(str(tmp_path))
        assert isinstance(rules, yara.Rules)

    def test_from_source_string(self) -> None:
        rules = _compile_rules("rule r { condition: true }")
        assert isinstance(rules, yara.Rules)

    def test_from_io_base(self) -> None:
        rules = _compile_rules(StringIO("rule r { condition: true }"))
        assert isinstance(rules, yara.Rules)

    def test_rejects_unsupported_type(self) -> None:
        with pytest.raises(TypeError, match="Unsupported rules type"):
            _compile_rules(42)  # pyright: ignore[reportArgumentType]


class TestMatchToDict:
    @pytest.fixture(scope="class")
    def matches(self) -> list[yara.Match]:
        rules = yara.compile(source='rule r { strings: $a = "x" condition: $a }')
        return rules.match(data=b"xxx")

    def test_single_match(self, matches: list[yara.Match]) -> None:
        result = _match_to_dict(matches[0])
        assert result["rule"] == "r"
        assert result["warnings"] == []
        assert result["strings"]

    def test_list_of_matches(self, matches: list[yara.Match]) -> None:
        result = cast(list[dict[str, Any]], _match_to_dict(matches))
        assert result[0]["rule"] == "r"

    def test_rejects_unsupported(self) -> None:
        with pytest.raises(TypeError, match="Unsupported match type"):
            _match_to_dict("nope")  # pyright: ignore[reportArgumentType]


class TestDeduplicateList:
    def test_preserves_order(self) -> None:
        assert _deduplicate_list([1, 2, 1, 3, 2]) == [1, 2, 3]

    def test_empty(self) -> None:
        assert _deduplicate_list([]) == []


class TestCarvePasswords:
    def test_extracts_parenthesized(self) -> None:
        passwords = _carve_passwords("The password is (hunter2) today")
        assert "hunter2" in passwords

    def test_extracts_angle_bracketed(self) -> None:
        passwords = _carve_passwords("The password is <hunter2> today")
        assert "hunter2" in passwords

    def test_includes_bare_tokens(self) -> None:
        assert "hunter2" in _carve_passwords("hunter2")


def test_scan_zip_with_in_memory_archive(tmp_path: Path) -> None:
    import zipfile

    from yaramail import MailScanner

    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("note.txt", "evil-marker")

    rules = 'rule marker { strings: $a = "evil-marker" condition: $a }'
    scanner = MailScanner(attachment_rules=rules)
    payload = archive.read_bytes()

    matches = scanner._scan_zip(payload)
    assert len(matches) == 1
    assert matches[0]["rule"] == "marker"


def test_scan_zip_rejects_non_zip() -> None:
    from yaramail import MailScanner

    scanner = MailScanner(attachment_rules="rule r { condition: true }")
    with pytest.raises(ValueError, match="not a ZIP"):
        scanner._scan_zip(b"not a zip")


def test_scan_zip_missing_file(tmp_path: Path) -> None:
    from yaramail import MailScanner

    scanner = MailScanner(attachment_rules="rule r { condition: true }")
    with pytest.raises(FileNotFoundError):
        scanner._scan_zip(str(tmp_path / "missing.zip"))


def test_scan_pdf_text_rejects_non_pdf() -> None:
    from yaramail import MailScanner

    scanner = MailScanner(attachment_rules="rule r { condition: true }")
    with pytest.raises(ValueError, match="not a PDF"):
        scanner._scan_pdf_text(b"not a pdf")


def test_scan_pdf_text_returns_empty_without_rules() -> None:
    from io import BytesIO

    from yaramail import MailScanner

    # Smallest possible PDF header — _scan_pdf_text only checks the magic.
    scanner = MailScanner()
    assert scanner._scan_pdf_text(BytesIO(b"%PDF-1.7\n")) == []


def test_scan_zip_returns_empty_without_rules(tmp_path: Path) -> None:
    import zipfile

    from yaramail import MailScanner

    archive = tmp_path / "x.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("x.txt", "hello")
    scanner = MailScanner()
    assert scanner._scan_zip(archive.read_bytes()) == []


def test_scan_zip_from_file_path(tmp_path: Path) -> None:
    import zipfile

    from yaramail import MailScanner

    archive = tmp_path / "marker.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("note.txt", "evil-marker")

    scanner = MailScanner(
        attachment_rules='rule m { strings: $a = "evil-marker" condition: $a }',
    )
    matches = scanner._scan_zip(str(archive))
    assert any(m["rule"] == "m" for m in matches)


def test_scan_zip_nested_archive(tmp_path: Path) -> None:
    import zipfile

    from yaramail import MailScanner

    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("payload.txt", "deep-marker")
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.write(inner, arcname="inner.zip")

    scanner = MailScanner(
        attachment_rules='rule m { strings: $a = "deep-marker" condition: $a }',
    )
    matches = scanner._scan_zip(outer.read_bytes())
    assert any(m["rule"] == "m" for m in matches)


def test_scanner_with_no_rules_returns_empty_match_shape() -> None:
    from mailsuite.utils import parse_email

    from yaramail import MailScanner

    sample = (RULES_DIR / "samples" / "safe" / "workday.eml").read_text()
    scanner = MailScanner()
    result = scanner.scan_email(parse_email(sample))
    assert result["matches"] == []
    assert result["verdict"] is None
    assert result["categories"] == []
