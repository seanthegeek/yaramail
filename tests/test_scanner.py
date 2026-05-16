"""Tests for the :class:`yaramail.MailScanner` public surface."""

from __future__ import annotations

import base64
import zipfile
from io import BytesIO
from pathlib import Path

import pytest
from mailsuite.utils import parse_email

from yaramail import MailScanner

SAMPLES = Path(__file__).parent / "samples"
SANS = (SAMPLES / "safe" / "sans.eml").read_text()
WORKDAY = (SAMPLES / "safe" / "workday.eml").read_text()
INVOICE = (SAMPLES / "credential-harvesting" / "Invoice.eml").read_text()


def test_scan_email_accepts_string_input() -> None:
    scanner = MailScanner(use_authentication_results_original=True)
    result = scanner.scan_email(SANS)
    assert set(result) == {
        "matches",
        "categories",
        "msg_from_domain",
        "has_attachment",
        "verdict",
    }


def test_scan_email_accepts_bytes_input() -> None:
    scanner = MailScanner(use_authentication_results_original=True)
    result = scanner.scan_email(SANS.encode())
    assert result["has_attachment"] is True
    assert result["msg_from_domain"]["domain"] == "email.sans.org"


def test_scan_email_use_raw_headers_and_body() -> None:
    scanner = MailScanner(use_authentication_results_original=True)
    parsed = parse_email(WORKDAY)
    result = scanner.scan_email(parsed, use_raw_headers=True, use_raw_body=True)
    assert "matches" in result


def test_credential_harvesting_zip_attachment_classification() -> None:
    rules_dir = SAMPLES.parent
    scanner = MailScanner(
        header_rules=str(rules_dir / "header.yar"),
        body_rules=str(rules_dir / "body.yar"),
        header_body_rules=str(rules_dir / "header_body.yar"),
        attachment_rules=str(rules_dir / "attachment.yar"),
        passwords=str(rules_dir / "passwords.txt"),
        use_authentication_results_original=True,
    )
    result = scanner.scan_email(parse_email(INVOICE))
    assert result["verdict"] == "credential-harvesting"
    locations = {match["location"] for match in result["matches"]}
    assert any(loc.startswith("attachment:invoice.zip") for loc in locations)


def test_implicit_safe_domain_promotes_verdict() -> None:
    scanner = MailScanner(
        implicit_safe_domains=["email.sans.org"],
        use_authentication_results_original=True,
    )
    result = scanner.scan_email(parse_email(SANS))
    assert result["verdict"] == "safe"
    assert result["msg_from_domain"]["implicit_safe"] is True


def test_passwords_deduplicated_and_extended() -> None:
    scanner = MailScanner(passwords=["alpha", "alpha", "malware"])
    # The constructor unconditionally extends with ["malware", "infected"]
    # and then deduplicates.
    assert scanner.passwords == ["alpha", "malware", "infected"]


def test_scan_attachments_accepts_single_dict(tmp_path: Path) -> None:
    archive = tmp_path / "marker.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("note.txt", "evil-marker")

    scanner = MailScanner(
        attachment_rules='rule m { strings: $a = "evil-marker" condition: $a }',
    )
    attachment = {
        "filename": "marker.zip",
        "payload": archive.read_bytes(),
        "binary": False,
    }
    matches = scanner._scan_attachments(attachment)
    assert any(m["rule"] == "m" for m in matches)


def test_safe_rule_without_from_domain_emits_warning() -> None:
    rule = (
        "rule loose_safe { "
        "meta: category = \"safe\" "
        'strings: $a = "evil-marker" '
        "condition: $a }"
    )
    scanner = MailScanner(body_rules=rule)
    eml = (
        "From: noone@example.com\r\nTo: a@b.c\r\n"
        "Subject: x\r\n\r\nevil-marker here\r\n"
    )
    result = scanner.scan_email(eml)
    warnings = result["matches"][0]["warnings"]
    assert "safe-rule-missing-from-domain" in warnings


def test_from_domain_mismatch_emits_warning() -> None:
    rule = (
        "rule scoped { "
        "meta: category = \"phishing\" from_domain = \"trusted.example\" "
        'strings: $a = "evil-marker" '
        "condition: $a }"
    )
    scanner = MailScanner(body_rules=rule)
    eml = (
        "From: attacker@other.example\r\nTo: a@b.c\r\n"
        "Subject: x\r\n\r\nevil-marker here\r\n"
    )
    result = scanner.scan_email(eml)
    warnings = result["matches"][0]["warnings"]
    assert "from-domain-mismatch" in warnings
    assert "domain-authentication-failed" in warnings


def test_no_attachments_meta_emits_warning_when_attachment_present() -> None:
    rule = (
        'rule clean { meta: no_attachments = true category = "safe" '
        'strings: $a = "marker" condition: $a }'
    )
    scanner = MailScanner(body_rules=rule)
    outer = (
        "From: a@example.com\r\nTo: b@c.d\r\n"
        'Content-Type: multipart/mixed; boundary="b1"\r\n'
        "\r\n--b1\r\nContent-Type: text/plain\r\n\r\nmarker\r\n"
        "--b1\r\nContent-Type: application/octet-stream; "
        'name="x.bin"\r\nContent-Disposition: attachment; filename="x.bin"\r\n\r\n'
        "data\r\n--b1--\r\n"
    )
    result = scanner.scan_email(outer)
    assert "unexpected-attachment" in result["matches"][0]["warnings"]


def test_alt_meta_key_spellings_are_supported() -> None:
    """``auth_optional``, ``no_attachment``, ``from_domains`` are accepted aliases."""
    rule = (
        'rule alts { meta: category = "phishing" auth_optional = true '
        'no_attachment = true from_domains = "a.example b.example" '
        'strings: $a = "marker" condition: $a }'
    )
    scanner = MailScanner(body_rules=rule)
    eml = (
        "From: x@b.example\r\nTo: y@z.example\r\n"
        "Subject: x\r\n\r\nmarker here\r\n"
    )
    result = scanner.scan_email(eml)
    # b.example is in the allowed list, so no from-domain-mismatch warning.
    warnings = result["matches"][0]["warnings"]
    assert "from-domain-mismatch" not in warnings


def test_ambiguous_verdict_when_multiple_categories_match() -> None:
    rules = (
        'rule one { meta: category = "first" authentication_optional = true '
        'strings: $a = "marker-a" condition: $a } '
        'rule two { meta: category = "second" authentication_optional = true '
        'strings: $a = "marker-b" condition: $a }'
    )
    scanner = MailScanner(body_rules=rules)
    eml = (
        "From: a@example.com\r\nTo: b@c.d\r\n"
        "Subject: x\r\n\r\nmarker-a then marker-b\r\n"
    )
    result = scanner.scan_email(eml)
    assert result["verdict"] == "ambiguous"
    assert set(result["categories"]) == {"first", "second"}


def test_header_rules_attach_header_location() -> None:
    rule = 'rule h { strings: $a = "X-Custom-Marker: 1" condition: $a }'
    scanner = MailScanner(header_rules=rule)
    eml = (
        "From: a@example.com\r\nTo: b@c.d\r\n"
        "X-Custom-Marker: 1\r\nSubject: x\r\n\r\nbody\r\n"
    )
    result = scanner.scan_email(eml)
    assert result["matches"]
    assert result["matches"][0]["location"] == "header"


def test_header_body_rules_attach_header_body_location() -> None:
    # The header_body content is "{headers}\n\n{body}", so a string spanning
    # both must hit a header_body rule.
    rule = 'rule hb { strings: $a = "X-Spans-Both: 1" $b = "body-token" condition: all of them }'
    scanner = MailScanner(header_body_rules=rule)
    eml = (
        "From: a@example.com\r\nTo: b@c.d\r\n"
        "X-Spans-Both: 1\r\nSubject: x\r\n\r\nbody-token here\r\n"
    )
    result = scanner.scan_email(eml)
    assert result["matches"]
    assert result["matches"][0]["location"] == "header_body"


def test_use_raw_body_matches_text_plain() -> None:
    rule = 'rule p { strings: $a = "plain-token" condition: $a }'
    scanner = MailScanner(body_rules=rule)
    eml = (
        "From: a@example.com\r\nTo: b@c.d\r\n"
        "Content-Type: text/plain\r\n"
        "Subject: x\r\n\r\nplain-token here\r\n"
    )
    result = scanner.scan_email(eml, use_raw_body=True)
    assert any(m["rule"] == "p" for m in result["matches"])


def test_use_raw_body_matches_text_html() -> None:
    rule = 'rule h { strings: $a = "html-token" condition: $a }'
    scanner = MailScanner(body_rules=rule)
    eml = (
        "From: a@example.com\r\nTo: b@c.d\r\n"
        "Content-Type: text/html\r\n"
        "Subject: x\r\n\r\n<p>html-token</p>\r\n"
    )
    result = scanner.scan_email(eml, use_raw_body=True)
    assert any(m["rule"] == "h" for m in result["matches"])


def test_attachment_decode_handles_garbage_base64() -> None:
    """An attachment marked binary with non-base64 payload is scanned as-is."""
    rule = 'rule m { strings: $a = "raw-bytes" condition: $a }'
    scanner = MailScanner(attachment_rules=rule)
    attachment = {
        "filename": "broken.bin",
        # base64-impossible string: contains the marker we want YARA to hit.
        "payload": "raw-bytes!! not valid base64",
        "binary": True,
    }
    matches = scanner._scan_attachments(attachment)
    assert any(m["rule"] == "m" for m in matches)


def test_attachment_with_binary_base64_payload() -> None:
    rule = 'rule m { strings: $a = "raw-bytes" condition: $a }'
    scanner = MailScanner(attachment_rules=rule)
    attachment = {
        "filename": "decoded.bin",
        "payload": base64.b64encode(b"raw-bytes-marker").decode(),
        "binary": True,
    }
    matches = scanner._scan_attachments(attachment)
    assert any(m["rule"] == "m" for m in matches)


def test_scan_attachments_returns_empty_without_rules() -> None:
    scanner = MailScanner()
    attachment = {"filename": "x.bin", "payload": "data", "binary": False}
    assert scanner._scan_attachments(attachment) == []


def test_scan_zip_accepts_bytesio(tmp_path: Path) -> None:
    archive = tmp_path / "marker.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("note.txt", "evil-marker")
    scanner = MailScanner(
        attachment_rules='rule m { strings: $a = "evil-marker" condition: $a }',
    )
    matches = scanner._scan_zip(BytesIO(archive.read_bytes()))
    assert any(m["rule"] == "m" for m in matches)


def test_scan_zip_recurses_into_nested_archive_when_depth_exceeded(
    tmp_path: Path,
) -> None:
    """With ``max_zip_depth=1``, the recursion guard allows one level deep."""
    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("deep.txt", "deep-marker")
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.write(inner, arcname="inner.zip")

    scanner = MailScanner(
        attachment_rules='rule m { strings: $a = "deep-marker" condition: $a }',
        max_zip_depth=1,
    )
    matches = scanner._scan_zip(outer.read_bytes())
    assert any(m["rule"] == "m" for m in matches)


def test_scan_zip_with_unreadable_entries_returns_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When every password attempt raises RuntimeError, we log and return []."""
    archive = tmp_path / "marker.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("note.txt", "evil-marker")

    original_open = zipfile.ZipFile.open

    def always_fails(
        self: zipfile.ZipFile,
        name: str | zipfile.ZipInfo,
        mode: str = "r",
        pwd: bytes | None = None,
        *,
        force_zip64: bool = False,
    ):
        raise RuntimeError("Bad password for file")

    monkeypatch.setattr(zipfile.ZipFile, "open", always_fails)
    try:
        scanner = MailScanner(
            attachment_rules='rule m { condition: true }',
        )
        assert scanner._scan_zip(archive.read_bytes()) == []
    finally:
        monkeypatch.setattr(zipfile.ZipFile, "open", original_open)


def test_scan_email_accepts_pre_parsed_dict_without_from() -> None:
    """Hand-rolled parsed-email dict missing ``from`` exercises the early branch."""
    scanner = MailScanner()
    parsed = {
        "raw_headers": "",
        "headers_string": "",
        "body_markdown": "",
        "text_plain": [""],
        "text_html": [""],
        "body": "",
    }
    result = scanner.scan_email(parsed)
    assert result["msg_from_domain"]["domain"] is None
    assert result["has_attachment"] is False


def test_scan_email_handles_from_dict_without_domain() -> None:
    scanner = MailScanner()
    parsed = {
        "from": {"address": "anonymous"},
        "raw_headers": "",
        "headers_string": "",
        "body_markdown": "",
        "text_plain": [""],
        "text_html": [""],
        "body": "",
        "attachments": [],
    }
    result = scanner.scan_email(parsed)
    assert result["msg_from_domain"]["domain"] is None


def test_scan_email_with_eml_attached_to_eml() -> None:
    """An .eml attachment should be recursively scanned via scan_email."""
    inner = (
        "From: outer@example.com\r\n"
        "To: victim@example.org\r\n"
        "Subject: nested\r\n"
        "\r\n"
        "evil-marker inside body\r\n"
    )
    outer = (
        "From: carrier@example.com\r\n"
        "To: victim@example.org\r\n"
        'Content-Type: multipart/mixed; boundary="b1"\r\n'
        "\r\n"
        "--b1\r\n"
        "Content-Type: text/plain\r\n\r\nsee attachment\r\n"
        "--b1\r\n"
        'Content-Type: message/rfc822; name="nested.eml"\r\n'
        'Content-Disposition: attachment; filename="nested.eml"\r\n\r\n'
        f"{inner}"
        "--b1--\r\n"
    )
    scanner = MailScanner(
        body_rules='rule m { strings: $a = "evil-marker" condition: $a }',
        attachment_rules='rule m { strings: $a = "evil-marker" condition: $a }',
    )
    result = scanner.scan_email(outer)
    assert any(match["rule"] == "m" for match in result["matches"])
