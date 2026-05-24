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
FIXTURES = Path(__file__).parent / "fixtures"
SANS = (SAMPLES / "safe" / "sans.eml").read_text()
INVOICE = (SAMPLES / "credential-harvesting" / "Invoice.eml").read_text()

PDF_MARKER_RULE = (
    'rule pdf_marker { strings: $a = "yaramail-pdf-marker" condition: $a }'
)
ENCRYPTED_ZIP_RULE = (
    'rule zip_marker { strings: $a = "evil-marker inside encrypted zip" condition: $a }'
)


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


def test_use_raw_headers_scans_folded_headers_verbatim() -> None:
    """``use_raw_headers`` keeps header folding; the default unfolds it.

    mailsuite unfolds continuation lines in ``headers_string`` (the default
    scan target) but leaves ``raw_headers`` intact, so a rule matching the
    indented continuation only fires when ``use_raw_headers=True``.
    """
    rule = 'rule folded { strings: $a = "first\\r\\n\\tsecond" condition: $a }'
    eml = (
        "From: a@example.com\r\nTo: b@c.d\r\n"
        "X-Folded: first\r\n\tsecond\r\nSubject: x\r\n\r\nbody\r\n"
    )
    scanner = MailScanner(header_rules=rule)
    # Default unfolds the header ("first second"), so the rule does not match.
    assert scanner.scan_email(eml)["matches"] == []
    raw = scanner.scan_email(eml, use_raw_headers=True)
    assert [m["rule"] for m in raw["matches"]] == ["folded"]
    assert raw["matches"][0]["location"] == "header"


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
        'meta: category = "safe" '
        'strings: $a = "evil-marker" '
        "condition: $a }"
    )
    scanner = MailScanner(body_rules=rule)
    eml = (
        "From: noone@example.com\r\nTo: a@b.c\r\nSubject: x\r\n\r\nevil-marker here\r\n"
    )
    result = scanner.scan_email(eml)
    warnings = result["matches"][0]["warnings"]
    assert "safe-rule-missing-from-domain" in warnings


def test_from_domain_mismatch_emits_warning() -> None:
    rule = (
        "rule scoped { "
        'meta: category = "phishing" from_domain = "trusted.example" '
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
    eml = "From: x@b.example\r\nTo: y@z.example\r\nSubject: x\r\n\r\nmarker here\r\n"
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


def _nested_zip(levels: int, marker: bytes = b"deep-marker") -> bytes:
    """Build ``levels`` of DEFLATE-compressed nested ZIPs around ``marker``.

    Compression matters: with ZIP_STORED the marker would survive as plaintext
    in every enclosing archive, so a scan would "find" it without recursing and
    the depth guard would never actually be exercised.
    """
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("payload.txt", marker)
    data = buf.getvalue()
    for level in range(levels - 1):
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"inner{level}.zip", data)
        data = buf.getvalue()
    return data


def test_scan_zip_max_zip_depth_limits_recursion() -> None:
    """``max_zip_depth`` is the number of times to recurse into nested ZIPs.

    ``0`` scans only the top-level archive, ``1`` allows one nested level,
    ``None`` is unlimited.
    """
    rule = 'rule m { strings: $a = "deep-marker" condition: $a }'
    # outer.zip -> inner.zip -> payload.txt: one recursion is needed.
    one_level = _nested_zip(2)

    def found(depth: int | None, data: bytes) -> bool:
        scanner = MailScanner(attachment_rules=rule, max_zip_depth=depth)
        return any(m["rule"] == "m" for m in scanner._scan_zip(data))

    assert found(None, one_level) is True
    assert found(1, one_level) is True
    assert found(0, one_level) is False  # no recursion at all

    # Three levels deep needs two recursions.
    two_levels = _nested_zip(3)
    assert found(2, two_levels) is True
    assert found(1, two_levels) is False


def test_scan_zip_member_location_is_relative_to_archive() -> None:
    """A ZIP-member match reports the member name, not ``None``."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("evil.js", "evil-marker here")
    scanner = MailScanner(
        attachment_rules='rule m { strings: $a = "evil-marker" condition: $a }',
    )
    matches = scanner._scan_zip(buf.getvalue())
    assert [m["location"] for m in matches] == ["evil.js"]
    assert "zip" in matches[0]["tags"]


def test_scan_zip_does_not_mutate_passwords_argument() -> None:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("note.txt", "hello")
    scanner = MailScanner(attachment_rules="rule r { condition: true }")
    passwords = ["hunter2"]
    scanner._scan_zip(buf.getvalue(), passwords=passwords)
    assert passwords == ["hunter2"]


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
            attachment_rules="rule m { condition: true }",
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


def test_scan_pdf_text_matches_rule() -> None:
    scanner = MailScanner(attachment_rules=PDF_MARKER_RULE)
    matches = scanner._scan_pdf_text((FIXTURES / "marker.pdf").read_bytes())
    assert any(m["rule"] == "pdf_marker" for m in matches)
    assert "pdf2text" in matches[0]["tags"]


def test_scan_pdf_text_accepts_bytesio() -> None:
    scanner = MailScanner(attachment_rules=PDF_MARKER_RULE)
    matches = scanner._scan_pdf_text(BytesIO((FIXTURES / "marker.pdf").read_bytes()))
    assert any(m["rule"] == "pdf_marker" for m in matches)


def test_scan_zip_with_pdf_member_runs_pdf_text_extraction() -> None:
    scanner = MailScanner(attachment_rules=PDF_MARKER_RULE)
    matches = scanner._scan_zip((FIXTURES / "pdf-in-zip.zip").read_bytes())
    assert any(m["rule"] == "pdf_marker" for m in matches)


def test_scan_zip_encrypted_with_correct_password() -> None:
    scanner = MailScanner(attachment_rules=ENCRYPTED_ZIP_RULE)
    matches = scanner._scan_zip(
        (FIXTURES / "protected.zip").read_bytes(),
        passwords=["hunter2"],
    )
    assert any(m["rule"] == "zip_marker" for m in matches)


def test_scan_zip_encrypted_without_password_returns_empty() -> None:
    scanner = MailScanner(attachment_rules=ENCRYPTED_ZIP_RULE)
    matches = scanner._scan_zip((FIXTURES / "protected.zip").read_bytes())
    # No working password → graceful empty result with a logged warning.
    assert matches == []


def test_scan_attachments_handles_malformed_pdf(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A payload with the PDF magic but invalid structure logs and continues."""
    scanner = MailScanner(attachment_rules=PDF_MARKER_RULE)
    attachment = {
        "filename": "broken.pdf",
        "payload": base64.b64encode(b"%PDF-1.7\nnot really a pdf").decode(),
        "binary": True,
    }
    with caplog.at_level("WARNING", logger="yaramail"):
        result = scanner._scan_attachments(attachment)
    assert result == []
    assert any(
        "Unable to convert broken.pdf to markdown" in rec.message
        for rec in caplog.records
    )


def test_scan_email_with_pdf_attachment() -> None:
    pdf_b64 = base64.b64encode((FIXTURES / "marker.pdf").read_bytes()).decode()
    eml = (
        "From: a@example.com\r\nTo: b@c.d\r\n"
        'Content-Type: multipart/mixed; boundary="b1"\r\n'
        "Subject: x\r\n\r\n"
        "--b1\r\nContent-Type: text/plain\r\n\r\nsee attachment\r\n"
        "--b1\r\n"
        'Content-Type: application/pdf; name="marker.pdf"\r\n'
        "Content-Transfer-Encoding: base64\r\n"
        'Content-Disposition: attachment; filename="marker.pdf"\r\n\r\n'
        f"{pdf_b64}\r\n"
        "--b1--\r\n"
    )
    scanner = MailScanner(attachment_rules=PDF_MARKER_RULE)
    result = scanner.scan_email(eml)
    locations = {m["location"] for m in result["matches"]}
    # Both raw and pdf2text passes produce an "attachment:marker.pdf" match.
    assert "attachment:marker.pdf" in locations


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


def test_malformed_eml_attachment_is_logged_not_raised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A .eml attachment that isn't a parseable email is logged, not raised."""
    garbage = base64.b64encode(b"\x00\x01 not an email").decode()
    outer = (
        "From: a@example.com\r\nTo: b@c.d\r\n"
        'Content-Type: multipart/mixed; boundary="b1"\r\nSubject: x\r\n\r\n'
        "--b1\r\nContent-Type: text/plain\r\n\r\nsee attachment\r\n--b1\r\n"
        'Content-Type: application/octet-stream; name="nested.eml"\r\n'
        "Content-Transfer-Encoding: base64\r\n"
        'Content-Disposition: attachment; filename="nested.eml"\r\n\r\n'
        f"{garbage}\r\n--b1--\r\n"
    )
    scanner = MailScanner(attachment_rules="rule r { condition: true }")
    with caplog.at_level("WARNING", logger="yaramail"):
        result = scanner.scan_email(outer)  # must not raise
    assert "matches" in result
    assert any("Unable to scan nested.eml" in rec.message for rec in caplog.records)


def test_scan_zip_with_malformed_pdf_member_is_logged_not_raised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A ZIP member with the PDF magic but a broken body is logged, not raised."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("broken.pdf", b"%PDF-1.7\nnot really a pdf")
    scanner = MailScanner(attachment_rules=PDF_MARKER_RULE)
    with caplog.at_level("WARNING", logger="yaramail"):
        matches = scanner._scan_zip(buf.getvalue())  # must not raise
    assert matches == []
    assert any(
        "Unable to convert 'broken.pdf' to markdown" in rec.message
        for rec in caplog.records
    )


def _zip_attachment_eml(filename: str, archive: bytes) -> str:
    zip_b64 = base64.b64encode(archive).decode()
    return (
        "From: a@example.com\r\nTo: b@c.d\r\n"
        'Content-Type: multipart/mixed; boundary="b1"\r\nSubject: x\r\n\r\n'
        "--b1\r\nContent-Type: text/plain\r\n\r\nsee attachment\r\n--b1\r\n"
        f'Content-Type: application/zip; name="{filename}"\r\n'
        "Content-Transfer-Encoding: base64\r\n"
        f'Content-Disposition: attachment; filename="{filename}"\r\n\r\n'
        f"{zip_b64}\r\n--b1--\r\n"
    )


def test_zip_attachment_location_has_no_duplicates() -> None:
    """A stored ZIP member matches both the raw archive scan and the member
    scan, but each must appear once with a correct location."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("evil.js", "evil-marker here")
    scanner = MailScanner(
        attachment_rules='rule m { strings: $a = "evil-marker" condition: $a }',
    )
    result = scanner.scan_email(_zip_attachment_eml("archive.zip", buf.getvalue()))
    locations = sorted(m["location"] for m in result["matches"])
    # Exactly two distinct matches: the raw archive scan and the member scan.
    assert locations == [
        "attachment:archive.zip",
        "attachment:archive.zip:evil.js",
    ]


def test_zip_attachment_nested_member_location_path() -> None:
    inner = BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("evil.js", "evil-marker here")
    outer = BytesIO()
    with zipfile.ZipFile(outer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("nested.zip", inner.getvalue())
    scanner = MailScanner(
        attachment_rules='rule m { strings: $a = "evil-marker" condition: $a }',
    )
    result = scanner.scan_email(_zip_attachment_eml("first.zip", outer.getvalue()))
    locations = {m["location"] for m in result["matches"]}
    assert "attachment:first.zip:nested.zip:evil.js" in locations


def test_corrupt_zip_attachment_is_logged_not_raised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A payload with the ZIP magic but a malformed body is logged, not raised."""
    bad = b"\x50\x4b\x03\x04" + b"garbage that is not a real zip"
    scanner = MailScanner(attachment_rules="rule r { condition: true }")
    with caplog.at_level("WARNING", logger="yaramail"):
        result = scanner.scan_email(_zip_attachment_eml("bad.zip", bad))
    # The raw-archive scan still produced a match; the member scan was skipped.
    assert any(m["location"] == "attachment:bad.zip" for m in result["matches"])
    assert any("Unable to scan bad.zip" in rec.message for rec in caplog.records)


def test_use_raw_body_scans_both_plain_and_html() -> None:
    rule = (
        'rule both { strings: $a = "plain-token" $b = "html-token" '
        "condition: all of them }"
    )
    scanner = MailScanner(body_rules=rule)
    eml = (
        "From: a@example.com\r\nTo: b@c.d\r\n"
        'Content-Type: multipart/alternative; boundary="b1"\r\nSubject: x\r\n\r\n'
        "--b1\r\nContent-Type: text/plain\r\n\r\nplain-token here\r\n--b1\r\n"
        "--b1\r\nContent-Type: text/html\r\n\r\n<p>html-token</p>\r\n--b1--\r\n"
    )
    result = scanner.scan_email(eml, use_raw_body=True)
    assert any(m["rule"] == "both" for m in result["matches"])
