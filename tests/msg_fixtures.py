"""Outlook ``.msg`` bytes and messages shared by the CLI and scanner tests."""

from __future__ import annotations

import base64

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
OLE_BYTES = OLE_MAGIC + b"\x00" * 64


def build_outer_with_msg_attachment(extra_header: str = "") -> str:
    """Build a message with a base64 ``nested.msg`` attachment of OLE bytes."""
    payload = base64.b64encode(OLE_BYTES).decode()
    return (
        f"From: a@example.com\r\nTo: b@c.d\r\n{extra_header}"
        'Content-Type: multipart/mixed; boundary="b1"\r\nSubject: x\r\n\r\n'
        "--b1\r\nContent-Type: text/plain\r\n\r\nsee attachment\r\n--b1\r\n"
        'Content-Type: application/octet-stream; name="nested.msg"\r\n'
        "Content-Transfer-Encoding: base64\r\n"
        'Content-Disposition: attachment; filename="nested.msg"\r\n\r\n'
        f"{payload}\r\n--b1--\r\n"
    )
