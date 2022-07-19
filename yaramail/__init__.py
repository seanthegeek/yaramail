import logging
from typing import Union, List, Dict
import binascii
import os
from os import path
from io import IOBase, BytesIO
import zipfile

import yara
import pdftotext

from mailsuite.utils import parse_email, decode_base64

formatter = logging.Formatter(
    fmt='%(levelname)8s:%(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S')
handler = logging.StreamHandler()
handler.setFormatter(formatter)

logger = logging.getLogger("yaramail")
logger.addHandler(handler)

__version__ = "1.0.1"


def _match_to_dict(match: Union[yara.Match,
                                List[yara.Match]]) -> Union[List[Dict],
                                                            Dict]:
    def match_to_dict_(_match: yara.Match) -> Dict:
        return dict(rule=_match.rule,
                    namespace=_match.namespace,
                    tags=_match.tags,
                    meta=_match.meta,
                    strings=_match.strings
                    )

    if isinstance(match, list):
        matches = match.copy()
        for i in range(len(matches)):
            matches[i] = _match_to_dict(matches[i])
        return matches
    elif isinstance(match, yara.Match):
        return match_to_dict_(match)


def _is_pdf(file_bytes: bytes) -> bool:
    return file_bytes.startswith(b"\x25\x50")


def _is_zip(file_bytes: bytes) -> bool:
    return file_bytes.startswith(b"\x50\x4B\03\04")


def _pdf_to_markdown(pdf_bytes: bytes) -> str:
    if not _is_pdf(pdf_bytes):
        raise ValueError("Not a PDF file")
    with BytesIO(pdf_bytes) as f:
        return "\n\n".join(pdftotext.PDF(f))


def _compile_rules(rules: Union[yara.Rules, IOBase, str]) -> yara.Rules:
    if isinstance(rules, yara.Rules):
        return rules
    if isinstance(rules, IOBase):
        rules = rules.read()
    if path.exists(rules):
        if path.isdir(rules):
            rules_str = ""
            for filename in os.listdir():
                file_path = path.join(rules, filename)
                if not path.isdir(file_path):
                    with open(file_path) as rules_file:
                        rules_str += rules_file.read()
            return yara.compile(source=rules_str)
        return yara.compile(filepath=rules)
    return yara.compile(source=rules)


class MailScanner(object):
    def __init__(self, header_rules: Union[str, IOBase, yara.Rules] = None,
                 body_rules: Union[str, IOBase, yara.Rules] = None,
                 header_body_rules: Union[str, IOBase, yara.Rules] = None,
                 attachment_rules: Union[str, IOBase, yara.Rules] = None):
        """
        A YARA scaner for emails

        Args:
            header_rules: Rules that only apply to email header content
            body_rules: Rules that only apply to email body content
            header_body_rules: Rules that apply to combined email \
            header and body content
            attachment_rules: Rules that only apply to file \
            attachment content

        .. note::
          Each ``_rules`` parameter can accept raw rule content, a path to a
          rules file, a file-like object, or a ``yara.Rule`` object.

        .. tip::
          Use the ``include`` directive in the YARA rule files that you
          pass to ``MailScanner`` to include rules from other files. That
          way, rules can be divided into separate files as you see fit.
        """
        self._header_rules = header_rules
        self._body_rules = body_rules
        self._header_body_rules = header_body_rules
        self._attachment_rules = attachment_rules
        if header_rules:
            self._header_rules = _compile_rules(header_rules)
        if body_rules:
            self._body_rules = _compile_rules(body_rules)
        if header_body_rules:
            self._header_body_rules = _compile_rules(header_body_rules)
        if attachment_rules:
            self._attachment_rules = _compile_rules(attachment_rules)

    def _scan_pdf_text(self, payload: Union[bytes, BytesIO]) -> List[Dict]:
        if isinstance(payload, BytesIO):
            payload = payload.read()
        if not _is_pdf(payload):
            raise ValueError("Payload is not a PDF file")
        pdf_markdown = _pdf_to_markdown(payload)
        markdown_matches = _match_to_dict(
            self._attachment_rules.match(pdf_markdown))
        for match in markdown_matches:
            tags = match["tags"].copy()
            tags.append("pdf2text")
            match["tags"] = list(set(tags))

        return markdown_matches

    def _scan_zip(self, filename: str, payload: Union[bytes, BytesIO],
                  _current_depth: int = 0, max_depth: int = None):
        if isinstance(payload, bytes):
            if not _is_zip(payload):
                raise ValueError("Payload is not a ZIP file")
            _current_depth += 1
            zip_matches = []
            payload = BytesIO(payload)
            with zipfile.ZipFile(payload) as zip_file:
                for name in zip_file.namelist():
                    with zip_file.open(name) as member:
                        tags = ["zip"]
                        location = "{}:{}".format(filename, name)
                        member_content = member.read()
                        matches = _match_to_dict(
                            self._attachment_rules.match(
                                data=member_content))
                        for match in matches:
                            if "location" in match:
                                existing_location = match["location"]
                                location = f"{existing_location}:{location}"
                            match["location"] = location
                        zip_matches += matches
                        if _is_pdf(member_content):
                            try:
                                zip_matches += self._scan_pdf_text(
                                    member_content)
                            except Exception as e:
                                logger.warning(
                                    "Unable to convert PDF to markdown. "
                                    f"{e} Scanning raw file content only"
                                    ".")
                        elif _is_zip(member_content):
                            if max_depth is None or _current_depth > max_depth:
                                zip_matches += self._scan_zip(
                                    name,
                                    member_content,
                                    _current_depth=_current_depth,
                                    max_depth=max_depth)
                        for match in zip_matches:
                            match["tags"] = list(set(match["tags"] + tags))

                        return zip_matches

    def _scan_attachments(self, attachments: Union[List, Dict],
                          max_zip_depth: int = None) -> List[Dict]:
        attachment_matches = []
        if isinstance(attachments, dict):
            attachments = [attachments]
        for attachment in attachments:
            filename = attachment["filename"]
            file_extension = filename.lower().split(".")[-1]
            payload = attachment["payload"]
            if "binary" in attachment:
                if attachment["binary"]:
                    try:
                        payload = decode_base64(attachment["payload"])
                    except binascii.Error:
                        pass
            attachment_matches += _match_to_dict(
                self._attachment_rules.match(data=payload))
            if _is_pdf(payload):
                try:
                    attachment_matches += self._scan_pdf_text(payload)
                except Exception as e:
                    logger.warning(
                        f"Unable to convert {filename} to markdown. {e}. "
                        f"Scanning raw file content only.")
            elif _is_zip(payload):
                try:
                    attachment_matches += self._scan_zip(
                        filename,
                        payload,
                        max_depth=max_zip_depth)
                except Exception as e:
                    logger.warning(f"Unable to scan {filename}. {e}.")
            elif file_extension in ["eml", "msg"]:
                try:
                    matches = self.scan_email(parse_email(payload))
                    attachment_matches += matches
                except Exception as e:
                    logger.warning(f"Unable to scan {filename}. {e}.")

            for match in attachment_matches:
                base_location = f"attachment:{filename}"
                if "location" in match:
                    og_location = match["location"]
                    match["location"] = f"{base_location}:{og_location}"
                else:
                    match["location"] = base_location

        return attachment_matches

    def scan_email(self, email: Union[str, IOBase, Dict],
                   use_raw_headers: bool = False,
                   use_raw_body: bool = False,
                   max_zip_depth: int = None) -> List[Dict]:
        """
        Scans an email using YARA rules

        Args:
            email: Email file content, a path to an email \
            file, a file-like object, or output from \
            ``mailsuite.utils.parse_email()``
            use_raw_headers: Scan headers with indentations included
            use_raw_body: Scan the raw email body instead of converting it to \
            Markdown first
            max_zip_depth: Number of times to recurse into nested ZIP files

        Returns: A list of rule matches

        Each match dictionary in the returned list contains
        the following key-value pairs:

        - ``name`` - The name of the rule.
        - ``namespace`` - The namespace of the rule.
        - ``meta`` - A dictionary of key-value pairs from the meta section.
        - ``tags`` - A list of the rule's tags.
        - ``strings`` - A list of identified strings or patterns that match.
          Each list item is also a list, with the following values:

              0. The location offset of the identified string/pattern
              1. The variable name of the string/pattern in the rule
              2. The matching string/pattern content

        - ``location`` - The part of the email where the match was found

          - ``header``
          - ``body``
          - ``header_body``
          - ``attachment:filename``
          - ``attachment:example.zip:evil.js``
          - ``attachment:first.zip:nested.zip:evil.js``
          - ``attachment:evil.eml:attachment:example.zip:evil.js``
        """
        if isinstance(email, str):
            if path.exists(email):
                with open(email, "rb") as email_file:
                    email = email_file.read()
        if isinstance(email, dict):
            parsed_email = email
        else:
            parsed_email = parse_email(email)
        if use_raw_headers:
            headers = parsed_email["raw_headers"]
        else:
            headers = parsed_email["headers_string"]
        body = ""
        if use_raw_body:
            if len(parsed_email["text_plain"]) > 0:
                body = "\n\n".join(parsed_email["text_plain"])
            if len(parsed_email["text_html"]) > 0:
                body = "\n\n".join(parsed_email["text_html"])
        else:
            body = parsed_email["body_markdown"]
        attachments = parsed_email["attachments"]

        matches = []
        if self._header_rules:
            header_matches = _match_to_dict(self._header_rules.match(
                data=headers))
            for header_match in header_matches:
                header_match["location"] = "header"
                matches.append(header_match)
        if self._body_rules:
            body_matches = _match_to_dict(self._body_rules.match(
                data=body))
            for body_match in body_matches:
                body_match["location"] = "body"
                matches.append(body_match)
        if self._header_body_rules:
            header_body_matches = _match_to_dict(
                self._header_body_rules.match(data=f"{headers}\n\n{body}"))
            for header_body_match in header_body_matches:
                header_body_match["location"] = "header_body"
                matches.append(header_body_match)
        if self._attachment_rules:
            matches += self._scan_attachments(attachments,
                                              max_zip_depth=max_zip_depth)

        return matches
