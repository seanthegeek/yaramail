import logging
from typing import Union, Optional, Any, overload
import re
import binascii
from os import path, listdir
from io import IOBase, BytesIO, StringIO
import zipfile

import yara
import pdftotext

from mailsuite.utils import parse_email, from_trusted_domain, decode_base64

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

__version__ = "3.3.0"


delimiters = [
    'r"',
    r"'",
    r"`",
    r"\*",
    r"\*\*",
    r"_",
    r"|",
    r"”",
    r"”",
    r"’",
    r"‚",
    r"＂",
    r"“",
    r"〝",
    r"‟",
    r"〞",
    r"”",
    ("❝", r"❞"),
    (r"❮", r"❯"),
    (r"\(", r"\)"),
    (r"\[", r"\]"),
    (r"\{", r"\}"),
    (r"<", r">"),
    (r">", "</"),
    (r"”", r"„"),
    (r"‘", r"’"),
    (r"‹", "›"),
    (r"»", "«"),
    (r"«", r"»"),
    (r"「", r"」"),
    (r"〔", r"〕"),
    (r"『", r"』"),
    (r"「", r"」"),
    (r"❬", "❭"),
]

password_regex = [re.compile(r"\s*(\S+)\s*", re.MULTILINE)]
for delimiter in delimiters:
    if isinstance(delimiter, str):
        regex = re.compile(f"{delimiter}(.+){delimiter}", re.MULTILINE)
        password_regex.append(regex)
        regex = re.compile(f"{delimiter}.+{delimiter}", re.MULTILINE)
        password_regex.append(regex)
    elif isinstance(delimiter, tuple):
        regex = re.compile(f"{delimiter[0]}(.+){delimiter[1]}", re.MULTILINE)
        password_regex.append(regex)
        regex = re.compile(f"{delimiter[0]}.+{delimiter[1]}", re.MULTILINE)
        password_regex.append(regex)


def _carve_passwords(content: str) -> list[str]:
    passwords = []
    for _regex in password_regex:
        matches = _regex.findall(content)
        passwords += matches
    additional_passwords = []
    for password in passwords:
        # Make object type clear to IDEs
        password = str(password)
        # Account for any extra spaces added during markdown conversion
        if " " in password:
            additional_passwords.append(password.replace(" ", ""))
            passwords += additional_passwords

    return passwords


def _deduplicate_list(og_list: list):
    new_list = []
    for item in og_list:
        if item not in new_list:
            new_list.append(item)
    return new_list


@overload
def _match_to_dict(match: yara.Match) -> dict[str, Any]: ...
@overload
def _match_to_dict(match: list[yara.Match]) -> list[dict[str, Any]]: ...  # pyright: ignore[reportOverlappingOverload]


def _match_to_dict(
    match: Union[yara.Match, list[yara.Match]],
) -> Union[dict[str, Any], list[dict[str, Any]]]:
    def match_to_dict_(_match: yara.Match) -> dict[str, Any]:
        strings: list[Any] = []
        for s in _match.strings:
            if isinstance(s, tuple):
                strings.append(s)
            else:
                for i in s.instances:
                    strings.append((i.offset, s.identifier, i.matched_data))
        strings = sorted(strings, key=lambda x: x[0])
        return dict(
            rule=_match.rule,
            namespace=_match.namespace,
            tags=_match.tags,
            meta=_match.meta,
            strings=strings,
            warnings=[],
        )

    if isinstance(match, list):
        matches = match.copy()
        for i in range(len(matches)):
            matches[i] = match_to_dict_(matches[i])
        return matches
    elif isinstance(match, yara.Match):
        return match_to_dict_(match)
    raise TypeError(f"Unsupported match type: {type(match)!r}")


def _is_pdf(file_bytes: bytes) -> bool:
    try:
        return file_bytes.startswith(b"\x25\x50\x44\x46\x2d")
    except TypeError:
        return False


def _is_zip(file_bytes: bytes) -> bool:
    try:
        return file_bytes.startswith(b"\x50\x4b\03\04")
    except TypeError:
        return False


def _pdf_to_markdown(pdf_bytes: bytes) -> str:
    if not _is_pdf(pdf_bytes):
        raise ValueError("Not a PDF file")
    with BytesIO(pdf_bytes) as f:
        return "\n\n".join(pdftotext.PDF(f))


def _input_to_str_list(_input: Union[list[str], str, IOBase, None]) -> list[str]:
    _list: list[str] = []
    if _input is None:
        return _list
    if isinstance(_input, list):
        _list = _input
    if isinstance(_input, str):
        if path.exists(_input):
            with open(_input) as f:
                _list = f.read().split("\n")
    if isinstance(_input, StringIO):
        _list = _input.read().split("\n")
    try:
        _list.remove("")
    except ValueError:
        pass
    return _list


def _compile_rules(rules: Union[yara.Rules, IOBase, str]) -> yara.Rules:
    if isinstance(rules, yara.Rules):
        return rules
    if isinstance(rules, IOBase):
        rules = rules.read()
    if isinstance(rules, str):
        if not path.exists(rules):
            return yara.compile(source=rules)
        if not path.isdir(rules):
            return yara.compile(filepath=rules)
        rules_str = ""
        for filename in listdir(rules):
            file_path = path.join(rules, filename)
            if not path.isdir(file_path):
                with open(file_path) as rules_file:
                    rules_str += rules_file.read()
        return yara.compile(source=rules_str)
    raise TypeError(f"Unsupported rules type: {type(rules)!r}")


class MailScanner(object):
    def __init__(
        self,
        header_rules: Optional[Union[str, IOBase, yara.Rules]] = None,
        body_rules: Optional[Union[str, IOBase, yara.Rules]] = None,
        header_body_rules: Optional[Union[str, IOBase, yara.Rules]] = None,
        attachment_rules: Optional[Union[str, IOBase, yara.Rules]] = None,
        passwords: Optional[Union[list, IOBase, str]] = None,
        max_zip_depth: Optional[int] = None,
        implicit_safe_domains: Optional[Union[list[str], IOBase, str]] = None,
        allow_multiple_authentication_results: bool = False,
        use_authentication_results_original: bool = False,
    ):
        """
        A YARA scanner for emails that can also check Authentication-Results
        headers.

        Args:

            header_rules: Rules that only apply to email header content
            body_rules: Rules that only apply to email body content
            header_body_rules: Rules that apply to combined email \
            header and body content
            attachment_rules: Rules that only apply to file \
            attachment content
            passwords: A list of passwords to use when attempting to scan \
            password-protected files
            max_zip_depth: Number of times to recurse into nested ZIP files
            implicit_safe_domains: Always add the ``safe`` category to \
            emails from these domains
            allow_multiple_authentication_results: Allow multiple \
            ``Authentication-Results-Original`` headers when checking \
            authentication results
            use_authentication_results_original: Use the \
            ``Authentication-Results-Original`` header instead of the \
            ``Authentication-Results`` header

        .. note::
          Each ``_rules`` parameter can accept raw rule content, a path to a
          rules file, a file-like object, or a ``yara.Rule`` object.

        .. tip::
          Use the ``include`` directive in the YARA rule files that you
          pass to ``MailScanner`` to include rules from other files. That
          way, rules can be divided into separate files as you see fit.


        .. warning ::
          Authentication results are based on the headers of the email sample,
          so only trust authentication results on emails that have been
          received by trusted mail servers, and not on third-party emails.

        .. warning::
          Set ``allow_multiple_authentication_results`` to ``True``
          **if and only if** the receiving mail service splits the results
          of each authentication method in separate ``Authentication-Results``
          headers **and always** includes DMARC results.

        .. warning::
          Set ``use_authentication_results_original`` to ``True``
          **if and only if** you use an email security gateway that adds an
          ``Authentication-Results-Original`` header, such as Proofpoint or
          Cisco IronPort. This **does not** include API-based email security
          solutions, such as Abnormal Security.

        .. note::
          ``infected`, ``malware``, and the contents of the message body \
            are always tried as passwords.

        .. note::
          Starting in version 2.1.0, the contents of the message body are \
          automatically tried as passwords for password-protected ZIP \
          attachments.
        """
        self._header_rules: Optional[yara.Rules] = (
            _compile_rules(header_rules) if header_rules else None
        )
        self._body_rules: Optional[yara.Rules] = (
            _compile_rules(body_rules) if body_rules else None
        )
        self._header_body_rules: Optional[yara.Rules] = (
            _compile_rules(header_body_rules) if header_body_rules else None
        )
        self._attachment_rules: Optional[yara.Rules] = (
            _compile_rules(attachment_rules) if attachment_rules else None
        )
        self.passwords = _input_to_str_list(passwords)
        self.passwords += ["malware", "infected"]
        self.passwords = _deduplicate_list(self.passwords)
        self.max_zip_depth = max_zip_depth
        self.implicit_safe_domains = _input_to_str_list(implicit_safe_domains)
        allow_multi_auth = allow_multiple_authentication_results
        self.allow_multiple_authentication_results = allow_multi_auth
        use_og_auth = use_authentication_results_original
        self.use_authentication_results_original = use_og_auth

    def _scan_pdf_text(self, payload: Union[bytes, BytesIO]) -> list[dict]:
        if isinstance(payload, BytesIO):
            payload = payload.read()
        if not _is_pdf(payload):
            raise ValueError("Payload is not a PDF file")
        pdf_markdown = _pdf_to_markdown(payload)
        if self._attachment_rules is None:
            return []
        markdown_matches = _match_to_dict(
            self._attachment_rules.match(data=pdf_markdown)
        )
        for match in markdown_matches:
            tags = match["tags"].copy()
            tags.append("pdf2text")
            match["tags"] = _deduplicate_list(tags)

        return markdown_matches

    def _scan_zip(
        self,
        payload: Union[bytes, BytesIO, str],
        filename: Optional[str] = None,
        passwords: Optional[list[Union[str, None]]] = None,
        _current_depth: int = 0,
    ):
        if self._attachment_rules is None:
            return []
        if isinstance(payload, str):
            if not path.exists(payload):
                raise FileNotFoundError(f"{payload} not found")
            with open(payload, "rb") as f:
                payload = f.read()
        if isinstance(payload, BytesIO):
            payload = payload.read()
        if isinstance(payload, bytes):
            if not _is_zip(payload):
                raise ValueError("Payload is not a ZIP file")
        payload = BytesIO(payload)
        _current_depth += 1
        matches = []
        tags = []
        zip_matches = []
        member_content = None
        with zipfile.ZipFile(payload) as zip_file:
            for name in zip_file.namelist():
                if passwords is None:
                    passwords = []
                if None not in passwords:
                    passwords.append(None)
                if "infected" not in passwords:
                    passwords.append("infected")
                for password in passwords:
                    if isinstance(password, str):
                        password = password.encode("utf-8")
                    matches = []
                    try:
                        with zip_file.open(name, pwd=password) as member:
                            tags = ["zip"]
                            location = name
                            if filename:
                                location = "{}:{}".format(filename, name)
                            member_content = member.read()
                            matches = _match_to_dict(
                                self._attachment_rules.match(data=member_content)
                            )
                            break
                    except RuntimeError:
                        continue

                if member_content is None:
                    logger.warning("Unable to read the contents of the ZIP file")
                    return zip_matches
                for match in matches:
                    location = None
                    if "location" in match:
                        existing_location = match["location"]
                        location = f"{existing_location}:{location}"
                    match["location"] = location
                zip_matches += matches
                if _is_pdf(member_content):
                    try:
                        zip_matches += self._scan_pdf_text(member_content)
                    except Exception as e:
                        logger.warning(
                            "Unable to convert PDF to markdown. "
                            f"{e} Scanning raw file content only"
                            "."
                        )
                elif _is_zip(member_content):
                    max_depth = self.max_zip_depth
                    if max_depth is None or _current_depth > max_depth:
                        zip_matches += self._scan_zip(
                            member_content,
                            filename=name,
                            passwords=passwords,
                            _current_depth=_current_depth,
                        )
                for match in zip_matches:
                    match["tags"] = _deduplicate_list(match["tags"] + tags)

        return zip_matches

    def _scan_attachments(
        self, attachments: Union[list, dict], passwords: Optional[list] = None
    ) -> list[dict]:
        def add_location(_attachment_matches: list[dict], _filename: str):
            for match in _attachment_matches:
                base_location = f"attachment:{_filename}"
                if "location" in match:
                    og_location = match["location"]
                    match["location"] = f"{base_location}:{og_location}"
                else:
                    match["location"] = base_location
            return _attachment_matches

        if passwords is None:
            passwords = []
        passwords = passwords + self.passwords
        combined_attachment_matches = []
        if isinstance(attachments, dict):
            attachments = [attachments]
        for attachment in attachments:
            filename = attachment["filename"]
            file_extension = filename.lower().split(".")[-1]
            payload = attachment["payload"]
            is_binary = attachment.get("binary", False)
            if is_binary:
                try:
                    payload = decode_base64(attachment["payload"])
                except binascii.Error:
                    pass
            if self._attachment_rules is None:
                return []
            attachment_matches = _match_to_dict(
                self._attachment_rules.match(data=payload)
            )
            attachment_matches = add_location(attachment_matches, filename)
            combined_attachment_matches += attachment_matches
            if is_binary and _is_pdf(payload):
                try:
                    attachment_matches = self._scan_pdf_text(payload)
                    attachment_matches = add_location(attachment_matches, filename)
                    combined_attachment_matches += attachment_matches
                except Exception as e:
                    logger.warning(
                        f"Unable to convert {filename} to markdown. {e}. "
                        f"Scanning raw file content only."
                    )
            elif is_binary and _is_zip(payload):
                try:
                    attachment_matches += self._scan_zip(
                        payload, passwords=passwords, filename=filename
                    )
                    attachment_matches = add_location(attachment_matches, filename)
                    combined_attachment_matches += attachment_matches
                except UserWarning as e:
                    logger.warning(f"Unable to scan {filename}. {e}.")
            elif file_extension in ["eml", "msg"]:
                try:
                    matches = self.scan_email(parse_email(payload))
                    combined_attachment_matches += matches
                except UserWarning as e:
                    logger.warning(f"Unable to scan {filename}. {e}.")

        return combined_attachment_matches

    def scan_email(
        self,
        email: Union[str, bytes, dict],
        use_raw_headers: bool = False,
        use_raw_body: bool = False,
    ) -> dict:
        """
        Scans an email using YARA rules

        Args:
            email: Email file content or output from \
            ``mailsuite.utils.parse_email()``
            use_raw_headers: Scan headers with indentations included
            use_raw_body: Scan the raw email body instead of converting it to \
            Markdown first

        Returns: A dictionary

        The returned dictionary contains the following key-value pairs:

        - ``matches`` - A list of YARA match dictionaries

          - ``name`` - The name of the rule.
          - ``namespace`` - The namespace of the rule.
          - ``meta`` - A dictionary of key-value pairs from the meta section.
          - ``tags`` - A list of the rule's tags.
          - ``strings`` - A list of lists identifying strings or patterns that
            match.

             0. The location/offset of the identified string
             1. The variable name of the string/pattern in the rule
             2. The matching string/pattern content

        - ``categories`` - A list of categories of YARA matches
        - ``msg_from_domain`` -  Message From domain details

          - ``domain``  - The message From domain
          - ``authenticated`` - bool: domain is authenticated
          - ``implicit_safe`` - bool: domain is in the implicit_safe_domains
            list

        - ``has_attachment`` - bool: The email sample has an attachment

        - ``warnings`` - A list of warnings. Possible warnings include:

          - ``domain-authentication-failed`` - Authentication of the message
            From domain failed
          - ``from-domain-mismatch`` - The message From domain did not exactly
            match the value of the ``meta`` key ``from_domain``
          - ``safe-rule-missing-from-domain`` - The rule is missing a
            ``from_domain`` ``meta`` key that is required for rules with the
            ``category`` meta key set to ``safe``
          - ``unexpected-attachment`` - An email win an attachment matched a
            rule with the ``meta`` key ``no attachment`` or ``no_attachments``
            set to ``true``

        - ``location`` - The part of the email where the match was
          found, for example:

          - ``header``
          - ``body``
          - ``header_body``
          - ``attachment:filename``
          - ``attachment:example.zip:evil.js``
          - ``attachment:first.zip:nested.zip:evil.js``
          - ``attachment:evil.eml:attachment:example.zip:evil.js``

        - ``verdict`` - The verdict of the scan. Possible verdicts include:

           - ``None`` - No categories matched
           - ``safe`` - The email is considered safe
           - ``ambiguous`` - Multiple categories matched
           - Any custom ``category`` specified in the ``meta`` section of a
             YARA rule
        """
        if isinstance(email, dict):
            parsed_email = email
        else:
            parsed_email = parse_email(email)
        msg_from_domain = None
        if "from" in parsed_email and parsed_email["from"] is not None:
            if "domain" in parsed_email["from"]:
                msg_from_domain = parsed_email["from"]["domain"]
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
        attachments = []
        if "attachments" in parsed_email:
            attachments = parsed_email["attachments"]

        matches = []
        if self._header_rules is not None:
            header_matches = _match_to_dict(self._header_rules.match(data=headers))
            for header_match in header_matches:
                header_match["location"] = "header"
                matches.append(header_match)
        if self._body_rules is not None:
            body_matches = _match_to_dict(self._body_rules.match(data=body))
            for body_match in body_matches:
                body_match["location"] = "body"
                matches.append(body_match)
        if self._header_body_rules is not None:
            header_body_matches = _match_to_dict(
                self._header_body_rules.match(data=f"{headers}\n\n{body}")
            )
            for header_body_match in header_body_matches:
                header_body_match["location"] = "header_body"
                matches.append(header_body_match)
        if self._attachment_rules is not None:
            passwords = _carve_passwords(parsed_email["body_markdown"])
            matches += self._scan_attachments(attachments, passwords=passwords)

        verdict = None
        multi_auth_headers = self.allow_multiple_authentication_results
        use_og_auth_results = self.use_authentication_results_original
        implicit_safe_domain = from_trusted_domain(
            parsed_email,
            self.implicit_safe_domains,
            allow_multiple_authentication_results=multi_auth_headers,
            use_authentication_results_original=use_og_auth_results,
        )
        authenticated_domain = from_trusted_domain(
            parsed_email,
            [msg_from_domain or ""],
            allow_multiple_authentication_results=multi_auth_headers,
            use_authentication_results_original=use_og_auth_results,
        )
        categories = []
        has_attachment = len(attachments) > 0
        for match in matches:
            auth_optional = False
            if "authentication_optional" in match["meta"]:
                auth_optional = match["meta"]["authentication_optional"]
            if "auth_optional" in match["meta"]:
                auth_optional = match["meta"]["auth_optional"]
            passed_authentication = authenticated_domain or auth_optional
            no_attachment = False
            if "no_attachments" in match["meta"]:
                no_attachment = match["meta"]["no_attachments"]
            if "no_attachment" in match["meta"]:
                no_attachment = match["meta"]["no_attachment"]
            if no_attachment and has_attachment:
                match["warnings"].append("unexpected-attachment")
            rule_from_domains = None
            if "from_domains" in match["meta"]:
                rule_from_domains = match["meta"]["from_domains"]
            elif "from_domain" in match["meta"]:
                rule_from_domains = match["meta"]["from_domain"]
            if rule_from_domains is not None:
                rule_from_domains = rule_from_domains.split(" ")
                if msg_from_domain not in rule_from_domains:
                    match["warnings"].append("from-domain-mismatch")
                if not passed_authentication:
                    match["warnings"].append("domain-authentication-failed")
            if "category" in match["meta"]:
                if match["meta"]["category"] == "safe":
                    if rule_from_domains is None:
                        match["warnings"].append("safe-rule-missing-from-domain")
                if len(match["warnings"]) == 0:
                    categories.append(match["meta"]["category"].lower())

        if implicit_safe_domain:
            categories.append("safe")
        categories = _deduplicate_list(categories)
        if len(categories) == 1:
            verdict = categories[0]
        elif len(categories) > 1:
            verdict = "ambiguous"

        msg_from_domain_results = dict(
            domain=msg_from_domain,
            authenticated=authenticated_domain,
            implicit_safe=implicit_safe_domain,
        )

        return dict(
            matches=matches,
            categories=categories,
            msg_from_domain=msg_from_domain_results,
            has_attachment=has_attachment,
            verdict=verdict,
        )
