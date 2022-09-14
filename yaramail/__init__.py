import logging
from typing import Union, List, Dict
import re
import binascii
from os import path, listdir
from io import IOBase, BytesIO, StringIO
import zipfile

import yara
import pdftotext
from publicsuffix2 import get_sld

from mailsuite.utils import parse_email, from_trusted_domain, decode_base64

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

__version__ = "2.1.0"


delimiters = ["\"", "'", "`", "\*\*",
              "_", ("\(", "\)"), ("\[", "\]"), ("\{", "\}")]

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


def _carve_passwords(content: str) -> List[str]:
    passwords = []
    for regex in password_regex:
        matches = regex.findall(content)
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
    try:
        return file_bytes.startswith(b"\x25\x50\x44\x46\x2D")
    except TypeError:
        return False


def _is_zip(file_bytes: bytes) -> bool:
    try:
        return file_bytes.startswith(b"\x50\x4B\03\04")
    except TypeError:
        return False


def _pdf_to_markdown(pdf_bytes: bytes) -> str:
    if not _is_pdf(pdf_bytes):
        raise ValueError("Not a PDF file")
    with BytesIO(pdf_bytes) as f:
        return "\n\n".join(pdftotext.PDF(f))


def _input_to_str_list(_input: Union[List[str], str, IOBase]) -> list:
    _list = []
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
    if not path.exists(rules):
        return yara.compile(source=rules)
    if not path.isdir(rules):
        return yara.compile(filepath=rules)
    rules_str = ""
    for filename in listdir():
        file_path = path.join(rules, filename)
        if not path.isdir(file_path):
            with open(file_path) as rules_file:
                rules_str += rules_file.read()
    return yara.compile(source=rules_str)


class MailScanner(object):
    def __init__(self, header_rules: Union[str, IOBase, yara.Rules] = None,
                 body_rules: Union[str, IOBase, yara.Rules] = None,
                 header_body_rules: Union[str, IOBase, yara.Rules] = None,
                 attachment_rules: Union[str, IOBase, yara.Rules] = None,
                 passwords: Union[List[str], IOBase, str] = None,
                 max_zip_depth: int = None,
                 trusted_domains: Union[List[str], IOBase, str] = None,
                 trusted_domains_yara_safe_required: Union[List[str], IOBase,
                                                           str] = None,
                 include_sld_in_auth_check: bool = False,
                 allow_multiple_authentication_results: bool = False,
                 use_authentication_results_original: bool = False):
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
            trusted_domains: A list of message From domains that return a \
            ``safe`` verdict if the domain is authenticated and no YARA \
            categories match other than ``safe``
            trusted_domains_yara_safe_required: A list of message From \
            domains that return a ``safe`` verdict if the domain is \
            authenticated **and** the email itself has a YARA ``safe`` verdict
            include_sld_in_auth_check: Check authentication results based on \
            Second-Level Domain (SLD) in addition to the \
            Fully-Qualified Domain Name (FQDN)
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
          ``infected`` and ``malware`` and the contents of the message body \
            are always tried as passwords.

        .. note::
          Starting in version 2.1.0, the contents of the message body are \
          automatically tried as passwords for password-protected ZIP \
          attachments.
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
        self.passwords = _input_to_str_list(passwords)
        self.passwords += ["malware", "infected"]
        self.passwords = _deduplicate_list(self.passwords)
        self.max_zip_depth = max_zip_depth
        self.trusted_domains = _input_to_str_list(trusted_domains)
        self.trusted_domains_yara_safe_required = _input_to_str_list(
            trusted_domains_yara_safe_required
        )
        self.include_sld_in_auth_check = include_sld_in_auth_check
        allow_multi_auth = allow_multiple_authentication_results
        self.allow_multiple_authentication_results = allow_multi_auth
        use_og_auth = use_authentication_results_original
        self.use_authentication_results_original = use_og_auth

    def _scan_pdf_text(self, payload: Union[bytes, BytesIO]) -> List[Dict]:
        if isinstance(payload, BytesIO):
            payload = payload.read()
        if not _is_pdf(payload):
            raise ValueError("Payload is not a PDF file")
        pdf_markdown = _pdf_to_markdown(payload)
        markdown_matches = _match_to_dict(
            self._attachment_rules.match(data=pdf_markdown))
        for match in markdown_matches:
            tags = match["tags"].copy()
            tags.append("pdf2text")
            match["tags"] = _deduplicate_list(tags)

        return markdown_matches

    def _scan_zip(self, payload: Union[bytes, BytesIO, str],
                  filename: str = None, passwords: List[str] = None,
                  _current_depth: int = 0):
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
        zip_matches = []
        with zipfile.ZipFile(payload) as zip_file:
            for name in zip_file.namelist():
                if passwords is None:
                    passwords == []
                for password in passwords:
                    if isinstance(password, str):
                        password = password.encode("utf-8")
                    member_content = None
                    matches = []
                    try:
                        with zip_file.open(name, pwd=password) as member:
                            tags = ["zip"]
                            location = name
                            if filename:
                                location = "{}:{}".format(filename, name)
                            member_content = member.read()
                            matches = _match_to_dict(
                                self._attachment_rules.match(
                                    data=member_content))
                            break
                    except RuntimeError:
                        continue

                if member_content is None:
                    logger.warning("Unable to read the contents "
                                   "of the ZIP file")
                    return zip_matches
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
                    max_depth = self.max_zip_depth
                    if max_depth is None or _current_depth > max_depth:
                        zip_matches += self._scan_zip(
                            member_content,
                            filename=name,
                            passwords=passwords,
                            _current_depth=_current_depth)
                for match in zip_matches:
                    match["tags"] = _deduplicate_list(match["tags"] + tags)

                return zip_matches

    def _scan_attachments(self, attachments: Union[List, Dict],
                          passwords: List[str] = None) -> List[Dict]:
        def add_location(_attachment_matches: List[Dict], _filename: str):
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
        passwords = [None] + passwords + self.passwords
        combined_attachment_matches = []
        if isinstance(attachments, dict):
            attachments = [attachments]
        for attachment in attachments:
            filename = attachment["filename"]
            file_extension = filename.lower().split(".")[-1]
            payload = attachment["payload"]
            is_binary = attachment.get('binary', False)
            if is_binary:
                try:
                    payload = decode_base64(attachment["payload"])
                except binascii.Error:
                    pass
            attachment_matches = _match_to_dict(
                self._attachment_rules.match(data=payload))
            attachment_matches = add_location(attachment_matches, filename)
            combined_attachment_matches += attachment_matches
            if is_binary and _is_pdf(payload):
                try:
                    attachment_matches = self._scan_pdf_text(payload)
                    attachment_matches = add_location(attachment_matches,
                                                      filename)
                    combined_attachment_matches += attachment_matches
                except Exception as e:
                    logger.warning(
                        f"Unable to convert {filename} to markdown. {e}. "
                        f"Scanning raw file content only.")
            elif is_binary and _is_zip(payload):
                try:
                    attachment_matches += self._scan_zip(
                        payload,
                        passwords=passwords,
                        filename=filename)
                    attachment_matches = add_location(attachment_matches,
                                                      filename)
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

    def scan_email(self, email: Union[str, IOBase, Dict],
                   use_raw_headers: bool = False,
                   use_raw_body: bool = False) -> Dict:
        """
        Scans an email using YARA rules

        Args:
            email: Email file content, a path to an email \
            file, a file-like object, or output from \
            ``mailsuite.utils.parse_email()``
            use_raw_headers: Scan headers with indentations included
            use_raw_body: Scan the raw email body instead of converting it to \
            Markdown first

        Returns: A dictionary

        The returned dictionary contains the following key-value pairs:

        - ``matches`` - A list of YARA match dictionaries
        - ``categories`` - A list of categories of YARA matches
        - ``msg_from_domain`` - The message From domain
        - ``trusted_domain`` - The message From domain is in the
          ``trusted_domains`` list **AND** is authenticated
        - ``trusted_domain_yara_safe_required`` - The message From domain is
          in the ``trusted_domain_yara_safe_required`` list **AND** is
          is authenticated
        - ``auth_optional`` - At least one matching YARA rule has
          ``auth_optional = true`` **AND** ``category = safe`` in its ``meta``
          section
        - ``has_attachment`` - The email sample has an attachment
        - ``verdict`` - The verdict of the scan

        Possible verdicts include:

         - ``None`` - No categories matched
         - ``safe`` - The email is considered safe
         - ``yara_safe_auth_fail`` -  Categorized at ``safe`` by YARA, but
           domain authentication failed
         - ``auth_pass_not_yara_safe`` - Domain authentication passed, but YARA
           did not return the required ``safe`` categorization
         - ``ambiguous`` - Multiple categories matched
         - Any custom ``category`` specified in the ``meta`` section of a YARA
           rule

        Each match dictionary in the returned list contains
        the following key-value pairs:

        - ``name`` - The name of the rule.
        - ``namespace`` - The namespace of the rule.
        - ``meta`` - A dictionary of key-value pairs from the meta section.
        - ``tags`` - A list of the rule's tags.
        - ``strings`` - A list of identified strings or patterns that match.

          Each ``strings`` list item is also a list, with the following values:

              0. The location/offset of the identified string
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
        msg_from_domain = None
        if "from" in parsed_email:
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
            passwords = _carve_passwords(parsed_email["body_markdown"])
            matches += self._scan_attachments(attachments, passwords=passwords)

        verdict = None
        multi_auth_headers = self.allow_multiple_authentication_results
        use_og_auth_results = self.use_authentication_results_original
        trusted_domain = from_trusted_domain(
            parsed_email, self.trusted_domains,
            allow_multiple_authentication_results=multi_auth_headers,
            use_authentication_results_original=use_og_auth_results,
            include_sld=self.include_sld_in_auth_check
        )
        trusted_domain_yara_safe_required = from_trusted_domain(
            parsed_email, self.trusted_domains_yara_safe_required,
            allow_multiple_authentication_results=multi_auth_headers,
            use_authentication_results_original=use_og_auth_results,
            include_sld=self.include_sld_in_auth_check
        )
        auth_optional = False
        categories = []
        has_attachment = len(attachments) > 0
        for match in matches:
            if "no_attachments" in match["meta"]:
                if match["meta"]["no_attachments"] and has_attachment:
                    continue
            if "no_attachment" in match["meta"]:
                if match["meta"]["no_attachment"] and has_attachment:
                    continue
            if "from_domain" in match["meta"]:
                sld = parsed_email["from"]["sld"]
                if sld != get_sld(match["meta"]["from_domain"]):
                    continue
            if "category" in match["meta"]:
                categories.append(match["meta"]["category"])
                if match["meta"]["category"] == "safe":
                    if "auth_optional" in match["meta"] and not auth_optional:
                        auth_optional = match["meta"]["auth_optional"]
        categories = _deduplicate_list(categories)
        if len(categories) == 1:
            verdict = categories[0]
        elif len(categories) > 1:
            verdict = "ambiguous"
        authenticated = any([trusted_domain, trusted_domain_yara_safe_required,
                             auth_optional])
        if verdict == "safe" and not authenticated:
            verdict = "yara_safe_auth_fail"
        if verdict != "safe" and trusted_domain_yara_safe_required:
            verdict = "auth_pass_not_yara_safe"
        if verdict is None and authenticated:
            verdict = "safe"

        safe_required = trusted_domain_yara_safe_required
        return dict(matches=matches, categories=categories,
                    msg_from_domain=msg_from_domain,
                    trusted_domain=trusted_domain,
                    trusted_domain_yara_safe_required=safe_required,
                    auth_optional=auth_optional,
                    has_attachment=has_attachment,
                    verdict=verdict)
