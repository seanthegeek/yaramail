"""A command-line interface to yaramail"""

import logging
import argparse
import os
from glob import glob
from sys import stdin

import simplejson
from mailsuite.utils import parse_email
from yaramail import __version__, MailScanner

formatter = logging.Formatter(
    fmt="%(levelname)s|%(message)s", datefmt="%Y-%m-%d:%H:%M:%S"
)
handler = logging.StreamHandler()
handler.setFormatter(formatter)

logger = logging.getLogger("yaramail")
logger.setLevel(logging.INFO)
logger.addHandler(handler)

arg_parser = argparse.ArgumentParser(
    "A YARA scanner for emails", formatter_class=argparse.ArgumentDefaultsHelpFormatter
)
arg_parser.add_argument(
    "scan_path",
    type=str,
    help="The file(s) to scan. Wildcards allowed. "
    "Use - to read from stdin. When used with "
    "-t/--test, this must be the directory where "
    "samples are stored, instead of an individual "
    "file or wildcard path.",
)
arg_parser.add_argument("-V", "--version", action="version", version=__version__)
arg_parser.add_argument(
    "-v", "--verbose", action="store_true", help="Output the entire parsed email."
)
arg_parser.add_argument(
    "-m",
    "--multi-auth",
    action="store_true",
    help="Allow multiple Authentication-Results headers",
)
arg_parser.add_argument(
    "-o",
    "--auth-original",
    action="store_true",
    help="Use Authentication-Results-Original instead of Authentication-Results",
)
arg_parser.add_argument(
    "-r",
    "--raw-headers",
    action="store_true",
    help="Scan headers with indentations included",
)
arg_parser.add_argument(
    "-b",
    "--raw-body",
    action="store_true",
    help="Scan the raw email body instead of converting it to Markdown first",
)
arg_parser.add_argument(
    "-s",
    "--sld",
    action="store_true",
    help="Use From domain the Second-Level Domain (SLD) "
    "for authentication in addition to the "
    "Fully-Qualified Domain Name (FQDN)",
)
arg_parser.add_argument(
    "-t",
    "--test",
    action="store_true",
    help="Test rules based on verdicts matching the name "
    "of the subdirectory a sample is in",
)
arg_parser.add_argument("--output", type=str, help="Redirect output to a file")
arg_parser.add_argument(
    "--rules",
    type=str,
    help="A path to a directory that contains YARA rules",
    default=".",
)
arg_parser.add_argument(
    "--header-rules",
    type=str,
    help="Filename of the header rules file",
    default="header.yar",
)
arg_parser.add_argument(
    "--body-rules", type=str, help="Filename of the body rules file", default="body.yar"
)
arg_parser.add_argument(
    "--header-body-rules",
    type=str,
    help="Filename of the header_body rules file",
    default="header_body.yar",
)
arg_parser.add_argument(
    "--attachment-rules",
    type=str,
    help="Filename of the attachment rules file",
    default="attachment.yar",
)
arg_parser.add_argument(
    "--passwords",
    type=str,
    help="Filename of a list of passwords to try against "
    "password-protected files in addition to email "
    "body content",
    default="passwords.txt",
)
arg_parser.add_argument(
    "--implicit-safe-domains",
    type=str,
    help="Filename of a list of message From domains that "
    "return a safe verdict if the domain is "
    "authenticated and no YARA categories match "
    "other than safe",
    default="implicit_safe_domains.txt",
)
arg_parser.add_argument(
    "--max-zip-depth",
    type=int,
    help="The maximum number of times to recurse into nested ZIP files",
)


def _main():
    args = arg_parser.parse_args()

    use_stdin = args.scan_path[0] == "-"
    if not use_stdin:
        og_scan_path = args.scan_path
        args.scan_path = glob(str(args.scan_path))
        if len(args.scan_path) == 0:
            logger.error(f"No files matching {og_scan_path} were found.")
            exit(-1)

    args.header_rules = os.path.join(args.rules, args.header_rules)
    if not os.path.exists(args.header_rules):
        logger.warning(
            f"{args.header_rules} does not exist. Skipping header-only scans."
        )
        args.header_rules = None
    args.body_rules = os.path.join(args.rules, args.body_rules)
    if not os.path.exists(args.body_rules):
        logger.warning(f"{args.body_rules} does not exist. Skipping body-only scans.")
        args.body_rules = None
    args.header_body_rules = os.path.join(args.rules, args.header_body_rules)
    if not os.path.exists(args.header_body_rules):
        logger.warning(
            f"{args.header_body_rules} does not exist. Skipping header_body scans."
        )
        args.header_body_rules = None
    args.attachment_rules = os.path.join(args.rules, args.attachment_rules)
    if not os.path.exists(args.attachment_rules):
        logger.warning(
            f"{args.attachment_rules} does not exist. Skipping attachment scans."
        )
        args.attachment_rules = None
    args.passwords = os.path.join(args.rules, args.passwords)
    if not os.path.exists(args.passwords):
        logger.warning(f"{args.passwords} does not exist.")
        args.passwords = None
    args.implicit_safe_domains = os.path.join(args.rules, args.implicit_safe_domains)
    if not os.path.exists(args.implicit_safe_domains):
        logger.warning(f"{args.implicit_safe_domains} does not exist.")
        args.implicit_safe_domains = None

    yara_safe_optional_domains = []
    if args.implicit_safe_domains is not None:
        try:
            with open(args.implicit_safe_domains) as yara_optional_file:
                yara_safe_optional_domains = yara_optional_file.read().strip()
                yara_safe_optional_domains = yara_safe_optional_domains.split("\n")
        except Exception as e:
            logger.error(f"Error reading {args.implicit_safe_domains}: {e}")

    try:
        scanner = MailScanner(
            header_rules=args.header_rules,
            body_rules=args.body_rules,
            header_body_rules=args.header_body_rules,
            attachment_rules=args.attachment_rules,
            implicit_safe_domains=yara_safe_optional_domains,
            passwords=args.passwords,
            allow_multiple_authentication_results=args.multi_auth,
            use_authentication_results_original=args.auth_original,
            max_zip_depth=args.max_zip_depth,
        )
    except Exception as e:
        scanner = MailScanner()
        logger.error(f"Failed to parse YARA rules: {e}")
        exit(-1)

    def _prune_parsed_email(_parsed_email):
        del _parsed_email["text_plain"]
        del _parsed_email["text_html"]
        del _parsed_email["body"]
        for attachment in _parsed_email["attachments"]:
            del attachment["payload"]
        if args.raw_headers:
            del _parsed_email["headers_string"]
        else:
            del _parsed_email["raw_headers"]
        if args.raw_body:
            del _parsed_email["body_markdown"]
        else:
            del _parsed_email["raw_body"]
        return _parsed_email

    def _test_rules(samples_dir, verbose=False):
        """Test YARA rules against known email samples"""
        if not os.path.isdir(samples_dir):
            logger.error(f"{samples_dir} is not a directory")
            exit(-1)
        test_failures = []
        total = 0
        for dirname, dirnames, filenames in os.walk(samples_dir):
            for directory in dirnames:
                category = directory
                for dirname_, dirnames_, filenames_ in os.walk(
                    os.path.join(samples_dir, directory)
                ):
                    for filename in filenames_:
                        if not str(filename).lower().endswith(".eml"):
                            continue
                        msg_path = os.path.join(dirname_, filename)
                        total += 1
                        try:
                            with open(msg_path, "r") as msg_file:
                                email = msg_file.read()
                            _parsed_email = parse_email(email)
                            results = scanner.scan_email(
                                _parsed_email,
                                use_raw_headers=args.raw_headers,
                                use_raw_body=args.raw_body,
                            )
                            verdict = results["verdict"]
                            if verbose:
                                pruned_email = _prune_parsed_email(_parsed_email)
                                pruned_email["yaramail"] = results
                                results = pruned_email
                            if verdict != category:
                                failure = dict(
                                    path=msg_path,
                                    verdict=verdict,
                                    expected=category,
                                    results=results,
                                )
                                test_failures.append(failure)
                        except Exception as e_:
                            logger.error(f"{msg_path}: {e_}")
                            exit(1)
        num_failed = len(test_failures)
        passed = total - num_failed

        print(
            simplejson.dumps(
                dict(
                    test_failures=test_failures,
                    passed=passed,
                    failed=num_failed,
                    total=total,
                ),
                indent=2,
            )
        )
        exit(num_failed)

    if args.test:
        _test_rules(args.scan_path[0], verbose=args.verbose)

    scanned_emails = {}
    for file_path in args.scan_path:
        if use_stdin:
            break
        if not os.path.exists(file_path):
            logger.error(f"{file_path} does not exist.")
            continue
        try:
            with open(file_path, "rb") as email_file:
                parsed_email = parse_email(email_file.read())
        except Exception as e:
            logger.error(f"Failed to parse email at {file_path}: {e}")
            continue
        try:
            scan_results = scanner.scan_email(
                parsed_email,
                use_raw_headers=args.raw_headers,
                use_raw_body=args.raw_body,
            )
            parsed_email["yaramail"] = scan_results
        except Exception as e:
            logger.error(f"Failed to scan {file_path}: {e}")
            continue
        parsed_email = _prune_parsed_email(parsed_email)
        if args.verbose:
            scanned_emails[file_path] = parsed_email
        else:
            scanned_emails[file_path] = parsed_email["yaramail"]

    if use_stdin:
        try:
            parsed_email = parse_email(stdin.read())
            if args.verbose:
                scanned_emails = parsed_email
            else:
                scanned_emails = parsed_email["yaramail"]

        except Exception as e:
            logger.error(f"Failed to scan email provided via stdin: {e}")

    scanned_emails = simplejson.dumps(scanned_emails, indent=2)
    if args.output is not None:
        try:
            if len(scanned_emails) > 0:
                with open(args.output, "w") as output_file:
                    output_file.write(scanned_emails)
            else:
                exit(-1)
        except Exception as e:
            logger.error(f"Error writing {args.output}: {e}")
    else:
        if len(scanned_emails) > 0:
            print(scanned_emails)
        else:
            exit(-1)


if __name__ == "__main__":
    _main()
