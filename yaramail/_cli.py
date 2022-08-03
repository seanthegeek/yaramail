"""A command-line interface to yaramail"""

import logging
import argparse
import os
from glob import glob
from sys import stdin

import simplejson
from mailsuite.utils import parse_email
from yaramail import __version__, MailScanner

logger = logging.getLogger("yaramail")

arg_parser = argparse.ArgumentParser(
    "A YARA scanner for emails",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
arg_parser.add_argument("scan_path", type=str,
                        help="The file(s) to scan. Wildcards allowed."
                             "Use - to read from stdin.")
arg_parser.add_argument("-V", "--version", action="version",
                        version=__version__)
arg_parser.add_argument("-v", "--verbose", action="store_true",
                        help="Output the entire parsed email")
arg_parser.add_argument("--output", "-o", type=str,
                        help="Redirect output to a file")
rules_help = "A path to a directory that contains YARA rules. Can be " \
             "set by the YARA_RULES_DIR environment variable."
arg_parser.add_argument("--rules", type=str, help=rules_help,
                        default=".")
header_help = "Filename of the header rules file. Can be set by the " \
              "YARA_HEADER_RULES environment variable."
arg_parser.add_argument("--header-rules", type=str, help=header_help,
                        default="header.yar")
body_help = "Filename of the body rules file. Can be set by the " \
            "YARAMAIL_BODY_RULES environment variable."
arg_parser.add_argument("--body-rules", type=str, help=body_help,
                        default="body.yar")
header_body_help = "Filename of the header_body rules file. Can be " \
                   "set by the YARAMAIL_HEADER_BODY_RULES " \
                   "environment variable."
arg_parser.add_argument("--header-body-rules", type=str,
                        help=header_body_help,
                        default="header_body.yar")
attachment_help = "Filename of the attachment rules file. Can be set" \
                  "by the YARAMAIL_ATTACHMENT_RULES environment variable."
arg_parser.add_argument("--attachment-rules", type=str, help=body_help,
                        default="attachment.yar")
passwords_help = "Filename of a list of passwords to try against " \
                 "password-protected files. Can be set by the " \
                 "YARAMAIL_PASSWORDS environment variable"
arg_parser.add_argument("--passwords", type=str, help=passwords_help,
                        default="passwords.txt")
trusted_help = "A path to a file containing a list of trusted domains. Can " \
               "be set by the YARAMAIL_TRUSTED_DOMAINS environment " \
               "variable."
arg_parser.add_argument("--trusted-domains", type=str, help=trusted_help,
                        default="trusted_domains.txt")
trusted_yara_help = "A path to a file containing a list of list of domains " \
                    "that require a YARA safe match. Can be set by the " \
                    "YARAMAIL_TRUSTED_DOMAINS_YARA environment variable."
arg_parser.add_argument("--trusted-domains-yara", type=str,
                        help=trusted_yara_help,
                        default="trusted_domains_yara_safe_required.txt")
test_help = "Test rules based on verdicts matching the name of the folder a " \
            "sample is in"
arg_parser.add_argument("-t", "--test", action="store_true",
                        help=test_help)


def _main():
    args = arg_parser.parse_args()

    use_stdin = args.scan_path[0] == "-"
    if not use_stdin:
        args.scan_path = glob(str(args.scan_path))

    if "YARAMAIL_RULES_DIR" in os.environ:
        args.rules = os.environ["YARAMAIL_RULES_DIR"]
    if "YARAMAIL_HEADER_RULES" in os.environ:
        args.header_rules = os.environ["YARAMAIL_HEADER_RULES"]
    args.header_rules = os.path.join(args.rules, args.header_rules)
    if not os.path.exists(args.header_rules):
        error = f"{args.header_rules} does not exist. Skipping " \
                f"header-only scans."
        logger.warning(error)
        args.header_rules = None
    if "YARAMAIL_BODY_RULES" in os.environ:
        args.body_rules = os.environ["YARAMAIL_BODY_RULES"]
    args.body_rules = os.path.join(args.rules, args.body_rules)
    if not os.path.exists(args.body_rules):
        error = f"{args.body_rules} does not exist. Skipping body-only scans."
        logger.warning(error)
        args.body_rules = None
    if "YARAMAIL_HEADER_BODY_RULES" in os.environ:
        args.header_body_rules = os.environ["YARAMAIL_HEADER_BODY_RULES"]
    args.header_body_rules = os.path.join(args.rules, args.header_body_rules)
    if not os.path.exists(args.header_body_rules):
        error = f"{args.header_body_rules} does not exist. Skipping " \
                f"header_body scans."
        logger.warning(error)
        args.header_body_rules = None
    if "YARAMAIL_ATTACHMENT_RULES" in os.environ:
        args.attachment_rules = os.environ["YARAMAIL_ATTACHMENT_RULES"]
    args.attachment_rules = os.path.join(args.rules, args.attachment_rules)
    if not os.path.exists(args.attachment_rules):
        error = f"{args.attachment_rules} does not exist. Skipping " \
                f"attachment scans."
        logger.warning(error)
        args.attachment_rules = None
    if "YARAMAIL_PASSWORDS" in os.environ:
        args.passwords = os.environ["YARAMAIL_PASSWORDS"]
    args.passwords = os.path.join(args.rules, args.passwords)
    if args.passwords and not os.path.exists(args.passwords):
        error = f"{args.passwords} does not exist. Skipping password " \
                f"brute force attempts."
        logger.warning(error)
        args.passwords = None
    if "YARAMAIL_TRUSTED_DOMAINS" in os.environ:
        args.trusted_domains = os.environ["YARAMAIL_TRUSTED_DOMAINS"]
    args.trusted_domains = os.path.join(args.rules, args.trusted_domains)
    if args.trusted_domains and not os.path.exists(args.trusted_domains):
        error = f"{args.trusted_domains} does not exist. Skipping trusted " \
                f"domain check."
        logger.warning(error)
        args.trusted_domains = None
    if "YARAMAIL_TRUSTED_DOMAINS_YARA" in os.environ:
        args.trusted_domains_yara = os.environ["YARAMAIL_TRUSTED_DOMAINS_YARA"]
    args.trusted_domains_yara = os.path.join(args.rules,
                                             args.trusted_domains_yara)
    if args.trusted_domains_yara and not os.path.exists(
            args.trusted_domains_yara):
        error = f"{args.trusted_domains_yara} does not exist. Skipping " \
                f"trusted domain check with required safe YARA verdict."
        logger.warning(error)
        args.trusted_domains_yara = None

    trusted_domains = []
    if args.trusted_domains is not None:
        try:
            with open(args.trusted_domains) as trusted_domains_file:
                trusted_domains = trusted_domains_file.read().strip().split(
                    "\n")
        except Exception as e:
            logger.error(f"Error reading {args.trusted_domains}: {e}")
    trusted_domains_yara_safe = []
    if args.trusted_domains_yara is not None:
        try:
            with open(args.trusted_domains_yara) as f:
                trusted_domains_yara_safe = f.read().strip().split(
                    "\n")
        except Exception as e:
            logger.error(f"Error reading {args.trusted_domains}: {e}")

    try:
        scanner = MailScanner(
            header_rules=args.header_rules,
            body_rules=args.body_rules,
            header_body_rules=args.header_body_rules,
            passwords=args.passwords,
            trusted_domains=trusted_domains,
            trusted_domains_yara_safe_required=trusted_domains_yara_safe)
    except Exception as e:
        scanner = MailScanner()
        logger.error(f"Failed to parse YARA rules: {e}")
        exit(-1)

    def test_rules(samples_dir):
        """Test YARA rules against known email samples"""
        if not os.path.isdir(samples_dir):
            logger.error(f"{samples_dir} is not a directory")
            exit(-1)
        logger.info("Testing email rules...")
        test_failures = 0
        total = 0
        for dirname, dirnames, filenames in os.walk(samples_dir):
            for directory in dirnames:
                category = directory
                for dirname_, dirnames_, filenames_ in os.walk(
                        os.path.join(samples_dir, directory)):
                    for filename in filenames_:
                        if not str(filename).lower().endswith(".eml"):
                            continue
                        msg_path = os.path.join(dirname_, filename)
                        total += 1
                        try:
                            with open(msg_path, "r") as msg_file:
                                email = msg_file.read()
                            results = scanner.scan_email(email)
                            verdict = results["verdict"]
                            if verdict != category:
                                logger.warning(
                                    f"Fail: {msg_path} - verdict {verdict}; "
                                    f"expected {category}: {results}")
                                test_failures += 1
                        except Exception as e_:
                            logger.warning(f"{msg_path}: {e_}")
                            test_failures += 1
                            exit()

        passed = total - test_failures
        logger.info(f"\n{passed}/{total} emails passed\n")
        exit(test_failures)

    if args.test:
        test_rules(args.scan_path[0])

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
            scan_results = scanner.scan_email(parsed_email)
            parsed_email["yaramail"] = scan_results
        except Exception as e:
            logger.error(f"Failed to scan {file_path}: {e}")
            continue
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
            with open(args.output, "w") as output_file:
                output_file.write(scanned_emails)
        except Exception as e:
            logger.error(f"Error writing {args.output}: {e}")
    else:
        print(scanned_emails)


if __name__ == "__main__":
    _main()
