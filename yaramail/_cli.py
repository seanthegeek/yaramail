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
    fmt='%(levelname)s|%(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S')
handler = logging.StreamHandler()
handler.setFormatter(formatter)

logger = logging.getLogger("yaramail")
logger.setLevel(logging.INFO)
logger.addHandler(handler)

arg_parser = argparse.ArgumentParser(
    "A YARA scanner for emails",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
arg_parser.add_argument("scan_path", type=str,
                        help="The file(s) to scan. Wildcards allowed. "
                             "Use - to read from stdin. When used with "
                             "-t/--test, this must be the directory where "
                             "samples are stored, instead of an individual "
                             "file or wildcard path.")
arg_parser.add_argument("-V", "--version", action="version",
                        version=__version__)
arg_parser.add_argument("-v", "--verbose", action="store_true",
                        help="Output the entire parsed email. "
                             "When used with -t/--test, this option outputs "
                             "passing results along with failing results.")
arg_parser.add_argument("-m", "--multi-auth",  action="store_true",
                        help="Allow multiple Authentication-Results headers")
arg_parser.add_argument("-o", "--auth-original", action="store_true",
                        help="Use Authentication-Results-Original instead of "
                             "Authentication-Results")
arg_parser.add_argument("-r", "--raw-headers", action="store_true",
                        help="Scan headers with indentations included")
arg_parser.add_argument("-b", "--raw-body", action="store_true",
                        help="Scan the raw email body instead of converting "
                             "it to Markdown first")
arg_parser.add_argument("-s", "--sld", action="store_true",
                        help="Use From domain the Second-Level Domain (SLD) "
                             "for authentication in addition to the "
                             "Fully-Qualified Domain Name (FQDN)")
arg_parser.add_argument("-t", "--test", action="store_true",
                        help="Test rules based on verdicts matching the name "
                             "of the subdirectory a sample is in")
arg_parser.add_argument("--output", type=str,
                        help="Redirect output to a file")
arg_parser.add_argument("--rules", type=str,
                        help="A path to a directory that contains YARA rules",
                        default=".")
arg_parser.add_argument("--header-rules", type=str,
                        help="Filename of the header rules file",
                        default="header.yar")
arg_parser.add_argument("--body-rules", type=str,
                        help="Filename of the body rules file",
                        default="body.yar")
arg_parser.add_argument("--header-body-rules", type=str,
                        help="Filename of the header_body rules file",
                        default="header_body.yar")
arg_parser.add_argument("--attachment-rules", type=str,
                        help="Filename of the attachment rules file",
                        default="attachment.yar")
arg_parser.add_argument("--passwords", type=str,
                        help="Filename of a list of passwords to try against "
                             "password-protected files in addition to email "
                             "body content",
                        default="passwords.txt")
arg_parser.add_argument("--implicit-safe-domains", type=str,
                        help="Filename of a list of message From domains that "
                             "return a safe verdict if the domain is "
                             "authenticated and no YARA categories match "
                             "other than safe",
                        default="implicit_safe_domains.txt")
arg_parser.add_argument("--max-zip-depth", type=int,
                        help="The maximum number of times to recurse into "
                             "nested ZIP files")


def _main():
    args = arg_parser.parse_args()
    if len(args.scan_path) == 0:
        logger.error("At least one scan_path must be specified")
        exit(-1)

    use_stdin = args.scan_path[0] == "-"
    if not use_stdin:
        args.scan_path = glob(str(args.scan_path))

    args.header_rules = os.path.join(args.rules, args.header_rules)
    if not os.path.exists(args.header_rules):
        logger.warning(f"{args.header_rules} does not exist. Skipping "
                       f"header-only scans.")
        args.header_rules = None
    args.body_rules = os.path.join(args.rules, args.body_rules)
    if not os.path.exists(args.body_rules):
        logger.warning(f"{args.body_rules} does not exist. Skipping body-only "
                       f"scans.")
        args.body_rules = None
    args.header_body_rules = os.path.join(args.rules, args.header_body_rules)
    if not os.path.exists(args.header_body_rules):
        logger.warning(f"{args.header_body_rules} does not exist. Skipping "
                       f"header_body scans.")
        args.header_body_rules = None
    args.attachment_rules = os.path.join(args.rules, args.attachment_rules)
    if not os.path.exists(args.attachment_rules):
        logger.warning(f"{args.attachment_rules} does not exist. Skipping "
                       f"attachment scans.")
        args.attachment_rules = None
    args.passwords = os.path.join(args.rules, args.passwords)
    if not os.path.exists(args.passwords):
        logger.warning(f"{args.passwords} does not exist.")
        args.passwords = None
    args.implicit_safe_domains = os.path.join(
        args.rules,
        args.implicit_safe_domains)
    if not os.path.exists(args.implicit_safe_domains):
        logger.warning(f"{args.implicit_safe_domains} does not exist.")
        args.implicit_safe_domains = None

    yara_safe_optional_domains = []
    if args.implicit_safe_domains is not None:
        try:
            with open(args.implicit_safe_domains) as yara_optional_file:
                yara_safe_optional_domains = yara_optional_file.read().strip()
                yara_safe_optional_domains = yara_safe_optional_domains.split(
                    "\n"
                )
        except Exception as e:
            logger.error(
                f"Error reading {args.implicit_safe_domains}: {e}")

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
            max_zip_depth=args.max_zip_depth
        )
    except Exception as e:
        scanner = MailScanner()
        logger.error(f"Failed to parse YARA rules: {e}")
        exit(-1)

    def _test_rules(samples_dir, verbose=False):
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
                            results = scanner.scan_email(
                                email,
                                use_raw_headers=args.raw_headers,
                                use_raw_body=args.raw_body)
                            verdict = results["verdict"]
                            if verdict != category:
                                results = simplejson.dumps(results)
                                logger.error(
                                    f"fail|path={msg_path}|verdict={verdict}|"
                                    f"expected={category}|results={results}")
                                test_failures += 1
                            elif verbose:
                                logger.info(
                                    f"pass|path={msg_path}|verdict={verdict}|"
                                    f"expected={category}|results={results}")
                        except Exception as e_:
                            logger.warning(f"{msg_path}: {e_}")
                            test_failures += 1
                            exit()

        passed = total - test_failures
        logger.info(f"{passed}/{total} emails passed\n")
        exit(test_failures)

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
                use_raw_body=args.raw_body)
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
