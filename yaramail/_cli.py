"""A command-line interface to yaramail"""

import logging
import argparse
import os
from glob import glob

import simplejson
from mailsuite.utils import parse_email, from_trusted_domain
from yaramail import __version__, MailScanner

logger = logging.getLogger("yaramail")

arg_parser = argparse.ArgumentParser(
    "A YARA scanner for emails",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
arg_parser.add_argument("scan_path", type=str,
                        help="The file(s) to scan (wildcards allowed)")
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
trusted_help = "A path to a file containing a list of trusted domains. Can " \
               "be set by the YARAMAIL_TRUSTED_DOMAINS environment " \
               "variable."
arg_parser.add_argument("--trusted-domains", type=str, help=trusted_help,
                        default="trusted_domains.txt")


def _main():
    args = arg_parser.parse_args()

    args.scan_path = glob(args.scan_path)

    if "YARAMAIL_RULES_DIR" in os.environ:
        args.rules = os.environ["YARAMAIL_RULES_DIR"]
    if "YARAMAIL_HEADER_RULES" in os.environ:
        args.header_rules = os.environ["YARAMAIL_HEADER_RULES"]
    args.header_rules = os.path.join(args.rules, args.header_rules)
    if not os.path.exists(args.header_rules):
        error = f"{args.header_rules} does not exist. Skipping " \
                f"header-only scans."
        logger.error(error)
        args.header_rules = None
    if "YARAMAIL_BODY_RULES" in os.environ:
        args.body_rules = os.environ["YARAMAIL_BODY_RULES"]
    args.body_rules = os.path.join(args.rules, args.body_rules)
    if not os.path.exists(args.body_rules):
        error = f"{args.body_rules} does not exist. Skipping body-only scans."
        logger.error(error)
        args.body_rules = None
    if "YARAMAIL_HEADER_BODY_RULES" in os.environ:
        args.header_body_rules = os.environ["YARAMAIL_HEADER_BODY_RULES"]
    args.header_body_rules = os.path.join(args.rules, args.header_body_rules)
    if not os.path.exists(args.header_body_rules):
        error = f"{args.header_body_rules} does not exist. Skipping " \
                f"header_body scans."
        logger.error(error)
        args.header_body_rules = None
    if "YARAMAIL_ATTACHMENT_RULES" in os.environ:
        args.attachment_rules = os.environ["YARAMAIL_ATTACHMENT_RULES"]
    args.attachment_rules = os.path.join(args.rules, args.attachment_rules)
    if not os.path.exists(args.attachment_rules):
        error = f"{args.attachment_rules} does not exist. Skipping " \
                f"attachment scans."
        logger.error(error)
        args.attachment_rules = None
    if "YARAMAIL_TRUSTED_DOMAINS" in os.environ:
        args.trusted_domains = os.environ["YARAMAIL_TRUSTED_DOMAINS"]
    args.trusted_domains = os.path.join(args.rules, args.trusted_domains)
    if args.trusted_domains and not os.path.exists(args.trusted_domains):
        error = f"{args.trusted_domains} does not exist. Skipping trusted " \
                f"domain check."
        logger.error(error)
        args.trusted_domains = None

    trusted_domains = []
    if args.trusted_domains is not None:
        try:
            with open(args.trusted_domains) as trusted_domains_file:
                trusted_domains = trusted_domains_file.read().strip().split(
                    "\n")
        except Exception as e:
            logger.error(f"Error reading {args.trusted_domains}: {e}")

    try:
        scanner = MailScanner(header_rules=args.header_rules,
                              body_rules=args.body_rules,
                              header_body_rules=args.header_body_rules)
    except Exception as e:
        scanner = MailScanner()
        logger.error(f"Failed to parse YARA rules: {e}")
        exit(-1)

    scanned_emails = {}
    for file_path in args.scan_path:
        if not os.path.exists(file_path):
            logger.error(f"{file_path} does not exist.")
            continue
        try:
            with open(file_path, "rb") as email_file:
                parsed_email = parse_email(email_file.read())
        except Exception as e:
            logger.error(f"Failed to parse {file_path}: {e}")
            continue
        try:
            scan_results = scanner.scan_email(parsed_email)
            parsed_email["yara_matches"] = scan_results
        except Exception as e:
            logger.error(f"Failed to scan {file_path}: {e}")
            continue
        trusted = from_trusted_domain(parsed_email,
                                      trusted_domains)
        parsed_email["from_trusted_domain"] = trusted

        if args.verbose:
            scanned_emails[file_path] = parsed_email
        else:
            scanned_emails[file_path] = dict(yara_matches=scan_results,
                                             from_trusted_domain=trusted)

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
