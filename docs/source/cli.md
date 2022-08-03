# CLI

```text
usage: A YARA scanner for emails [-h] [-V] [-v] [--output OUTPUT]
                                 [--rules RULES] [--header-rules HEADER_RULES]
                                 [--body-rules BODY_RULES]
                                 [--header-body-rules HEADER_BODY_RULES]
                                 [--attachment-rules ATTACHMENT_RULES]
                                 [--passwords PASSWORDS]
                                 [--trusted-domains TRUSTED_DOMAINS]
                                 [--trusted-domains-yara TRUSTED_DOMAINS_YARA]
                                 [-t]
                                 scan_path

positional arguments:
  scan_path             The file(s) to scan. Wildcards allowed.Use - to read
                        from stdin.

options:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  -v, --verbose         Output the entire parsed email (default: False)
  --output OUTPUT, -o OUTPUT
                        Redirect output to a file (default: None)
  --rules RULES         A path to a directory that contains YARA rules. Can be
                        set by the YARA_RULES_DIR environment variable.
                        (default: .)
  --header-rules HEADER_RULES
                        Filename of the header rules file. Can be set by the
                        YARA_HEADER_RULES environment variable. (default:
                        header.yar)
  --body-rules BODY_RULES
                        Filename of the body rules file. Can be set by the
                        YARAMAIL_BODY_RULES environment variable. (default:
                        body.yar)
  --header-body-rules HEADER_BODY_RULES
                        Filename of the header_body rules file. Can be set by
                        the YARAMAIL_HEADER_BODY_RULES environment variable.
                        (default: header_body.yar)
  --attachment-rules ATTACHMENT_RULES
                        Filename of the body rules file. Can be set by the
                        YARAMAIL_BODY_RULES environment variable. (default:
                        attachment.yar)
  --passwords PASSWORDS
                        Filename of a list of passwords to try against
                        password-protected files. Can be set by the
                        YARAMAIL_PASSWORDS environment variable (default:
                        passwords.txt)
  --trusted-domains TRUSTED_DOMAINS
                        A path to a file containing a list of trusted domains.
                        Can be set by the YARAMAIL_TRUSTED_DOMAINS environment
                        variable. (default: trusted_domains.txt)
  --trusted-domains-yara TRUSTED_DOMAINS_YARA
                        A path to a file containing a list of list of domains
                        that require a YARA safe match. Can be set by the
                        YARAMAIL_TRUSTED_DOMAINS_YARA environment variable.
                        (default: trusted_domains_yara_safe_required.txt)
  -t, --test            Test rules based on verdicts matching the name of the
                        folder a sample is in (default: False)
```
