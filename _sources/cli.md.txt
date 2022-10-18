# CLI

<script id="asciicast-529801" src="https://asciinema.org/a/529801.js" async></script>

```text
usage: A YARA scanner for emails [-h] [-V] [-v] [-m] [-o] [-r] [-b] [-s] [-t]
                                 [--output OUTPUT] [--rules RULES]
                                 [--header-rules HEADER_RULES]
                                 [--body-rules BODY_RULES]
                                 [--header-body-rules HEADER_BODY_RULES]
                                 [--attachment-rules ATTACHMENT_RULES]
                                 [--passwords PASSWORDS]
                                 [--implicit-safe-domains IMPLICIT_SAFE_DOMAINS]
                                 [--max-zip-depth MAX_ZIP_DEPTH]
                                 scan_path

positional arguments:
  scan_path             The file(s) to scan. Wildcards allowed. Use - to read
                        from stdin. When used with -t/--test, this must be the
                        directory where samples are stored, instead of an
                        individual file or wildcard path.

options:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  -v, --verbose         Output the entire parsed email. When used with
                        -t/--test, this option outputs passing results along
                        with failing results. (default: False)
  -m, --multi-auth      Allow multiple Authentication-Results headers
                        (default: False)
  -o, --auth-original   Use Authentication-Results-Original instead of
                        Authentication-Results (default: False)
  -r, --raw-headers     Scan headers with indentations included (default:
                        False)
  -b, --raw-body        Scan the raw email body instead of converting it to
                        Markdown first (default: False)
  -s, --sld             Use From domain the Second-Level Domain (SLD) for
                        authentication in addition to the Fully-Qualified
                        Domain Name (FQDN) (default: False)
  -t, --test            Test rules based on verdicts matching the name of the
                        subdirectory a sample is in (default: False)
  --output OUTPUT       Redirect output to a file (default: None)
  --rules RULES         A path to a directory that contains YARA rules
                        (default: .)
  --header-rules HEADER_RULES
                        Filename of the header rules file (default:
                        header.yar)
  --body-rules BODY_RULES
                        Filename of the body rules file (default: body.yar)
  --header-body-rules HEADER_BODY_RULES
                        Filename of the header_body rules file (default:
                        header_body.yar)
  --attachment-rules ATTACHMENT_RULES
                        Filename of the attachment rules file (default:
                        attachment.yar)
  --passwords PASSWORDS
                        Filename of a list of passwords to try against
                        password-protected files in addition to email body
                        content (default: passwords.txt)
  --implicit-safe-domains IMPLICIT_SAFE_DOMAINS
                        Filename of a list of message From domains that return
                        a safe verdict if the domain is authenticated and no
                        YARA categories match other than safe (default:
                        implicit_safe_domains.txt)
  --max-zip-depth MAX_ZIP_DEPTH
                        The maximum number of times to recurse into nested ZIP
                        files (default: None)
```
