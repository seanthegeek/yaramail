# Changelog

## 2.0.16

- Bump `mailsuite` version requirement to `>=1.9.7`

## 2.0.15

- Bump `mailsuite` version requirement to `>=1.9.6`

## 2.0.14

- Require the `yara-python` version to be at least [4.2.3][yara-4.2.3] to address an arbitrary code execution vulnerability    

## 2.0.13

- Fix multiple ZIP scanning bugs

## 2.0.12

- Output passing results along with failing results when `/t`/`--test` and `-v/--verbose` options are passed to the CLI

## 2.0.11

- Add `msg_from_domain` to the dictionary returned by `MailScanner.scan_email()`

## 2.0.10

- Fix invalid `location` when an email has multiple attachments

## 2.0.9

- Bump `mailsuite` required version to `>=1.9.5`

## 2.0.8

- Fix `has_attachment` Boolean (PR #5)

## 2.0.7

- Update the docstring of `MailScanner.scan_email()` again

## 2.0.6

- Update the docstring of `MailScanner.scan_email()`

## 2.0.5

- Fix bug where lists from empty files returned `[""]` instead of `[]`
- Add `has_attachment` Boolean to the dictionary returned by `MailScanner.scan_email()` for easy troubleshooting of rules with `no_attachment = true` set

## 2.0.4

- Fix  `-b`/`--raw-body` CLI option
- Add `no_attachments` option for YARA rule meta sections

## 2.0.3

- Add `-r`/`--raw-headers` and `-b`/`--raw-body` options to the CLI

## 2.0.2

- The `include_sld_in_auth_check` parameter in `MailScanner.__init__()` is now `False` by default
- Added `-s/--sld` and `--max-zip-depth` options to the CLI
- Removed CLI and installation documentation from `README.md`

## 2.0.1

- Remove CLI environment variables
- Add CLI options `-m` and `-o`
- Only honor `auth_optional` rule `meta` value if rule `meta` value `category` is `safe`
- Fix attachment rules not being used in the CLI

## 2.0.0

- Major refactoring
  - Many arguments added to `MailScanner.__init__()` or moved from `MailScanner.scan_email()` to `MailScanner.__init__()`
    - `passwords`
    - `max_zip_depth`
    - `trusted_domains`
    - `trusted_domains_yara_safe_required`
    - `include_sld_in_auth_check`
    - `allow_multiple_authentication_results`
    - `use_authentication_results_original`
  - Instead of returning a list of matches, `MailScanner.scan_email()` now returns a dictionary with the following keys
    - `matches` - The list of YARA matches
    - `categories` - A deduplicated list of categories from the `catagory` meta value in YARA rule matches
    - `trused_domain` - A boolean indicating if the authenticated from domain is in the `trusted_domains` list
    - `trusted_domain_yara_safe_required` - A boolean indicating if the authenticated from domain is in the `trusted_domains_yara_safe_required` list
    - `auth_optional` - A boolean indicating if the from domain authentication check is optional
    - `verdict` a verdict based on the above
- Added new options to the CLI
  - Pass `-` as the scan path to scan a single email from standard input (stdin)
  - `--passwords` - A path to a list of passwords to use when brute-forcing password-protected attachments
  - `--trusted-domains-yara` - A path to a list of from domains that also require a YARA safe match
  - `-t` `--test` - Test rules based on verdicts matching the name of the folder a sample is in 

## 1.1.1

- Fix encrypted ZIP scanning

## 1.1.0

- Attempt to scan encrypted ZIP files
  - Customizable password list
    - `[None, "malware", "infected"]` is always included

## 1.0.4

- Fix typo in `MailScanner` docstring

## 1.0.3

- Fix PDF scanning bugs
- Bump `mailsuite` requirement to `>=1.9.3`
  - Fix crash when parsing some `DKIM-Signature` headers
  - Fix `from_trusted_domain()` DMARC check
  - Don't convert plain text email bodies to markdown
  - Always include `body_markdown` in parsed results
  - Decode utf-8 encoded `Subject` and `Thread-Topic` headers in `headers_str`
  - Silence noisy `mailparser` log output

## 1.0.2

- Remove some documentation from `README.md`, so the PyPI listing won't have outdated info
- Add `Issues` and `Changelog` URLs to the PyPI listing
- Rename the `yaramail.cli` module to `yaramail.cli`
- Bump `mailsuite` dependency version to `>=1.9.2`

## 1.0.1

- Bump `mailsuite` dependency version to `>=1.9.1`
  - Add warnings about `msgconvert` not being suitable for forensics
- Clean up `README.md`
- Add `CHANGELOG.md`

# 1.0.0

- Initial release

[yara-4.2.3]: https://github.com/VirusTotal/yara/releases/tag/v4.2.3
