# Changelog

## 3.4.2

### Fixes

- The CLI now exits non-zero without printing `{}` when scanning produces no
  results (for example, when the email provided via stdin cannot be scanned).
  The empty-results check ran after the results were serialized to JSON, so it
  never triggered — an empty result set serializes to the non-empty string
  `{}`, making the CLI report silent success on a failed scan.

### Improvements

- Automate releases and docs deployment: pushing a `v`-prefixed version tag
  (e.g. `v3.4.2`) now runs the full CI suite (lint, type check, and a
  Python 3.10–3.14 test matrix), builds the package, publishes it to PyPI via
  Trusted Publishing, creates the GitHub Release with the tag's changelog
  section as its notes, and deploys the Sphinx docs to GitHub Pages. This
  replaces the manual `build.sh` and `publish-docs.sh` scripts.
- Relax the `pdftotext` pin from `==2.2.2` to `>=3.0.0`. The exact pin was
  just the latest version at the time (2022); newer releases only drop
  long-unsupported Python and Poppler versions.
- Raise dependency floors: `mailsuite>=2.3.1` (fixes a crash when scanning
  malformed `.eml` attachments under mail-parser 4.6.2), `yara-python>=4.5.4`
  (bundles YARA 4.5.4 parser robustness fixes), and `simplejson>=4.1.0`.
- Test coverage is now 100% (statements and branches) and enforced. A dead
  compatibility branch for tuple-style match strings in yara-python < 4.3 —
  unreachable under the new `yara-python>=4.5.4` floor — was removed along the
  way.

## 3.4.1

### Fixes

- ZIP attachment scanning now reports the correct match `location`. The member
  name was dropped before (`attachment:archive.zip:None`); it is now included
  (`attachment:archive.zip:evil.js`), including for nested archives
  (`attachment:first.zip:nested.zip:evil.js`).
- `max_zip_depth` now limits nested-ZIP recursion as documented: `0` scans only
  the top-level archive, `1` allows one nested level, and `None` is unlimited.
  The comparison was inverted, so any positive value disabled recursion while
  `0` recursed without limit.
- ZIP attachment matches are no longer duplicated. A match was added once and
  then re-added with a doubled location prefix
  (`attachment:archive.zip:attachment:archive.zip`).
- A ZIP attachment with the ZIP magic bytes but a malformed body is now logged
  and skipped instead of raising `zipfile.BadZipFile`.
- A malformed `.eml`/`.msg` attachment is now logged and skipped instead of
  raising `ValueError`. The previous `except UserWarning` never matched the
  exception `parse_email()` actually raises, so the error reached the caller.
- `_scan_zip()` no longer reuses a previous member's contents when a later
  member cannot be decrypted, and it now continues scanning the remaining
  members instead of stopping at the first unreadable one.
- `_scan_zip()` no longer appends `infected` to the caller's password list.
- `_carve_passwords()` no longer emits duplicate candidates (it modified the
  list while iterating over it).
- `use_raw_body=True` now scans both the plain-text and HTML parts when a
  message has both, instead of dropping the plain-text part.
- `_input_to_str_list()` drops every blank line, not just the first, and no
  longer mutates a caller-supplied list.
- Removed the `-s`/`--sld` CLI flag. It had no effect (the underlying
  `include_sld_in_auth_check` option was removed in 3.0.0).
- Fixed the `Changelog` project URL, which pointed at a `master` branch that
  does not exist (the default branch is `main`).
- Documentation typo, grammar, and stale-content fixes, including the CLI
  reference, which still advertised the removed `-s`/`--sld` flag and
  out-of-date `-v`/`--verbose` behavior.

### Improvements

- Minimum `mailsuite` version raised to `>=2.2.0` to pick up upstream fixes.
- Narrowed broad `except Exception` handlers in the package to the specific
  errors they recover from (`pdftotext.Error`, `zipfile.BadZipFile`).

## 3.4.0

### Fixes

- `_scan_attachments()` now extracts the nested `matches` list from
  recursively-scanned `.eml`/`.msg` attachments. Previously it tried to extend
  its match list with the full result dict, which crashed the caller.
- The CLI's stdin path now actually scans the email it reads (previously it
  parsed but never invoked the scanner, returning an empty result).
- `_scan_zip()` no longer mutates its `passwords` argument when adding `None`
  and `infected` to the candidate list.

### Improvements

- Tooling brought in line with `mailsuite` / `checkdmarc`: pyright strict mode
  is now clean, `ruff` is the only style check, and `pytest` (with coverage)
  replaces the ad-hoc CLI-based test harness.
- Modern PEP 604/585 type hints across the package.
- CI runs a Python 3.10/3.11/3.12/3.13/3.14 test matrix on a fresh
  `actions/setup-python@v5` with pip caching, plus a dedicated lint job.
- Test suite expanded from a single integration check to 93 tests covering
  ~96% of the package (98% on `yaramail/__init__.py`, 94% on the CLI), with
  on-disk fixtures for a minimal PDF, a PDF-in-ZIP, and a password-protected
  (ZipCrypto) archive so the relevant scan paths run on every CI build.
- Minimum Python version bumped to 3.10 (3.9 reached EOL in October 2025).
- Fixed the broken logo URL in the README.

## 3.3.0

### Breaking changes

`parse_email()` no longer checks the file path for security reasons. It will no longer treat input as a potential file path. Applications must now do this explicitly themselves when needed.

### Improvements

- The password `infected` will now automatically be tried when scanning zip files.
- Better typing across the library.
- Code reformatting with `ruff`.

### Fixes

- Fixed potential crashes when scanning zip files.

## 3.2.3

- Better validation of data from `mailsuite`

## 3.2.2

- Better handling of an invalid email from address

## 3.2.1

- Upgrade `mailsuite` requirement to `>=1.9.20`
- Gracefully handle an invalid email from address

## 3.2.0

- Support `yara-python` `4.3.0`
- CLI: Output an error message if no files are found at the `scan_path`
- CLI: Do not output an empty dictionary when no emails could be parsed

## 3.1.10

- Pin `yara-python` version at `4.2.3`

## 3.1.9

- Require `mailsuite>=1.9.13`
  - Normalize the case of a header name when testing header values

## 3.1.8

- Require `mailsuite>=1.9.12`
  - Ignore all `dmarc` `Authentication-Results` if multiple `dmarc` results are found

## 3.1.7

- Add even more quote punctuation as password delimiters

## 3.1.6

- More quotation mark password delimiter variations

## 3.1.5

- Add possible password delimiters
  - Start and end HTML tags
  - Other forms of quotation marks used in various languages

## 3.1.4

- Fix issue where the `from_domain` rule meta key value was not split into a list as expected

## 3.1.3

- Add `|` and `< >` as possible password delimiters

## 3.1.2

- Update minimum `mailsuite` version to `>=1.9.12`
  - Fix parsing of `Authentication-Results` and `DKIM-Signature` headers when Windows line breaks (`\r\n`) are used
  - Strip leading and trailing spaces from `DKIM-Signature` header `h=` list item

## 3.1.1

- Fix testing in verbose mode

## 3.1.0

- Update minimum `mailsuite` version to `>=1.9.9`
  - Fix header and body separation when Windows line breaks (`\r\n`) are used
- CLI changes
  - Remove unused formats in verbose output
  - Remove attachment payloads in verbose output
  - Test results are now in JSON
  - Using the verbose option in testing now is the same as normal operations, instead of outputting all results

## 3.0.3

- Fix: Other warnings were ignored when the `unexpected-attachment` warning was raised

## 3.0.2

- Increase minimum version requirement for `mailsuite` to `1.9.8`
  - Fix parsing of email addresses in message `From` headers with encoded display names.

## 3.0.1

- in the dictionary returned by `MailScanner.scan_email()`, rename
  `["msg_from_domain"]["implicit_safe_domain"]` to `["msg_from_domain"]["implicit_safe"]`

## 3.0.0

*Warning*
This release is a major rewrite that includes changes breaking existing use

- Logic changes
  - Rules with a category of `safe` must have a `from_domain` `meta` value for the category to apply
    - This logic replaces `trusted_domains_yara_safe_required`
    - `trusted_domain_yara_safe_required`, and `auth_optional` removed from results
  - The `auth_optional`rule `meta` key only applies to that rule
  - Warnings are located inside a `warnings` list in each match, instead of as a `verdict`
    - A rule category does not apply if one or more warning is raised
      - Possible warnings include
        - `domain-authentication-failed` - Authentication of the message
            From domain failed
          - `from-domain-mismatch` - The message From domain did not exactly
            match the value of the `meta` key `from_domain`
          - `safe-rule-missing-from-domain` - The rule is missing a
            `from_domain` `meta` key that is required for rules with the
            `category` meta key set to `safe`
          - `unexpected-attachment` - An email with an attachment matched a
            rule with the `meta` key `no_attachment` or `no_attachments`
            set to `true`
  - Trusted domains are now called implicit safe domains
- API changes
  - `trusted_domains` renamed to `implicit_safe_domains`
  - `trusted_domains_yara_safe_required` parameter removed
  - `include_sld_in_auth_check` parameter removed
  - Returned data structure changed (see docs for details)
- CLI changes
  - `--trusted-domains` renamed to `--implicit-safe-domains`
  - `--trusted-domains-yara` removed
  - `--sld` removed
  - Log output delimiter changed from `:` to `|` to avoid conflicting with JSON

## 2.1.0

- Use email body content to brute force password-protected ZIPs

## 2.0.17

- Fix CLI log message output

## 2.0.16

- Bump `mailsuite` version requirement to `>=1.9.7`

## 2.0.15

- Bump `mailsuite` version requirement to `>=1.9.6`

## 2.0.14

- Require the `yara-python` version to be at least [4.2.3][yara-4.2.3] to address an arbitrary code execution vulnerability

## 2.0.13

- Fix multiple ZIP scanning bugs

## 2.0.12

- Output passing results along with failing results when `-t`/`--test` and `-v/--verbose` options are passed to the CLI

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
    - `categories` - A deduplicated list of categories from the `category` meta value in YARA rule matches
    - `trusted_domain` - A boolean indicating if the authenticated from domain is in the `trusted_domains` list
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
- Rename the `yaramail.cli` module to `yaramail._cli`
- Bump `mailsuite` dependency version to `>=1.9.2`

## 1.0.1

- Bump `mailsuite` dependency version to `>=1.9.1`
  - Add warnings about `msgconvert` not being suitable for forensics
- Clean up `README.md`
- Add `CHANGELOG.md`

## 1.0.0

- Initial release

[yara-4.2.3]: https://github.com/VirusTotal/yara/releases/tag/v4.2.3
