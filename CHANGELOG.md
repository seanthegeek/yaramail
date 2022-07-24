# Changelog

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
