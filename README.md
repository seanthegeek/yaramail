<div align="center">
  <img src="https://raw.githubusercontent.com/seanthegeek/yaramail/main/docs/source/_static/yaramail-logo.png" alt="yaramail logo">
  <h1>yaramail</h1>

  [![Python tests](https://github.com/seanthegeek/yaramail/actions/workflows/python-tests.yaml/badge.svg)](https://github.com/seanthegeek/yaramail/actions/workflows/python-tests.yaml)
  [![Code Coverage](https://codecov.io/gh/seanthegeek/yaramail/branch/main/graph/badge.svg)](https://codecov.io/gh/seanthegeek/yaramail)
  [![PyPI](https://img.shields.io/pypi/v/yara-mail)](https://pypi.org/project/yara-mail/)
  [![PyPI - Downloads](https://img.shields.io/pypi/dm/yara-mail?color=blue)](https://pypistats.org/packages/yara-mail)
</div>

`yaramail` is a Python package and command line utility for scanning emails with
[YARA rules][yara]. It is ideal for automated triage of phishing reports.

## CLI Demo

[![asciicast](https://asciinema.org/a/529801.svg)][cli-demo]

## Features

- Scans all parts of an email via API or CLI
  - Headers
    - Removes header indents by default for consistent scanning
  - Plain text and HTML body content
    - Converts body content to Markdown by default for consistent scanning
  - Attachments
    - Raw file content
    - Emails attached to emails
    - PDF document text
    - ZIP file contents, including nested ZIP files
      - Uses message body content as a list of possible ZIP passwords
      - Customizable list of passwords to use when attempting to scan encrypted ZIP files
- Provides a built-in methodology for categorizing emails
- Parses `Authentication-Results` headers

[yara]: https://yara.readthedocs.io/en/stable/writingrules.html
[cli-demo]: https://seanthegeek.github.io/yaramail/tutorial.html#using-the-cli
