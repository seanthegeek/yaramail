# Welcome to yaramail's documentation!

[![PyPI](https://img.shields.io/pypi/v/yara-mail)](https://pypi.org/project/yara-mail/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/yara-mail?color=blue)](https://pypistats.org/packages/yara-mail)

yaramail is a Python package and command line utility for scanning emails with
[YARA rules][yara]. It is Ideal for automated triage of phishing reports.

## Features

- Scans all parts of an email via API or CLI
  - Headers
    -  Removes header indents by default for consistent scanning
  - Plain text and HTML body content
    - Converts body content to Markdown by default for consistent scanning
  - Attachments
    - Raw file content
    - Emails attached to emails
    - PDF document text
    - ZIP file contents, including nested ZIP files
      - Customizable list of passwords to use when attempting to scan encrypted ZIP files
- Provides a built-in methodology for categorizing emails

## Further reading

```{toctree}
---
maxdepth: 2
---
installation
tutorial
collecting_samples
api
cli
regex
```

### Indices and tables

```{eval-rst}
* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
```

[yara]: https://yara.readthedocs.io/en/stable/writingrules.html
