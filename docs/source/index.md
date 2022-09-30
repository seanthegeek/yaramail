# Welcome to yaramail's documentation

[![Python tests](https://github.com/seanthegeek/yaramail/actions/workflows/python-tests.yaml/badge.svg)](https://github.com/seanthegeek/yaramail/actions/workflows/python-tests.yaml)
[![PyPI](https://img.shields.io/pypi/v/yara-mail)](https://pypi.org/project/yara-mail/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/yara-mail?color=blue)](https://pypistats.org/packages/yara-mail)

yaramail is a Python package and command line utility for scanning emails with
[YARA rules][yara]. It is Ideal for automated triage of phishing reports.

<iframe src="https://onedrive.live.com/embed?cid=5BEBF72EB17AB44F&amp;resid=5BEBF72EB17AB44F%2138962&amp;authkey=AGuJcdaXNmelzE0&amp;em=2&amp;wdAr=1.7777777777777777" width="476px" height="288px" frameborder="0">This is an embedded <a target="_blank" href="https://office.com">Microsoft Office</a> presentation, powered by <a target="_blank" href="https://office.com/webapps">Office</a>.</iframe>

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
