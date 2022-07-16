# Welcome to yaramail's documentation!

yaramail is a Python package and command-line utility for scanning emails with
YARA rules. It is Ideal for automated triage of phishing reports.

## Features

yaramail scans all parts of an email via API or CLI

- Headers
  -  Removes header indents by default for consistent scanning
- Plain text and HTML body content
  - Converts body content to Markdown by default for consistent scanning
- Nested email attachments
- ZIP file contents, including nested ZIP files
- Raw content and text content in PDF documents

## Installation



## CLI


## API

```{eval-rst}
.. automodule:: yaramail
   :members:
```

```{eval-rst}
.. autoclass:: yaramail.MailScanner
   :members:
```

## Contents

```{toctree}
---
maxdepth: 2
---
phishing
```

## Indices and tables


```{eval-rst}
* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
```
