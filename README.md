# yaramail


A Python package and command-line utility for scanni emails with YARA rules.
Ideal for automated triage of phishing reports.

## Features


- Scans all parts of an email via API or CLI

  - Headers

    -  Removes header indents by default for consistent scanning
  - Plain text and HTML body content

    - Converts body content to Markdown by default for consistent scanning

  - Nested email attachments
  - ZIP file contents, including nested ZIP files
  - Raw content and text content in PDf documents


