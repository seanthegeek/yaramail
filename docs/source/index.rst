.. yaramail documentation master file, created by
   sphinx-quickstart on Sat Jul 16 01:33:38 2022.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to yaramail's documentation!
====================================

yaramail is a Python package and command-line utility for scanni emails with YARA rules.
Ideal for automated triage of phishing reports.

Features
========

- Scans all parts of an email via API or CLI

  - Headers

    -  Removes header indents by default for consistent scanning
  - Plain text and HTML body content

    - Converts body content to Markdown by default for consistent scanning

  - Nested email attachments
  - ZIP file contents, including nested ZIP files
  - Raw content and text content in PDf documents

CLI
===

API
===

.. autoclass:: Mailscanner
   :maxdepth: 2
   :caption: Contents:

.. toctree::
   - phishing
   :maxdepth: 2
   :caption: Contents:



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
