# yaramail

[![PyPI](https://img.shields.io/pypi/v/yara-mail)](https://github.com/seanthegeek/yara-mail/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/yara-mail?color=blue)](https://pypistats.org/packages/yara-mail)

yaramail is a Python package and command line utility for scanning emails with
[YARA rules][yara]. It is Ideal for automated triage of phishing reports.

## Features

yaramail scans all parts of an email via API or CLI

- Headers
  -  Removes header indents by default for consistent scanning
- Plain text and HTML body content
  - Converts body content to Markdown by default for consistent scanning
- Attachments
  - Raw file content
  - Emails attached to emails
  - Non-password-protected ZIP file contents, including nested ZIP files
  - PDF document text

## CLI

```text
usage: A YARA scanner for emails [-h] [-V] [-v] [--output OUTPUT]
                                 [--rules RULES] [--header-rules HEADER_RULES]
                                 [--body-rules BODY_RULES]
                                 [--header-body-rules HEADER_BODY_RULES]
                                 [--attachment-rules ATTACHMENT_RULES]
                                 [--trusted-domains TRUSTED_DOMAINS]
                                 scan_path

positional arguments:
  scan_path             The file(s) to scan (wildcards allowed)

options:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  -v, --verbose         Output the entire parsed email (default: False)
  --output OUTPUT, -o OUTPUT
                        Redirect output to a file (default: None)
  --rules RULES         A path to a directory that contains YARA rules. Can be
                        set by the YARA_RULES_DIR environment variable.
                        (default: .)
  --header-rules HEADER_RULES
                        Filename of the header rules file. Can be set by the
                        YARA_HEADER_RULES environment variable. (default:
                        header.yar)
  --body-rules BODY_RULES
                        Filename of the body rules file. Can be set by the
                        YARAMAIL_BODY_RULES environment variable. (default:
                        body.yar)
  --header-body-rules HEADER_BODY_RULES
                        Filename of the header_body rules file. Can be set by
                        the YARAMAIL_HEADER_BODY_RULES environment variable.
                        (default: header_body.yar)
  --attachment-rules ATTACHMENT_RULES
                        Filename of the body rules file. Can be set by the
                        YARAMAIL_BODY_RULES environment variable. (default:
                        attachment.yar)
  --trusted-domains TRUSTED_DOMAINS
                        A path to a file containing a list of trusted domains.
                        Can be set by the YARAMAIL_TRUSTED_DOMAINS environment
                        variable. (default: trusted_domains.txt)
```

## Installation

```{warning}
It is not recommended to use `yaramail` in the same OS that is targeted by 
the potential malware you are scanning. Consider using `yaramail` inside of a
container or VM for additional security.
```

### System dependencies

Some system dependencies **must** be installed before installing `yaramail`.

#### Debian, Ubuntu, and friends

```
sudo apt install build-essential libpoppler-cpp-dev pkg-config python3-dev libemail-outlook-message-perl
```

#### Fedora, Red Hat, and friends

```
sudo yum install gcc-c++ pkgconfig poppler-cpp-devel python3-devel
```

#### macOS

Install [Homebrew][homebrew], then run the following command in a terminal.

```
brew install pkg-config poppler python
```

#### Windows

1. Install the [Microsoft Visual Studio Build Tools][build_tools]
2. Install [Anaconda Distribution][anaconda_distribution]
3. Use Anaconda Navigator to create a new Anaconda Environment
4. Click the play button for the Anaconda Environment
5. Click Open Terminal 
6. Run this command and leave the terminal open:
   ```
   conda install -c conda-forge poppler
   ```
7. Configure your Python IDE/project to use the Anaconda Environment

### Install yaramail


```{note}
The official name for this project, package, and module is `yaramail`. 
Unfortunately, the Python Package Index (PyPI) [did not allow that name to be
used there][pypi-name-issue], so the PyPI project name for `yaramail` is 
`yara-mail`.
```

In a terminal, run

```
pip3 install -U yara-mail
```

## Email samples and Outlook clients

### Microsoft Outlook for Windows

If you save an email to a file using Microsoft Outlook on Windows, it will
save the file in a proprietary Microsoft OLE format with a `.msg` extension.
There are tools like `msgconvert` that make an attempt to convert a `.msg`
file to a standard RFC 822 `.eml` file, and `yaramail` will attempt to use
this tool when encountering a `.msg` file if it is installed on the system.
However, anomalies are introduced during conversion that make the results
unsuitable for forensic analysis.

Instead of using `msgconvert`, use one of these other Outlook clients.

### Microsoft Outlook for macOS

Drag the email from the inbox or other folder and drop it on the desktop.
Attached emails can be saved to a file like any other attachment.

### Outlook Web Access (OWA)

1. Create a new email and leave it open a separate window.
2. Drag from the inbox or other folder and drop it in the message of the draft.
3. Download the attachment that was created in step 2

Emails that are already attached to an email can be downloaded from OWA like
any other attachment.

[yara]: https://yara.readthedocs.io/en/stable/writingrules.html
[homebrew]: https://brew.sh/
[build_tools]: https://visualstudio.microsoft.com/downloads/#microsoft-visual-c-redistributable-for-visual-studio-2022
[anaconda_distribution]: https://www.anaconda.com/products/distribution
[pypi-name-issue]: https://github.com/pypa/pypi-support/issues/2098
