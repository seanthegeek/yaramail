# yaramail

yaramail is a Python package and command line utility for scanning emails with
[YARA rules][yara]. It is Ideal for automated triage of phishing reports.

## Features

yaramail scans all parts of an email via API or CLI

- Headers
  -  Removes header indents by default for consistent scanning
- Plain text and HTML body content
  - Converts body content to Markdown by default for consistent scanning
- Nested email attachments
- ZIP file contents, including nested ZIP files
- Raw content and text content in PDF documents

## CLI

```
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
  -v, --verbose         Output the entire parsed email
  --output OUTPUT, -o OUTPUT
                        Redirect output to a file
  --rules RULES         A path to a directory that contains YARA rules. Can be
                        substituted by the YARA_RULES_DIR environment
                        variable.
  --header-rules HEADER_RULES
                        Filename of the header rules file. Can be substituted
                        by the YARA_HEADER_RULES environment variable.
  --body-rules BODY_RULES
                        Filename of the body rules file. Can be substituted by
                        the YARAMAIL_BODY_RULES environment variable.
  --header-body-rules HEADER_BODY_RULES
                        Filename of the header_body rules file. Can be
                        substituted by the YARAMAIL_HEADER_BODY_RULES
                        environment variable.
  --attachment-rules ATTACHMENT_RULES
                        Filename of the body rules file. Can be substituted by
                        the YARAMAIL_BODY_RULES environment variable.
  --trusted-domains TRUSTED_DOMAINS
                        A path to a file containing a list of trusted domains.
                        Can be substituted by the YARAMAIL_TRUSTED_DOMAINS
                        environment variable.
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

In a terminal, run

```
pip3 install -U yaramail
```

### Working with .msg files

If you would like to be able to parse and scan Microsoft Outlook `.msg`
emails, you'll need to install the `Email::Outlook::Message` Perl module, which
includes the `msgconvert` utility that is used to convert `.msg` files into the
standard RFC 822 format. Ubuntu and Debian make this easy because they have a
package for it (which is included in the above instructions). On 
Fedora/RHEL/CentOS based distributions and macOS, you'll need to install
[Perlbrew][perlbrew].

Perlbrew installs a local copy of Perl within the user's home directory,
similar to how Homebrew works (which is why the initial installation can take
a while). That way, you don't need to use `sudo` to  install Perl modules, and 
risk breaking your system's Perl installation in the process.

Once Perlbrew is installed, use `cpan` to install `Email::Outlook::Message`.

```
cpan install Email::Outlook::Message
```

The installation process will take a few minutes while `cpan` builds and
installs all the dependencies. Once complete, the `msgconvert` utility will be
in your `PATH`, ready for use.

[yara]: https://yara.readthedocs.io/en/stable/writingrules.html
[homebrew]: https://brew.sh/
[build_tools]: https://visualstudio.microsoft.com/downloads/#microsoft-visual-c-redistributable-for-visual-studio-2022
[anaconda_distribution]: https://www.anaconda.com/products/distribution
[perlbrew]: https://perlbrew.pl/