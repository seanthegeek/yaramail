# Installation

```{warning}
It is recommended to use `yaramail` in a different OS than what is targeted by 
the potential malware you are scanning. Consider using `yaramail` inside of a
container or VM for additional security.
```

## System dependencies

Some system dependencies **must** be installed before installing `yaramail`.

### Debian, Ubuntu, and friends

```
sudo apt install build-essential libpoppler-cpp-dev pkg-config python3-dev libemail-outlook-message-perl
```

### Fedora, Red Hat, and friends

```
sudo yum install gcc-c++ pkgconfig poppler-cpp-devel python3-devel
```

### macOS

Install [Homebrew][homebrew], then run the following command in a terminal.

```
brew install pkg-config poppler python
```

### Windows

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

## Install yaramail

```{note}
The official name for this project, package, and module is `yaramail`. 
Unfortunately, the Python Package Index (PyPI) [did not allow that name to be
used there][pypi-name-issue], so the PyPI project name for `yaramail` is 
`yara-mail`.
```

In a terminal, run

```
pip3 install -U yaramail
```

[homebrew]: https://brew.sh/
[build_tools]: https://visualstudio.microsoft.com/downloads/#microsoft-visual-c-redistributable-for-visual-studio-2022
[anaconda_distribution]: https://www.anaconda.com/products/distribution
[pypi-name-issue]: https://github.com/pypa/pypi-support/issues/2098
