# Installation

:::{warning}
It is recommended to use `yaramail` in a different OS than what is targeted by
the potential malware you are scanning. Consider using `yaramail` inside of a
container or VM for additional security.
:::

## System dependencies

Some system dependencies **must** be installed before installing `yaramail`.

### Debian, Ubuntu, and friends

```text
sudo apt install build-essential libssl-dev libpoppler-cpp-dev pkg-config python3-dev
```

### Fedora, Red Hat, and friends

```text
sudo yum install gcc-c++ pkgconfig openssl-devel poppler-cpp-devel python3-devel
```

### macOS

Install [Homebrew][homebrew], then run the following command in a terminal.

```text
brew install pkg-config poppler python
```

### Windows

1. Install the [Microsoft Visual Studio Build Tools][build_tools]
2. Install [Anaconda Distribution][anaconda_distribution]
3. Use Anaconda Navigator to create a new Anaconda Environment
4. Click the play button for the Anaconda Environment
5. Click Open Terminal
6. Run `conda install -c conda-forge poppler` and leave the terminal open:
7. Configure your Python IDE/project to use the Anaconda Environment

## Install yaramail

:::{important}
The official name for this project, package, and module is `yaramail`.
Unfortunately, the Python Package Index (PyPI) [did not allow that name to be
used there][pypi-name-issue], so the PyPI project name for `yaramail` is
`yara-mail`.
:::

:::{warning}
**Never** install Python packages as `root` or with `sudo`. Not only is it a
huge security risk, but doing that will also pollute the system Python
environment.
:::

It is recommended to create a separate Python [virtual environment][venv]
for any project that will use `yaramail`.

:::{note}
Conda environments are a type of virtual environment, so if you are using a
Conda environment, there is no need to create a virtual environment.
:::

Once the virtual environment has been created and activated, use `pip` to
install `yaramail`.

```text
pip3 install -U yaramail
```

Alternatively, if you would like to install the `yaramail` CLI as a user tool,
run this command **outside** a virtual environment:

```text
pip3 install --user -U yaramail
```

[homebrew]: https://brew.sh/
[build_tools]: https://visualstudio.microsoft.com/downloads/#microsoft-visual-c-redistributable-for-visual-studio-2022
[anaconda_distribution]: https://www.anaconda.com/products/distribution
[pypi-name-issue]: https://github.com/pypa/pypi-support/issues/2098
[venv]: https://docs.python.org/3/tutorial/venv.html
