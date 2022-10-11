#!/usr/bin/env bash

set -e

case "$OSTYPE" in 
  *darwin*)
    if ! [ -x "$(command -v brew)" ]; then
      echo 'Error: Homebrew is not installed. Please install it.' >&2
      exit 1
    fi
    brew install pkg-config poppler python
    ;;
esac

if [ -x "$(command -v apt)" ]; then
  sudo apt install -y build-essential libpoppler-cpp-dev pkg-config python3-dev
  if [ ! -x "$(command -v virtualenv)" ]; then
    sudo apt install -y python3-virtualenv
  fi
fi

if [ -x "$(command -v dnf)" ]; then
  sudo dnf install gcc-c++ pkgconfig poppler-cpp-devel python3-devel
  if [ ! -x "$(command -v virtualenv)" ]; then
    sudo dnf install python3-virtualenv
  fi
  elif [ -x "$(command -v yum)" ]; then
  sudo yum install gcc-c++ pkgconfig poppler-cpp-devel python3-devel
    if [ ! -x "$(command -v virtualenv)" ]; then
      sudo yum install python3-virtualenv
    fi
fi

if [ ! -d "venv" ]; then
  virtualenv venv || exit
fi

. venv/bin/activate
pip install -U -r requirements.txt
cd docs
make clean 
make html
touch build/html/.nojekyll
cp -rf build/html/* ../../yaramail-docs/
cd ..
flake8 yaramail
python3 -m yaramail._cli -to test/samples  --rules test
rm -rf dist/ build/
hatch build
