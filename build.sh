#!/usr/bin/env bash

set -e

if [ ! -d "venv" ]; then
  virtualenv venv || exit
fi

. venv/bin/activate
case "$OSTYPE" in 
  *darwin*)
    if ! [ -x "$(command -v brew)" ]; then
      echo 'Error: Homebrew is not installed. Please install it.' >&2
      exit 1
    fi
    export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
    export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include"
    ;;
esac
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
