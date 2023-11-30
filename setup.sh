#!/usr/bin/env bash

set -e

case "$OSTYPE" in 
  *darwin*)
    if ! [ -x "$(command -v brew)" ]; then
      echo 'Error: Homebrew is not installed. Please install it.' >&2
      exit 1
    fi
    if ! [ -x "$(command -v clang)" ]; then
      echo 'Error: clang not found. Please run xcode-select --install.' >&2
      exit 1
    fi
    brew install pkg-config openssl@3 poppler python
    ;;
  *linux*)
    if [ -x "$(command -v apt)" ]; then
      sudo apt install -y build-essential libssl-dev libpoppler-cpp-dev pkg-config python3-dev
      if [ ! -x "$(command -v virtualenv)" ]; then
        sudo apt install -y python3-virtualenv
      fi
    elif [ -x "$(command -v dnf)" ]; then
      sudo dnf install gcc-c++ pkgconfig openssl-devel poppler-cpp-devel python3-devel
      if [ ! -x "$(command -v virtualenv)" ]; then
          sudo dnf install python3-virtualenv
      fi
    elif [ -x "$(command -v yum)" ]; then
      sudo yum install gcc-c++ pkgconfig openssl-devel poppler-cpp-devel python3-devel
      if [ ! -x "$(command -v virtualenv)" ]; then
        sudo yum install python3-virtualenv
      fi
    fi
  ;;
esac
