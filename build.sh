#!/usr/bin/env bash

. venv/bin/activate
pip install -U -r requirements.txt && cd docs && make clean && make html && touch build/html/.nojekyll && cp -rf build/html/* ../../yaramail-docs/ && cd .. && flake8 yaramail  && rm -rf dist/ build/ && hatch build
