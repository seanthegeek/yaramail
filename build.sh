#!/usr/bin/env bash

. venv/bin/activate
pip install -U -r requirements.txt && rstcheck --report-level warning README.rst && cd docs && make html && touch _build/html/.nojekyll && cp -rf _build/html/* ../../yaramail-docs/ && cd .. && flake8 yaramail  && rm -rf dist/ build/ && python3 setup.py sdist && python3 setup.py bdist_wheel
