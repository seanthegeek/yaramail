#!/bin/bash
./build.sh
cd ../yaramail-docs
git add .
git commit -m "Update docs"
git push
