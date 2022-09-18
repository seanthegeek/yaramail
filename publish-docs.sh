#!/bin/bash
cd ../yaramail-docs || exit
git pull
cd ../yaramail || exit
./build.sh
cd ../yaramail-docs || exit
git add .
git commit -m "Update docs"
git push
