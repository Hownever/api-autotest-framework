#!/bin/bash

mkdir -p output
cp -rf bin output/
cp -rf CronUI output/
cp -rf monitor output/
chmod +x output/bin/control

# copy test case to output directory and ignore the env directory
for i in `ls testcases`;do
    echo "copy testcase for $i, and chmod -x for the sub-files."
    mkdir -p output/testcases/$i
    rsync -av --progress testcases/$i output/testcases --exclude=$i/env --exclude=$i/reports --exclude=$i/__pycache__ --exclude=*.env --exclude=*.html --exclude=*.pyc
done