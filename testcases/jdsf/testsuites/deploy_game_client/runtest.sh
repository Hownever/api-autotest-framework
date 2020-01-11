#!/bin/env bash

if [ ! -f lib.sh ];then
    echo "no lib.sh file found! Job abort!"
    exit -1
fi

# import functions
source lib.sh

iecho "[TESTSTART] JDSF test start"
deploy.sh
iecho "[TESTEND] JDSF test end"
