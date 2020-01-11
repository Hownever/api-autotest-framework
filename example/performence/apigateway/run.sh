#!/bin/bash

CNT_CPU_CORE=`lscpu | grep ^CPU\(s\): | awk '{print $2}'`


usage(){
    echo "Usage:"
    echo "    $0 HOST SCRIPT -m/-s [masterip]"
    echo "    -m/-s means master or slave, when -s , you must give the masterip value"
    echo "example:"
    echo "    $0 http://www.jdcloud.com jdcloud.py -m"
    echo "    $0 http://www.jdcloud.com jdcloud.py -s 10.0.0.3"
    exit 1
}
eecho(){
    echo $1
    exit 1
}
stop(){
    ps ax | grep "locust" | grep -v grep | awk '{print $1}' | xargs kill -9 
    exit 0
}
callstop(){
    [ "x$1" == "xstop" ] || usage
    stop
}


[ ${CNT_CPU_CORE} -gt 0 ] || eecho "Fail to get cpu core by lscpu command!"
[ $# == 1 ] && stop
[ $# == 3 -o $# == 4 ] || usage
[ "x$3" == "x-m" -o "x$3" == "x-s" ] || eecho "Invalid args for -m/-s"
[ "x$3" == "x-s"  -a "x$4" == "x" ] && eecho "Invalid args or miss masterip for -s with args [$4]"

[[ x$1 =~ ^xhttp.* ]] || eecho "HOST value($1) error, must start with http!" 

[[ x$2 =~ ^x.*\.py$  ]] || eecho "SCRIPT($2) must be end with .py!"

[[ -f $2 ]] || eecho "SCRIPT($2) is not a valid file!"

HOST=$1
SCRIPT=$2
curl $HOST > /dev/null 2>&1
[ $? == 0 ] || eecho "$HOST is not a valid host, curl failed!"

# run master
if [ "x$3" == "x-m" ];then
    echo "Start master ..."
    cmd="locust -f $SCRIPT -H $HOST --master &"
    nohup locust -f $SCRIPT -H $HOST --master > /dev/null 2>&1 &
    [ $? == 0 ] || eecho "run $cmd failed!"
# run slave
elif [ "x$3" == "x-s" ];then
    # sleep 3s  to support slave's connection
    # sleep 3

    # run slave accord to the cpu cores
    i=1
    while [ $i -lt ${CNT_CPU_CORE} ]; do
        echo "run slave $i"
        nohup locust -f $SCRIPT --slave --master-host=$4 -H $HOST > /dev/null 2>&1 &
        [ $? == 0 ] || eecho "run salve $i failed!" 
        let i=$i+1
    done
else
    eecho "Invalid options $3"
fi

echo "All Done!"
exit 0
