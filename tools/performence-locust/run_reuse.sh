#!/bin/bash -x

# filename: run_reuse.sh
WS=`pwd`
JOB_LOG=${WS}/server.log
SERVER_FILE=${WS}/server_pairs

REUSE_CMD="sysctl net.ipv4.tcp_tw_reuse=1"

if [ -f lib.sh ];then
    source lib.sh
else
    echo "No lib.sh file found! function can not import, abort!"
    exit -1
fi

set_reuse(){
    local host=$1
    local reuse=$2
    ark_run $host "nohup sysctl net.ipv4.tcp_tw_reuse=$2"
}

set_reuses(){
    local hosfile=$1
    shift

    for server in $(cat ${SERVER_FILE});do
        set_reuse $server $*
    done
}


usage(){
    echo "$0 {status|set num}"
}

if [[ $# -ge 1 ]];then
    if [[ "x$1" = "xstatus" ||  "x$1" = "xs" ]];then
        for server in  $(cat ${SERVER_FILE});do
            ark_run $server "sysctl -a | grep -E 'net.ipv4.tcp_tw_reuse|net.ipv4.tcp_timestamps|net.ipv4.ip_local_port_range'"
        done
    elif [[ "x$1" = "xset" ||  "x$1" = "xset" ]];then
        echo "==> Set reuse to $2"
        set_reuses $SERVER_FILE $2
    else
        eecho "Unknow cmd: $*"
    fi
else
    usage
    exit -1
fi

#shift
#main $*
