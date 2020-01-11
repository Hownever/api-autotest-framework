#!/bin/bash -x

WS=`pwd`
JOB_LOG=${WS}/server.log
SERVER_FILE=${WS}/server_pairs


if [ -f lib.sh ];then
    source lib.sh
else
    echo "No lib.sh file found! function can not import, abort!"
    exit -1
fi

get_diskspace(){
    local host=$1
    local mount_point=$2
    ark_run $host "df $mount_point | awk '/^\\/dev/{print \$5,\$6}'"
}

get_diskspaces(){
    local hostfile=$1
    local mount_point=$2
    for server in $(cat ${hostfile});do
        get_diskspace $server $mount_point
    done
}

clear_file(){
    local host=$1
    local c_file=$2
    ark_run $host "if [[ -e $c_file ]];then echo > $c_file;else echo 'File not found: "$c_file"'; fi"
}

clear_files(){

    local hostfile=$1
    local c_file=$2
    for server in $(cat ${hostfile});do
        clear_file $server $c_file
    done
}

rm_file(){
    local host=$1
    local rmfile=$2
    ark_run $host "rm -f $rmfile"
}

rm_files(){
    local hostfile=$1
    local rmfile=$2

    for server in $(cat ${hostfile});do
        rm_file $server $rmfile
    done

}

usage(){
    echo "$0 {s|status} [/mnt]"
    echo "$0 {c|clear} host/ip /export/Logs/mesh.log"
    echo "$0 {cs|clears} /export/Logs/mesh.log"
    echo "$0 {rm|remove} host/ip /export/Logs/mesh.log"
    echo "$0 {rms|removes} /export/Logs/mesh.log"
}

if [[ $# -ge 1 ]];then
    if [[ "x$1" = "xstatus" ||  "x$1" = "xs" ]];then
        get_diskspaces $SERVER_FILE "$2"
    elif [[ "x$1" = "xclear" ||  "x$1" = "xc" ]];then
        clear_file $2 $3
    elif [[ "x$1" = "xclears" ||  "x$1" = "xcs" ]];then
        clear_files $SERVER_FILE $2
    elif [[ "x$1" = "xremove" ||  "x$1" = "xrm" ]];then
        rm_file $2 $3
    elif [[ "x$1" = "xremoves" ||  "x$1" = "xrms" ]];then
        rm_files $SERVER_FILE $2
    else
        usage
        exit -1
    fi
else
    usage
    exit -1
fi

#shift
#main $*
