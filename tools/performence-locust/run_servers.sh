#!/bin/bash -x

# filename: run_server.sh

WS=`pwd`
JOB_LOG=${WS}/server.log
SLAVE_FILE=${WS}/slavers
SERVER_FILE=${WS}/server_pairs

SERVER_LOCAL_PATH=${WS}/go_server
SERVER_BIN_FILE_NAME="go_server/server"
SERVER_ENV_FILE_NAME="go_server/env_go_server_remove_jaeger_enable_go_pprof"
SERVER_REMOTE_PATH="/root"

DEFAULT_TEST_RATE=500
DEFAULT_TEST_DURATION=60

DEFAULT_ARK_INSTANCE_USER="root"
DEFAULT_ARK_INSTANCE_PASSWD="123456"

if [ -f lib.sh ];then
    source lib.sh
else
    echo "No lib.sh file found! function can not import, abort!"
    exit -1
fi

start_go_server(){
    local host=$1
    local go_server_bin_file=$2
    local go_server_env_file=$3
    ark_run $host "source ${go_server_env_file}&& chmod +x ${go_server_bin_file} && nohup ${go_server_bin_file} &> /root/server.log &"
}

start_go_servers(){
    local hostfile=$1
    local go_server_bin_file=$2
    local go_server_env_file=$3
    for server in $(cat ${SERVER_FILE});do
        start_go_server $server ${go_server_bin_file} ${go_server_env_file} &
    done

}

deploy_go_servers(){
    local hostfile=$1
    local local_go_files_path=$2
    local remote_go_save_path=$3
    for server in $(cat ${SERVER_FILE});do
        ark_cp $server "${local_go_files_path}" "${remote_go_save_path}"
        echo "Deploy local server from ${local_go_files_path} to $server at ${remote_go_save_path}"
    done
}

stop_go_server(){

    local host=$1
    ark_run $host "ps ax | grep '/root/go_server/server\$' | awk '{print \$1}' | xargs kill -9"

}

stop_go_servers(){

    local hostfile=$1
    local go_server_bin_file=$2
    local go_server_env_file=$3
    for server in $(cat ${SERVER_FILE});do
        stop_go_server $server
    done

}


if [[ $# -lt 2 ]];then
    if [[ "x$1" = "xstop" ||  "x$1" = "xk" ]];then
        stop_go_servers $SERVER_FILE
    elif [[ "x$1" = "xstart" ||  "x$1" = "xs" ]];then
        start_go_servers $SERVER_FILE ${SERVER_REMOTE_PATH}/${SERVER_BIN_FILE_NAME} ${SERVER_REMOTE_PATH}/${SERVER_ENV_FILE_NAME}
    elif [[ "x$1" = "xdeploy" ||  "x$1" = "xd" ]];then
        echo "Deploy server ..."
	deploy_go_servers $SERVER_FILE "${SERVER_LOCAL_PATH}/" "${SERVER_REMOTE_PATH}/"
    elif [[ "x$1" = "xdeployandrestart" ||  "x$1" = "xds" ]];then
        echo "Deploy server ..."
        $0 deploy
        echo "Stop server ..."
        $0 stop
        echo "Start server ..."
        $0 start
    else
        eecho "Unknow cmd: $*"
    fi
fi

#shift
#main $*
