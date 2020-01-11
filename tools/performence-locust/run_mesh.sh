#!/bin/bash -x

# filename: run_mesh.sh
WS=`pwd`
JOB_LOG=${WS}/server.log
SERVER_FILE=${WS}/server_pairs

MESH_SCRIPT=/etc/init.d/mesh-agent
DEFAULT_MESH_START_CMD='START_COMMAND="/export/pilot-agent proxy \\$PROXY_ROUTER --serviceregistry Ark --serviceCluster \\$APP_NAME --discoveryAddress \\$PILOT_SERVER --configPath /var/lib/istio \\$TEMPLATE_FILE --log_target /export/Logs/agent.log --controlPlaneAuthPolicy NONE --log_output_level \\$LOG_LEVEL"'

if [ -f lib.sh ];then
    source lib.sh
else
    echo "No lib.sh file found! function can not import, abort!"
    exit -1
fi

run_mesh(){
    local host=$1
    shift
    ark_run $host "${MESH_SCRIPT} $*"
}

run_meshs(){
    local hostfile=$1
    shift
    for server in $(cat ${SERVER_FILE});do
        run_mesh $server $*
    done
}

set_mesh(){
    local host=$1
    local concurrency=$2
    if [[ $concurrency -eq 0 ]];then
        ark_run $host "sed -i 's/^\\(START_COMMAND.*LOG_LEVEL\\)\\(.*\\)/\\1\"/g' ${MESH_SCRIPT}"
    elif [[ $concurrency -gt 0 ]];then
        ark_run $host "sed -i 's/^\\(START_COMMAND.*LOG_LEVEL\\)\\(.*\\)/\\1 --concurrency $concurrency\"/g' ${MESH_SCRIPT}"
    else
        eecho "**> Invalid concurrnecy: $2"
    fi
}

set_meshs(){
    local hosfile=$1
    shift

    for server in $(cat ${SERVER_FILE});do
        set_mesh $server $*
    done

}

usage(){
    echo "$0 {status|start|restart|set num}"
}

if [[ $# -ge 1 ]];then
    if [[ "x$1" = "xstatus" ||  "x$1" = "xs" ]];then
        run_meshs $SERVER_FILE $1
    elif [[ "x$1" = "xstart" ||  "x$1" = "xstart" ]];then
        run_meshs $SERVER_FILE start
    elif [[ "x$1" = "xrestart" ||  "x$1" = "xr" ]];then
        echo "==> mesh-agent restart"
        run_meshs $SERVER_FILE restart
    elif [[ "x$1" = "xset" ||  "x$1" = "xset" ]];then
        echo "==> Set mesh-agent currency to $2"
        set_meshs $SERVER_FILE $2
    else
        eecho "Unknow cmd: $*"
    fi
else
    usage
    exit -1
fi

#shift
#main $*
