#!/bin/bash

#filename: lib.sh

WS=${WS:-`dirname $0`}
JOB_LOG=${JOB_LOG:-${WS}/job.log}
SLAVE_FILE=${DEFALUT_SLAVE_FILE:-${WS}/slavers}

TEST_RATE=${DEFAULT_TEST_RATE:-10}
TEST_DURATION=${DEFAULT_TEST_DURATION:-60}

ARK_INSTANCE_USER=${DEFAULT_ARK_INSTANCE_USER:-root}
ARK_INSTANCE_PASSWD=${DEFAULT_ARK_INSTANCE_PASSWD:-"123456"}


eecho(){
    echo "**> $*"
    exit 1
}
iecho(){
    echo "==> $*"
}

remote_run(){
    #[[ $# < 4  ]] && eecho "remote_run function need more than 4 params, only $# given: $*"
    local remote_host=$1
    local remote_user=$2
    local remote_password=$3
    shift
    shift
    shift
    local run_cmd="$*"

    sshpass -p ${remote_password} ssh -o StrictHostKeyChecking=no ${remote_user}@${remote_host} "${run_cmd}"
}

remote_cp(){
    # $1: to
    # $2: remote user name
    # $3: remote password
    # $4: src_file
    # $5: remote file full path
    local remote_host=$1
    local remote_user=$2
    local remote_password=$3

    local src_file=$4
    local save_to=$5
    sshpass -p ${remote_password} scp -o StrictHostKeyChecking=no -r "$src_file" ${remote_user}@${remote_host}:"$save_to"

}

ark_cp(){
    local remote_host=$1
    shift
    remote_cp $remote_host ${ARK_INSTANCE_USER} ${ARK_INSTANCE_PASSWD} $*
}

ark_run(){
    local remote_host=$1
    shift
    remote_run $remote_host ${ARK_INSTANCE_USER} ${ARK_INSTANCE_PASSWD} "$*"
}

get_slaves_cpu(){
    local host=$1
    local cpu=0
    cpu=$(ark_run "$1" 'q=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us);p=$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us);let c=$q/$p;echo $c') 2>/dev/null
    echo $cpu
}

run_locust_slaver(){

    [[ $# != 4 ]] && eecho "run_locust_slaver function need 4 params, only $# given: $*"
    local remote_host=$1
    shift
    local locust_master=$1
    local locust_script=$2
    local locust_host=$3
    local run_locust_cmd="locusts3 -f ${locust_script} -H ${locust_host} --master-host=${locust_master} --slave"
    ark_run ${remote_host} "${run_locust_cmd}" &
}

run_locust_slavers(){

    [[ $# != 4 ]] && eecho "run_locust_slavers function need 4 params, only $# given: $*"
    local remote_host=$1
    shift
    local locust_master=$1
    local locust_script=$2
    local locust_host=$3
    local cpu_core=$(get_slaves_cpu ${remote_host})
    local i=0
    echo "We will start ${cpu_core} slaves at ${remote_host} for master ${locust_master}"
    while [[ true ]];do
        run_locust_slaver $remote_host ${locust_master} ${locust_script} ${locust_host} &
        sleep 0.5
        let i=$i+1
        echo "Slave $i started! $i/${cpu_core}"
        if [[ $i -ge ${cpu_core} ]];then
            break
        fi
    done
    echo "Slaver start finished!"
}

