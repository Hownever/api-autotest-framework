#!/bin/bash

# filename: run_noweb.sh

WS=`pwd`
JOB_LOG=${WS}/job.log
SLAVE_FILE=${WS}/slavers

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

usage(){
    echo "$0 {start|stop} vuser_num [rate duration(s)]"
    echo "eg:"
    echo "  $0 stop"
    echo "  $0 start 500         # run 500 vuser with ${DEFAULT_TEST_RATE} user added per second, run ${DEFAULT_TEST_DURATION} seconds"  
    echo "  $0 start 500 10      # run 500 vuser with 10 user added per second, run ${DEFAULT_TEST_DURATION} seconds"  
    echo "  $0 start 500 100 300 # run 500 vuser with 100 user added per second, run 300 seconds"
}

main(){
    local vuser=${1:-0}
    local rate=${2:-${DEFAULT_TEST_RATE}}
    local duration=${3:-${DEFAULT_TEST_DURATION}}
    local server_under_test=${4:-"http://10.226.205.7:8080"}
    local logfile=${WS}/log_$vuser.log
    
    # 1. get the cpu core for all the slaves
    local total_cpu=0
    local s_cpu=0
 
    local master_ip=$(ip addr | grep inet | grep eth0 | awk '{print $2}' | awk -F'/' '{print $1}')

    [ -e ${SLAVE_FILE} ] || echo "127.0.0.1" > ${SLAVE_FILE}
    for slave in `cat ${SLAVE_FILE}`;do
        s_cpu=$(get_slaves_cpu $slave)
        echo "Get cpu core for $slave: ${s_cpu}"
        let total_cpu=${total_cpu}+${s_cpu}
    done
    [[ ${total_cpu} == 0  ]] && eecho "No valid cpu found for slaves: $slaves"
    RUN_CMD_MASTER="locusts3 -f go_call.py -H ${server_under_test} --master --no-web -c $vuser -r ${rate} -t ${duration}s --expect-slaves=${total_cpu}"

    echo ${RUN_CMD_MASTER} >$logfile
    echo "Start master with cmd: ${RUN_CMD_MASTER} "
    ${RUN_CMD_MASTER} &> $logfile &
    echo "Wait 3s for master started finish."
    sleep 3
    for slave in $(cat ${SLAVE_FILE});do
        echo "Copy script (go_call.py) to slave host: $slave"
        ark_cp $slave go_call.py /root/go_call.py 
        echo "start slavers $slave"
        run_locust_slavers $slave  ${master_ip} /root/go_call.py http://10.226.205.7:8080 
    done
} &> ${JOB_LOG}


#remote_run 10.226.211.184 root "123456" $*
#cpu=$(get_slaves_cpu 10.226.211.184)
#echo "cpu=$cpu"
if [[ $# -gt 2 ]];then
    if [[ "x$1" = "xstop" ||  "x$1" = "xk" ]];then
        echo "Stop .."
        for slave in $(cat ${SLAVE_FILE});do
            ark_run $slave "ps ax | grep 'locusts3 -f' | grep -v grep | awk '{print \$1}' | xargs kill -9"
        done
        exit 0
    elif [[ "x$1" = "xstart" ||  "x$1" = "xs" ]];then
        shift
        if [[ $# -lt 1 ]];then 
            usage && exit -1
        fi
        echo "Start ..($*)"
        main $*
    else
        usage
        exit 3
    fi
else
    usage
    exit 2
fi


