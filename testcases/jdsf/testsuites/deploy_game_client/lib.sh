
eecho(){
    echo $*
    exit 1
}
iecho(){
    echo $*
}

pecho(){
    echo $*
}

fecho(){
    echo $*
}

# start demo project
# $1 : jar file, full path
# $2 : Log file, full path
restart_jar(){
    local opwd=`pwd`
    local jar_file=`basename $1`
    local jar_dir=`dirname $1`    

    stop_jarfile $1
    cd ${jar_dir}
    nohup java -jar ${jar_file} &> $2 &  
    cd $opwd
}

# stop process
# $1 process keyword of name
stop_kw(){
    local pid=`ps ax | grep  $1 | grep -v grep | awk '{print $1}'`
    for p in $pid; do
        kill -9 $p
    done
}

status_jarfile(){
    local jar_dir=`dirname $1`
    local jar_name=`basename $1`
    local process_jar_dir=""
    local pid=`ps ax | grep  ${jar_name} | grep -v grep | awk '{print $1}'`
    for p in $pid;do
        this_dir=`realpath /proc/$p/cwd`
        killpid=$p
        [ "x${this_dir}" == "x${jar_dir}" ] && process_jar_dir=${this_dir}
        [ "x${process_jar_dir}" == "x${jar_dir}" ] && break
    done
    [ "x${process_jar_dir}" == "x${jar_dir}" ] && echo $killpid
}

# stop process by process jar file
stop_jarfile(){
    local killpid=`status_jarfile "$1"`
    if [ ! -z $killpid ];then  
        #iecho "kill pid $killpid"
        kill -9 $killpid
        return $?
    fi
    return 1
}

# set the value of key for the file
# $1: the file
# $2: key
# $3: value
set_value(){
    [ -f $1 ] || return -1
    [ $# == 3 ] || retrun -2
    #echo "set_value: [$1] [$2] [$3]"
    sed -i 's#'$2'.*$#'$2'='$3'#g' $1
}


# replace registry url of given file
# $1: the file
# $2: the url
replace_registry_url(){
    set_value $1 "spring.cloud.consul.host"  $2
}

replace_callchain_url(){
    set_value $1 "opentracing.jaeger.http-sender.url" $2
}

replace_registry_port(){
    set_value $1 "spring.cloud.consul.port" $2
}

replace_descovery_hostname(){
    set_value $1 "spring.cloud.consul.discovery.hostname" $2
}

# get registry by keyword from log file
# $1 the log file
# $2 the keyword
get_registry_info_from_log(){
    local reginfos=`awk -FG '/'$2'/{print $3}' $1`
    [ -z ${reginfos} ] && return 0
    reginfos=`echo $reginfos | sed 's/://' | sed 's/;/ /g'`
    echo  "${reginfos}"
}

get_callchain_info_from_log(){
    local ccinfos=`awk -FG '/'$2'/{print $2}' $1`
    [ -z ${ccinfos} ] && return 0
    ccinfos=`echo $ccinfos | sed 's/://' | sed 's/,/ /g'`
    echo  "${ccinfos}"
}

# start app
# $1: jar file
# $2: Log file
# $3: max_wait_time
# $4: check interval
# $5: Flag in log for app start successfully
start_app(){
    local app=$1
    local log=$2
    local waittime=$3
    local ckinterval=$4
    local flag=$5

    local starttime=`date +%s`
    local endtime=$((${starttime}+${waittime}))
    local isfound=0

    restart_jar $app $log
    thispid=`status_jarfile $app`

    echo "Start $app at pid $thispid, log to $log, we will check its status with [$flag] in the log to make sure start successfully, max wait time set to ${waittime}s with interval ${ckinterval}s"
    
    while [ `date +%s` -le ${endtime} ];do
        isfound=`grep "$flag" "$log"`
        if [ "x${isfound}" != "x" ];then
            iecho "Sucess flag $flag found in log file($log): $isfound"
            return 0
        fi
        sleep $ckinterval
    done
    iecho "Fail to find flag $flag in log file $log"
    return 1
}

