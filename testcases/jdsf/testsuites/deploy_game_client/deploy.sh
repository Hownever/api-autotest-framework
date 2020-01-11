#!/bin/bash
# project path and file config
WS=/root/openapi_auto
JAVA_LOG_FILE=${WS}/logs/reg-operation3.log
DEMO_PATH=${WS}/demo
DEMO_DB_JAR=${DEMO_PATH}/db-service/db-service-0.0.1-SNAPSHOT.jar
DEMO_GAME_CLIENT_JAR=${DEMO_PATH}/game-client/game-client-0.0.1-SNAPSHOT.jar
DEMO_GAME_SERVICE_JAR=${DEMO_PATH}/game-service/game-service-0.0.1-SNAPSHOT.jar
DEMO_ROOM_SERVICE_JAR=${DEMO_PATH}/room-service/room-service-0.0.1-SNAPSHOT.jar

DEMO_DB_CONFIG=${DEMO_PATH}/db-service/application.properties
DEMO_GAME_CLIENT_CONFIG=${DEMO_PATH}/game-client/application.properties
DEMO_GAME_SERVICE_CONFIG=${DEMO_PATH}/game-service/application.properties
DEMO_ROOM_SERVICE_CONFIG=${DEMO_PATH}/room-service/application.properties

TEST_LOG_PATH=/root/avocado/latest
TEST_LOG_DB_SERVICE=${TEST_LOG_PATH}/db-service.log
TEST_LOG_ROOM_SERVICE=${TEST_LOG_PATH}/room-service.log
TEST_LOG_GAME_SERVICE=${TEST_LOG_PATH}/game-service.log
TEST_LOG_GAME_CLIENT=${TEST_LOG_PATH}/game-client.log

# Test result config
KW_REG=REGISTRY_ADDRESS_TAG
KW_CHAIN=TRACE_ADDRESS_TAG
KW_PASS=onTestSuccess
KW_FAIL=onTestFailure
KW_SKIP=onTestSkip

MAX_WAIT_JAVA_TIME=20 # max wait time for scan job signal
CHECK_INTERVAL_JAVA=2 # check job signal interval
MAX_WAIT_APP_TIME=30
CHECK_INTERVAL_APP=2

START_TIME=`date +%s`  # time passed
END_TIME=$((${START_TIME}+${MAX_WAIT_JAVA_TIME}))

FLAG_REG=0
FLAG_CC=0
FLAG_DEPLOY=0


if [ ! -f lib.sh ];then
    echo "no lib.sh file found! Job abort!"
    exit -1
fi

# import functions
source lib.sh
[ -d ${TEST_LOG_PATH} ] || mkdir -p ${TEST_LOG_PATH}
[ -f ${DEMO_DB_JAR} ] || eecho "${DEMO_DB_JAR} not exist! Job abort!"
[ -f ${DEMO_GAME_CLIENT_JAR} ] || eecho "${DEMO_GAME_CLIENT_JAR} not exist! Job abort!"
[ -f ${DEMO_GAME_SERVICE_JAR} ] || eecho "${DEMO_GAME_SERVICE_JAR} not exist! Job abort!"
[ -f ${DEMO_ROOM_SERVICE_JAR} ] || eecho "${DEMO_ROOM_SERVICE_JAR} not exist! Job abort!"

# stop app first
stop_jarfile ${DEMO_DB_JAR}
stop_jarfile ${DEMO_GAME_CLIENT_JAR}
stop_jarfile ${DEMO_GAME_SERVICE_JAR}
stop_jarfile ${DEMO_ROOM_SERVICE_JAR}

iecho "Start to scan job signal(Registry_Tag=${FLAG_REG}, Callchain_Tag=${FLAG_CC}) ... (UsedTime/MaxWaitTime)"
while [ `date +%s` -le ${END_TIME} ];do
    iecho "Start to scan job signal(Registry_Tag=${FLAG_REG}, Callchain_Tag=${FLAG_CC}) ... ($((`date +%s`-${START_TIME}))s/${MAX_WAIT_JAVA_TIME}s)"
    
    # find the registry info from java test log, set it to the apps
    if [ -f ${JAVA_LOG_FILE} ];then
        if [ ${FLAG_REG} -eq 0 ];then
        regs=`get_registry_info_from_log ${JAVA_LOG_FILE} ${KW_REG}`
        for reg in $regs; do
            # use the first only
            url=`echo $reg | awk -F: '{print $1}'`
            port=`echo $reg | awk -F: '{print $2}'`
            replace_registry_url "${DEMO_DB_CONFIG}" "$url"
            replace_registry_port "${DEMO_DB_CONFIG}" "$port"

            replace_registry_url "${DEMO_GAME_CLIENT_CONFIG}" "$url"
            replace_registry_port "${DEMO_GAME_CLIENT_CONFIG}" "$port"

            replace_registry_url "${DEMO_GAME_SERVICE_CONFIG}" "$url"
            replace_registry_port "${DEMO_GAME_SERVICE_CONFIG}" "$port"

            replace_registry_url "${DEMO_ROOM_SERVICE_CONFIG}" "$url"
            replace_registry_port "${DEMO_ROOM_SERVICE_CONFIG}" "$port"
            FLAG_REG=1
            break
        done
        fi
        if [ ${FLAG_CC} -eq 0 ];then
        cchains=`get_callchain_info_from_log  ${JAVA_LOG_FILE} ${KW_CHAIN}`
        for cc in $cchains;do
            url="http://$cc/api/traces"
            replace_callchain_url "${DEMO_DB_CONFIG}" "$url"
            replace_callchain_url "${DEMO_GAME_CLIENT_CONFIG}" "$url"
            replace_callchain_url "${DEMO_GAME_SERVICE_CONFIG}" "$url"
            replace_callchain_url "${DEMO_ROOM_SERVICE_CONFIG}" "$url"
            FLAG_CC=1
            break
        done    
        fi
    fi
    if [ ${FLAG_REG} -ge 1 -a ${FLAG_CC} -ge 1 ];then
        iecho "Found TAG from log file: ${JAVA_LOG_FILE}"
        break
    fi
    sleep ${CHECK_INTERVAL}
done

# start app one by one if registry tag found
if [ ${FLAG_REG} -ge 1 ];then
    start_app "${DEMO_DB_JAR}" "${TEST_LOG_DB_SERVICE}" ${MAX_WAIT_APP_TIME} ${CHECK_INTERVAL_APP} "Started DbServiceApplication in"
    RLT=[FAIL]  
    [ $? == 0 ] && RLT=PASS
    iecho "[DEPLOY] [$RLT] App ${DEMO_DB_JAR}"
    
    start_app "${DEMO_ROOM_SERVICE_JAR}" "${TEST_LOG_ROOM_SERVICE}" ${MAX_WAIT_APP_TIME} ${CHECK_INTERVAL_APP} "Started RoomServiceApplication in"
    RLT=[FAIL]  
    [ $? == 0 ] && RLT=PASS
    iecho "[DEPLOY] [$RLT] App ${DEMO_ROOM_SERVICE_JAR}"
    
    start_app "${DEMO_GAME_SERVICE_JAR}" "${TEST_LOG_GAME_SERVICE}" ${MAX_WAIT_APP_TIME} ${CHECK_INTERVAL_APP} "Started GameServiceApplication in"
    RLT=[FAIL]  
    [ $? == 0 ] && RLT=PASS
    iecho "[DEPLOY] [$RLT] App ${DEMO_GAME_SERVICE_JAR}"
    
    start_app "${DEMO_GAME_CLIENT_JAR}" "${TEST_LOG_GAME_CLIENT}" ${MAX_WAIT_APP_TIME} ${CHECK_INTERVAL_APP} "Started GameClientApplication in"
    RLT=[FAIL]  
    [ $? == 0 ] && RLT=PASS
    iecho "[DEPLOY] [$RLT] App ${DEMO_GAME_CLIENT_JAR} "
    

    # do the test
    url="localhost:9138/api/getgamedetial?gameid=0"
    res=`curl localhost:9138/api/getgamedetial?gameid=0`
    
    iecho "[TEST] curl $url, response:$res"

    rlt=`echo $res | grep "炉石传说" | grep "炉石传说1" | grep "炉石传说3"`
    if [ "x$rlt" != "x"  ];then
        pecho "[TESTRESULT] [PASS] curl game client api test pass: localhost:9138/api/getgamedetial?gameid=0"
    else
        fecho "[TESTRESULT] [FAIL] curl game client api test fail: localhost:9138/api/getgamedetial?gameid=0"
    fi
    
fi

exit 0

