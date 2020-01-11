if [ -e "$1" ];then
    source $1
    chmod +x server
    echo > nohup.out
    nohup ./server &
    sleep 1
    cat nohup.out
else
    echo "Env config file $1 not exist!"
    echo "Usage: $0 envfile"
fi
