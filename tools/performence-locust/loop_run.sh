start=500
end=16000
concurrency_min=0
concurrency_max=16
duration=300
interval=240

run_locusts(){
    local s=$1
    local e=$2
    while [[ $s -le $e ]];do
        echo "====> loop run for $s"
        /root/run_noweb.sh start $s 500 $duration
        let s=$s+500
        sleep $(($duration+$interval))
    done
}


while [[ $concurrency_min -le $concurrency_max ]];do
    mkdir -p cpu4_concurrency_$concurrency_min
    /root/run_mesh.sh set $concurrency_min
    /root/run_mesh.sh restart
    /root/run_reuse.sh set 1
    # check disk space, remove mesh.log mesh_*.log
    /root/run_diskspace.sh rms /export/Logs/mesh_2019*.log
    /root/run_diskspace.sh cs /export/Logs/mesh.log
    run_locusts $start $end
    mv log_*.log cpu4_concurrency_$concurrency_min
    mv job.log cpu4_concurrency_$concurrency_min
    let concurrency_min=$concurrency_min+2
done
echo "===> ALL DONE"
