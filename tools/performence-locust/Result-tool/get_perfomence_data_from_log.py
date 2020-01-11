#!/usr/bin/python
# -*- coding: UTF-8 -*-

import sys
import os
import requests
import time
#from client import HttpSession
from requests import Session as HttpSession
import json


def get_ark_cookies():
    url = "http://10.219.24.54/api/v1/mockserver/mocks/ark.jdcloud.com"
    http_client_session = HttpSession()
    method = "GET"
    
    res = http_client_session.request(
        method,
        url,
    )
    
    if res.ok and res.json:
        return res.json()["data"]["content"]["cookie"]
    return None

    
cookie = get_ark_cookies()
def get_cpu_used_avg(start, end, ark_cookie = cookie):
    """
    hosts: list, ["ip1", "ip2"]
    start: timestamp 13
    end: timestamp 13
    """
    rlt={}
    http_client_session = HttpSession()
    
    method = "POST"
    url = "http://ark.jdcloud.com/hawkeye/api/v2/graph"
    if cookie is None:
        raise Exception("Get ark cookies failed!")
    headers = {
        "Content-Type": "application/json", 
        "Cookie": cookie
        }
    body = """{"start":%s,"end":%s,"path":"/v2/graph","query":[{"metricNameList":["cpu.use"],"product":"microservices","defaultValues":["AVG"],"nsType":"HOST","nsList":["10.226.205.11","10.226.205.7"],"subNsType":"HOST","tags":[]}]}"""%(start,end)
    res = http_client_session.request(
            method,
            url,
            headers=headers,
            data=body
        )
    #print(res.text)
    jres = json.loads(res.text)
    rlt[jres["data"]["items"][0]["ns"]]=jres["data"]["items"][0]["summary"]
    rlt[jres["data"]["items"][1]["ns"]]=jres["data"]["items"][1]["summary"]
    # print (rlt)
    return rlt
    
#rlt = get_cpu_used_avg(1573506526895, 1573528126894)
#print(rlt)
#sys.exit(1)

flag_locust_start = "Starting Locust 0.11.0"
flag_locust_end = "Running teardowns..."
flag_avg = " Name                                                          # reqs      # fails     Avg     Min     Max  |  Median   req/s"
flag_Total = " Total"
flag_percent = "Percentage of the requests completed within given times"
flag_error = "Error report"
flag_url = " GET /call"

for r,ds,fs in os.walk(sys.argv[1]):
    # 找到测试结果日志文件，并进行适当排序
    logfiles = list(filter(lambda lfs : lfs.startswith("log_") and lfs.endswith(".log"), fs))
    logfiles.sort(key=len)
    for f in logfiles:
        if f.endswith(".log"):
            starttime = None
            endtime = None
            # 每个日志文件目前不到1000行，不是很大，循环处理找到需要的数据
            # 1.开始和结束时间，并使用此时间获取云翼中统计的对应时间段内的CPU平均使用率
            # 2.Percentage数据
            # 3.QPS数据
            # 4.Error数据
            with open(os.path.join(r,f),'rb') as fd:
            
                starttime = None
                endtime = None
                avg = None
                min = None
                max = None
                request = None
                failure = None
                qps = None
                percent_datas = None
                
                for line in fd.readlines():
                    if line.decode().find(flag_locust_start) != -1:
                        s = time.mktime(time.strptime(line.decode().split("]")[0][1:20], "%Y-%m-%d %H:%M:%S"))
                        ms = line.decode().split("]")[0][21:24]
                        starttime = int(s)*1000 + int(ms)
                    if line.decode().find(flag_locust_end) != -1:
                        s = time.mktime(time.strptime(line.decode().split("]")[0][1:20], "%Y-%m-%d %H:%M:%S"))
                        ms = line.decode().split("]")[0][21:24]
                        endtime = int(s)*1000 + int(ms)
                    if line.decode().startswith(flag_Total):
                        sline = line.decode().split()
                        # print(len(sline))
                        if len(sline) == 4:
                            request = sline[1]
                            failure = sline[2]
                            qps = sline[-1]
                        elif len(sline) == 11:
                            percent_datas = sline[2:]
                    if line.decode().startswith(flag_url):
                        sline = line.decode().split()
                        if len(sline) == 10:
                            avg = sline[4]
                            min = sline[5]
                            max = sline[6]
                            median = sline[8]
                            
                vuser = f.split("_")[1].split(".")[0]
                cup_used = get_cpu_used_avg(starttime-60000, endtime-60000)
                testtime = endtime - starttime
                cpu_used_7_avg = str(cup_used["10.226.205.7"]["AVG"]) + "%"
                cpu_used_7_min = str(cup_used["10.226.205.7"]["MIN"]) + "%"
                cpu_used_7_max = str(cup_used["10.226.205.7"]["MAX"]) + "%"
                cpu_used_11_avg = str(cup_used["10.226.205.11"]["AVG"]) + "%"
                cpu_used_11_min = str(cup_used["10.226.205.11"]["MIN"]) + "%"
                cpu_used_11_max = str(cup_used["10.226.205.11"]["MAX"]) + "%"
                #print(vuser, qps, request, avg, min, max, median, " ".join(percent_datas), failure, cpu_used_7_avg, cpu_used_11_avg, starttime, endtime, testtime, f, )
                print(vuser, qps, request, avg, min, max, median, " ".join(percent_datas), failure, cpu_used_7_avg, cpu_used_11_avg)
                