# coding=utf-8
import requests
from locust import HttpLocust,TaskSet,task

#from requests.packages.urllib3.exceptions import InsecureRequestWarning
# 禁用安全请求警告
#requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class MyPerfTest(TaskSet):
    # 
    @task(1)
    def get_go_demo(self):
        # 定义请求头
        header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36"}

        req = self.client.get("/test",  headers=header, verify=False)
        if req.status_code == 200:
            print("success:", req.text)
        else:
            print("fails", req.text)

class websitUser(HttpLocust):
    task_set = MyPerfTest
    min_wait = 5  # 单位为毫秒
    max_wait = 10  # 单位为毫秒

if __name__ == "__main__":
    import sys
    import os
    host = sys.argv[1]
    if not host.startswith("http"):
        print("**> argument error, Usage: python %s http://127.0.0.1:8080" % __file__)
        sys.exit(-1)
    os.system("locust -f %s --host=%s" % (__file__, host))
