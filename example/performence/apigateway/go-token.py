# coding=utf-8
import requests
from locust import HttpLocust,TaskSet,task

#from requests.packages.urllib3.exceptions import InsecureRequestWarning
# 禁用安全请求警告
#requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class MyBlogs(TaskSet):
    # 
    @task(1)
    def get_go_demo(self):
        # 定义请求头
        header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36", "jdcloud-apim-subscription-key":"d4bd314ec1774dde0dfab8b5e54097ee"}

        req = self.client.get("/test",  headers=header, verify=False)
        if req.status_code == 200:
            print("success:", req.text)
        else:
            print("fails", req.text)

class websitUser(HttpLocust):
    task_set = MyBlogs
    min_wait = 1000  # 单位为毫秒
    max_wait = 5000  # 单位为毫秒

if __name__ == "__main__":
    import os
    os.system("locust -f perftest.py --host=http://xuegosvxp95y.cn-east-2.jdcloud-api.net")
