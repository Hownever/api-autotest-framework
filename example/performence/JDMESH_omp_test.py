from locust import HttpLocust, TaskSet, task
from debugtalk import MyTestSigner, gen_ompopenapi_header


#HOST = "http://10.226.222.94:8100"
#HOST = "http://10.226.201.70:8100"
HOST = "http://10.226.221.2:8100"
URI = "/v1/routesList"
full_url = HOST + URI


def login(l):
    r = l.client.get(URI, headers=gen_ompopenapi_header(full_url, ""))
    result = r.json()
    print("+"*80)
    print(result)


class UserBehavior(TaskSet):
    @task(1)
    def on_start(self):
        login(self)




class WebsiteUser(HttpLocust):
    task_set = UserBehavior
    host = HOST
    min_wait = 1000
    max_wait = 9000
