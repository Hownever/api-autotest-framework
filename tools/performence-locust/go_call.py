from locust import HttpLocust, TaskSet, task


class WebsiteTasks(TaskSet):
    @task
    def index(self):
        token="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXlWZXJzaW9uIjoicnNhdjEyIiwicHJvZHVjdCI6Im1pY3Jvc2VydmljZXMiLCJzZXJ2aWNlTmFtZSI6ImpkbWVzaC10ZXN0LWltYWdlcyIsImdyb3VwIjoiZWFzdDItcHJlLWF6MSIsImlwIjoiMTAuMjI2LjIwNS43IiwiaW5zdGFuY2VOYW1lIjoiIiwiZXhwIjoxNjA0NDYwNDM2LCJpYXQiOjE1NzI5MjQ0MzcsImlzcyI6Imxpa3VpMzQifQ.EUVWI1BQ_X_WYlhW36PWjv_6vUJZylumMSIyKCYhAGYqqPyXYH5748ZdfFjY0WuXGD58XdhxSSqFZZZ0xCHPmukqOY7OsVKyBJkswQQCSV5tGFcCDQ6niOcCR0tC0Qj5qgmG3J6w1P64e8RT3_oHgONnV98fihLenW19ptyyk80"
        header = {"authtoken": token}
        self.client.get("/call", headers=header)


class WebsiteUser(HttpLocust):
    task_set = WebsiteTasks
    min_wait = 10
    max_wait = 9000


