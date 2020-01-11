#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    index.py
    ~~~~~~~~~
    Modified default flask app called Flask.
    :license: Apache License 2.0, see LICENSE for more details.
"""

from flask import Flask, request, render_template, send_file, abort, g, jsonify, make_response
import json
import os
import re
import sys
import logging
import re
import time

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

from openapigatewaybackend.backend import backend as gw_backend
from client import HttpSession
import pickle
import threading

# start app, inject modules
app = Flask(__name__)
app.register_blueprint(gw_backend)
lock = threading.Lock()

gunicorn_logger = logging.getLogger("gunicorn.error")
app.logger.handlers = gunicorn_logger.handlers
app.logger.setLevel(gunicorn_logger.level)

# check if being executed with root privileges | terminate if not root
if os.name == 'nt':
    pass
elif os.geteuid() == 0:
    app.logger.debug("All set up. Running in privileged mode.")
else:
    app.logger.error("This program needs to be run as root.")
    app.logger.error("Example: export FLASK_APP='index.py'; sudo -E python -m flask run --host=0.0.0.0")
    exit(1)

# Settings
config = ConfigParser.ConfigParser()
config.read('crontab.cfg')
cronDir = config.get('cron', 'directory')
cronPrefix = config.get('cron', 'prefix')

# 由于使用gunicorn来管理flask app， 会周期性重启worker，导致存放在内存中的内容，在重启后，会丢失
# 临时方案：将buff内容存储到文件中进行持久化，worker启动时，如果文件存在，则从文件load数据
TMPFILE = "/tmp/buff_for_flask_app"


@app.before_first_request
def init_queue():
    if os.path.exists(TMPFILE):
        with open(TMPFILE, 'rb') as f:
            app.logger.debug("Data file {} found, try to load it!".format(TMPFILE))
            datas = pickle.load(f)
            if isinstance(datas, dict):
                app.mock_queue = datas.get("mock_queue", {})
                app.mock_request_queue = datas.get("mock_request_queue", {})
                app.logger.debug("Load data from file {}: mock_queue = {}, "
                                 "mock_request_queue = {}".format(TMPFILE, app.mock_queue, app.mock_request_queue))
            else:
                app.mock_queue = {}
                app.mock_request_queue = {}
                app.logger.error("Data file {} format error: {}".format(TMPFILE, datas))
            del datas
    else:
        app.logger.debug("No data file found, set buff to null for default!")
        app.mock_queue = {}
        app.mock_request_queue = {}


# log config
def make_dir(make_dir_path):
    path = make_dir_path.strip()
    if not os.path.exists(path):
        os.makedirs(path)
    return path


#
def save_data_to_file(mock_queue, mock_request_queue, tmpfile=TMPFILE):
    with lock:
        with open(tmpfile, 'wb+') as f:
            f.write(pickle.dumps({"mock_queue": mock_queue, "mock_request_queue": mock_request_queue}))


# read in cron files to dict
def readcron():
    crons = {}
    try:
        for cronfile in os.listdir(cronDir):
            if cronfile.startswith(cronPrefix):
                with open(os.path.join("/etc/cron.d", cronfile)) as f:
                    records = []
                    # scan password like keyword to replace with *
                    for line in f.readlines():
                        if "password" in line.lower() or "token" in line.lower():
                            # app.logger.debug("PASSWORD LINE: %s" % line)
                            # options like:
                            # 1. --password=abcd, --token=abcdtokenefg=!$#@
                            # 2. --abc-password 123 , --token abcdtokenefg=!$#@
                            # 3. --no-password -other options, --no-token --others
                            # 4. --no-password testcase, --no-token other-options
                            sline = []
                            for item in line.split():
                                if "password" in item.lower():
                                    # app.logger.debug("PASSWORD ITEMS: %s" % item)
                                    # 1. --password=abcd=efg
                                    if "=" in item:
                                        # check key include "password" ?
                                        key = item.split("=")[0]
                                        if "password" in key.lower():
                                            item = item.split("=")[0] + "=*"
                                    # TODO : other conditions TBC

                                # app.logger.debug("PASSWROD REPLACE: %s" % item)
                                sline.append(item)
                            line = " ".join(sline)
                        records.append(line)
                    crons[cronfile] = records
        return crons
    except IOError:
        pass
    return "Unable to read file"


# input validation of cron time format 
# https://gist.github.com/harshithjv/c58f0dfce0656cf94c8c
def validate_cron(cron_entry):
    cron = cron_entry.split(" ")[0:5]
    cron[0] = cron[0].lstrip("#")
    validate_crontab_time_format_regex = re.compile(
        "{0}\s+{1}\s+{2}\s+{3}\s+{4}".format(
            "(?P<minute>\*|[0-5]?\d)",
            "(?P<hour>\*|[01]?\d|2[0-3])",
            "(?P<day>\*|0?[1-9]|[12]\d|3[01])",
            "(?P<month>\*|0?[1-9]|1[012])",
            "(?P<day_of_week>\*|[0-6](\-[0-6])?)"
        )  # end of str.format()
    )  # end of re.compile()
    if validate_crontab_time_format_regex.match(" ".join(cron)) is None:
        return False
    else:
        return True


# root site 
@app.route('/')
def default():
    crons = readcron()
    return render_template("crontab.html", lines=crons)


# root site
@app.route('/logs/', defaults={'req_path': ''}, methods=['GET'])
@app.route('/logs/<path:req_path>', methods=['GET'])
def describe_avocado_logs(req_path):
    base_dir = '/export/Logs'

    # Joining the base and the requested path
    abs_path = os.path.join(base_dir, req_path)

    # Return 404 if path doesn't exist
    if not os.path.exists(abs_path):
        return abort(404)

    # Check if path is a file and serve
    if os.path.isfile(abs_path):
        return send_file(abs_path)

    # Show directory contents
    files = os.listdir(abs_path)
    # sort by desc
    files.sort(reverse=True)

    try:
        pagesize = int(request.args.get("size", 20)) if int(request.args.get("size", 20)) > 0 else 20
        pagenumber = int(request.args.get("page", 1)) if int(request.args.get("page", 1)) > 0 else 1
    except TypeError:
        app.logger.error("**> get page and size failed, set to default: pagenumber=1, pagesize=20")
        pagenumber = 1
        pagesize = 20

    pages = len(files)//pagesize + 1
    if pagenumber > pages:
        pagenumber = pages

    fileinfos = {
        "totals": len(files),
        # default line of page is 20
        "size": pagesize,
        # default start page is 1
        "page": pagenumber,
        "page_previous": 0,
        "page_next": 0,
        "pagelist": [],
        "filter": request.args.get("filter", "ALL"),
        "filters": ["ALL", "FAILED", "PASSED"],
        "goback": '/'.join(req_path.split('/')[:-1]) if req_path else "",
        "breadcrumbs": [],
        "breadcrumb_last": req_path.split('/')[-1] if len(req_path.split('/')) else "/",
        "has_avocado_result_dir": False,
        "filesinfos": []
    }

    if len(req_path.split('/')) > 1:
        index_p = 0
        for p in req_path.split('/')[:-1]:
            fileinfos["breadcrumbs"].append((p, "/".join(req_path.split('/')[0:index_p+1])))
            index_p += 1

    # only choose files  from start to end in the list
    start = (fileinfos["page"] - 1) * fileinfos["size"] if (fileinfos["page"] - 1) * fileinfos["size"] >= 0 else 0

    # if start > total, let start = total - 1, the last one
    if start > fileinfos["totals"]:
        start = fileinfos["totals"] - 1
    end = start + fileinfos["size"]

    if end > fileinfos["totals"]:
        end = fileinfos["totals"]

    if start <= 0:
        fileinfos["page_previous"] = 0
        start = 0
    else:
        fileinfos["page_previous"] = pagenumber - 1 if pagenumber - 1 > 0 else 0

    if end <= 0:
        fileinfos["page_next"] = 0
        end = 0
    else:
        fileinfos["page_next"] = pagenumber + 1 if pagenumber + 1 < pages else pages

    cnt = 0
    # fileinfos["pagelist"] item like:
    # 1. fileinfos["totals"] >= 9: << 1 2 3 ... 5 6 7 ... 9 >>
    # 2. fileinfos["totals"] < 9: << 1 2 3 4 5 6 7 8 >>
    for i in range(1, pages + 1):  # start to end -1
        if i == pagenumber:
            fileinfos["pagelist"].append((i, "active"))
        else:
            fileinfos["pagelist"].append((i, ""))
        cnt += 1
        if cnt > 9:  # 0 to 6 has 7 item in the list
            fileinfos["pagelist"][3] = ("...", "")
            fileinfos["pagelist"][7] = ("...", "")
            del fileinfos["pagelist"][8]
    # do active for pagelist
    for j, _ in fileinfos["pagelist"]:
        if j == pagenumber:
            break
    else:
        try:
            if pagenumber == 4:
                fileinfos["pagelist"][4] = ("4", "active")
                fileinfos["pagelist"][5] = ("5", "")
                fileinfos["pagelist"][6] = ("6", "")
            elif pagenumber - 1 == 8:
                fileinfos["pagelist"][4] = ("6", "")
                fileinfos["pagelist"][5] = ("7", "")
                fileinfos["pagelist"][6] = ("8", "active")
            else:
                fileinfos["pagelist"][4] = (pagenumber-1, "")
                fileinfos["pagelist"][5] = (pagenumber, "")
                fileinfos["pagelist"][6] = (pagenumber+1, "active")
        except IndexError:
            pass

    filter_files = []
    added_file = start

    for f in files[start:]:

        if added_file >= end:
            break

        file = {
            "isavocadoresultdir": False,
            "filename": f,
            "path": req_path + "/" + f if req_path else f,
            "avocado_job_has_results_json": False,
            "result": None,
            "isdir": False,
            "file_httprunner_report_file": []
        }
        # avocado job finished:
        if re.match("^job-\d{4}-\d\d-\d\dT\d\d\.\d\d-\w{7}$|latest", f):
            result_file = os.path.join(abs_path, f, "results.json")
            file["isavocadoresultdir"] = True
            fileinfos["has_avocado_result_dir"] = True
            file["isdir"] = True
            file["result"] = {}
            if os.path.isfile(result_file):
                with open(result_file) as fd:
                    result = json.load(fd)

                file["avocado_job_has_results_json"] = True
                file["result"] = result if result else {}
                if file["result"]["total"] == file["result"]["pass"]:
                    if fileinfos["filter"].upper() == "FAILED":
                        continue
                else:
                    if fileinfos["filter"].upper() == "PASSED":
                        continue
                # find the httprunner report file(html) and result for the folder
                for rrs, rds, rfs in os.walk(os.path.join(abs_path, f)):
                    for rf in rfs:
                        if rf.endswith("html"):
                            try:
                                http_ruuner_file = {
                                    "filename": rf,
                                    "path": os.path.join(req_path + "/" + f if req_path else f, rf)
                                }
                                for test in result["tests"]:
                                    avocado_test_filename = test["id"].split("/")[-1]
                                    avocado_test_filename_no_suffix = "".join(avocado_test_filename.split(".")[:-1])
                                    if rf.find(avocado_test_filename_no_suffix) != -1:
                                        http_ruuner_file["test_result"] = test
                            except IndexError:
                                continue
                            file["file_httprunner_report_file"].append(http_ruuner_file)
            # name like job-2019-10-29T19.40-9b85788, but no "results.json", job running ...
            else:
                pass
        elif os.path.isdir(os.path.join(abs_path, f)):
            file["isdir"] = True
        else:
            pass
        added_file += 1
        filter_files.append((added_file, file))

    fileinfos["filesinfos"].append(filter_files)
    fileinfos["totals_filter"] = len(filter_files)

    if request.json:
        protocol = request.json.get("protocol", None)
        datas = request.json.get("datas", None)

    # add / for folder in frontend
    file_type = []
    for f in files:
        if os.path.isdir(os.path.join(abs_path, f)):
            file_type.append("/")
        else:
            file_type.append("")

    abs_path_file = {}
    up = "/"
    if req_path:
        up = '/'.join(req_path.split('/')[:-1])

    for f in files:
        abs_path_file[f] = req_path + "/" + f if req_path else f

    return render_template("logs.html", files=fileinfos)


@app.route('/file', defaults={'req_path': ''})
@app.route('/file/', defaults={'req_path': ''})
@app.route('/file/<path:req_path>')
def dir_listing(req_path):
    base_dir = '/export/Logs'

    # Joining the base and the requested path
    abs_path = os.path.join(base_dir, req_path)

    # Return 404 if path doesn't exist
    if not os.path.exists(abs_path):
        return abort(404)

    # Check if path is a file and serve
    if os.path.isfile(abs_path):
        return send_file(abs_path)

    # Show directory contents
    files = os.listdir(abs_path)
    # sort by desc
    files.sort(reverse=True)

    # add / for folder in frontend
    file_type = []
    for f in files:
        if os.path.isdir(os.path.join(abs_path, f)):
            file_type.append("/")
        else:
            file_type.append("")

    abs_path_file = {}
    up = "/"
    if req_path:
        up = '/'.join(req_path.split('/')[:-1])

    for f in files:
        abs_path_file[f] = req_path + "/" + f if req_path else f

    return render_template('files.html', files=abs_path_file, up=up, sort_key=files, file_type=file_type)


# crontab site
@app.route('/crontab')
def crontab():
    crons = readcron()
    return render_template("crontab.html", lines=crons)


# writes cron files on POST
@app.route('/crontabsave', methods=['POST'])
def crontabsave():
    return json.dumps({'ERROR': "Change crond job from web frontend is disabled."}), 400, {
        'ContentType': 'application/json'}
    # if request.method == 'POST':
    #     data = json.loads(request.data)
    #     target_file = data.pop()
    #     app.logger.info('%s', target_file)
    #     for i in data:
    #         app.logger.info('%s', i)
    #         # for line in data:
    #         #    if validate_cron(line):
    #         #        continue
    #         #    else:
    #         #        return(json.dumps({'ERROR':"Wrong cron format: "+line}), 400, {'ContentType':'application/json'})
    #         with open(cronDir + target_file, "wb") as fo:
    #             for line in reversed(data):
    #                 fo.write(line + "\n")
    #
    #     return json.dumps({'success': True}), 200, {'ContentType': 'application/json'}
    # else:
    #     return json.dumps({'ERROR': "Writing file."}), 400, {'ContentType': 'application/json'}


@app.before_request
def before_req():
    """
    dir(request): |
    ['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__enter__', '__eq__', '__exit__', '__format__',
    '__ge__', '__getattribute__', '__gt__', '
    __hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__',
    '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '_
    _weakref__', '_cached_json', '_get_data_for_json', '_get_file_stream', '_get_stream_for_parsing', '_load_form_data',
    '_parse_content_type', 'accept_charsets', 'accept_encodings', 'accept_languages', 'accept_mimetypes',
    'access_route', 'application', 'args', 'authorization', 'base_url', 'blueprint', 'cache_control',
    'charset', 'close', 'content_encoding', 'content_length', 'content_md5', 'content_type', 'cookies',
    'data', 'date', 'dict_storage_class', 'disable_data_descriptor', 'encoding_errors', 'endpoint', 'environ',
    'files', 'form', 'form_data_parser_class', 'from_values', 'full_path', 'get_data', 'get_json',
    'headers', 'host', 'host_url', 'if_match', 'if_modified_since', 'if_none_match', 'if_range',
    'if_unmodified_since', 'input_stream', 'is_json', 'is_multiprocess', 'is_multithread', 'is_run_once',
    'is_secure', 'is_xhr', 'json', 'list_storage_class', 'make_form_data_parser', 'max_content_length',
    'max_form_memory_size', 'max_forwards', 'method', 'mimetype', 'mimetype_params', 'on_json_loading_failed',
     'parameter_storage_class', 'path', 'pragma', 'query_string', 'range', 'referrer', 'remote_addr', 'remote_user',
     'routing_exception', 'scheme', 'script_root', 'shallow', 'stream', 'trusted_hosts', 'url',
    'url_charset', 'url_root', 'url_rule', 'user_agent', 'values', 'view_args', 'want_form_data_parsed']
    """

    def get_request(data_id, remove=True):
        """
        根据request data_id，获取对应的request信息，一般用于获取达到mock server上的请求信息的确认
        :param data_id:
        :param remove:
        :return:
        """
        this_request = app.mock_request_queue.get(data_id, {})
        if remove and this_request:
            app.logger.debug("Remove request data [{}]: {}".format(data_id, this_request))
            del app.mock_request_queue[data_id]
            save_data_to_file(app.mock_queue, app.mock_request_queue)

        return make_response(jsonify(this_request), 200)

    def add_request_to_queue(request, force=True):
        """
        保存Mock server接收到的请求对象的相关数据，用于需要确认request内容的情况
        :param request:
        :param force:
        :return:
        """
        request_id = request.headers.get("X-Jdcloud-Test-Configs-Request-Setter-Id", None)
        res = {"id": request_id, "request": None, "code": 500, "error": None}
        try:
            if request_id is None:
                res["error"], res["code"] = ("No X-Jdcloud-Test-Configs-Request-Setter-Id"
                                             " in your request header!",
                                             403)
            if res["error"] is None:
                raw_header = {}
                for k, v in request.headers:
                    raw_header[k] = v
                raw_req = {
                    "url": request.url,
                    "method": request.method,
                    "path": request.path,
                    "scheme": request.scheme,
                    "url_charset": request.url_charset,
                    "base_url": request.base_url,
                    "environ": str(request.environ),
                    "params": str(request.query_string),
                    "data": str(request.data),
                    "form": str(request.form),
                    "full_path": request.full_path,
                    "headers": raw_header,
                    "host": request.host,
                    "host_url": request.host_url,
                    "cookies": request.cookies,
                    "files": str(request.files),
                    "auth": request.authorization,
                    # "timeout": 120,
                    "allow_redirects": True,
                    "proxies": None,
                    "hooks": None,
                    "verify": None,
                    "remote_addr": request.remote_addr,
                    # "json": request.json if request.is_json else None,
                    "user_agent": str(request.user_agent),
                }

                if force:
                    if request_id in app.mock_request_queue.keys():
                        app.logger.warning("Request data [{}] "
                                           "covered: {} to {}".format(request_id,
                                                                      app.mock_request_queue[request_id],
                                                                      raw_req))
                else:
                    res["error"], res["code"] = ("Request id [{}] exist already, use "
                                                 "X-Jdcloud-Test-Configs-Request-Setter-Force-Covered"
                                                 " if you recover the value, force={}, "
                                                 "list={}".format(request_id, force, app.mock_request_queue.keys()),
                                                 403)
                if res["error"] is None:
                    res["request"] = raw_req
                    res["code"] = 200
                    app.mock_request_queue[request_id] = raw_req
                    save_data_to_file(app.mock_queue, app.mock_request_queue)
                    app.logger.debug("Add request data [{}]: {}".format(request_id, app.mock_request_queue[request_id]))
                else:
                    app.logger.debug("Add request data error : {}".format(res["error"]))

            else:
                app.logger.debug("Add request data error : {}".format(res["error"]))
        except Exception as e:
            app.logger.error("Error for add_request_to_queue: {}".format(str(e)))
            res["error"], res["code"] = ("Error for add_request_to_queue: {}".format(str(e)),
                                         500)
        return make_response(jsonify(res), res["code"])

    def get_mock_content(data_id, remove=True):
        content = app.mock_queue.get(data_id, {})
        content_type = content.get("content-type", "application/json")
        return_code = content.get("code", 404)
        return_content = content.get("content", "")
        return_headers = content.get("headers", {})
        return_delay = content.get("delaysecs", 0)

        if content and remove:
            app.logger.debug("Remove Mock data [{}]: {}".format(data_id, content))
            del app.mock_queue[data_id]
            save_data_to_file(app.mock_queue, app.mock_request_queue)

        if not content:
            return_code = None
            res = make_response(jsonify(return_content), 404)
        elif "application/json" in content_type:
            app.logger.debug("Return json mock data [{}]: {}".format(data_id, content))
            res = make_response(jsonify(return_content), return_code)
        else:
            app.logger.debug("Return not json Mock data [{}]: {}".format(data_id, content))
            res = make_response(return_content, return_code)
        if return_headers:
            has_content_length = return_headers.get("Content-Length", None)
            if has_content_length is not None:
                del return_headers["Content-Length"]
            app.logger.debug("Return and update header for mock data [{}]: {}".format(data_id, return_headers))

            res.headers = return_headers
        if isinstance(return_delay, int) and return_delay >= 0:
            app.logger.debug("Return mock data after {}s".format(return_delay))
            time.sleep(return_delay)
        else:
            app.logger.debug("Return delay time format error, "
                             "do not delay and return the content, delaysecs is: {}".format(return_delay))
        return res, return_code

    def set_mock_content(request, force=False):
        res = {"id": None, "content": None, "headers": None, "code": 200, "content-type": "application/json",
               "error": None, "delaysecs": 0}
        if request.method != "POST":
            res["error"], res["code"] = ("Mock server setter must use POST "
                                         "method! post json like:"
                                         "{ *id: your_mock_data_id,"
                                         " *code: your_mocker_return_code,"
                                         " *body: your_mock_return_datas,"
                                         " headers: your_mock_return_headers,"
                                         " type: your_mock_data_type},"
                                         " type like application/json for"
                                         " json return(default if not set), * is must option",
                                         403)
        else:
            data = request.json
            data_id = data.get("id", None)
            data_code = data.get("code", None)
            if data_id is None:
                res["error"], res["code"] = ("Mock post data format error! no id found, json data:"
                                             "{ *id: your_mock_data_id,"
                                             " *code: your_mocker_return_code, default is 200"
                                             " *body: your_mock_return_datas,"
                                             " headers: your_mock_return_headers,"
                                             " delaysecs: your_mock_return_delay_secs, default is 0,"
                                             " type: your_mock_data_type},"
                                             " type like application/json for"
                                             " json return(default if not set), * is must option",
                                             406)
            elif data_code is None:
                res["error"], res["code"] = ("Mock post data format error! no code found, json data:"
                                             "{ *id: your_mock_data_id,"
                                             " *code: your_mocker_return_code,"
                                             " *body: your_mock_return_datas,"
                                             " headers: your_mock_return_headers,"
                                             " type: your_mock_data_type},"
                                             " type like application/json for"
                                             " json return(default if not set), * is must option",
                                             406)
            else:
                if data_id in app.mock_queue.keys():
                    if not force:
                        res["error"], res["code"] = ("Mock post data id exist already, use "
                                                     "X-Jdcloud-Test-Configs-Mock-Setter-Force-Covered"
                                                     " if you recover the value!",
                                                     403)
                    else:
                        app.logger.warning("Mock data [{}] covered: {} to {}".format(data_id,
                                                                                     app.mock_queue[data_id], data))
                if res["error"] is None:
                    data_code = data.get("code", None)
                    data_type = data.get("type", "application/json")
                    data_content = data.get("body", "")
                    data_headers = data.get("headers", "")
                    data_return_delay = data.get("delaysecs", 0)

                    app.mock_queue[data_id] = {
                        "content-type": data_type,
                        "code": data_code,
                        "content": data_content,
                        "headers": data_headers,
                        "delaysecs": data_return_delay
                    }
                    save_data_to_file(app.mock_queue, app.mock_request_queue)

                    res["id"], res["data"], res["code"] = (
                        data_id,
                        app.mock_queue[data_id],
                        200
                    )
                    app.logger.debug("Add Mock data [{}]: {}".format(data_id, app.mock_queue[data_id]))
        return make_response(jsonify(res), res["code"])

    # app.logger.debug("Request: %s" % dir(request))
    # app.logger.debug("Request args: %s" % request.args)
    # app.logger.debug("Request base url: %s" % request.base_url)
    # app.logger.debug("Request blueprint: %s" % request.blueprint)
    # app.logger.debug("Request cookies: %s" % request.cookies )
    # app.logger.debug("Request data: %s" % str(request.data))
    # app.logger.debug("Request endpoint: %s" % request.endpoint)
    # app.logger.debug("Request environ: %s" % request.environ)
    # app.logger.debug("Request files: %s" % request.files)
    # app.logger.debug("Request form: %s" % request.form)
    # app.logger.debug("Request from_values: %s" % request.from_values)
    # app.logger.debug("Request full_path: %s" % request.full_path)
    # app.logger.debug("Request headers(%s): %s" % (type(request.headers), request.headers))
    # app.logger.debug("Request host: %s" % request.host)
    # app.logger.debug("Request host_url: %s" % request.host_url)
    # app.logger.debug("Request is_json: %s" % request.is_json)
    # app.logger.debug("Request json: %s" % str(request.json))
    # app.logger.debug("Request method: %s" % request.method)
    # app.logger.debug("Request mimetype: %s" % request.mimetype)
    # app.logger.debug("Request mimetype_params: %s" % request.mimetype_params)
    # app.logger.debug("Request path: %s" % request.path)
    # app.logger.debug("Request pragma: %s" % request.pragma)
    # app.logger.debug("Request query_string: %s" % str(request.query_string))
    #
    # app.logger.debug("Request range: %s" % request.range)
    # app.logger.debug("Request referrer: %s" % request.referrer)
    # app.logger.debug("Request remote_addr: %s" % request.remote_addr)
    # app.logger.debug("Request remote_user: %s" % request.remote_user)
    # app.logger.debug("Request scheme: %s" % request.scheme)
    # app.logger.debug("Request url: %s" % request.url)
    # app.logger.debug("Request url_charset: %s" % request.url_charset)
    # app.logger.debug("Request url_root: %s" % request.url_root)
    # app.logger.debug("Request url_rule: %s" % request.url_rule)
    # app.logger.debug("Request user_agent: %s" % request.user_agent)
    # app.logger.debug("Request values: %s" % request.values)
    # app.logger.debug("Request view_args: %s" % request.view_args)

    # get mock data request:
    request_getter_id = request.headers.get("X-Jdcloud-Test-Configs-Request-Getter", None)
    is_rm_request = True \
        if str(request.headers.get("X-Jdcloud-Test-Configs-Request-Getter-Remove", "enable")
               ).lower() == "enable" else False
    request_setter_flag = request.headers.get("X-Jdcloud-Test-Configs-Request-Setter", None)
    request_force_covered = True \
        if str(request.headers.get("X-Jdcloud-Test-Configs-Request-Setter-Force-Covered", "enable")
               ).lower() == "enable" else False

    if request_getter_id is not None:
        app.logger.debug("Get request data [{}]".format(request_getter_id))
        return get_request(request_getter_id, is_rm_request)

    if str(request_setter_flag).lower() == "enable":
        app.logger.debug("Set request data request_setter_flag={} force={}".format(request_setter_flag,
                                                                                   request_force_covered))
        return add_request_to_queue(request, request_force_covered)

    # get mock data request:
    mock_getter_id = request.headers.get("X-Jdcloud-Test-Configs-Mock-Getter", None)
    is_rm = True \
        if str(request.headers.get("X-Jdcloud-Test-Configs-Mock-Getter-Remove", "enable")
               ).lower() == "enable" else False
    mock_setter_flag = request.headers.get("X-Jdcloud-Test-Configs-Mock-Setter", None)
    force_covered = True \
        if str(request.headers.get("X-Jdcloud-Test-Configs-Mock-Setter-Force-Covered", "no")
               ).lower() == "enable" else False

    if mock_getter_id is not None:
        app.logger.debug("Get mock data [{}]".format(mock_getter_id))
        res, returncode = get_mock_content(mock_getter_id, is_rm)
        return res

    # 支持请求method+url来定位一个mockdata并，按照mockdata来返回
    mock_data_id_method_and_url = str(request.method).lower() + \
                                  str(request.full_path).replace('?', '').replace('/', '_')
    res, returncode = get_mock_content(mock_data_id_method_and_url)
    if returncode is not None:
        app.logger.debug("Return mock data [{}]: {}".format(mock_data_id_method_and_url, returncode))
        return res

    if str(mock_setter_flag).lower() == "enable":
        return set_mock_content(request, force_covered)

    if str(request.headers.get("x-jdcloud-test-configs-redirect", "")) == "enable":

        http_client_session = HttpSession()

        app.logger.debug(request)
        app.logger.debug("redirect_req: %s" % request)

        url = request.headers.get("X-Jdcloud-Test-Configs-Url", None)
        method = request.headers.get("X-Jdcloud-Test-Configs-Method", None)
        test_header_transfer_to_backend = request.headers.get("X-Jdcloud-Test-Configs-Headers-Transfer", None)

        redirect_old_header = {}
        for k, v in request.headers:
            if not test_header_transfer_to_backend and \
                    k.lower().startswith("x-jdcloud-test-configs"):
                continue

            redirect_old_header[k] = v
        #
        # url = redirect_old_header.pop("X-Jdcloud-Test-Configs-Url")
        # method = redirect_old_header.pop("X-Jdcloud-Test-Configs-Method")
        # request.headers = redirect_old_header

        app.logger.debug("url: %s" % url)
        app.logger.debug("method: %s" % method)
        app.logger.debug("header: %s" % redirect_old_header)
        app.logger.debug("request: %s" % request.__dict__)

        redirect_req = {
            "params": str(request.query_string),
            "data": request.data,
            "headers": redirect_old_header,
            "cookies": request.cookies,
            "files": request.files,
            "auth": request.authorization,
            "timeout": 120,
            "allow_redirects": True,
            "proxies": None,
            "hooks": None,
            "stream": request.stream,
            "verify": None,
            "cert": None,
            # "json": request.json
        }

        app.logger.debug("redirect_req: %s" % redirect_req)

        # params = None, data = None, headers = None, cookies = None, files = None,
        # auth = None, timeout = None, allow_redirects = True, proxies = None,
        # hooks = None, stream = None, verify = None, cert = None, json = None

        redirect_res = http_client_session.request(
            method,
            url,
            name="test",
            **redirect_req
        )
        app.logger.debug("get redirect response: %s" % redirect_res)
        # app.logger.debug("meta data: %s" % http_client_session.meta_data)
        return make_response(jsonify(http_client_session.meta_data["data"]),
                             http_client_session.meta_data["data"][-1]["response"]["status_code"])


@app.route('/api/v1/mockserver/mocks', methods=['GET'])
def mock_server_mock_datas():
    return_code = 200
    res = {"data": app.mock_queue, "error": None, "code": return_code}
    app.logger.debug("/api/v1/mockserver/mocks return: {}".format(app.mock_queue))
    return make_response(jsonify(res), return_code)


@app.route('/api/v1/mockserver/requests', methods=['GET'])
def mock_server_request_datas():
    return_code = 200
    res = {"data": app.mock_request_queue, "error": None, "code": return_code}
    app.logger.debug("/api/v1/mockserver/requests return: {}".format(res))
    return make_response(jsonify(res), return_code)


@app.route('/api/v1/mockserver/mocks/<data_id>', methods=['GET'])
def mock_server_mock_data(data_id):
    return_code = 200
    data = app.mock_queue.get(data_id, None)
    if data is not None:
        res = {"data": app.mock_queue[data_id], "error": None, "code": return_code, "id": data_id}
    else:
        res = {"data": None, "error": "Not Found!", "code": 404, "id": data_id}
    app.logger.debug("/api/v1/mockserver/mocks/{} return: {}".format(data_id, res))
    return make_response(jsonify(res), return_code)


# call from gateway, url like /version/balba....
@app.route('/v1/api/mockserver/mocks/<data_id>', methods=['POST'])
def mock_server_mock_data_sdk(data_id):
    return_code = 200
    data = app.mock_queue.get(data_id, None)
    requestid = request.headers.get("X-Jdcloud-Request-Id", "12345678901234567890123456789012")

    if data is not None:
        tag_data = data.get("content", {})
        res = {"result": tag_data, "requestId": requestid}
    else:
        res = {"result": None, 'error': {'message': 'Mock data not found!', 'status': 'NOT_FOUND', 'code': 404},
               "requestId": requestid}
    app.logger.debug("/api/v1/mockserver/mocks/{} return: {}".format(data_id, res))
    return make_response(jsonify(res), return_code)


@app.route('/api/v1/mockserver/requests/<data_id>', methods=['GET'])
def mock_server_request_data(data_id):
    return_code = 200
    data = app.mock_request_queue.get(data_id, None)
    if data is not None:
        res = {"data": app.mock_request_queue[data_id], "error": None, "code": return_code, "id": data_id}
    else:
        res = {"data": None, "error": "Not Found!", "code": 404, "id": data_id}
    app.logger.debug("/api/v1/mockserver/mocks/{} return: {}".format(data_id, res))
    return make_response(jsonify(res), return_code)


@app.route('/api/v1/mockserver/mocks/<data_id>', methods=['DELETE'])
def mock_server_mock_data_remove(data_id):
    return_code = 200
    data = app.mock_queue.get(data_id, None)
    if data is not None:
        res = {"data": app.mock_queue[data_id], "error": None, "code": return_code, "id": data_id}
        del app.mock_queue[data_id]
        save_data_to_file(app.mock_queue, app.mock_request_queue)
    else:
        return_code = 404
        res = {"data": None, "error": "Not Found the data", "code": return_code, "id": data_id}
    app.logger.debug("/api/v1/mockserver/mocks return: {}".format(res))
    return make_response(jsonify(res), return_code)


@app.route('/api/v1/mockserver/requests/<data_id>', methods=['DELETE'])
def mock_server_request_data_remove(data_id):
    return_code = 200
    data = app.mock_request_queue.get(data_id, None)
    if data is not None:
        res = {"data": app.mock_request_queue[data_id], "error": None, "code": return_code, "id": data_id}
        del app.mock_request_queue[data_id]
        save_data_to_file(app.mock_queue, app.mock_request_queue)
    else:
        return_code = 404
        res = {"data": None, "error": "Not Found the request data", "code": return_code, "id": data_id}
    app.logger.debug("/api/v1/mockserver/request return: {}".format(res))
    return make_response(jsonify(res), return_code)


if __name__ == '__main__':
    from flask.logging import default_handler

    app.logger.addHandler(default_handler)
    app.logger.setLevel(logging.DEBUG)

    if len(sys.argv) < 2:
        app.logger.debug("usage: %s port" % (sys.argv[0]))
        sys.exit(-1)

    p = int(sys.argv[1])
    app.logger.debug("start at port %s" % p)
    app.run(host='0.0.0.0', port=p, debug=True, threaded=True)
