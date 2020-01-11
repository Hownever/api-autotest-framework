# -*- coding: utf-8 -*-

import os
import json
import time
import xml.etree.ElementTree as ET

from flask import Response
from flask import Flask, jsonify, abort, request, make_response, url_for
from flask_httpauth import HTTPBasicAuth
from flask import Blueprint
import logging

backend = Blueprint('backend', __name__, template_folder='templates')
auth = HTTPBasicAuth()

logger = logging.getLogger('gunicorn.error')

ClientClosed = 499
J_MSG = {ClientClosed: 'ClientClosed'}


@auth.get_password
def get_password(username):
    if username == 'jiashuo':
        return "test"
    return None


class CustomFlaskErr(Exception):
    status_code = 400

    def __init__(self, return_code=None, status_code=None, payload=None):
        Exception.__init__(self)
        self.return_code = return_code
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['error'] = J_MSG[self.return_code]
        return rv


@backend.errorhandler(CustomFlaskErr)
def handle_flask_error(error):
    response = jsonify(error.to_dict())

    response.status_code = error.status_code

    return response


@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 403)
    # return 403 instead of 401 to prevent browsers from displaying the default auth dialog


@backend.errorhandler(400)
def bad_request(error):
    return make_response(jsonify({'error': 'Bad request'}), 400)


@backend.errorhandler(401)
def unauthorized(error):
    return make_response(jsonify({'error': 'Unauthorized'}), 401)


@backend.errorhandler(403)
def forbidden(error):
    return make_response(jsonify({'error': 'Forbidden'}), 403)


@backend.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


@backend.errorhandler(409)
def conflict(error):
    return make_response(jsonify({'error': 'Conflict'}), 409)


@backend.errorhandler(410)
def gone(error):
    return make_response(jsonify({'error': 'Gone'}), 410)


@backend.errorhandler(429)
def too_many_requests(error):
    return make_response(jsonify({'error': 'Too Many Requests'}), 429)


@backend.errorhandler(500)
def internal_server_error(error):
    return make_response(jsonify({'error': 'Internal Server Error'}), 500)


@backend.errorhandler(502)
def bad_gateway(error):
    return make_response(jsonify({'error': 'Bad Gateway'}), 502)


@backend.errorhandler(503)
def service_unavailable(error):
    return make_response(jsonify({'error': 'Service Unavailable'}), 503)


@backend.errorhandler(504)
def gateway_timeout(error):
    return make_response(jsonify({'error': 'Gateway Timeout'}), 504)


tasks = [
    {
        'id': 1,
        'title': u'Buy groceries',
        'description': u'Milk, Cheese, Pizza, Fruit, Tylenol',
        'done': False
    },
    {
        'id': 2,
        'title': u'Learn Python',
        'description': u'Need to find a good Python tutorial on the web',
        'done': False
    }
]


def make_public_task(task):
    new_task = {}
    for field in task:
        if field == 'id':
            new_task['uri'] = url_for('backend.get_task', task_id=task['id'], _external=True)
        else:
            new_task[field] = task[field]
    return new_task


@backend.route('/todo/api/v1/tasks/getAllOrUniqueTask', methods=['GET'])
# @auth.login_required
def get_tasks():
    if request.args:
        try:
            tasks_back = list()
            for task in tasks:
                flag = 1
                for j in request.args.keys():
                    if request.args[j] != task[j]:
                        flag = 0
                        break
                if flag:
                    tasks_back.append(task)
            if tasks_back:
                return jsonify({'task': map(make_public_task, tasks_back), 'result': True})
            else:
                abort(404)
        except KeyError:
            abort(400)
    return jsonify({'task': map(make_public_task, tasks), 'result': True})


@backend.route('/todo/api/v1/tasks/getTaskById/<int:task_id>', methods=['GET'])
# @auth.login_required
def get_task(task_id):
    task = filter(lambda t: t['id'] == task_id, tasks)
    if len(task) == 0:
        abort(404)
    return jsonify({'task': make_public_task(task[0]), 'result': True})


@backend.route('/todo/api/v1/tasks/createTask/<req_type>', methods=['POST'])
# @auth.login_required
def create_task(req_type):
    task = dict()
    if not request.json:
        try:
            xml = ET.fromstring(request.get_data())
            logger.debug(xml.iter)
            task = {
                'id': tasks[-1]['id'] + 1,
                'title': xml[0].text,
                'description': xml[1].text,
                'done': False
            }
        except Exception as e:
            logger.error(e)
            abort(400)
    elif 'title' not in request.json:
        abort(400)
    else:
        task = {
            'id': tasks[-1]['id'] + 1,
            'title': request.json['title'],
            'description': request.json.get('description', ""),
            'done': False
        }
    tasks.append(task)
    return jsonify({'task': make_public_task(task), 'result': True}), 201


@backend.route('/todo/api/v1/tasks/modifyTaskById/<int:task_id>/<req_type>', methods=['PUT', 'PATCH'])
# @auth.login_required
def update_task(task_id, req_type):
    task = filter(lambda t: t['id'] == task_id, tasks)
    if len(task) == 0:
        abort(404)
    if not request.json:
        try:
            xml = ET.fromstring(request.get_data())
            task[0]['title'] = xml[0].text
            task[0]['description'] = xml[1].text
            task[0]['done'] = xml[2].text
        except Exception as e:
            logger.error(e)
            abort(400)
    elif 'title' in request.json and type(request.json['title']) != unicode:
        abort(400)
    elif 'description' in request.json and type(request.json['description']) is not unicode:
        abort(400)
    elif 'done' in request.json and type(request.json['done']) is not bool:
        abort(400)
    else:
        task[0]['title'] = request.json.get('title', task[0]['title'])
        task[0]['description'] = request.json.get('description', task[0]['description'])
        task[0]['done'] = request.json.get('done', task[0]['done'])
    return jsonify({'task': make_public_task(task[0]), 'result': True})


@backend.route('/todo/api/v1/tasks/deleteTaskById/<int:task_id>', methods=['DELETE'])
# @auth.login_required
def delete_task(task_id):
    task = filter(lambda t: t['id'] == task_id, tasks)
    if len(task) == 0:
        abort(404)
    tasks.remove(task[0])
    return jsonify({'result': True})


@backend.route('/todo/api/v1/tasks/getHead/<int:task_id>', methods=['HEAD'])
# @auth.login_required
def head_task():
    pass


@backend.route('/todo/api/v1/tasks/getError/<errno>', methods=['GET'])
# @auth.login_required
def get_error(errno):
    try:
        abort(int(errno))
    except LookupError:
        raise CustomFlaskErr(ClientClosed, status_code=499)


@backend.route('/todo/api/v1/tasks/returnAllHead', methods=['GET', 'POST', 'HEAD', 'DELETE', 'PUT', 'PATCH'])
# @auth.login_required
def return_header():
    header_dict = {"error": "No Header"}
    try:
        header_dict = request.headers
    except Exception as e:
        logger.error(e)
        abort(400)
    return jsonify(dict(header_dict))


@backend.route('/v1/global/<status>', methods=['GET'])
# @auth.login_required
def return_global_error(status):
    logger.debug(request.headers)
    language = request.headers["Accept-Language"] if "Accept-Language" in request.headers else None
    content_language = request.headers["Content-Language"] if "Content-Language" in request.headers else None
    if language in ["zh", "zh_cn", "cn", "zh-cn"]:
        language = "zh"
    elif language in ["en"]:
        language = "en"
    else:
        language = "zh"
    error_return = {}
    request_id = request.headers["X-Jcloud-Request-Id"]
    with open(os.path.join(os.path.dirname(__file__),
                           "global_test_{}.json".format(language)), "r", encoding="utf-8") as apigateway_file:
        error_code_list = json.load(apigateway_file)
    if not status:
        abort(404)
    else:
        if "OUTOFRANGE" in str(status):
            operator_judge = {
                "zh": {"le": u"小于等于", "lt": u"小于", "ge": u"大于等于", "gt": u"大于"},
                "en": {"le": "le", "lt": "lt", "ge": "ge", "gt": "gt"}
            }
            message = {
                "zh": {"no1": u"参数取值不合法",
                       "no2": u"参数{}取值应该介于{}和{}之间",
                       "no3": u"参数{}取值应该介于和之间",
                       "no4": u"参数{}取值应该介于{}和之间",
                       "no5": u"参数{}取值应该介于和{}之间",
                       "no6": u"参数{}取值应该{}{}",
                       "no7": u"参数{}取值应该{}",
                       "no8": u"参数{}取值不合法"},
                "en": {"no1": "Parameter values are not valid",
                       "no2": "Parameter {} values should between {} and {}",
                       "no3": "Parameter {} values should between and ",
                       "no4": "Parameter {} values should between {} and ",
                       "no5": "Parameter {} values should between and {}",
                       "no6": "Parameter {} values should {}{}",
                       "no7": "Parameter {} values should {}",
                       "no8": "Parameter {} values are not valid"}
            }
            try:
                argument = status.split("_")[1]
                operator = status.split("_")[2]
                operand1 = status.split("_")[3]
                operand2 = status.split("_")[4]
                error_return["error"] = dict()
                error_return["error"]["details"] = [{}]
                if argument == "None":
                    error_return["error"].update({"code": 400,
                                                  "message": message[language]["no1"], "status": "OUT_OF_RANGE"})
                elif operator == "between" and operand1 != "None" and operand2 != "None":
                    error_return["error"].update({"code": 400,
                                                  "message": message[language]["no2"].format(argument, operand1, operand2),
                                                  "status": "OUT_OF_RANGE"})
                    error_return["error"]["details"][0]["argument"] = argument
                    error_return["error"]["details"][0]["operator"] = "between"
                    error_return["error"]["details"][0]["operand1"] = operand1
                    error_return["error"]["details"][0]["operand2"] = operand2
                elif operator == "between" and operand1 == "None" and operand2 == "None":
                    error_return["error"].update({"code": 400,
                                                  "message": message[language]["no3"].format(argument),
                                                  "status": "OUT_OF_RANGE"})
                    error_return["error"]["details"][0]["argument"] = argument
                    error_return["error"]["details"][0]["operator"] = "between"
                elif operator == "between" and operand1 != "None" and operand2 == "None":
                    error_return["error"].update({"code": 400,
                                                  "message": message[language]["no4"].format(argument, operand1),
                                                  "status": "OUT_OF_RANGE"})
                    error_return["error"]["details"][0]["argument"] = argument
                    error_return["error"]["details"][0]["operator"] = "between"
                    error_return["error"]["details"][0]["operand1"] = operand1
                elif operator == "between" and operand1 == "None" and operand2 != "None":
                    error_return["error"].update({"code": 400,
                                                  "message": message[language]["no5"].format(argument, operand2),
                                                  "status": "OUT_OF_RANGE"})
                    error_return["error"]["details"][0]["argument"] = argument
                    error_return["error"]["details"][0]["operator"] = "between"
                    error_return["error"]["details"][0]["operand2"] = operand2
                elif operator in operator_judge[language] and operand1 != "None":
                    error_return["error"].update({"code": 400,
                                                  "message": message[language]["no6"].format
                                                  (argument, operator_judge[language][operator], operand1),
                                                  "status": "OUT_OF_RANGE"})
                    error_return["error"]["details"][0]["argument"] = argument
                    error_return["error"]["details"][0]["operator"] = operator
                    error_return["error"]["details"][0]["operand1"] = operand1
                elif operator in operator_judge[language] and operand1 == "None":
                    error_return["error"].update({"code": 400,
                                                  "message": message[language]["no7"].
                                                 format(argument, operator_judge[language][operator]),
                                                  "status": "OUT_OF_RANGE"})
                    error_return["error"]["details"][0]["argument"] = argument
                    error_return["error"]["details"][0]["operator"] = operator
                else:
                    error_return["error"].update({"code": 400, "message": message[language]["no8"].format(argument),
                                                  "status": "OUT_OF_RANGE"})
                    error_return["error"]["details"][0]["argument"] = argument
                    error_return["error"]["details"][0]["operator"] = operator
                error_return["requestId"] = request_id
                # logger.error(e)rror_return
                resp = Response(json.dumps(error_return), status=500, mimetype='application/json')
                return resp
            except IndexError as e:
                logger.error(e)
                abort(400)
        for error_code in error_code_list:
            if str(status) in str(error_code["status"]):
                logger.debug(error_code)
                if "param" in error_code["message"]:
                    error_code["details"] = [{}]
                if "param0" in error_code["message"]:
                    error_code["details"][0]["param0"] = u"檀聪" if language == "zh" else "Tancong"
                if "param1" in error_code["message"]:
                    error_code["details"][0]["param1"] = u"李强" if language == "zh" else "Liqiang"
                if "param2" in error_code["message"]:
                    error_code["details"][0]["param3"] = u"边维天" if language == "zh" else "Bianweitian"
                error_return["error"] = error_code
                error_return["requestId"] = request_id
                # logger.debug(e)rror_return
                resp = Response(json.dumps(error_return), status=500 if status != "APIGATEWAY_SUCCESS" else 200,
                                mimetype='application/json')
                if content_language:
                    resp.headers["Content-Language"] = content_language
                return resp
        return jsonify(dict({"error": "No Such Error"}))


@backend.route('/v1/tasks/orderHead/<head_key>', methods=['GET'])
# @auth.login_required
def get_order_head(head_key):
    header_dict = {"error": "No Header"}
    head_tran_dict = {
        "userId": "x-jdcloud-userId",
        "accountId": "x-jdcloud-accountId",
    }
    try:
        request_id = request.headers["X-Jcloud-Request-Id"]
        header_dict = request.headers
        if head_tran_dict[head_key] in header_dict:
            return jsonify({head_key: header_dict[head_tran_dict[head_key]], "requestId": request_id})
        else:
            return jsonify({head_key: False, "requestId": request_id})
    except Exception as e:
        logger.error(e)
        abort(400)
    return jsonify(dict(header_dict))


@backend.route('/v1/tasks/backendsign/<switch>', methods=['GET'])
# @auth.login_required
def backendsign(switch):
    header_dict = {"error": "No Header"}
    backendsign_keys = ["x-jdcloud-gw-nonce", "x-jdcloud-gw-sign", "x-jdcloud-gw-signheaders", "x-jdcloud-gw-version"]
    try:
        request_id = request.headers["X-Jcloud-Request-Id"]
        header_dict = request.headers
        if switch == "open":
            for key in backendsign_keys:
                if key not in header_dict:
                    abort(400)
            return jsonify({"is_backendsign": True, "requestId": request_id})
        elif switch == "close":
            for key in backendsign_keys:
                if key in header_dict:
                    abort(400)
            return jsonify({"is_backendsign": False, "requestId": request_id})
        else:
            abort(400)
    except Exception as e:
        logger.error(e)
        abort(400)
    return jsonify(dict(header_dict))


@backend.route('/todo/api/v1/tasks/returntype/<type_of_return>', methods=['GET'])
# @auth.login_required
def return_type(type_of_return):
    if not type_of_return:
        abort(400)
    if type_of_return == "string":
        return "jiashuo"
    if type_of_return == "float":
        return "12.34"
    if type_of_return == "int32":
        return "123"
    if type_of_return == "boolean":
        return "True"
    if type_of_return == "int64":
        return "2147483646"
    if type_of_return == "double":
        return "12.3456789123456789"
    if type_of_return == "additionalProperties":
        return jsonify({"additionalProperties": 111})
    if type_of_return == "date":
        return time.time()
    if type_of_return == "arrayint64":
        return "[1, 2, 3, 4]"
    if type_of_return == "arrayobject":
        return '[{"a": "b"}]'
    if type_of_return == "arraystring":
        return '["a", "b", "c", "d"]'
    abort(400)


@backend.route('/todo/api/v1/v2/poi/PoiPortraitAsy', methods=['GET'])
# @auth.login_required
def PoiPortraitAsy():
    gemo = request.query_string.split("&")[0]
    distance = request.query_string.split("&")[1]
    month = request.query_string.split("&")[2]
    poi_type = request.query_string.split("&")[3]
    grid_type = request.query_string.split("&")[4]
    region = request.query_string.split("&")[5]
    if isinstance(gemo, str) & isinstance(distance, str) & isinstance(month, str) & isinstance(poi_type, str) & \
        isinstance(grid_type, str) & isinstance(region, str):

        return jsonify({"result_code": "certi_ok", "result_msg": "ok", "result_data": {"job_code": "job_code"}})
    else:
        abort(404)


@backend.route('/todo/api/v1/v2/poi/PoiPortraitSyn', methods=['GET'])
# @auth.login_required
def PoiPortraitSyn():
    gemo = request.query_string.split("&")[0]
    distance = request.query_string.split("&")[1]
    month = request.query_string.split("&")[2]
    poi_type = request.query_string.split("&")[3]
    grid_type = request.query_string.split("&")[4]
    region = request.query_string.split("&")[5]
    if isinstance(gemo, str) & isinstance(distance, str) & isinstance(month, str) & isinstance(poi_type, str) & \
        isinstance(grid_type, str) & isinstance(region, str):
        return jsonify({
            "result_code": "result_code",
            "result_msg": "result_msg",
            "result_data": {
                "portrait_list": [{
                    "type": "type",
                    "data": {
                        "label": "label",
                        "resultMap": [{
                            "name": "name",
                            "value": "value"
                        }]
                    }
                }]
            }
        })
    else:
        abort(404)


@backend.route('/todo/api/v1/task/RE1/<aps>/<bpi>/<cpl>/<dpf>/<epd>/<fpb>', methods=['POST', 'GET'])
# @auth.login_required
def test_all_type(aps, bpi, cpl, dpf, epd, fpb):
    logger.debug(aps, bpi, cpl, dpf, epd, fpb)
    logger.debug(request.query_string)
    logger.debug(request.headers)
    logger.debug(request.data)
    return "True"


@backend.route('/5BC514F59E844A4DBE81C9D5878D1FA4/jingdong.hufu.jdBindQuery', methods=['POST'])
# @auth.login_required
def test_hufu():
    logger.debug(request.query_string)
    logger.debug(request.headers)
    logger.debug(request.data)
    resp = Response("a", status=200, mimetype='text/xml')
    return resp


if __name__ == '__main__':
    app.run(debug=True, host="10.226.149.55", port=5111)
