# -*- coding: utf-8 -*-

import json
import time
import xlrd
import chardet
import hashlib
from flask import Response
import xml.etree.ElementTree as ET
from flask import Flask, jsonify, abort, request, make_response, url_for
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__, static_url_path="")
auth = HTTPBasicAuth()


ClientClosed = 499
J_MSG = {ClientClosed: 'ClientClosed'}

wb = xlrd.open_workbook("1.xls", encoding_override="utf-8")
sheet = wb.sheet_by_name("Sheet1")
lineb = sheet.col_values(2)


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
def bad_request(error):
    return make_response(jsonify({'error': 'xml wrong'}), 401)


@backend.errorhandler(403)
def bad_request(error):
    return make_response(jsonify({'error': 'sign result not same'}), 403)


@backend.errorhandler(405)
def bad_request(error):
    return make_response(jsonify({'error': 'lack of query parameters'}), 405)


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


def walkData(root_node, tag_list):
    tag_list.append(root_node.tag)

    # 遍历每个子节点
    children_node = root_node.getchildren()
    if len(children_node) == 0:
        return
    for child in children_node:
        walkData(child, tag_list)


order_list = ["app_key", "customerId", "format", "method", "sign_method", "timestamp", "v"]


def creat_md5(api_name, payload):
    md5_str = "2842F49D50ABFCAFC3C8E358EF496987"
    querystring["method"] = str(api_name)
    for i in order_list:
        md5_str += i
        md5_str += querystring[i]
    md5_str += payload.decode(chardet.detect(payload)["encoding"])
    md5_str += "2842F49D50ABFCAFC3C8E358EF496987"
    hash_md5 = hashlib.md5(md5_str.encode("utf-8"))
    return hash_md5.hexdigest()


querystring = {
    "timestamp": "2019-03-01+15:46:19",
    "format": "xml",
    "app_key": "sandbox4169F82DD7753AC46C6586C54B84E9A5",
    "v": "1.0",
    "sign_method": "md5",
    "customerId": "5BC514F59E844A4DBE81C9D5878D1FA4",
}


# @backend.route('/<customerId>/<method_url>', methods=['POST'])
# @auth.login_required
@backend.route('/', methods=['POST'])
def test_hufu():

    try:
        querystring["timestamp"] = request.args.get('timestamp')
        querystring["app_key"] = request.args.get('app_key')
        querystring["v"] = request.args.get('v')
        querystring["sign_method"] = request.args.get('sign_method')
        querystring["format"] = request.args.get('format')
        querystring["customerId"] = request.args.get('customerId')
        new_sign = creat_md5(request.args.get('method'), request.data)
        sign = request.args.get('sign')
    except Exception as e:
        print(e)
        abort(405)

    if new_sign != sign:
        print("sign:", sign)
        print("new_sign:", new_sign)
        abort(403)

    for i in range(len(lineb)):
        if request.args.get('method') == lineb[i]:
            req_data_http = ET.fromstring(request.get_data())
            req_data_excel = ET.fromstring(sheet.cell_value(i, 3).encode("utf-8"))
            req_data_excel_tag = list()
            walkData(req_data_excel, req_data_excel_tag)
            req_data_http_tag = list()
            walkData(req_data_http, req_data_http_tag)
            if not set(req_data_excel_tag) == set(req_data_http_tag):
                print("req_data_excel_tag:", set(req_data_excel_tag))
                print("req_data_http_tag:", set(req_data_http_tag))
                #abort(401)
            res_data_excel = sheet.cell_value(i, 4).encode("utf-8")

    resp = Response(res_data_excel, status=200, mimetype='text/xml')
    return resp


if __name__ == '__main__':
    app.run(debug=True, host="10.226.149.55", port=5112)
