#
# coding=utf-8
import os
import sys
import datetime
import uuid
import hashlib
import hmac
import re
import traceback
import json
import abc
import time
import base64
import socket

from httprunner.loader import load_file, load_debugtalk_functions
from httprunner import exceptions
from httprunner import logger as log
from httprunner import utils
from httprunner import parser

if sys.version_info.major == 2:
    from urllib import quote
elif sys.version_info.major == 3:
    from urllib.parse import quote

DEBUGTALK_DEBUG = False

# VERSION in sdk
VERSION = '1.4.0'


# const.py in sdk
class Const:
    JDCLOUD2 = 'JDCLOUD2'
    JDCLOUD_ALGORITHM = 'JDCLOUD2-HMAC-SHA256'
    JDCLOUD_REQUEST = 'jdcloud2_request'
    JDCLOUD_DATE = 'x-jdcloud-date'
    JDCLOUD_SECURITY_TOKEN = 'x-jdcloud-security-token'
    JDCLOUD_CONTENT_SHA256 = 'x-jdcloud-content-sha256'
    JDCLOUD_NONCE = 'x-jdcloud-nonce'
    JDCLOUD_AUTH = 'Authorization'

    METHOD_GET = 'GET'
    METHOD_PUT = 'PUT'
    METHOD_POST = 'POST'
    METHOD_PATCH = 'PATCH'
    METHOD_DELETE = 'DELETE'
    METHOD_HEAD = 'HEAD'

    SCHEME_HTTP = 'http'
    SCHEME_HTTPS = 'https'

    HEADER_REQUESTID = 'x-jdcloud-request-id'
    HEADER_CONTENT_LEN = 'Content-Length'
    HEADER_JCLOUD_PREFIX = 'x-jcloud'
    HEADER_JDCLOUD_PREFIX = 'x-jdcloud'
    HEADER_ERROR = ('x-jcloud-pin', 'x-jcloud-erp', 'x-jcloud-security-token')
    HEADER_BASE64 = ('x-jdcloud-pin', 'x-jdcloud-erp', 'x-jdcloud-security-token')

    def __init__(self):
        pass


const = Const()


class ClientException(Exception):
    def __init__(self, message):
        super(ClientException, self).__init__()
        self.message = message

    def __str__(self):
        return self.message


class ServerException(Exception):
    def __init__(self, status, code, message):
        super(ServerException, self).__init__()
        self.code = code
        self.message = message
        self.status = status

    def __str__(self):
        return str(self.code) + "::" + self.status+"::" + self.message


class Credential(object):

    def __init__(self, access_key, secret_key):
        self.access_key = access_key
        self.secret_key = secret_key


class Config(object):

    def __init__(self, endpoint='www.jdcloud-api.com', scheme="https", timeout=10):
        self.endpoint = endpoint
        self.scheme = scheme
        self.timeout = timeout

    def __getitem__(self, key):
        return getattr(self, key)


class ParameterBuilder(object):

    @abc.abstractmethod
    def build_url(self, request, scheme, endpoint):
        pass

    @abc.abstractmethod
    def build_body(self, request):
        pass

    def _build_req_params(self, parameters):
        if parameters is None:
            return {}

        pairs = {}
        for key in parameters.keys():
            value = parameters[key]
            if isinstance(value, list) or value is None:
                continue
            pairs.update({key: value})
        return pairs

    # remove path params
    def _build_query_params(self, parameters, url):
        result = ''
        result_list = self._build_params(parameters, url, '', [])
        if result_list.__len__() != 0:
            result += '?'

        return result + '&'.join(result_list)

    def _build_params(self, param_dict, url, prefix, result_list):
        for key in param_dict:
            value = param_dict[key]

            if url.find("{" + key + "}") != -1:
                continue

            if value is None:
                continue

            if isinstance(value, list):
                i = 1
                for item in value:
                    sub_prefix = "%s.%d." % (key, i)
                    if isinstance(item, (int, str)):
                        result_list.append("%s%s.%d=%s" % (prefix, key, i, item))
                    elif isinstance(item, dict):
                        result_list = self._build_params(item, url, sub_prefix, result_list)
                    else:
                        result_list = self._build_params(item.__dict__, url, sub_prefix, result_list)
                    i += 1
            else:
                result_list.append("%s%s=%s" % (prefix, key, value))

        return result_list

    def _replace_url_with_value(self, url, params_obj):
        if url.count('{') == 0:
            return url

        params = self._build_req_params(params_obj)
        pattern = r'{([a-zA-Z0-9-_]+)}'
        matches = re.findall(pattern, url)
        for match in matches:
            url = url.replace('{' + match + '}', self.__get_path_param_value(params, match))
        return url

    def __get_path_param_value(self, params, field):
        return str(params.get(field, ''))


# GET/DELETE
class WithoutBodyBuilder(ParameterBuilder):

    def build_url(self, request, scheme, endpoint):
        parameters = get_parameter_dict(request.get("parameters"))
        query_params = quote(self._build_query_params(parameters, request.get("url")), safe='&=?')
        url = self._replace_url_with_value(request.get("url"), parameters)
        return '%s://%s/%s%s%s' % (scheme, endpoint, request.get("version"), url, query_params)

    def build_body(self, request):
        return ''


# PUT/POST/PATCH
class WithBodyBuilder(ParameterBuilder):

    def build_url(self, request, scheme, endpoint):
        parameters = get_parameter_dict(request.get("parameters"))
        url = self._replace_url_with_value(request.get("url"), parameters)
        return '%s://%s/%s%s' % (scheme, endpoint, request.get("version"), url)

    def build_body(self, request):
        if isinstance(request.get("parameters"), dict):
            return json.dumps(request.get("parameters"))
        return json.dumps(request.get("parameters"), cls=ParametersEncoder)


class ParametersEncoder(json.JSONEncoder):
    def default(self, o):
        return o.__dict__


# base64 encode
def base64encode(value):
    if value is None:
        return ""
    if sys.version_info.major == 2:
        return base64.b64encode(value)
    elif sys.version_info.major == 3:
        encoded_value = base64.b64encode(value.encode('utf-8'))
        return str(encoded_value, 'utf-8')


def get_parameter_dict(parameters):
    if parameters is None:
        return {}
    return parameters if isinstance(parameters, dict) else parameters.__dict__


class MyTestSigner(object):
    ignored_headers = ['authorization', 'user-agent']

    def __init__(self):
        pass

    def sign(self, method, service, region, uri, headers, data, credential, security_token, cur_time):
        uri_dict = self.__url_path_to_dict(uri)
        if DEBUGTALK_DEBUG:
            print("uri = ", uri)
            print("uri_dict = ", uri_dict)
        host = uri_dict['host']
        port = uri_dict['port']
        query = uri_dict['query']
        canonical_uri = quote(uri_dict['path'])

        if port and port not in ['80', '443']:
            full_host = host + ':' + port
        else:
            full_host = host

        jdcloud_date = cur_time
        datestamp = cur_time[:8]  # Date w/o time, used in credential scope
        nonce = str(uuid.uuid4())
        headers[const.JDCLOUD_DATE] = jdcloud_date
        headers[const.JDCLOUD_NONCE] = nonce

        canonical_querystring = self.__normalize_query_string(query)
        canonical_headers, signed_headers = self.__build_canonical_headers(headers, security_token, full_host)

        payload_hash = self.__sha256_hash(data)

        canonical_request = (method + '\n' +
                             canonical_uri + '\n' +
                             canonical_querystring + '\n' +
                             canonical_headers + '\n' +
                             signed_headers + '\n' +
                             payload_hash)

        algorithm = const.JDCLOUD_ALGORITHM
        credential_scope = (datestamp + '/' +
                            region + '/' +
                            service + '/' +
                            const.JDCLOUD_REQUEST)
        string_to_sign = (algorithm + '\n' +
                          jdcloud_date + '\n' +
                          credential_scope + '\n' +
                          self.__sha256_hash(canonical_request))
        if DEBUGTALK_DEBUG:
            log.log_debug('---Debug canonical_request---\n' + canonical_request)
            log.log_debug('----Debug string_to_sign---\n' + string_to_sign)

        signing_key = self.__get_signature_key(credential.secret_key, datestamp, region, service)
        encoded = string_to_sign.encode('utf-8')
        signature = hmac.new(signing_key, encoded, hashlib.sha256).hexdigest()

        authorization_header = (
                algorithm + ' ' +
                'Credential=' + credential.access_key + '/' + credential_scope + ', ' +
                'SignedHeaders=' + signed_headers + ', ' +
                'Signature=' + signature
        )

        headers.update({
            const.JDCLOUD_AUTH: authorization_header,
            const.JDCLOUD_DATE: jdcloud_date,
            const.JDCLOUD_CONTENT_SHA256: payload_hash,
            const.JDCLOUD_ALGORITHM: const.JDCLOUD_ALGORITHM,
            const.JDCLOUD_NONCE: nonce
        })

        if security_token:
            headers.update({const.JDCLOUD_SECURITY_TOKEN: security_token})

        return headers

    def __normalize_query_string(self, query):
        params = (list(map(str.strip, s.split("=")))
                  for s in query.split('&')
                  if len(s) > 0)

        normalized = '&'.join('%s=%s' % (p[0], p[1] if len(p) > 1 else '')
                              for p in sorted(params))
        return normalized

    def __url_path_to_dict(self, path):
        """http://stackoverflow.com/a/17892757/142207"""

        pattern = (r'^'
                   r'((?P<schema>.+?)://)?'
                   r'((?P<user>.+?)(:(?P<password>.*?))?@)?'
                   r'(?P<host>.*?)'
                   r'(:(?P<port>\d+?))?'
                   r'(?P<path>/.*?)?'
                   r'(\?(?P<query>.*?))?'
                   r'$')
        regex = re.compile(pattern)
        match = regex.match(path)
        group_dict = match.groupdict() if match is not None else None

        if group_dict['path'] is None:
            group_dict['path'] = '/'

        if group_dict['query'] is None:
            group_dict['query'] = ''

        return group_dict

    def __sign(self, key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def __get_signature_key(self, key, date_stamp, region_name, service_name):
        k_date = self.__sign((const.JDCLOUD2 + key).encode('utf-8'), date_stamp)
        k_region = self.__sign(k_date, region_name)
        k_service = self.__sign(k_region, service_name)
        k_signing = self.__sign(k_service, const.JDCLOUD_REQUEST)
        return k_signing

    def __sha256_hash(self, val):
        return hashlib.sha256(str(val).encode('utf-8')).hexdigest()

    def __build_canonical_headers(self, req_headers, security_token, full_host):
        headers = ['host']  # add host header first
        signed_values = {}

        for key in req_headers.keys():
            value = req_headers[key]

            lower_key = key.lower()
            if lower_key in self.ignored_headers:
                continue

            headers.append(lower_key)
            signed_values[lower_key] = value

        headers.sort()
        signed_headers = ';'.join(headers)

        canonical_values = []
        for key in headers:
            if key == 'host':
                canonical_values.append('host:' + full_host)
            else:
                canonical_values.append(key + ':' + signed_values[key])

        canonical_headers = '\n'.join(canonical_values) + '\n'

        return canonical_headers, signed_headers


class MyHeaderGenerator(object):
    def __init__(self, credential, config, service_name, regionid):
        self.__config = config
        self.__service_name = service_name
        self.__credential = credential
        self.__regionid = regionid

        self.__builder_map = {const.METHOD_GET: WithoutBodyBuilder,
                              const.METHOD_DELETE: WithoutBodyBuilder,
                              const.METHOD_HEAD: WithoutBodyBuilder,
                              const.METHOD_PUT: WithBodyBuilder,
                              const.METHOD_POST: WithBodyBuilder,
                              const.METHOD_PATCH: WithBodyBuilder}

    def __merge_headers(self, request_header):
        mheaders = dict()
        mheaders['User-Agent'] = 'api-autotest-framework/%s' % VERSION
        mheaders['Content-Type'] = 'application/json'

        if request_header is not None and isinstance(request_header, dict):
            for key, value in request_header.items():
                if key.lower() in const.HEADER_ERROR:
                    raise ClientException('Please use header with prefix x-jdcloud')
                if key.lower() in const.HEADER_BASE64:
                    value = base64encode(value)
                mheaders[key] = value

        return mheaders

    def gen_headers(self, url, method, header, body, timestamp):
        if self.__config is None:
            raise ClientException('Miss config object')
        if self.__credential is None:
            raise ClientException('Miss credential object')

        region = self.__regionid

        try:
            header = self.__merge_headers(header)
            token = header.get(const.JDCLOUD_SECURITY_TOKEN, '')

            # param_builder = self.__builder_map[method]()
            url = url
            body = body
            if DEBUGTALK_DEBUG:
                log.log_debug('url=' + url)
                log.log_debug('body=' + str(body))

            cur_time = timestamp
            signer = MyTestSigner()
            myheader = signer.sign(method, self.__service_name, region, url,
                                   headers=header, data=body,
                                   credential=self.__credential,
                                   security_token=token, cur_time=cur_time)
            return myheader
        except Exception as expt:
            msg = traceback.format_exc()
            log.log_error("**> %s" % msg)
            raise expt


def get_api_file_from_jdcloud_openapi_yaml(product, version, api, src_yaml=None):
    if api is None or not isinstance(api, str):
        raise exceptions.ParamsError("**> Request params error: %s" % api)

    # return None if no yaml file path
    if src_yaml is None:
        return None

    yaml_path = os.path.join(src_yaml, product, version, "service")
    yaml_file = None

    for (root, dirs, files) in os.walk(yaml_path):
        for file in files:
            open_file = os.path.join(root, file)
            with open(open_file, 'r', encoding="utf-8") as fd:
                for line in fd.readlines():
                    # 找到对应的以"operationId: " + api结尾的行，说明找到对应的文件
                    if line.strip().startswith("operationId:") and line.strip().endswith(api):
                        yaml_file = open_file
                        break
            if yaml_file is not None:
                break
        if yaml_file is not None:
            break
    else:
        raise exceptions.ApiNotFound("**> Api %s not found for "
                                     "product %s in path: %s." % (api, product, src_yaml))
    return yaml_file


def get_swagger_path_and_method(yaml_file, operationid):
    loader = load_file(yaml_file)

    const_method = [const.METHOD_GET, const.METHOD_POST, const.METHOD_PUT,
                    const.METHOD_DELETE, const.METHOD_PATCH, const.METHOD_HEAD]
    lower_const_method = [m.lower() for m in const_method]

    # 遍历paths，找到对指定api的path和method
    for path in loader.get("paths", {}):
        # 尝试获取每个path下的对应的method，判断是不是要查找的operationId
        for m in lower_const_method:
            for k, v in loader["paths"][path].get(m, {}).items():
                if v == operationid:
                    return path, m, loader
    return None, None, None


def gen_jdcloud_header(request, ak, sk, product, regionid):

    url = request.get("url")
    scheme = url.split(":")[0]
    if scheme not in [const.SCHEME_HTTP, const.SCHEME_HTTPS]:
        raise exceptions.ParamsError("**> Url Error in request: %s" % url)

    body = request.get("body", None)
    if body is None:
        body = request.get("data", None)
    if body is None:
        body = request.get("json", "")
    method = request.get("method")

    credential = Credential(ak, sk)
    config = Config(url, scheme=scheme)
    attach_header = request.get("headers", {})

    if DEBUGTALK_DEBUG:
        log.log_debug('==> attach_header=' + str(attach_header))

    cur_time = datetime.datetime.now().strftime('%Y%m%dT%H%M%SZ')

    client = MyHeaderGenerator(credential, config, product, regionid)

    return client.gen_headers(url, method, attach_header, body, cur_time)


def hook_update_jdcloud_request(request, ak, sk, product, version, spec, regionId):
    operationid = request.get("operationid", None)
    base_url = request.get("base_url", None)
    regionid = regionId
    # if regionid is None:
    #     regionid = config.get("request").get("regionId", "jdcloud-api")

    url = request.get("url", None)
    method = request.get("method", None)

    # 如果operationid不是None， 那么就会根据operationid去swagger定义文件找到对应的url和method，
    # 作为请求时使用的url和method
    if operationid is not None:
        # 找到operationid所对应的swagger文件
        yaml_file = get_api_file_from_jdcloud_openapi_yaml(product, version,
                                                           operationid, src_yaml=spec)

        # 解析出operationi对应的path， method，和 对象
        p, m, o = get_swagger_path_and_method(yaml_file, operationid)
        if p is None:
            raise exceptions.ApiNotFound("**> Api %s not found in "
                                         "swagger file: %s." % (operationid, yaml_file))

        if url is not None or method is not None:
            log.log_warning("**> url or method has defined in the yaml file, "
                            "will be replaced by operationID:" + operationid)

        # 拼接basepath到url中
        swagger_base_path = o.get("basePath", "")
        request["url"] = "{}/{}".format(swagger_base_path.rstrip("/"), p.lstrip("/"))
        request["method"] = m.upper()
        del request["operationid"]

    # JD header gen:
    if base_url is not None and base_url.startswith("http"):
        pass
    # else:  # get base_url from config
    #     base_url = config.get("request").get("base_url")

    # # 拼接version：
    # base_url = "{}/{}".format(base_url.rstrip("/"), version.lstrip("/"))

    # 替换uri中的变量：
    rl = []
    for rk, rv in request.items():
        pattern = r'{(' + rk + ')}'
        if request["url"].lower().find(pattern):
            for m in re.findall(pattern, request["url"].lower()):
                request["url"] = request["url"].lower().replace("{" + m + "}", str(rv))
                rl.append(rk)
    for i in rl:
        del request[i]  # 删除多余的字段

    # 单独处理各种method请求时，query参数需要拼接到url中的情况：
    params = request.get("params", None)
    if params is not None:
        if isinstance(params, dict):
            request["url"] += "?"
            for pk, pv in params.items():
                request["url"] += "{}={}&".format(pk, pv)
            request["url"] = request["url"][:-1]
            del request["params"]
        else:
            raise Exception("params format error: %s" % params)
    # rl = []
    # for ck, cv in config.get("request", {}).items():
    #     pattern = r'{(' + ck + ')}'
    #     if request["url"].find(pattern):
    #         for m in re.findall(pattern, request["url"]):
    #             request["url"] = request["url"].replace("{" + m + "}", cv)
    # for i in rl:
    #     del request[i]  # 删除多余的字段

    # 完善request中的url，填充完整的url
    if not request["url"].startswith("http"):
        request["url"] = "{}/{}".format(base_url.rstrip("/"), request["url"].lstrip("/"))

    request["headers"] = gen_jdcloud_header(request, ak, sk, product, regionid)

    return request


def hook_print(c):
    log.log_debug("==>hook_print: %s" % c)


def hook_sleep_n_secs(sec):
    log.log_debug("==> teardown_hook_sleep_N_secs(response, %s)" % sec)


def get_ip():
    return socket.gethostbyname(socket.gethostname())


def get_service_lines_from_yaml(yamlfile, branch):
    """
    获取指定branch的yaml文件对应的业务线列表
    :param yamlfile: yaml项目的本地目录（git clone保存的路径）
    :param branch: 要获取的分支，如master， draft， release
    :return: list
    """
    # check yamlfile exists:
    if not os.path.isdir(yamlfile):
        raise exceptions.FileNotFound("**> Yaml file directory not found: %s" % yamlfile)

    # switch branch
    if os.system("cd %s && git checkout %s" % (yamlfile, branch)) != 0:
        raise exceptions.MyBaseError("Switch branch failed: %s" % branch)

    # count service line
    serviceline = []
    for f in os.listdir(yamlfile):
        fpath = os.path.join(yamlfile, f)
        if os.path.isdir(fpath):
            if f.startswith("."):
                continue
            serviceline.append(f)
    if len(serviceline) == 0:
        raise exceptions.ParamsError("**> Yaml file directory is null: %s" % yamlfile)

    print("==> serviceline(%s): %s" % (len(serviceline), serviceline))
    return serviceline


def list_compare(a, b):
    if set(a.json.get("result",{}).get("service", {})) == set(b):
        return 1  # pass
    print("==> list diff(api - yaml) = %s" % (set(a.json.get("result", {}).get("service", {})) - set(b)))
    print("==> list diff(yaml - api) = %s" % (set(b) - set(a.json.get("result", {}).get("service", {}))))
    raise exceptions.ValidationFailure("missed service line: %s" % ((set(b) -
                                                                     set(a.json.get("result", {}).get("service", {})))))
    # return 0  # failed


def get_apis_for_serviceline_from_yaml(yamlfile, productline):
    """
    获取某个业务线productline的所有api
    :param yamlfile:
    :param productline:
    :return:
    """
    const_method = [const.METHOD_GET, const.METHOD_POST, const.METHOD_PUT,
                    const.METHOD_DELETE, const.METHOD_PATCH, const.METHOD_HEAD]

    api_yaml = os.path.join(yamlfile, productline)
    apis = []
    external_apis = []
    for version in os.listdir(api_yaml):
        fpath = os.path.join(api_yaml, version)
        if os.path.isdir(fpath):  # version folder
            servicepath = os.path.join(fpath, "service")
            if os.path.isdir(servicepath):
                for yf in os.listdir(servicepath):
                    if not yf.endswith("yaml"):
                        continue
                    loadf = load_file(os.path.join(servicepath, yf))
                    # print("==> load file: %s" % os.path.join(servicepath, yf))
                    basepath = loadf.get("basePath", "")
                    thisapi = {}
                    for api in loadf.get("paths", {}):
                        thisapi["path"] = basepath + api
                        thisapi["version"] = version
                        for m in loadf.get("paths", {}).get(api, {}):
                            thisapi["method"] = m.upper()
                            if m.upper() not in const_method:
                                print("===>Find invalid method [%s], ignored" % m)
                                continue
                            # print("===> %s" % loadf.get("paths", {}).get(api, {}).get(m, {}))
                            thisapi["operationId"] = loadf.get("paths",
                                                               {}).get(api, {}).get(m, {}).get("operationId", None)
                            thisapi["internal"] = 1 if loadf.get("paths",
                                                                 {}).get(api,
                                                                         {}).get(m,
                                                                                 {}).get("x-jdcloud-internal",
                                                                                         None) else 0
                            thisapi["description"] = loadf.get("paths",
                                                               {}).get(api, {}).get(m, {}).get("operationId", None)
                    if thisapi["internal"] == 0:
                        external_apis.append(thisapi)
                    apis.append(thisapi)
    return apis, external_apis


def serviceline_external_api_validate(response, productline, yamlfile):
    apis = response.json.get("result", {}).get("dataList", {})
    yapis, external_apis = get_apis_for_serviceline_from_yaml(yamlfile, productline)

    # verify path
    for api in external_apis:
        operationid = api.get("operationId", None)
        if operationid is None:
            raise exceptions.ParamsError("**> Fail to get operationId for %s!" % productline)
        # search operationId in the response
        this_response_api = None
        for rapi in apis:
            if rapi.get('interfaceName', None) == operationid:
                this_response_api = rapi.get('interfaceName', None)
                break
        else:
            raise exceptions.ValidationFailure("**> operationId(%s) not found in response: %s" % (productline,
                                                                                                       operationid))
        if this_response_api.get("method", "").strip() != api.get("method", "").strip():
            raise exceptions.ValidationFailure("**> operationId(%s) method not "
                                               "matched: %s vs %s" % (productline,
                                                                      this_response_api.get("method", None),
                                                                      api.get("method", "")))
        if this_response_api.get("path", "").strip() != api.get("path", "").strip():
            raise exceptions.ValidationFailure("**> operationId(%s) method not "
                                               "matched: %s vs %s" % (productline,
                                                                      this_response_api.get("method", None),
                                                                      api.get("method", "")))
        if this_response_api.get("internal", "").strip() != api.get("internal", "").strip():
            raise exceptions.ValidationFailure("**> operationId(%s) internal not "
                                               "matched: %s vs %s" % (productline,
                                                                      this_response_api.get("internal", None),
                                                                      api.get("internal", "")))
        print("==> interface passed: %s" % operationid)
    return 1


def serviceline_external_api_validate2(response, productline, yamlfile):
    """
    根据yaml（swagger）项目中的yaml文件来判断业务线和业务线开放的API
    :param response:
    :param productline:
    :param yamlfile:
    :return:
    """
    apis = response.json.get("result", {}).get("dataList", {})
    yapis, external_apis = get_apis_for_serviceline_from_yaml(yamlfile, productline)
    print("==> response:", apis)
    print("==> swagger :", external_apis)

    if len(external_apis) == 0 and len(apis) == 0:
        return 1

    # show operationid missed
    yoperationids = [api['operationId'] for api in external_apis]
    goperationids = [api['interfaceName'] for api in apis]
    missed = set(goperationids) - set(yoperationids)
    if len(missed) > 0:
        raise exceptions.ValidationFailure("**> operationId(%s) out of yaml(api - yaml): %s" % (productline, missed))

    # verify path
    for api in apis:
        operationid = api.get("interfaceName", None)
        if operationid is None:
            raise exceptions.ParamsError("**> Fail to get operationId for %s!" % productline)
        # search operationId in the response
        this_response_api = None
        for rapi in yapis:
            if rapi.get('operationId', None) == operationid:
                this_response_api = rapi
                break
        else:
            raise exceptions.ValidationFailure("**> operationId(%s) not found in response: %s" % (productline,
                                                                                                       operationid))
        if this_response_api.get("method", "").strip().upper() != api.get("method", "").strip().upper():
            raise exceptions.ValidationFailure("**> operationId(%s) method not "
                                               "matched: %s vs %s" % (productline,
                                                                      this_response_api.get("method", None),
                                                                      api.get("method", "")))
        # if this_response_api.get("path", "").strip() != api.get("path", "").strip():
        #     raise exceptions.ValidationFailure("**> operationId(%s) method not "
        #                                        "matched: %s vs %s" % (productline,
        #                                                               this_response_api.get("method", None),
        #                                                               api.get("method", "")))
        if str(this_response_api.get("internal", "")).strip() != str(api.get("internal", "")).strip():
            raise exceptions.ValidationFailure("**> operationId(%s) internal not "
                                               "matched: %s vs %s" % (productline,
                                                                      this_response_api.get("internal", None),
                                                                      api.get("internal", "")))
        print("==> interface passed: %s" % operationid)
    return 1


def get_apis_from_api_operation_list_external(yamlfile, productline):
    apis = []
    external_apis = []
    with open(yamlfile, 'r') as fd:
        for line in fd.readlines():
            api = {}
            if line.startswith("service=%s" % productline):
                for item in line.split():
                    if item.startswith("version"):
                        api["version"] = item.split("=")[-1]
                    if item.startswith("method"):
                        api["method"] = item.split("=")[-1]
                    if item.startswith("operationid"):
                        api["operationId"] = item.split("=")[-1]
                    if item.startswith("ypath"):
                        api["ypath"] = item.split("=")[-1]
                    if item.startswith("path"):
                        api["path"] = item.split("=")[-1]
                    if item.startswith("is_internal"):
                        api["internal"] = 0 if item.split("=")[-1] == "False" else 1
                apis.append(api)
                if api["internal"] == 0:
                    external_apis.append(api)
    return apis, external_apis


def get_service_lines_from_txt(txtfile):
    servlist = []
    with open(txtfile, 'r') as fd:
        for line in fd.readlines():
            if line.startswith("service="):
                serv = line.split()[0].split("=")[1]
                if serv not in servlist:
                    servlist.append(serv)
    return servlist


def serviceline_external_api_validate3(response, productline, yamlfile):
    """
    根据yaml项目的api_operation_list_external.txt文件判断业务线和对外公开的API
    :param response:
    :param productline:
    :param yamlfile:
    :return:
    """
    apis = response.json.get("result", {}).get("dataList", {})
    yapis, external_apis = get_apis_from_api_operation_list_external(yamlfile, productline)
    print("==> response:", apis)
    print("==> swagger :", external_apis)

    if len(external_apis) == 0 and len(apis) == 0:
        return 1

    # show operationid missed
    yoperationids = [api['operationId'] for api in external_apis]
    goperationids = [api['interfaceName'] for api in apis]
    missed = set(yoperationids) - set(goperationids)
    if len(missed) > 0:
        raise exceptions.ValidationFailure("**> operationId(%s) missed: %s" % (productline, missed))

    # verify path
    for api in apis:
        operationid = api.get("interfaceName", None)
        if operationid is None:
            raise exceptions.ParamsError("**> Fail to get operationId for %s!" % productline)
        # search operationId in the response
        this_response_api = None
        for rapi in yapis:
            if rapi.get('operationId', None) == operationid:
                this_response_api = rapi
                break
        else:
            raise exceptions.ValidationFailure("**> operationId(%s) not found in response: %s" % (productline,
                                                                                                       operationid))
        if this_response_api.get("method", "").strip().upper() != api.get("method", "").strip().upper():
            raise exceptions.ValidationFailure("**> operationId(%s) method not "
                                               "matched: %s vs %s" % (productline,
                                                                      this_response_api.get("method", None),
                                                                      api.get("method", "")))
        # if str(this_response_api.get("path", "")).strip() != str(api.get("path", "")).strip():
        #     raise exceptions.ValidationFailure("**> operationId(%s) path not "
        #                                        "matched: %s vs %s" % (productline,
        #                                                               this_response_api.get("path", None),
        #                                                               api.get("path", "")))
        if str(this_response_api.get("internal", "")).strip() != str(api.get("internal", "")).strip():
            raise exceptions.ValidationFailure("**> operationId(%s) internal not "
                                               "matched: %s vs %s" % (productline,
                                                                      this_response_api.get("internal", None),
                                                                      api.get("internal", "")))
        print("==> interface passed: %s" % operationid)
    return 1


def get_value(para, groupName):
    if isinstance(para, dict):
        if groupName:
            return para.get("groupName", {})
    raise exceptions.ParamsError("**> para not dict value: %s" % para)


def get_name(name):
    return name + str(time.time()).replace(".", "")


def get_uuid1():
    return "groupName_" + uuid.uuid1().__str__().replace("-", "")[0:9]


def return_string(apiGroupId, env=None, offline=None, bindGroup=None, host=None, regionId=None):
    if offline:
        return apiGroupId + "-" + env + ":offline"
    if bindGroup:
        return apiGroupId + ":bindGroup"
    if host:
        if env != "online":
            return apiGroupId.replace("ag-", "") + "-" + env + "." + regionId + ".jdcloud-api.net"
        else:
            return apiGroupId.replace("ag-", "") + "." + regionId + ".jdcloud-api.net"
    return apiGroupId + "-" + env


def get_id_from_list(idlist, key, value, return_key):
    print(idlist, key, value, return_key)
    for i in idlist:
        if i[key] == value:
            print(i[return_key])
            return i[return_key]
    return 0


def get_value_from_userinfo(userinfo, key):
    if key == "header":
        pin = userinfo.get("pin", None)
        header = userinfo.get("headers", None)
        if header is not None:
            return header
        if pin is not None:
            return {"Content-Type": "application/json;charset=UTF-8", "x-jdcloud-pin": pin, "requestId": "bnnoh3rdq9tif3rg33cu3j48stc2pj43"}
        else:
            return {"Content-Type": "application/json;charset=UTF-8", "requestId": "bnnoh3rdq9tif3rg33cu3j48stc2pj43"}
    return userinfo[key]


def delay_sec(second):
    time.sleep(second)


def to_base64(str_to_64):
    return base64.b64encode(str_to_64.encode(encoding="utf-8")).decode("utf-8")


def validate_skip(check_value, expect_value, comparator="eq"):
    print("==============", check_value, expect_value, comparator)
    if comparator == "eq":
        if str(check_value) == str(expect_value):
            return 1
        else:
            return 0
    elif comparator == "noeq":
        if str(check_value) != str(expect_value):
            return 1
        else:
            return 0


def get_value_from_struct(struct, key, list_num=None):
    # print(struct, key, list_num)
    if isinstance(struct, dict):
        if key in struct.keys():
            return struct[key]
    if isinstance(struct, list):
        if key in struct[list_num].keys():
            return struct[list_num][key]


def get_value_from_struct_gray(struct, key, ispin=None, flag=None):
    if isinstance(struct, dict):
        if ispin:
            key = to_base64(key)
        value = struct["result"]["value"]
        value_list = value.split(",")
        value_list_new = list()
        for i in value_list:
            if i.replace(" ", "") != "":
                value_list_new.append(i.replace(" ", ""))
        if flag:
            if key not in value_list_new:
                value_list_new.append(key.replace(" ", ""))
                return ",".join(value_list_new)
            else:
                return value
        else:
            if key not in value_list_new:
                return value
            else:
                value_list_new.remove(key)
                return ",".join(value_list_new)


def sleep_N_secs(n_secs):
    """ sleep n seconds
    """
    print("==> time sleep: %ss" % n_secs)
    time.sleep(int(n_secs))


def get_subuser_pin(createSubUser_pin, mainuser):
    """ get_subuser_pin
    """
    createSubUser_pin = "{} @ {}".format(createSubUser_pin, mainuser)
    return createSubUser_pin


def append_value_to_list(l, v):
    if l is None:
        l = []
    l.append(v)
    return l


def get_uniform_comparator(comparator):
    """ convert comparator alias to uniform name
    """
    if comparator in ["eq", "equals", "==", "is"]:
        return "equals"
    elif comparator in ["lt", "less_than"]:
        return "less_than"
    elif comparator in ["le", "less_than_or_equals"]:
        return "less_than_or_equals"
    elif comparator in ["gt", "greater_than"]:
        return "greater_than"
    elif comparator in ["ge", "greater_than_or_equals"]:
        return "greater_than_or_equals"
    elif comparator in ["ne", "not_equals"]:
        return "not_equals"
    elif comparator in ["str_eq", "string_equals"]:
        return "string_equals"
    elif comparator in ["len_eq", "length_equals", "count_eq"]:
        return "length_equals"
    elif comparator in ["len_gt", "count_gt", "length_greater_than", "count_greater_than"]:
        return "length_greater_than"
    elif comparator in ["len_ge", "count_ge", "length_greater_than_or_equals", \
                        "count_greater_than_or_equals"]:
        return "length_greater_than_or_equals"
    elif comparator in ["len_lt", "count_lt", "length_less_than", "count_less_than"]:
        return "length_less_than"
    elif comparator in ["len_le", "count_le", "length_less_than_or_equals", \
                        "count_less_than_or_equals"]:
        return "length_less_than_or_equals"
    else:
        return comparator


def validate(check_value, expect_value, comparator="eq"):
    """ 验证check_value与expect_value是否满足comparator，返回True和False
    """

    comp = get_uniform_comparator(comparator)
    debugtalk_map = load_debugtalk_functions()
    validate_func = parser.get_mapping_function(comp, {})

    if (check_value is None or expect_value is None) \
            and comp not in ["is", "eq", "equals", "=="]:
        raise exceptions.ParamsError("Null value can only be compared with comparator: eq/equals/==")

    validate_msg = "validate: {} {}({})".format(
        comp,
        expect_value,
        type(expect_value).__name__
    )

    try:
        log.log_debug("----> call function %s with arg1=%s, arg2=%s" % (validate_func, check_value, expect_value))
        validate_func(check_value, expect_value)
        return True
    except (AssertionError, TypeError):
        validate_msg += "\t==> fail"
        validate_msg += "\n{}({}) {} {}({})".format(
            check_value,
            type(check_value).__name__,
            comp,
            expect_value,
            type(expect_value).__name__
        )
        log.log_debug(validate_msg)
    return False


def return_list(num):
    """ return num of list
    """
    a = list()
    for i in range(num):
        a.append(i)
    return a


if __name__ == "__main__":
    a = "a,   b, c,  e"
    print(get_value_from_struct(a, "aaa"))
    # a = [{'createTime': 1557391931000, 'userId': '354880097637', 'secretKey': '6D93ED22AB22FE21CCB755DCB82F4B7B', 'accessKey': '16B38983D84EC344BACA3DEFA82ADC62', 'keyDesc': '', 'pin': 'amRjbG91ZC1hcGlndy10ZXN0Mg==', 'keyId': '57c0046f9fa1', 'keyName': '1KMSname1'}]
    # b = get_id_from_list(a, "keyName", "1KMSname1", "keyId")
    # print(validate_skip(b, "aaa", "eq"))
