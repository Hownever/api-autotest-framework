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
import base64
import socket
import time
import random

from httprunner.loader import load_file, load_debugtalk_functions
from httprunner import exceptions
from httprunner import logger as log
from httprunner import utils
from httprunner.utils import get_os_environ
from httprunner import parser
from httprunner.compat import basestring, builtin_str, integer_types, str

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
        return str(self.code) + "::" + self.status + "::" + self.message


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


def hook_update_request_insert_global_headers(request, insert_headers={}):
    # 从insert_headers字典中获取要注入的headers，当这些headers不在request的header中时，
    # 注入它
    for k, v in insert_headers.items():
        if request.get("headers", None) is not None:
            if request.get("headers").get(k, None) is None:
                request["headers"][k] = v
        else:
            request["headers"] = {k: v}
        if request.get("json", None) is not None:
            if request.get("json").get("params", None) is None:
                request["json"]["params"] = {"x-extra-header": {k: v}}
            elif request.get("json").get("params", {}).get("x-extra-header", None) is None:
                request["json"]["params"]["x-extra-header"] = {k: v}
            else:
                request["json"]["params"]["x-extra-header"][k] = v

        else:
            request["json"] = {"params": {"x-extra-header": {k: v}}}

    return request


def hook_print(c):
    print("==>hook_print: %s" % c)


def hook_sleep_n_secs(sec):
    print("==> teardown_hook_sleep_N_secs(response, %s)" % sec)


def get_ip():
    return socket.gethostbyname(socket.gethostname())


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


def sleep_N_secs(n_secs):
    """ sleep n seconds
    """
    print("==> time sleep: %ss" % n_secs)
    time.sleep(int(n_secs))


def sleep_N_secs_if_condition(n_secs, condition):
    """ sleep n seconds if condition is true
    """

    if condition:
        print("==> time sleep: %ss, condition=%s" % (n_secs, condition))
        time.sleep(int(n_secs))
    else:
        print("==> time sleep: skiped, condition=%s" % condition)


def get_whitelist_ids(items):
    """
    从whiteListQuery接口的whiteList对象中，获取所有的id
    :param items:
    :return: list of ids
    """
    ids = []
    try:
        if isinstance(items, list):
            for item in items:
                ids.append(item["id"])
            return ids
    except:
        raise exceptions.ParamsError("**> WhiteList item not dict value: %s" % items)
    raise exceptions.ParamsError("**> WhiteList not list value: %s" % items)


def get_remotecall_data(datas, what):
    try:
        if isinstance(datas, dict):
            if what in ["protocol", "datas"]:
                return datas[what]
    except:
        raise exceptions.ParamsError("**> WhiteList item not dict value: %s" % datas)

    raise exceptions.ParamsError("**> Datas format error: %s" % datas)


def append_value_to_list(l, v):
    if l is None:
        l = []
    l.append(v)
    return l


def validate_route_balance(hostnames, index, ignore_index, host_count, offset_min, offset_max):
    """
    验证负载均衡主机是否满足规格：
        1.不重复主机数量为host_count；
        2.负载均衡分布率满足(1/host_count + min, 1/host_count + max);
        3.当前次数index < ignore_index，忽略验证，return 1

    :param hostnames: 主机列表 list
    :param index: 当前第几次loop测试，用于忽略验证
    :param ignore_index: 当前次数index < ignore_index，忽略验证，return 1
    :param host_count: 期望的负载均衡的主机个数
    :param min: 负载均衡主机分布率下限偏移量
    :param max: 负载均衡主机分布率上限偏移量
    :return:
        "PASSED: 负载均衡满足要求：{}"
        PASSED: 忽略校验（{} < {}）
        FAILED(-1): 共计执行了{}次，收集到转发的主机数量为{}, 执行次数与主机统计数量不符
        FAILED(-2): 主机去重之后数量（{}）与期望数量不符（{}）,实际主机为：{}
        FAILED(-3): 负载均衡分布比率超出规范(30% ~ 35%): {}
    """
    total_host_cnt = len(hostnames)
    spec_host_count = int(host_count)
    spec_rate_min = float(offset_min) + 1.000/spec_host_count
    spec_rate_max = float(offset_max) + 1.000/spec_host_count
    if int(index) <= int(ignore_index):
        log.log_debug("return 1 when index({}) less than {}, "
                      "do not validate the rate spec and hosts".format(index, ignore_index))
        return "PASSED: 忽略校验（{} < {}）".format(index, ignore_index)

    if total_host_cnt != int(index):
        msg = "FAILED(-1): 共计执行了{}次，收集到转发的主机数量为{}, 执行次数与主机统计数量不符".format(index, total_host_cnt)
        log.log_debug(msg)
        return msg

    if isinstance(hostnames, list):
        hostlist = set(hostnames)
        actual_host_cnt = len(hostlist)
        if actual_host_cnt != spec_host_count:
            msg = "FAILED(-2): 主机去重之后数量（{}）与期望数量不符（{}）,实际主机为：{}".format(actual_host_cnt,
                                                                        spec_host_count, hostlist)
            log.log_debug(msg)
            return msg

        failed = []
        rlt = []
        passed = []
        for host in hostlist:
            host_cnt = hostnames.count(host)
            rate = host_cnt*1.00/total_host_cnt
            rlt.append([host, host_cnt, total_host_cnt, rate])
            if not (spec_rate_min < rate < spec_rate_max):
                failed.append([host, rate])
            else:
                passed.append([host, rate])

        log.log_debug("host rate: {}".format(rlt))
        if failed:
            msg = "FAILED(-3): 负载均衡分布比率超出规格({:.3f} ~ {:.3f}): " \
                  "Failed:{}, Passed: {}".format(spec_rate_min, spec_rate_max, failed, passed)
            log.log_debug(msg)
            return msg
        return "PASSED: 负载均衡满足要求：{}".format(rlt)
    return "FAILED(0): 未知错误"


def get_delta_timestamp(str_len=13, delta=0):
    """ get timestamp string, length can only between 0 and 16
    delta: ms for delta time
    """
    if isinstance(str_len, integer_types) and 0 < str_len < 17:
        now = int(builtin_str(time.time()).replace(".", "")[:str_len])
        if isinstance(delta, integer_types):
            return builtin_str(now + delta)

    raise exceptions.ParamsError("timestamp length can only between 0 and 16.")


def gen_list(length, prefix=None):
    if prefix is None:
        prefix = ''
    else:
        prefix = str(prefix)

    if not isinstance(length, integer_types):
        raise exceptions.ParamsError("List length can only be integer value.")

    rlt = []
    for i in range(1, length + 1):
        rlt.append(prefix + str(i))

    return rlt


BUF = []


def clear_buffer():
    global BUF
    print("clear global buffer to {}".format(BUF))
    BUF = []


def get_buffer():
    global BUF
    return BUF


def add_buffer(i):
    global BUF
    BUF.append(i)
    return BUF


def config_dump_match_the_service_entry_settings(content, service_entry, findstr=None):
    if not isinstance(service_entry, list):
        raise exceptions.ParamsError("service_entry value can only be list value:{}".format(service_entry))
    if len(service_entry) == 1:
        if findstr is None:
            findstr = service_entry[0].get("host", None)
        if findstr is None:
            raise exceptions.ParamsError("service_entry value format error, "
                                         "can not find host value.:{}".format(service_entry))
        if findstr in str(content):
            return 1
    elif len(service_entry) == 0:
        if findstr is None:
            return 0
        if findstr in str(content):
            return 0
        else:
            return 1
    else:
        raise exceptions.ParamsError("service_entry value not support, "
                                     "only support one entry now: {}".format(service_entry))
    return 0


def is_should_skip_config_dumps_test(test_protocol, http_return_code, tcp_return_code, expected_status_code):
    if test_protocol.upper() == "HTTP":
        return 1 if http_return_code in expected_status_code else 0
    elif test_protocol.upper() == "TCP":
        return 1 if tcp_return_code in expected_status_code else 0
    return 1


def all_true(*args):
    # print("or_value: {}".format(args))
    return all(args)


def plus(a, b):
    if isinstance(a, integer_types) or isinstance(b, integer_types):
        return int(a) + int(b)
    rlt = a + b
    # print("===> plus: {} + {} = {}".format(a, b, rlt))
    return rlt


def get_host_from_url(url):
    s_url = url.split("//")
    if len(s_url) > 1:
        remove_http_prefix_url = s_url[1]
    else:
        remove_http_prefix_url = s_url[0]
    return remove_http_prefix_url.split("/")[0]


def gen_rand_int(a, b):
    return random.randint(int(a), int(b))


def set_os_environ(variables_mapping):
    """ set variables mapping to os.environ
    """
    for variable in variables_mapping:
        os.environ[variable] = variables_mapping[variable]
        print("Set OS environment variable: {}".format(variable))


def validate_token_settings(settings, whitelist, checkip, docheck, ipwhitelist, sendlog, tenantname):
    """
    检查settings字典中token白名单的配置是否与传入要配置的值都相同，相同返回True，否则返回False
    settings是调用云翼api查询时返回的内容的data值：
    {'data': [
        {
            'appId': 1657,
            'appName': 'productpage',
            'appWhiteList': 0,
            'checkIp': 0,
            'createTime': 1568274732483,
            'createUser': 'likui34',
            'doCheck': 1,
            'id': 4,
            'ipWhiteList': 0,
            'sendLog': 0,
            'tenantName': 'jcloud',
            'updateTime': 1568702250883,
            'updateUser': 'likui34'
        }
        ],
        'status': {'code': 'OK'},
        'trace': {
            'destIp': '172.18.167.136',
            'id': 'aae315d1-8669-4e49-bb56-f47f6d506c60',
            'srcIp': '10.12.136.130',
            'timestamp': 1568702251551
            }
    }

    :param settings:
    :param whitelist:
    :param checkip:
    :param docheck:
    :param ipwhitelist:
    :param sendlog:
    :param tenantname:
    :return:
    """
    if not isinstance(settings, list) or len(settings) != 1:
        print("==> validate_token_settings: settings is not list or len != 1: {}".format(settings))
        return False
    try:
        setting = settings[0]
        if setting["appWhiteList"] != whitelist:
            print("==> validate_token_settings: appWhiteList not same: {} to {}".format(setting["appWhiteList"],
                                                                                        whitelist))
            return False
        elif setting["checkIp"] != checkip:
            print("==> validate_token_settings: checkip not same: {} to {}".format(setting["checkIp"], checkip))
            return False
        elif setting["doCheck"] != docheck:
            print("==> validate_token_settings: doCheck not same: {} to {}".format(setting["doCheck"], docheck))
            return False
        elif setting["ipWhiteList"] != ipwhitelist:
            print("==> validate_token_settings: ipwhitelist not same: {} to {}".format(setting["ipWhiteList"],
                                                                                       ipwhitelist))
            return False
        elif setting["sendLog"] != sendlog:
            print("==> validate_token_settings: sendlog not same: {} to {}".format(setting["sendlog"], sendlog))
            return False
        elif setting["tenantName"] != tenantname:
            print("==> validate_token_settings: tenantname not same: {} to {}".format(setting["tenantName"],
                                                                                      tenantname))
            return False
        print("==> validate_token_settings: all settings option is same: "
              "whitelist={} checkip={} docheck={} "
              "ipwhitelist={} sendlog={} tenantname={}".format(whitelist, checkip, docheck,
                                                               ipwhitelist, sendlog, tenantname))
        return True

    except Exception as e:
        print("validate_token_settings: exception found: {}".format(str(e)))


def transfer_deadline_to_int_for_token_payload(payload):
    if isinstance(payload, dict):
        try:
            payload["deadline"] = int(payload["deadline"])
        except KeyError:
            pass
        except ValueError:
            raise
    print("==> payload={}".format(payload))
    return payload


def decode_base64(data):
    """Decode base64, padding being optional.
    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.

    """
    missing_padding = 4 - len(data) % 4
    if missing_padding:
        data += '=' * missing_padding
    return base64.b64decode(data)


def decode_token(token):
    jwt_header = token.split(".")[0]
    jwt_payload = token.split(".")[1]

    print("==> JWT Header:  {} -> {}".format(jwt_header, decode_base64(jwt_header)))
    print("==> JWT Payload: {} -> {}".format(jwt_payload, decode_base64(jwt_payload)))
    print("==> JWT Signature: {}".format(token.split(".")[2]))
    return [json.loads(decode_base64(jwt_header)), json.loads(decode_base64(jwt_payload)), token.split(".")[2]]


def get_random_list_items(a_list):
    if isinstance(a_list, list):
        if len(a_list) > 0:
            return a_list[gen_rand_int(0, len(a_list)-1)]

    raise exceptions.ParamsError("Not a list or no items in it: {}".format(a_list))
