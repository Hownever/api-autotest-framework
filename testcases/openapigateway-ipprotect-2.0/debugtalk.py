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

from httprunner.loader import load_file
from httprunner import exceptions
from httprunner import logger as log
from httprunner import utils
from httprunner.utils import get_os_environ
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


def hook_update_jdcloud_request(config, request, ak, sk, product, version, spec):
    operationid = request.get("operationid", None)
    base_url = request.get("base_url", None)
    regionid = request.get("regionid", None)
    if regionid is None:
        regionid = config.get("request").get("regionId", "jdcloud-api")

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
    else:  # get base_url from config
        base_url = config.get("request").get("base_url")

    # 拼接version：
    base_url = "{}/{}".format(base_url.rstrip("/"), version.lstrip("/"))

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

    rl = []
    for ck, cv in config.get("request", {}).items():
        pattern = r'{(' + ck + ')}'
        if request["url"].find(pattern):
            for m in re.findall(pattern, request["url"]):
                request["url"] = request["url"].replace("{" + m + "}", cv)
    for i in rl:
        del request[i]  # 删除多余的字段

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


def validate(check_value, expect_value, comparator="eq"):
    """ 验证check_value与expect_value是否满足comparator，返回True和False
    """
    comp = utils.get_uniform_comparator(comparator)
    validate_func = parser.get_mapping_function(comparator, {})

    if (check_value is None or expect_value is None) \
            and comp not in ["is", "eq", "equals", "=="]:
        raise exceptions.ParamsError("Null value can only be compared with comparator: eq/equals/==")

    validate_msg = "validate: {} {}({})".format(
        comp,
        expect_value,
        type(expect_value).__name__
    )

    try:
        print("----> call function %s with arg1=%s, arg2=%s" % (validate_func, check_value, expect_value))
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


def get_user_pin(user):
    if isinstance(user, dict):
        return user.get("userpin", "")

    raise exceptions.ParamsError("**> No user pin found: %s" % user)


def get_user_ak(user):
    if isinstance(user, dict):
        # print("AK=", user.get("AK", ""))
        return user.get("AK", "")

    raise exceptions.ParamsError("**> No user AK found: %s" % user)


def get_user_sk(user):
    if isinstance(user, dict):
        # print("SK=", user.get("SK", ""))
        return user.get("SK", "")

    raise exceptions.ParamsError("**> No user SK found: %s" % user)


def get_user_keytype(user):
    if isinstance(user, dict):
        return user.get("keytype", "")

    raise exceptions.ParamsError("**> No user keytype found: %s" % user)


def get_user_account_main(user):
    if isinstance(user, dict):
        userpin = user.get("userpin", "")
        if "@" in userpin:
            return user.get("userpin", "").split("@")[-1].strip()
        else:
            return userpin

    raise exceptions.ParamsError("**> No user keytype found: %s" % user)


def to_list_value(v):
    if "," in v:
        return [i.strip() for i in v.split(",")]
    else:
        return [v.strip()]


def get_user_ip():
    import requests
    try:
        return get_os_environ("ENV_SET_STATIC_CLIENT_IP_ADDR")
    except exceptions.EnvNotFound:
        pass
    try:
        if get_os_environ("ENV_ENV_UNDER_TEST").lower() == "pre" or \
                get_os_environ("ENV_ENV_UNDER_TEST").lower() == "stag":
            server = "http://10.226.201.235:8080/v1/user/ip?pin=jdcloud-api-test"
        elif get_os_environ("ENV_ENV_UNDER_TEST").lower() == "test" or \
                get_os_environ("ENV_ENV_UNDER_TEST").lower() == "ite":
            server = "http://account-inner-openapi-ite.jdcloud.com/v1/user/ip?pin=jdcloud-api-test"
        elif get_os_environ("ENV_ENV_UNDER_TEST").lower() == "product" or \
                get_os_environ("ENV_ENV_UNDER_TEST").lower() == "online":
            server = "http://account-inner-openapi.jdcloud.com/v1/user/ip?pin=jdcloud-api-test"
        else:
            server = "http://account-inner-openapi-ite.jdcloud.com/v1/user/ip?pin=jdcloud-api-test"
        res = requests.get(server)
    except requests.ConnectionError:
        raise
    return res.json()["result"]["ip"]


def get_user_header(userinfo):
    if isinstance(userinfo, dict):
        headers = userinfo.get("headers", {})
        if isinstance(headers, dict):
            return headers
    raise exceptions.ParamsError("**> User info not dict value: %s" % userinfo)


def skip_outer_gw(userinfo):
    if isinstance(userinfo, dict):
        try:
            if str(get_os_environ("ENV_SKIP_OUTER_GW_REQUEST")) == "1":
                return 1
        except exceptions.EnvNotFound:
            pass

        usertype = userinfo.get("keytype", "")
        if "console" in usertype.lower() or "ompuser" in usertype.lower() or "servicerole" in usertype.lower():
            return 1
        return 0
    raise exceptions.ParamsError("**> User info not dict value: %s" % userinfo)


def skip_inter_gw(userinfo):
    if isinstance(userinfo, dict):
        try:
            if str(get_os_environ("ENV_SKIP_INTER_GW_REQUEST")) == "1":
                return 1
        except exceptions.EnvNotFound:
            pass

        return 0
    raise exceptions.ParamsError("**> User info not dict value: %s" % userinfo)


def get_user_item(userinfo, item):
    """
    :param userinfo:
    :param item:
    :return:
    """
    if isinstance(userinfo, dict):
        value = None
        try:
            if str(get_os_environ("ENV_CACHE_WAITTIME_GET_FROM_ENV")) != "1":
                value = userinfo.get(item, None)
        except exceptions.EnvNotFound:
            value = None

        if value is None:
            if item == "uc_ipprotect_open_wait_time":
                value = get_os_environ("ENV_UC_IPPROTECT_OPEN_WAIT_TIME")
            elif item == "uc_ipprotect_close_wait_time":
                value = get_os_environ("ENV_UC_IPPROTECT_CLOSE_WAIT_TIME")
            elif item == "gw_ipprotect_close_wait_time":
                value = get_os_environ("ENV_GW_IPPROTECT_CLOSE_WAIT_TIME")
            elif item == "gw_ipprotect_open_wait_time":
                value = get_os_environ("ENV_GW_IPPROTECT_OPEN_WAIT_TIME")
            else:
                return 0

        return value
    raise exceptions.ParamsError("**> User info not dict value: %s" % userinfo)


def sleep_N_secs(n_secs):
    """ sleep n seconds
    """
    print("==> time sleep: %ss" % n_secs)
    time.sleep(int(n_secs))


def gen_openapi_header(request, env, service_name, AK=None, SK=None, regionId=None):

    if env == "ET":
        # 82keys：
        internal_access_key = '5FE5223DFE3FDC9E6E2ECE886E7DAF07'
        internal_secret_key = 'D375D9DAA59BA2471A1192C264B0307D'
    elif env == "test":
        # 测试keys：
        internal_access_key = 'DD1B0BFA7BAA5DAED057ACF4817AF55B'
        internal_secret_key = '6FC47989E4F4B1F489004F12FFFD89DE'
    elif env == "pre":
        # 预发keys：
        internal_access_key = '379E1234E8EBB9942284FBA0F84EB6A2'
        internal_secret_key = '36D959BFF6BD6D86E83E5BD8A899E25E'
    elif env == "product":
        # 线上keys：
        internal_access_key = 'DD1B0BFA7BAA5DAED057ACF4817AF55B'
        internal_secret_key = '6FC47989E4F4B1F489004F12FFFD89DE'
    else:
        internal_access_key = 'DD1B0BFA7BAA5DAED057ACF4817AF55B'
        internal_secret_key = '6FC47989E4F4B1F489004F12FFFD89DE'
    if AK and SK:
        internal_access_key = AK
        internal_secret_key = SK

    # rev = "0.1.0"
    service_name = service_name
    regionid = regionId

    url = request.get("url")
    body = request.get("body", "")
    method = request.get("method")

    credential = Credential(internal_access_key, internal_secret_key)
    config = Config(url, scheme="http")

    attach_header = request.get("headers", {})

    cur_time = datetime.datetime.now().strftime('%Y%m%dT%H%M%SZ')

    client = MyHeaderGenerator(credential, config, service_name, regionid)
    genheader = client.gen_headers(url, method, attach_header, body, cur_time)

    return genheader


def update_JD_headers(request, base_url=None, env=None, service_name="apigateway", AK=None, SK=None, regionId=None):
    if base_url is not None:
        request["url"] = base_url + request["url"]

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
    header = gen_openapi_header(request, env, service_name, AK, SK, regionId)
    for k, v in header.items():
        request['headers'][k] = v
