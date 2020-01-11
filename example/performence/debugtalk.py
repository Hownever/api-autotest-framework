# coding=utf-8
import datetime
import uuid
import hashlib
import hmac
import re
import traceback
import json
import abc

from jdcloud_sdk.core import const
from jdcloud_sdk.core.util import quote, base64encode
from jdcloud_sdk.core.credential import Credential
from jdcloud_sdk.core.version import VERSION
from jdcloud_sdk.core.config import Config
from jdcloud_sdk.core.const import SCHEME_HTTP
from jdcloud_sdk.core.signer import Signer
from jdcloud_sdk.core.exception import ClientException


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


def get_parameter_dict(parameters):
    if parameters is None:
        return {}
    return parameters if isinstance(parameters, dict) else parameters.__dict__


class MyTestSigner(object):
    ignored_headers = ['authorization', 'user-agent']

    def __init__(self):
        self.__logger = None

    def sign(self, method, service, region, uri, headers, data, credential, security_token, cur_time):
        uri_dict = self.__url_path_to_dict(uri)
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

        # now = cur_time
        # jdcloud_date = now.strftime('%Y%m%dT%H%M%SZ')
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

        print('---Debug canonical_request---\n' + canonical_request)
        print('----Debug string_to_sign---\n' + string_to_sign)

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

        # rheader={}
        # for k, v in headers.items():
        #     rheader[k] = v

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
        return hashlib.sha256(val.encode('utf-8')).hexdigest()

    def __build_canonical_headers(self, req_headers, security_token, full_host):
        headers = ['host']  # add host header first
        signed_values = {}

        for key in req_headers.keys():
            value = req_headers[key]

            lower_key = key.lower()
            if lower_key in Signer.ignored_headers:
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
        # print("==>canonical_headers:\n", canonical_headers)
        # print("==>signed_headers:\n", signed_headers)

        return canonical_headers, signed_headers


class MyHeaderGenerator(object):
    def __init__(self, credential, config, service_name, revision, regionid):
        self.__config = config
        self.__service_name = service_name
        self.__credential = credential
        self.__revision = revision
        self.__regionid = regionid

        self.__builder_map = {const.METHOD_GET: WithoutBodyBuilder,
                              const.METHOD_DELETE: WithoutBodyBuilder,
                              const.METHOD_HEAD: WithoutBodyBuilder,
                              const.METHOD_PUT: WithBodyBuilder,
                              const.METHOD_POST: WithBodyBuilder,
                              const.METHOD_PATCH: WithBodyBuilder}

    def __merge_headers(self, request_header):
        mheaders = dict()
        mheaders['User-Agent'] = 'JdcloudSdkPython/%s %s/%s' % (VERSION, self.__service_name, self.__revision)
        mheaders['Content-Type'] = 'application/json'

        if request_header is not None and isinstance(request_header, dict):
            for key, value in request_header.items():
                if key.lower().startswith(const.HEADER_JDCLOUD_PREFIX) \
                        or key.lower().startswith(const.HEADER_JCLOUD_PREFIX):
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
            print('url=' + url)
            print('body=' + body)

            cur_time = timestamp
            signer = MyTestSigner()
            myheader = signer.sign(method, self.__service_name, region, url,
                                   headers=header, data=body,
                                   credential=self.__credential,
                                   security_token=token, cur_time=cur_time)
            return myheader
        except Exception as expt:
            msg = traceback.format_exc()
            print("**> ", msg)
            raise expt


def gen_ompopenapi_header(url, body):
    internal_access_key = 'DD1B0BFA7BAA5DAED057ACF4817AF55B'
    internal_secret_key = '6FC47989E4F4B1F489004F12FFFD89DE'

    credential = Credential(internal_access_key, internal_secret_key)
    config = Config(url, scheme=SCHEME_HTTP)
    rev = "0.1.0"
    service_name = "ompopenapi"
    regionid = "jdcloud-api"

    attach_header = {'x-jdcloud-pin': 'jdcloud-api-test', 'x-jdcloud-erp': "lixuenan2"}
    cur_time = datetime.datetime.now().strftime('%Y%m%dT%H%M%SZ')

    client = MyHeaderGenerator(credential, config, service_name, rev, regionid)
    genheader = client.gen_headers(url, "GET", attach_header, body, cur_time)

    return genheader
