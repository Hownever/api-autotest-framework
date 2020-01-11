# -*- coding: utf-8 -*-
# @File  : ss.py
# @Author: jiashuo1
# @Date  : 2019/5/25
# @Desc  :

a = """
        - prepareinfo: 灰度-添加业务线-$serviceLine，添加业务线用户jiashuo-stag；灰度-添加接口$apis，添加接口用户jiashuo-stag
          info: 使用主账号AKSK，不传PIN
          pin:
          AK: ${ENV(ENV_USER_AK)}
          SK: ${ENV(ENV_USER_SK)}
          serviceLinePin: jiashuo-stag
          apisPin: jiashuo-stag
          serviceLineFlag: True
          serviceLinePinFlag: True
          apisFlag: True
          apisPinFlag: True
          openapi_manage_host: $openapi_manage_host
          openapi_data_host: $openapi_data_host
          serviceLine: $serviceLine
          apis: $apis
          ser_ver_api: $ser_ver_api
"""

for serviceLineFlag in ["True", "False"]:
    for serviceLinePinFlag in ["True", "False"]:
        for apisFlag in ["True", "False"]:
            for apisPinFlag in ["True", "False"]:
                b = a.replace("serviceLineFlag: True", "serviceLineFlag: {}".format(serviceLineFlag)).replace(
                    "serviceLinePinFlag: True", "serviceLinePinFlag: {}".format(serviceLinePinFlag)).replace(
                    "apisFlag: True", "apisFlag: {}".format(apisFlag)).replace(
                    "apisPinFlag: True", "apisPinFlag: {}".format(apisPinFlag))
                c = b.replace("灰度-添加业务线", "灰度-添加业务线" if serviceLineFlag == "True" else "灰度-删除业务线").replace(
                    "添加业务线用户", "添加业务线用户" if serviceLinePinFlag == "True" else "删除业务线用户").replace(
                    "灰度-添加接口", "灰度-添加接口" if apisFlag == "True" else "灰度-删除接口").replace(
                    "添加接口用户", "添加接口用户" if apisPinFlag == "True" else "删除接口用户")
                print(c)

