#
# coding=utf-8

# build_in module
import logging
import sys
import os

import avocado
from avocado import Test
from avocado.utils import process
from avocado import main

sys.path.insert(0, "../../")
from core.codegen_go import GolangCodeGen
from core.codegen_python import PythonCodeGen


class SdkTester(Test):

    def setUp(self):
        """
        用来初始化sdk相关工作，比如更新最新版本的sdk，配置相应语言sdk的测试环境，
        解析对应yaml文件的数据等等
        :return:
        """
        # 配置测试环境，检查go语言环境
        self.cwd = os.getcwd()
        pass

    def test(self):
        print("===>cwd:", self.cwd)
        print("===>product:", self.params.get("product"))
        print("===>ak:", self.params.get("ak", "*"))
        print("===>sk:", self.params.get("sk", path="*"))

    @avocado.fail_on(process.CmdError)
    def test_python_sdk(self):
        """
        Fail test for python code
        """
        code = PythonCodeGen("tmp.py", "python")
        code.add(["#", "# coding=utf-8", "# Jdcloud openapi sdk autotest"])
        code.add(["# This is the header comment1", "# This is the header comment1"])

        code.add("import os")
        code.add("import sys")
        code.add("""print("hello world")""")
        code.add("""sys.exit(0)""")
        rlt = code.run()
        self.log.info(rlt)

    @avocado.fail_on(process.CmdError)
    def test_golang_sdk_from_yaml(self):
        products = self.params.get("product")
        PRO = {}
        for op in products:
            for p in op.keys():
                PRO[p] = {}
                dis = []
                args = []
                for t in op[p]:
                    for k, v in t.items():
                        for kk, vv in v.items():
                            if kk == "DescribeInstances":
                                dis.append(vv)
                            if kk == "request_args":
                                args.append(vv)
                self.assertEquals(len(dis), len(args))
                PRO[p]["di"] = dis
                PRO[p]["args"] = args

        code = GolangCodeGen("tmp.go")

        code.add(["//", "// Jdcloud openapi sdk autotest"])

        # gen header
        code.add("// This is the header comment1")
        code.add("// This is the header comment2")
        code.add("")
        code.add("package main")
        code.add("")

        code.add('import (')
        # 导入基本模块
        code.add('    "fmt"')
        code.add('    "os"')
        code.add('    . "github.com/jdcloud-api/jdcloud-sdk-go/core"')

        # 根据配置的产品导入对应SDK模块
        for p in PRO.keys():
            code.add('    . "github.com/jdcloud-api/'
                     'jdcloud-sdk-go/services/{product}/apis"'.format(product=p))
            code.add('    . "github.com/jdcloud-api/'
                     'jdcloud-sdk-go/services/{product}/client"'.format(product=p))

        code.add(')')
        code.add('')

        # go main 函数
        code.add('func main(){')

        # 配置 AK 和 SK相关代码，并生成认证对象
        code.add('    accessKey := "{ak}"'.format(ak=self.params.get("ak", default="")))
        code.add('    secretKey := "{sk}"'.format(sk=self.params.get("sk", default="")))
        code.add('')
        code.add('    credentials := NewCredentials(accessKey, secretKey)')
        code.add('')

        for p in PRO.keys():

            # 生成client
            code.add('    client{product} := New{product}Client(credentials)'.format(product=p.capitalize()))
            code.add('')
            for i in range(0, len(PRO[p]['di'])):

                # 生成request：
                code.add('    req{i} := New{DescribeInstances}Request("{req_args}")'.format(
                    i=i,
                    DescribeInstances=PRO[p]["di"][i],
                    req_args=PRO[p]["args"][i]))

                # 调用API
                code.add('    resp{t}, err{j} := client{product}.{DescribeInstances}(req{k})'.format(
                    t=i,
                    j=i,
                    product=p.capitalize(),
                    DescribeInstances=PRO[p]["di"][i],
                    k=i
                ))

                # API结果处理
                code.add('    if err%d != nil {' % i)
                code.add('        fmt.Println("Fail to get response:", req{}.GetURL)'.format(i))
                code.add('        os.Exit(-1)')
                code.add('    }')
                code.add('')

                # 输出API结果，方便后续处理
                code.add('    fmt.Println(resp{}.RequestID)'.format(i))
                code.add('    fmt.Println("error status:", resp{}.Error.Status)'.format(i))
                code.add('    fmt.Println("error code:", resp{}.Error.Code)'.format(i))
                code.add('    fmt.Println("error msg:", resp{}.Error.Message)'.format(i))
                code.add('')

        code.add('    os.Exit(0)')
        code.add('')
        code.add('')
        code.add('}')

        # go run
        rlt = code.run()

        # check ...
        print("==>rlt.stdout:", rlt.stdout)
        self.log.info("==>rlt.stdout:", rlt.stdout)
        self.log.info("==>rlt.stderr:", rlt.stderr)


if __name__ == "__main__":
    main()