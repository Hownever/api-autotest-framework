#
# -*- coding:utf-8 -*-
import datetime

try:
    from SocketServer import ThreadingTCPServer, BaseRequestHandler
except ImportError:
    from socketserver import ThreadingTCPServer, BaseRequestHandler
import traceback


class TcpEchoServerRequestHandler(BaseRequestHandler):
    """
    # 从BaseRequestHandler继承，并重写handle方法
    """
    def handle(self):
        # self.client_address是客户端的连接(host, port)的元组
        print('{} Accepted connection from {}'.format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
                                                      self.client_address))
        # 循环监听（读取）来自客户端的数据
        while True:
            # 当客户端主动断开连接时，self.recv(1024)会抛出异常
            try:
                # 一次读取1024字节,并去除两端的空白字符(包括空格,TAB,\r,\n)
                data = self.request.recv(1024).strip()
                # 如果收到内容为空，则断开链接
                if data.decode() == "":
                    print('{} Receive null data, Client connection closed.'.format(
                        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")))
                    break

                # 原样返回给客户端
                response = data
                print('{} {} Receive:[{}], Send: [{}]'.format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
                                                              self.client_address, data, response))

                if self.request.send(response) is not None:
                    print('{} Send data return result is not None: {}'.format(
                        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"), response))


                # 如果收到bye，则表示客户端希望结束链接
                if data.decode().lower() == "bye":
                    print('{} Receive bye, Client connection closed.'.format(
                        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")))
                    break
            except ConnectionAbortedError:
                print('{} Client connection abort.'.format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")))
                traceback.print_exc()
                break
            except ConnectionRefusedError:
                print('{} Client connection refused.'.format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")))
                traceback.print_exc()
                break
            except ConnectionResetError:
                print('{} Client connection reset.'.format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")))
                traceback.print_exc()
                break
            except ConnectionError:
                print('{} Client connection error.'.format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")))
                traceback.print_exc()
                break
            except:
                traceback.print_exc()
                break


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: {} port".format(sys.argv[0]))
        exit(-1)
    host = ""  # 主机名，可以是ip,像localhost的主机名,或""
    port = int(sys.argv[1])  # 端口
    addr = (host, port)

    print('{} Tcp echo server running at {}'.format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"), addr))
    server = ThreadingTCPServer(addr, TcpEchoServerRequestHandler)

    # 启动服务监听
    server.serve_forever()
