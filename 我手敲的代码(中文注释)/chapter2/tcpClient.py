#-*- coding:utf8 -*-

import socket

target_host = "127.0.0.1"
target_port = 8888

#建立一个socket对象(AF_INET:使用标准IPV4地址和主机名，  SOCK_STREAM：TCP客户端)
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 连接客户端
client.connect((target_host,target_port))

# 发送一些数据
client.send("GET / HTTP/1.1\r\nHost:baidu.com\r\n\r\n")

# 接收一些数据（4096个字符）
response = client.recv(4096)

print response
