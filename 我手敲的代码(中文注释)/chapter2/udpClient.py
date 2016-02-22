#-*- coding:utf8 -*-
import socket

target_host = "127.0.0.1"
target_port = 9999

#建立一个socket对象(SOCK_DGRAM:UDP客户端)
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# 发送一些数据
client.sendto("AAABBBCCC你收到了吗",(target_host,target_port))

# 接收一些数据(4096个字符),将会收到回传的数据和远程主机的信息和端口号
data, addr = client.recvfrom(4096)

print data
print addr