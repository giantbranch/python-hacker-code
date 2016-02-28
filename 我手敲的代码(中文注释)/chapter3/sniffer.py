#-*- coding:utf8 -*-

import socket
import os

# 监听主机，即监听那个网络接口，下面的为我的kali的ip
host = "10.10.10.145"

# 创建原始套接字,然后绑定在公开接口上
if  os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)   #raw的中文是生的意思,大概就是原始套接字的意思吧

sniffer.bind((host, 0)) #这里端口为0,监听所有端口吧~

# 设置在捕获的数据包中包含IP头
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# 在Windows平台上,我们需要设置IOCTL以启用混杂模式
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# 读取单个数据包
print sniffer.recvfrom(65565)

# 在Windows平台上关闭混杂模式
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)