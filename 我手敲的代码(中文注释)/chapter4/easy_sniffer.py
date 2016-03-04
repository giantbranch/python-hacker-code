#-*- coding:utf8 -*-

from scapy.all import *

# 定义数据包回调函数
def packet_callback(packet):
    print packet.show()

# 开启嗅探器
sniff(prn=packet_callback, count=1)