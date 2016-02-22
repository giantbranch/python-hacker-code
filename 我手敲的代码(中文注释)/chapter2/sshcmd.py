#-*- coding:utf8 -*-

import threading
import paramiko
import subprocess

def ssh_command(ip, user, passwd, command):
    client = paramiko.SSHClient()
    # client.load_host_keys('/home/root/.ssh/known_hosts') #支持用密钥认证代替密码验证,实际环境推荐使用密钥认证
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())    #设置自动添加和保存目标ssh服务器的ssh密钥
    client.connect(ip, username=user, password=passwd)  #连接
    ssh_session = client.get_transport().open_session() #打开会话
    if ssh_session.active:
        ssh_session.exec_command(command)   #执行命令
        print ssh_session.recv(1024)    #返回命令执行结果(1024个字符)
    return

#调用函数,以用户pi及其密码连接我自己的树莓派,并执行id这个命令
ssh_command('192.168.88.105', 'pi', 'raspberry', 'id')

