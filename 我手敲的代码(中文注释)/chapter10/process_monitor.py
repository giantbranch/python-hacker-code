#-*- coding:utf8 -*-  

"""
@version: 
@author: giantbranch
@file: process_monitor.py
@time: 2016/3/13 20:12
"""

import win32con
import win32api
import win32security

import wmi
import sys
import os

def get_process_privileges(pid):
    try:
        # 通过pid获取目标进程句柄
        hproc = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)

        # 打开主进程的令牌
        htok = win32security.OpenProcessToken(hproc, win32con.TOKEN_QUERY)

        # 解析已启用的权限列表，获得令牌信息
        privs = win32security.GetTokenInformation(htok, win32security.TokenPrivileges)

        # 迭代每个权限并输出其中已经启用的
        # i[0]:具体权限
        # i[1]：该权限是否启用
        priv_list = ""
        for i in privs:
            # 检测权限是否已经启用
            if i[1] == 3:
                # 获取并连接权限的名称
                priv_list += "%s|" % win32security.LookupPrivilegeName(None, i[0])
    except:
        priv_list = "N/A"

    return priv_list


# 保存数据到文件中
def log_to_file(message):
    fd = open("process_monitor_log.csv", "ab")
    fd.write("%s\r\n" % message)
    fd.close()

    return

# 创建一个日志文件的头
log_to_file("Time,User,Executable,CommandLine,PID,Parent PID,Privileges")

# 初始化WMI接口
c = wmi.WMI()

# 创建进程监控器（监控进程创建）
process_watcher = c.Win32_Process.watch_for("creation")

while True:
    try:
        # 有创建进程事件会返回
        new_process = process_watcher()

        proc_owner = new_process.GetOwner()
        # for i in proc_owner:
        #     print i
        proc_owner = "%s\\%s" % (proc_owner[0], proc_owner[2])
        # 时间
        create_data = new_process.CreationDate
        # 路径
        executable = new_process.ExecutablePath
        # 命令行（就是实际的命令是什么）
        cmdline = new_process.CommandLine
        pid = new_process.ProcessId
        parent_pid = new_process.ParentProcessId

        # N/A：不可用的意思
        # privileges = "N/A"
        privileges = get_process_privileges(pid)

        process_log_message = "%s,%s,%s,%s,%s,%s,%s\r\n" % (create_data, proc_owner, executable, cmdline, pid, parent_pid, privileges)

        print process_log_message

        log_to_file(process_log_message)

    except:
        pass