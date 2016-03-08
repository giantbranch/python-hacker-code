#-*- coding:utf8 -*-

import os

def run(**args):
    print "[*] In dirlister module."
    # 列出当前目录的所有文件,并作为字符串返回
    files = os.listdir(".")
    return str(files)

