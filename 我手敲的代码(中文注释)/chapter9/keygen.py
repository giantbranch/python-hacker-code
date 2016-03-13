#-*- coding:utf8 -*-  

"""
@version: 
@author: giantbranch
@file: keygen.py
@time: 2016/3/13 9:55
"""

from Crypto.PublicKey import RSA

# 随机地生成一个新的RSA key对象
new_key = RSA.generate(2048, e = 65537)

# 导出公钥和私钥
public_key = new_key.publickey().exportKey("PEM")
private_key = new_key.exportKey("PEM")

# 分别输出公钥和私钥
print public_key
print private_key

