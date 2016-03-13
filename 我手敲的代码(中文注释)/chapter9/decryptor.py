#-*- coding:utf8 -*-  

"""
@version: 
@author: giantbranch
@file: decryptor.py
@time: 2016/3/13 10:21
"""

import zlib
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

private_key = ""

rsakey = RSA.importKey(private_key)
rsakey = PKCS1_OAEP.new(rsakey)

chunk_size = 256
offset = 0
decrypted = ""
encrypted = base64.b64decode(encrypted)

while offset < len(encrypted):
    decrypted += rsakey.decrypt(encrypted[offset:offset+chunk_size])
    offset += chunk_size

# 解压负载
plaintext = zlib.decompress(decrypted)

print plaintext
