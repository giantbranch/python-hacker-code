#-*- coding:utf8 -*-

import urllib2
try:
    body = urllib2.urlopen("http://www.360.cn/12323")
    print body.read()
except urllib2.URLError, e:
    print(e.code)
