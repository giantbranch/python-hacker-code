#-*- coding:utf8 -*-
from burp import IBurpExtender
from burp import IContextMenuFactory

from javax.swing import JMenuItem
from java.util import List, ArrayList
from java.net import URL

import re
from datetime import datetime
from HTMLParser import HTMLParser

#
class TagStripper(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.page_text = []
    # 遇到两个标签之间的数据时调用
    def handle_data(self, data):
        self.page_text.append(data)
    # 遇到注释时调用
    def handle_comment(self, data):
        self.handle_data(data)

    def strip(self,html):
        # 会调用上面的两个函数
        self.feed(html)
        return "".join(self.page_text)

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self,callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.context = None
        self.hosts = set()

        # 按部就班,先设定一个非常常见的密码，因为是字典，不能重复最好，所以用集合
        self.wordlist = set(["password"])

        # 建立起我们的扩展工具
        callbacks.setExtensionName("Build Wordlist")
        callbacks.registerContextMenuFactory(self)

        return

    # 添加菜单
    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Bulid Wordlist", actionPerformed=self.wordlist_menu))

        return menu_list

    def wordlist_menu(self, event):

        # 抓取用户点击细节
        http_traffic = self.context.getSelectedMessages()

        # 获取ip或主机名(域名)
        for traffic in http_traffic:
            http_service = traffic.getHttpService()
            host = http_service.getHost()

            self.hosts.add(host)
            # 获取网站的返回信息
            http_response = traffic.getResponse()
            # 若有回应就调用get_word
            if http_response:
                self.get_words(http_response)

        self.display_wordlist()
        return

    def get_words(self, http_response):

        headers, body = http_response.tostring().split("\r\n\r\n", 1)

        # 忽略下一个请求
        if headers.lower().find("content-type: text") == -1:
            return

        # 获取标签中的文本
        tag_stripper = TagStripper()
        page_text = tag_stripper.strip(body)

        # 匹配第一个是字母的，后面跟着的是两个以上的字母，数字或下划线／
        words = re.findall("[a-zA-Z]\w{2,}", page_text)

        # 感觉这里的长度有点短啊,作者是12，我改成15了
        for word in words:
            # 过滤长字符串
            if len(word) <= 15:
                self.wordlist.add(word.lower())

        return

    # 再后面添加更多的猜测
    def mangle(self, word):
        year = datetime.now().year
        suffixes = ["", "1", "!", year]
        mangled = []

        for password in (word, word.capitalize()):
            for suffix in suffixes:
                mangled.append("%s%s" % (password, suffix))

        return mangled

    def display_wordlist(self):

        print "#!comment: BHP Wordlist for site(s) %s" % ", ".join(self.hosts)

        for word in sorted(self.wordlist):
            for password in self.mangle(word):
                print password

        return
