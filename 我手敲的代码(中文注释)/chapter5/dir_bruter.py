#-*- coding:utf8 -*-  
  
import urllib2  
import threading  
import Queue  
import urllib  
  
threads = 50  
target_url = "http://testphp.vulnweb.com"  
wordlist_file = "./all.txt"  
resume = None   #作者说用于网络中断时，延续上一个尝试的字符串，而不用从头开始，这里好像没用到  
user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.80 Safari/537.36"  
  
  
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
  
def dir_bruter(word_queue, extentsions=None):  
  
    while not word_queue.empty():  
        attempt = word_queue.get() 

        #用于储存要尝试的url
        attempt_list = []  
  
        #检查是否有文件扩展名，如果没有就是我们要爆破路径，否则爆破文件  
        if "." not in attempt:  
            attempt_list.append("/%s/" % attempt)  
        else:  
            attempt_list.append("/%s" % attempt)  
  
        #如果我们想暴力破解扩展名  
        if extentsions:  
            for extentsion in extentsions:  
                attempt_list.append("/%s%s" % (attempt, extentsion))  
  
        #迭代我们要尝试的文件列表  
        for brute in attempt_list:  
            #构造url
            url = "%s%s" % (target_url, urllib.quote(brute))  
            #print url  
            try:  
                headers = {}  
                headers['User-Agent'] = user_agent  
                r = urllib2.Request(url, headers=headers)  
  
                response = urllib2.urlopen(r)  
                #print response.__dict__
                if len(response.read()):  
                    print "[%d] ＝＞　%s" % (response.code, url) 
            #用ｅ接收URLError的信息 
            except urllib2.URLError,e:  
                # code属性存在，并且code不是404  
                if hasattr(e, 'code') and e.code != 404:  
                    print "!!! %d => %s" % (e.code, url)  
                pass  
  
  
word_queue = built_wordlist(wordlist_file)  
extentsions = [".php", ".bak", ".orig",".inc"]  

#开启多线程扫描
for i in range(threads):  
    t = threading.Thread(target=dir_bruter, args=(word_queue, extentsions))  
    t.start()  
