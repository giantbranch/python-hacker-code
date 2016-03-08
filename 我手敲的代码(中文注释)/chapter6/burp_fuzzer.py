#-*- coding:utf8 -*-

# 导入三个类，其中IBurpExtender类是编写扩展工具必须的类，后两个是Intruder的，我们就是要扩展它
from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator

from java.util import List, ArrayList

import random

#定义自己的BurpExtender类，继承和扩展IBurpExtender和IIntruderPayloadGeneratorFactory类
class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        #用registerIntruderPayloadGeneratorFactory函数注册BurpExtender类，这样Intruder才能生成攻击载荷
        callbacks.registerIntruderPayloadGeneratorFactory(self)

        return

    #返回载荷生成器的名称
    def getGeneratorName(self):
        return "BHP Payload Generator"

    # 接受攻击相关参数，返回IIntruderPayloadGenerator类型的实例，作者将他命名为BHPFuzzer
    def createNewInstance(self, attack):
        return BHPFuzzer(self, attack)

# 定义BHPFuzzer类，扩展了IIntruderPayloadGenerator类
# 增加了max_payload(最大的payload), num_iterations(迭代次数)两个变量，用于控制模糊测试的次数
class BHPFuzzer(IIntruderPayloadGenerator):
    def __init__(self, extender, attack):
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        self.max_payload = 1000
        self.num_iterations = 0
        return

    # 通过比较判断迭代是否达到上限
    def hasMorePayloads(self):
        if self.num_iterations == self.max_payload:
            return False
        else:
            return True

    # 接受原始的HTTP负载，current_payload是数组，转化成字符串，传递给模糊测试函数mutate_payload
    def getNextPayload(self, current_payload):
        # 转换成字符串
        payload = "".join(chr(x) for x in current_payload)
        # 调用简单的变形器对POST请求进行模糊测试
        payload = self.mutate_payload(payload)
        # 增加FUZZ的次数
        self.num_iterations += 1
        return payload

    # 重置
    def reset(self):
        self.num_iterations = 0
        return

    def mutate_payload(self, original_payload):
        # 仅生成随机数或者调用一个外部脚本
        picker = random.randint(1,3)

        # 再载荷中选取一个随机的偏移量去变形
        offset = random.randint(0, len(original_payload)-1)
        payload = original_payload[:offset]

        # 在随机偏移位置插入SQL注入尝试
        if picker == 1:
            payload += "'"

        # 插入跨站尝试
        if picker == 2:
            payload += "<script>alert('xss');</script>"

        # 随机重复原始载荷
        if picker == 3:
            chunk_length = random.randint(len(payload[offset:]), len(payload)-1)
            repeater = random.randint(1,10)

            for i in range(repeater):
                payload += original_payload[offset:offset+chunk_length]


        # 添加载荷中剩余的字节
        payload += original_payload[offset:]

        return payload