#-*- coding:utf8 -*-

import ctypes
import random
import time
import sys

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# 用于记录鼠标单击，键盘按键和双击的总数量
keystrokes = 0
mouse_clicks = 0
double_clicks = 0

#  定义LASTINPUTINFO结构体
class LASTINPUTINFO(ctypes.Structure):
    _fields_ = [
                ("cbsize", ctypes.c_uint),  # 结构体大小
                ("dwTime", ctypes.c_ulong)  # 系统最后输入时间
                ]

def get_last_input():
    struct_lastinputinfo = LASTINPUTINFO()
    struct_lastinputinfo.cbSize = ctypes.sizeof(LASTINPUTINFO)

    # 获得用户最后输入的相关信息
    user32.GetLastInputInfo(ctypes.byref(struct_lastinputinfo))

    # 获取系统开机以来的时间
    run_time = kernel32.GetTickCount()

    elapsed = run_time - struct_lastinputinfo.dwTime
    print "[*] It's been %d milliseconds since the last input event." % elapsed

    return elapsed

# 测试后删除下面代码，这只是测试上面代码能否运行成功
# while True:
#     get_last_input()
#     time.sleep(1)

def get_key_press():
    global mouse_clicks
    global keystrokes

    for i in range(0,0xff):
        # 检测某个按键是否被按下
        if user32.GetAsyncKeyState(i) == -32767:
            # 左键点击为0x1
            if i == 0x1:
                # 鼠标单击的数目和时间
                mouse_clicks += 1
                return time.time()
            # 键盘ASCII按键是从23-127（具体可看ASCII表），为可打印字符，这就获取了键盘的敲击次数
            elif i > 32 and i < 127:
                keystrokes += 1

    return None

def detect_sandbox():
    global mouse_clicks
    global keystrokes

    # 定义键盘，单击，双击的最大值（阀值）
    max_keystrokes = random.randint(10,25)
    max_mouse_clicks = random.randint(5,25)
    max_double_clicks = 10

    double_clicks = 0
    double_click_threshold = 0.250 #秒为单位
    first_double_click = None

    average_mousetime = 0
    max_input_threshold = 30000 #毫秒为单位

    previous_timestamp = None
    detection_complete = False

    # 获取用户最后一次输入之后经历的时间
    last_input = get_last_input()

    # 超过设定的阀值时强制退出，就是用户最后一次输入之后经历的时间太长，都没用户活动了
    if last_input >= max_input_threshold:
        sys.exit(0)

    # 循环检测
    while not detection_complete:

        # 获取按下鼠标的时间，不懂的看函数的返回值
        keypress_time = get_key_press()

        if keypress_time is not None and previous_timestamp is not None:
            # 计算两次点击的相隔时间
            elapsed = keypress_time - previous_timestamp
            # 间隔时间短的话，则为用户双击
            if elapsed <= double_click_threshold:
                double_clicks += 1
                if first_double_click is None:
                    # 获取第一次双击的时间
                    first_double_click = time.time()
                else:
                    # 是否是沙盒的管理者在沙盒中模仿用户的点击（因为普通用户通常不会双击这么多）
                    if double_clicks == max_double_clicks:
                        # 短时间内，鼠标点击达到了我们设定的最大值（最大次数*双击间隔）
                        if keypress_time - first_double_click <= (max_double_clicks * double_click_threshold):
                            sys.exit(0)
            # 是否达到了我们检测的最大数量，是就退出
            if keystrokes >= max_keystrokes and double_clicks >= max_double_clicks and mouse_clicks >=max_mouse_clicks:
                return

            previous_timestamp = keypress_time
        elif keypress_time is not None:
            previous_timestamp = keypress_time



detect_sandbox()
print "We are Ok!"



