#-*- coding:utf8 -*-

import win32gui
import win32ui
import win32con
import win32api

# 获取窗口桌面的句柄
hdesktop = win32gui.GetDesktopWindow()

# 获得显示屏的像素尺寸
width = win32api.GetSystemMetrics(win32con.SM_CXVIRTUALSCREEN)
height = win32api.GetSystemMetrics(win32con.SM_CYVIRTUALSCREEN)
left = win32api.GetSystemMetrics(win32con.SM_XVIRTUALSCREEN)
top = win32api.GetSystemMetrics(win32con.SM_YVIRTUALSCREEN)

# 创建设备描述表
desktop_dc = win32gui.GetWindowDC(hdesktop)
img_dc = win32ui.CreateDCFromHandle(desktop_dc)

# 创建基于内存的设备描述表,用于储存我们捕获到的图片的数据，直到我们保存到文件
mem_dc = img_dc.CreateCompatibleDC()

# 创建位图对象
screenshot = win32ui.CreateBitmap()
screenshot.CreateCompatibleBitmap(img_dc, width, height)
mem_dc.SelectObject(screenshot)

# 复制屏幕到我们的内存设备描述表中
mem_dc.BitBlt((0,0), (width,height), img_dc, (left, top), win32con.SRCCOPY)

# 将位图保存到文件中
screenshot.SaveBitmapFile(mem_dc, "C:\\test.bmp")

# 释放对象
mem_dc.DeleteDC()
win32gui.DeleteObject(screenshot.GetHandle())