#-*- coding:utf8 -*-  

"""
@version: 
@author: giantbranch
@file: grabhashes.py
@time: 2016/3/15 20:16
"""

import sys
import struct
import volatility.conf as conf
import volatility.registry as registry

# 要分析的内存文件位置
memory_file = "D:\\Windows XP Professional-f6b49762.vmem"

# volatility的下载的路径
sys.path.append("D:\\volatility-2.3")

registry.PluginImporter()
config = conf.ConfObject()

import volatility.commands as commands
import volatility.addrspace as addrspace

config.parse_options()
config.PROFILE = "WinXPSP3x86"
config.LOCATION = "file://%s" % memory_file

# 注册全局参数
registry.register_global_options(config, commands.Command)
registry.register_global_options(config, addrspace.BaseAddressSpace)

from volatility.plugins.registry.registryapi import RegistryApi
from volatility.plugins.registry.lsadump import HashDump

# 实例化一个RegistryApi类对象（包含常用的注册表帮助类）
registry = RegistryApi(config)
# 等同与hivelist命令
registry.populate_offsets()

sam_offset = None
sys_offset = None

# 循环检索SAM和system键值
for offset in registry.all_offsets:
    if registry.all_offsets[offset].endswith("\\SAM"):
        sam_offset = offset
        print "[*] SAM: 0x%08x" % offset

    if registry.all_offsets[offset].endswith("\\system"):
        sys_offset = offset
        print "[*] System: 0x%08x" % offset

    if sam_offset is not None and sys_offset is not None:
        config.sys_offset = sys_offset
        config.sam_offset = sam_offset

        # 创建HashDump对象
        hashdump = HashDump(config)

        for hash in hashdump.calculate():
            print hash

        break


if sam_offset is None or sys_offset is None:
    print "[*] Failed to find the system or SAM offsets."
