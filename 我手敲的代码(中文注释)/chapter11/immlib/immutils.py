#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}


MOSDEF utils for non-CANVAS users

"""


__VERSION__ = '1.0'

# TODO check:
# -----------
# cparse: dInt
# spark: prettyprint
# x86opcodes: issignedbyte, intel_byte, intel_2byte
# pelib: hexdump
# mosdef: isprint, strisprint
# makeexe: binstring?

import sys, os
sys.path.append('.')

#try:
#    from internal import *
#except:
def __ignore(*args, **kargs):
   return False
def __retsamearg(arg):
   return arg
devlog = __ignore
isdebug = __ignore
warnings_safely_ignore = __ignore
warning_restore = __ignore
deprecate = __ignore
uniqlist = __retsamearg


# --------------------
#
#   __MOSDEFimport__
#
# --------------------
#
# global options: (set it to False to desactivate)
_MOSDEFimport_hook = True              # desactivate the current hook
_MOSDEFimport_cachefailedimport = True # cache can be dangerous (breaks reload()?)
#
# normally you DONT want to hack in the <MOSDEFimport> tag.
# NOTE: can we optimize speed here?
#
# <MOSDEFimport> begin
from traceback import format_exc
def __MOSDEFimport__(*args):
    global _failed_imported_module_table
    def mod_hash(modname):
        return hash(str(hash(str(sys.path))) + modname)
    modname = args[0]
    if __debug__:
        if len(args) < 4 or args[3] == None:
            devlog('MOSDEFimport', "IMPORT %s" % modname)
        else:
            if len(args[3]) == 1:
                val = args[3][0]
            else:
                val = str(args[3])[1:-1]
            devlog('MOSDEFimport', "FROM %s IMPORT %s" % (modname, val), nofile = True)
    if _MOSDEFimport_cachefailedimport:
        modhash = mod_hash(modname)
        if modhash in _failed_imported_module_table:
            devlog('MOSDEFimport', "already failed to import <%s>" % modname, nofile = True)
            raise ImportError
    cwd = os.getcwd()
    filepath = os.path.dirname(globals()['__file__'])
    mosdefpath = filepath.replace(cwd, ".")
    #print "[!] mosdef cwd: %s"%cwd
    #print "[!] filepath: %s"%filepath
    #print "[!] mosdefpath: %s"%mosdefpath
    sys.path = uniqlist(sys.path)
    if cwd != mosdefpath and mosdefpath not in sys.path:
        sys.path.insert(0, mosdefpath)
    import_time = time.time()
    try:
        return sys.modules['__builtin__'].__import__orig(*args)
    except:
        if _MOSDEFimport_cachefailedimport:
            _failed_imported_module_table += [modhash]
        devlog('all', "failed to import <%s> (lost %ss)" % (modname, time.time() - import_time), nofile = True)
        devlog('ImportError', format_exc(0).split('\n')[1], nodesc = True)
        if isdebug('ImportErrorTrace'):
            backtrace()
        raise
import __builtin__
if _MOSDEFimport_hook and not hasattr(__builtin__, '__import__orig'):
    import time
    __builtin__.__import__orig = __builtin__.__import__
    __builtin__.__import__ = __MOSDEFimport__
    _MOSDEFimport_hook = False
    _failed_imported_module_table = []
    devlog('all', "__import__ hooked with __MOSDEFimport__")
del __builtin__
# </MOSDEFimport> end


#####################################################
#
#
#    dictionary class that hold floats as integers
#
#
#####################################################

import types

class antifloatdict(types.DictType):
    
    def __init__(self, arg = {}):
        if type(arg) == types.DictType:
            d = {}
            for item in arg.items():
                d.__setitem__(item[0], item[1])
            arg = d
        return types.DictType.__init__(self, arg)
    
    def __setitem__(self, itemname, itemvalue):
        if type(itemvalue) == types.FloatType:
            itemvalue = int(itemvalue)
        return types.DictType.__setitem__(self, itemname, itemvalue)
    
    def __getitem__(self, itemname):
        item = types.DictType.__getitem__(self, itemname)
        if type(item) == types.FloatType:
            item = int(item)
        return item
    
    def copy(self):
        return antifloatdict(self)

def hasbadchar(word,badchars):
    try:
        wordstr=intel_order(word)
    except:
        wordstr=str(word)
    for ch in badchars:
        if wordstr.count(ch):
            return 1
    return 0



#####################################################
#
#
#    little/big endian management functions
#
#
#####################################################

def check_bits_consistancy(bits):
    assert not bits % 8, "bits should be sizeof(char) aligned, got %d" % bits

def check_string_len(s, l, assertmsg=""):
    if assertmsg != "":
        assertmsg += "\n"
    assert len(s) >= l, "%sexpecting a at_least_%d_chars string, got %d_chars instead.\nstring is: %s" % \
        (assertmsg, l, len(s), prettyprint(s))

def split_int_bits(bits, i):
    check_bits_consistancy(bits)
    # we cast to uint_bits here to be sure to return (bits/8) x uint8
    u = uint_bits(bits, i)
    r = []
    for b in range(0, bits, 8):
        r += [ (u >> (bits - (b + 8))) & 0xff ]
    return r

# 0x12345678 -> [0x12, 0x34, 0x56, 0x78]
def split_int32(int32):
    return split_int_bits(32, int32)

def int2list_bits(bits, i, swap=0):
    check_bits_consistancy(bits)
    l = split_int_bits(bits, i)
    #devlog("int2list: l = %s" % l)
    lc = []
    for n in l:
        #devlog("int2list: n = 0x%x" % n)
        lc += [chr(n)]
    if swap:
        lc.reverse()
    return lc

def int2list32(int32, swap=0):
    return int2list_bits(32, int32, swap=swap)

#def int2list(int32):
#    deprecate("use int2list32 instead")
#    return int2list32(int32)

def int2str_bits(bits, i, swap=0):
    check_bits_consistancy(bits)
    return "".join(int2list_bits(bits, i, swap=swap))

def int2str32(int32, swap=0):
    return int2str_bits(32, int32, swap=swap)

def int2str16(int16, swap=0):
    return int2str_bits(16, int16, swap=swap)

def int2str32_swapped(int32):
    return int2str_bits(32, int32, swap=1)

def int2str16_swapped(int16):
    return int2str_bits(16, int16, swap=1)

#def int2str(int32):
#    deprecate("use int2str32 instead")
#    return int2str32(int32)

def str2int_bits(bits, s):
    check_bits_consistancy(bits)
    assert type(s) == type(""), "str2int_bits() expects a string argument, got %s" % type(s)
    nchars = bits / 8
    check_string_len(s, nchars, "str2int_bits(%d, s): string=<%s> len=%d" % (bits, s, len(s)))
    r = 0
    warnings_safely_ignore(FutureWarning)
    for i in range(0, nchars):
        #print "%d = %x << %d" % (ord(s[i]) << 8*i, ord(s[i]), 8*i)
        r += ord(s[nchars-i-1]) << 8*i
    warning_restore()
    return r

def str2int_bits_swapped(bits, s):
    check_string_len(s, bits/8)
    return byteswap_bits(bits, str2int_bits(bits, s))

def str2int16(s):
    return str2int_bits(16, s)

def str2int32(s):
    return str2int_bits(32, s)

def str2int64(s):
    return str2int_bits(64, s)

def str2int16_swapped(s):
    return str2int_bits_swapped(16, s)

def str2int32_swapped(s):
    return str2int_bits_swapped(32, s)

def str2int64_swapped(s):
    return str2int_bits_swapped(64, s)

# "\x12\x34\x56\x78" -> 0x12345678
#def str2int32_old(s):
#    #return str2int_bits(32, s)
#    assert type(s) == type(""), "str2int32() expects a string argument, got %s" % type(s)
#    if len(s) < 4:
#        devlog("str2int32: string=<%s> len=%d" % (s, len(s)))
#        raise AssertionError, "str2int32 called with a less_than_4_chars string (%d chars)" % len(s)
#    (a,b,c,d)=(ord(s[0]),ord(s[1]),ord(s[2]),ord(s[3]))
#    return sint32((a << 24) + (b << 16) + (c << 8) + d)

#returns the integer that the 4 byte string represents
#Note: If you are getting OverflowError in this function, you need to upgrade to Python
#2.2. !!

def str2bigendian(astring):
    """
    oppposite of istr2int
    """
    return str2int32(astring)

# >>> print "0x%x" % str2littleendian("\x12\x34\x56\x78")
# 0x78563412
def str2littleendian(astring):
    return byteswap_32(str2int32(astring))

def byteswap_bits(bits, i):
    check_bits_consistancy(bits)
    r = 0
    warnings_safely_ignore(FutureWarning)
    for b in range(0, bits, 8):
        r += (((i >> b) & 0xff) << (bits - (b + 8)))
    warning_restore()
    return r

def byteswap_64(int64):
    return byteswap_bits(64, int64)

def byteswap_32(int32):
    return byteswap_bits(32, int32)

def byteswap_16(int16):
    return byteswap_bits(16, int16)

"""
istr2halfword(halfword2bstr(dInt(x))) == byteswap_16(x)
"""

#####################################################
#
#
#               print crap nicely
#
#
#####################################################

#wee little function for printing strings nicely
def hexprint(s):
    if not type(s) == type(""):
        return "can not hexdump %s" % type(s)
    tmp=""
    for c in s:
        tmp+="[0x%2.2x]"%ord(c)
    return tmp

goodchars=".()~!#$%^&*()-=_/\\:<>"
#let's not mess up our tty
def prettyprint(instring):
    import string
    if not type(instring) == type(""):
        devlog("prettyprint got %s and not string" % type(instring))
        instring = str(instring)
        #return "can not prettyprint %s" % type(instring)
    tmp=""
    for ch in instring:
        #if (ch.isalnum() or ch in goodchars) and ord(ch)<127:
        if ch in string.printable and ch not in ["\x0c"]:
            tmp+=ch
        else:
            value="%2.2x" % ord(ch)
            tmp+="["+value+"]"
    
    return tmp

def c_array(data, desc = None):
    if not type(data) == type(""):
        devlog("c_array() got %s and not string" % type(data))
        return "c_array() can not dump %s" % type(data)
    if not len(data):
        return "c_array() got void buffer"
    
    ucharbuf = "unsigned char buf[] = \""
    for uchar in data:
        ucharbuf += "\\x%02x" % ord(uchar)
    ucharbuf += "\"; // %d byte" % len(data)
    if len(data) > 1:
        ucharbuf += "s"
    if desc:
        ucharbuf += ", %s" % desc
    
    return ucharbuf 

def shellcode_dump(sc, align=0, alignpad="  ", alignmax=16, mode=None):
    import types
    assert type(align) == type(0), "error in arguments, expecting an int for 'align'"
    if not type(sc) in [types.StringType, types.BufferType]:
        devlog("shellcode_dump() got %s and not string" % type(sc))
        return type(sc)
    if not len(sc):
        return "void buffer"
    if mode and mode.upper() == "RISC":
        align=4
        alignmax=4
    if align:
        alignmax *= align
    buf = ""
    i = 0
    for c in sc:
        buf += "%02x " % ord(c)
        if align and (i % align) == (align - 1):
            buf += alignpad
        if alignmax and (i % alignmax) == (alignmax - 1):
            buf += "\n"
        i += 1
    if buf[-1] == "\n":
        buf = buf[:-1]
    return buf

def dummywrite(fd, data):
    """
    we just want to write some data on any fd, opened or closed.
    """
    import os
    try:
        os.write(fd, data)
    except OSError, errargs:
        import errno
        if errargs.errno != errno.EBADF:
            raise

def warnmsg(msg):
    sys.stderr.write("WARNING: %s\n" % msg)

#####################################################
#
#
#    return a binary representation of an integer
#
#
#####################################################

def binary_string_bits(bits, i):
    binstr = ""
    for bit in range(0, bits):
        if i & (long(1) << bit):
            binstr = "1" + binstr
        else:
            binstr = "0" + binstr
    return binstr

def binary_string_int8(int8):
    return binary_string_bits(8, int8)

def binary_string_int16(int16):
    return binary_string_bits(16, int16)

def binary_string_int32(int32):
    return binary_string_bits(32, int32)

def binary_string_int64(int64):
    return binary_string_bits(64, int64)

def binary_string_char(c):
    return binary_string_int8(c)

def binary_string_short(s):
    return binary_string_int16(s)

def binary_string_int(i):
    return binary_string_int32(i)

#####################################################
#
#
#        how to handle python fucking integers
#
#
#####################################################

def dInt(sint):
    """
    Turns sint into an int, hopefully
    python's int() doesn't handle negatives with base 0 well
    """
    if sint==None or type(sint) in [type( (1,1) ), type( [1]), type( {} ) ]:
        devlog("Type ERROR: dInt(%s)!"%str(sint))
        #should we call bugcheck here?
        raise TypeError, "type %s for dInt(%s)" % (type(sint), str(sint))

    s=str(sint)
    if s[0:2]=="0x":
        return long(s,0)
    else:
        #if you have long("5.0") it throws a horrible exception
        #so we convert to float and then back to long to avoid this
        return long(float(s))

def binary_from_string(astr,bits=None):
    """ returns [1,0,0,0,0,0,0,0] from "\x80"
    """
    if not bits:
        #print "Setting bits to 8*length"
        bits=len(astr)*8
    ret=[]
    
    for c in astr:
        #for each character
        mask=0x80
        for i in range(0,8):
            #for each bit in the character
            if mask & ord(c):
                bit=1
            else:
                bit=0
            ret+=[bit]
            if len(ret)==bits:
                break
            mask=mask >> 1
    return ret

def b(mystr):
    mydict={"1":1,"0":0}
    tmp=0
    for c in mystr:
        value=mydict[c]
        tmp=(tmp<<1)+value
    return tmp

# Note: this is a 5m lame function
def hexdump(buf):
    tbl=[]
    tmp=""
    hex=""
    i=0
    for a in buf:
        hex+="%02X "% ord(a)
        i+=1
        if ord(a) >=0x20 and ord(a) <0x7f:
            tmp+=a
        else:
            tmp+="."
        if i%16 == 0:
            tbl.append((hex, tmp))
            hex=""
            tmp=""
    tbl.append((hex, tmp))
    return tbl

def prettyhexprint(s,length=8):
    """
    A nicely displayed hexdump as a string
    """
    # we are expecting a string here
    if not type(s) == type(""):
        return "can not hexdump %s" % type(s)
    tmp=[]
    i=1
    for c in s:
        tmp+=["%2.2x "%ord(c)]
        if i%length==0:
            tmp+=["\n"]
        i+=1
    return "".join(tmp)

# generic functions for integers

def sint_is_signed(bits, c):
    return uint_bits(bits, c) >> (bits - 1)

def uint_bits(bits, c):
    # WARNING i dunno if dInt is safe here
    c=dInt(c)
    # [Python < 2.4] FutureWarning: x<<y losing bits or changing sign will return a long in Python 2.4 and up
    # [Python < 2.4] 1 << 32 = 0
    # so we force python < 2.4 to use a long.
    return c & ((long(1) << bits) - 1)

def sint_bits(bits, c):
    u = uint_bits(bits, c)
    if sint_is_signed(bits, c):
        return u - (long(1) << bits)
    else:
        return u

def fmt_bits(bits):
    n = 1 << 3
    while True:
        if bits <= n:
            break
        n <<= 1
    n /= 4
    return "0x%%0%dx" % n

# what do we expect if arg is None? (to track upper level bug/failure)
def uintfmt_bits(bits, c):
    # XXX assert c is not type number?
    #if c is None:
    #    return "None"
    return fmt_bits(bits) % uint_bits(bits, c)

def sintfmt_bits(bits, c):
    # XXX assert c is not type number?
    #if c is None:
    #    return "None"
    sign = ""
    if sint_is_signed(bits, c):
        sign = '-'
        c = abs(c)
    return sign + uintfmt_bits(bits, c)

def bits(myint, maxbits=32):
    """counts the number of bits in an integer the slow way"""
    b = 0
    myint = uint_bits(maxbits, myint)
    while myint >> b:
        b += 1
    return b

# a.k.a. MACROS for integers

def uint8(c):
    return uint_bits(8, c)

def uint16(c):
    return uint_bits(16, c)

def uint32(c):
    return uint_bits(32, c)

def uint64(c):
    return uint_bits(64, c)

def sint16(c):
    return sint_bits(16, c)

def sint32(c):
    return sint_bits(32, c)

def sint64(c):
    return sint_bits(64, c)

def uint8fmt(c):
    return uintfmt_bits(8, c)

def uint16fmt(c):
    return uintfmt_bits(16, c)

def uint32fmt(c):
    return uintfmt_bits(32, c)

def uint64fmt(c):
    return uintfmt_bits(64, c)

def sint16fmt(c):
    return sintfmt_bits(16, c)

def sint32fmt(c):
    return sintfmt_bits(32, c)

def sint64fmt(c):
    return sintfmt_bits(64, c)

def IsInt(str):
    """
    Checks for integer, hex or no
    """
    try:
        num = int(str,0)
        return 1
    except ValueError:
        return 0

#####################################################
#
#
#         old functions [ now deprecated ]
#
#
#####################################################

# <transition>

def signedshort(i):
    deprecate("use sint16() instead")
    return sint16(i)

def big2int(big):
    deprecate("use sint32() instead")
    return sint32(big)

def int2uns(small):
    assert sys.version_info[0] >= 2 and (sys.version_info[0] == 2 and sys.version_info[1] >= 4), \
        "\nyou tried to call int2uns() but your python %d.%d is too old to handle it correctly\n" \
        "Python versions before 2.4 are fucked up with integers, rely on 2.4 only!" % \
        (sys.version_info[0], sys.version_info[1])
    deprecate("use uint32() instead")
    return uint32(small)

def istr2halfword(astring):
    #deprecate("use str2int16_swapped() instead")
    return str2int16_swapped(astring)

def nstr2halfword(astring):
    #deprecate("use str2int16() instead")
    return str2int16(astring)

#def intel_str2int_old(astring):
#    if len(astring) < 4:
#        devlog("intel_str2int: astring=<%s> len=%d" % (astring, len(astring)))
#        raise AssertionError, "intel_str2int called with a less_than_4_chars string"
#    
#    (a,b,c,d)=(ord(astring[0]),ord(astring[1]),ord(astring[2]),ord(astring[3]))
#    #print "%x:%x:%x:%x"%(a,b,c,d)
#    result=a
#    result=result+b*256
#    result=result+c*65536
#    result=result+d*16777216
#    #change 2 int type, if long
#    result=uint32(result)
#    return result
#
def intel_str2int(astring):
    deprecate("use str2littleendian instead")
    return str2littleendian(astring)

#just a nice short wrapper
def istr2int(astring):
    #devlog("istr2int(%s)" % astring)
    return str2littleendian(astring)

#def halfword2istr(halfword):
#    data=""
#    a=halfword & 0xff
#    b=halfword/256 & 0xff
#    data+=chr(a)+chr(b)
#    return data
#
#def halfword2bstr(halfword):
#    data=""
#    a=halfword & 0xff
#    b=halfword/256 & 0xff
#    data+=chr(b)+chr(a)
#    return data
#
#def short2bigstr(short):
#    """
#    changes an int to a two byte big endian string
#    """
#    data=""
#    #short=uint16(short)
#    #print "short=%x /256=%x"%(short,short/256)
#    data+=chr(short / 256)
#    data+=chr(short & 0xff)
#    return data

"""
>>> print hexprint(halfword2bstr(0x1234))
[0x12][0x34]
>>> print hexprint(short2bigstr(0x1234))
[0x12][0x34]
>>> print hexprint("".join(int2list(uint16(0x1234))[2:4]))
[0x12][0x34]

>>> print hexprint(halfword2istr(0x1234))
[0x34][0x12]
>>> print hexprint("".join(int2list(byteswap_16(uint16(0x1234)))[2:4]))
[0x34][0x12]

>>> print uint16fmt(istr2halfword(halfword2bstr(dInt(0x1234))))
0x3412
>>> print uint16fmt(byteswap_16(0x1234))
0x3412

>>> print hexprint(halfword2bstr(0x1234))
[0x12][0x34]
>>> print hexprint(int2str_bits(16, 0x1234))
[0x12][0x34]
>>> print hexprint(halfword2bstr(0x12345678))
[0x56][0x78]
>>> print hexprint(int2str_bits(16, 0x12345678))
[0x56][0x78]
>>> print hexprint(int2str16(0x1234))
[0x12][0x34]
>>> print hexprint(int2str16(0x1234, swap=1))
[0x34][0x12]
>>> print hexprint(int2str16_swapped(0x1234))
[0x34][0x12]
"""

def halfword2istr(halfword):
    #deprecate("use int2str16_swapped instead")
    return int2str16_swapped(halfword)

def halfword2bstr(halfword):
    #deprecate("use int2str16 instead")
    return int2str16(halfword)

def short2bigstr(short):
    return halfword2bstr(short)

def intel_short(halfword):
    return halfword2istr(halfword)

def big_short(short):
    return short2bigstr(short)

#def big_order_old(myint):
#    """
#    Opposite of str2bigendian
#    """
#    str=""
#    a=chr(myint % 256)
#    myint=myint >> 8
#    b=chr(myint % 256)
#    myint=myint >> 8
#    c=chr(myint % 256)
#    myint=myint >> 8
#    d=chr(myint % 256)
#    
#    str+="%c%c%c%c" % (d,c,b,a)
#    return str

##int to intelordered string conversion
#def intel_order_old(myint):
#    #struct.pack is non-intuitive for non-python programers, which is why I do this sort of thing.
#    #it's for people who wish they were using perl, imo. <LH@$! :>
#    str=""
#    a=chr(myint % 256)
#    myint=myint >> 8
#    b=chr(myint % 256)
#    myint=myint >> 8
#    c=chr(myint % 256)
#    myint=myint >> 8
#    d=chr(myint % 256)
#    
#    str+="%c%c%c%c" % (a,b,c,d)
#    
#    return str

def big_order(int32):
    """
    Opposite of str2bigendian
    """
    #deprecated("use int2str32() instead")
    return int2str32(int32)

def intel_order(int32):
    """
    bijection of str2littleendian()
    """
    #deprecated("use int2str32_swapped() instead")
    return int2str32_swapped(int32)

#def binary_string_long(l):
#    return binary_string_int64(l)

#def print_binary_old(myint):
#    tmp=""
#    for i in range(0,32):
#        if (long(1)<<i) & myint:
#            tmp="1"+tmp
#        else:
#            tmp="0"+tmp
#    return tmp

def print_binary(int32):
    deprecate("use binary_string_int32 instead")
    return binary_string_int(int32)

def decimal2binary(num):
        if num == 0:
                return '0'*32
        if num < 0 :
                return ''
        ret=''
        # while num > 0:
        for a in range(0,32):
              ret = str(num&0x1) + ret
              num = num >> 1
              
        return ret

# </transition>

#####################################################
#
#
#                   test ...
#
#
#####################################################

if __name__=="__main__":

    warnings_safely_ignore(FutureWarning)
    
    def test(funcname):
        print "testing %s() ..." % funcname
    
    print "running tests..."
    
    test("split_int32")
    assert split_int32(0x12345678) == [0x12, 0x34, 0x56, 0x78]
    
    test("str2int16")
    assert str2int16('\x12\x34\x56') == 0x1234
    assert nstr2halfword('\x12\x34\x56\x78') == 0x1234 #DEPRECATED
    
    test("str2int16_swapped")
    assert str2int16_swapped('\x12\x34') == 0x3412
    assert istr2halfword('\x12\x34') == 0x3412 #DEPRECATED
    assert str2int16_swapped('\x12\x34\x56\x78') == 0x3412
    
    test("str2littleendian")
    assert str2littleendian('\x12\x34\x56\x78') == 0x78563412
    assert intel_str2int('\x12\x34\x56\x78') == 0x78563412 #DEPRECATED
    assert istr2int('\x12\x34\x56\x78') == 0x78563412 #DEPRECATED
    
    test("str2bigendian/str2int32")
    assert str2int32('\x12\x34\x56\x78') == 0x12345678
    assert str2bigendian('\x12\x34\x56\x78') == 0x12345678
    
    test("int2str16")
    assert int2str16(0x1234) == '\x12\x34'
    assert halfword2bstr(0x1234) == '\x12\x34' #DEPRECATED
    assert short2bigstr(0x1234) == '\x12\x34' #DEPRECATED
    assert big_short(0x1234) == '\x12\x34' #DEPRECATED
    
    test("int2str16_swapped")
    assert int2str16_swapped(0x1234) == '\x34\x12'
    assert halfword2istr(0x1234) == '\x34\x12' #DEPRECATED
    assert intel_short(0x1234) == '\x34\x12' #DEPRECATED
    assert intel_short(0x12345678) == '\x78\x56' #DEPRECATED
    
    test("int2str32")
    assert int2str32(0x12345678) == '\x12\x34\x56\x78'
    assert big_order(0x12345678) == '\x12\x34\x56\x78' #DEPRECATED
    
    test("int2str32_swapped")
    assert int2str32_swapped(0x12345678) == '\x78\x56\x34\x12'
    assert intel_order(0x12345678) == '\x78\x56\x34\x12' #DEPRECATED
    
    test("binary_string_int")
    assert print_binary(0x12345678) == '00010010001101000101011001111000'
    
    test("binary_string_int")
    assert binary_string_short(0x12345678) == '0101011001111000'
    
    try:
        assert int2uns(-1) == 0xffffffffL #DEPRECATED
    except AssertionError:
        print "[!] failed: int2uns(-1) == 0xffffffff"
        assert sys.version_info[0] >= 2, "word, what an old Python you have :/"
        if sys.version_info[0] == 2 and sys.version_info[1] < 4:
            print "Python 2.3 integers are fucked up, rely on 2.4 only!"
            print "your version can not handle int2uns() correctly"
            pass
        else:
            raise
    
    test("uint16")
    assert uint16(0xffff) == 0xffff
    assert uint16(0x12345678) == 0x5678
    
    test("sint16")
    assert sint16(0xffff) == -1
    assert sint16(0xffff) == sint16(-1)
    assert signedshort(0xffff) == -1 #DEPRECATED
    
    test("sint32")
    assert sint32(-1) == -1
    assert big2int(0x123456789) == 0x23456789 #DEPRECATED
    
    test("uintfmt_bits")
    assert uintfmt_bits(32, 0x12345678) == '0x12345678'
    assert uintfmt_bits(32, 0x1234) == '0x00001234'
    assert uintfmt_bits(24, 0x1234) == '0x00001234'
    assert uintfmt_bits(16, 0x1234) == '0x1234'
    
    test("uint16fmt")
    assert uint16fmt(0x123456) == '0x3456'
    assert uint16fmt(-0x123456) == '0xcbaa'
    
    test("uint32fmt")
    assert uint32fmt(0x1234) == '0x00001234'
    
    test("uint64fmt")
    assert uint64fmt(0x12345678) == '0x0000000012345678'
    assert uint64fmt(-1) == '0xffffffffffffffff'
    
    test("sint16fmt")
    assert sint16fmt(0x1234) == '0x1234'
    assert sint16fmt(-0x1234) == '-0x1234'
    assert sint16fmt(-0x12345678) == '-0x5678'
    # TODO check that
    #assert sint16fmt(0xffff) == '-0x0001'
    
    test("sint32fmt")
    assert sint32fmt(0x1234) == '0x00001234'
    assert sint32fmt(-0x1234) == '-0x00001234'
    
    test("sint64fmt")
    assert sint64fmt(-1) == '-0x0000000000000001'
    
    test("byteswap_32")
    assert byteswap_32(0x12345678) == 0x78563412
    
    test("byteswap_64")
    assert byteswap_64(0x1234567890123456) == 0x5634129078563412
    
    #print "0f=%s"%uint8fmt(0xf)
    assert uint8fmt(0x0f) == '0x0f'
    
    print "done."
