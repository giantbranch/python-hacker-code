#!/usr/bin/env python
"""
Immunity Discovery Data Type API for Immunity Debugger

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>} Discovery Data Type API for python



"""

__VERSION__ = '1.1'

import immutils
import struct

MEM      = 1
DWORD    = 2
MEM_ADDR = 3

INT     = 0
STRING  = 1
UNICODE = 2
POINTER = 3
DOUBLEL = 4

PLAINASCII  = 0x01
DIACRITICAL = 0x02
RAREASCII   = 0x10

ctable = [ 
  # 0x00.. 0x0F (TAB, Line feed, Carriage Return)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x13, 0x13, 0x00, 0x00, 0x13, 0x00, 0x00,
  # 0x10.. 0x1F
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  # 0x20.. 0x2F (space, punctuation, parentheses)
  0x03, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
  0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
  # 0x30.. 0x3F (digits, punctuation)
  0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
  0x03, 0x03, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
  # 0x40.. 0x4F (@, letters A..O)
  0x13, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
  0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
  # 0x50.. 0x5F (letters P..Z, brackets, delimiters)
  0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
  0x03, 0x03, 0x03, 0x13, 0x13, 0x13, 0x13, 0x13,
  # 0x60.. 0x6F (`, letters a..o)
  0x13, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
  0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
  # 0x70.. 0x7F (letters p..z, braces)
  0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
  0x03, 0x03, 0x03, 0x13, 0x13, 0x13, 0x13, 0x00,
  # 0x80.. 0x8F
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x02, 0x00, 0x02, 0x02, 0x02, 0x02,
  # 0x90.. 0x9F
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x02, 0x00, 0x02, 0x02, 0x02, 0x02,
  # 0xA0.. 0xAF
  0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02,
  0x00, 0x03, 0x02, 0x00, 0x00, 0x00, 0x03, 0x02,
  # 0xB0.. 0xBF
  0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00,
  0x00, 0x02, 0x02, 0x00, 0x02, 0x00, 0x02, 0x02,
  # 0xC0.. 0xCF (capital diacritical characters)
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
  # 0xD0.. 0xDF (capital diacritical characters)
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x00,
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
  # 0xE0.. 0xEF (small diacritical characters)
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
  # 0xF0.. 0xFF (small diacritical characters)
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x00,
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x00 ]

class Data:
    def __init__(self, type, address,  data = None, size = 0):
        """ Base Data Class """
        self.type = type
        self.size = size
        self.data = data
        self.address = address
        self.comment = '' # for the future
        self.name = 'Data'
        
    def setComment(self, comment):
        self.comment = comment
        
    def setData(self, data):
        self.data = data

    def Print(self):
        """
        Return information on the object
        
        @rtype:  STRING
        @return: Object information   
        """
        return str(self.data)
    
    def getSize(self):
        """
        Return object's size
        
        @rtype:  Integer
        @return: Object's Size
        """
        return self.size    

    def getAddress(self):
        """
        Return object's address
        
        @rtype:  Integer
        @return: Object's address
        """
        return self.address
    
class String(Data):
    def __init__(self, address, data):
        """ String Class """
        Data.__init__(self, STRING, address,  data, len(data) )
        self.name = 'String'
        
    def Print(self):
        if self.data[-1] == "\x00":
            return self.data[0:-1]
        else:
            return "'%s'" % self.data

class Unicode(Data):
    def __init__(self, address, data):
        """ Unicode Class """
        Data.__init__(self, UNICODE, address,  data, len(data)*2 )
        self.name = 'Unicode'
    def Print(self):
        if self.data[-1] == "\x00":
            return immutils.prettyhexprint( self.data[0:-1] )
        else:
            return "'%s'" % self.data
        
        
class DoubleLinkedList(Data):
    def __init__(self, address, data):
        """ Double Linked list Class """
        Data.__init__(self, DOUBLEL, address, data, 8)
        self.name = 'Double Linked List'

    def Print(self):
        return "( 0x%08x, 0x%08x )" % ( self.data[0], self.data[1] )

PTR          = 0
FUNCTION_PTR = 1
DATA_PTR     = 2
STACK_PTR    = 3

class Pointer(Data):
    def __init__(self, address, data):
        """ Pointer Class """
        Data.__init__(self, POINTER, address, data, 4 )
        self.mem = None
        self.name = 'Pointer'
        self.ptype = PTR
        
    def isFunctionPointer(self):
        return self.ptype == FUNCTION_PTR

    def isCommonPointer(self):
        return self.ptype == PTR

    def isDataPointer(self):
        return self.ptype == DATA_PTR

    def isStackPointer(self):
        return self.ptype == STACK_PTR
    
    def Print(self):
        mem = self.mem        

        if self.mem:
            return "0x%08x in %s|%s " % (self.data, self.mem.getOwner(), self.mem.section)         
        return "0x%08x" % self.data
    
    def setMemPage(self, mem):
        self.mem = mem

        if self.mem:
            
            if self.mem.section == ".text":
                self.ptype = FUNCTION_PTR                
                self.name  = 'Function Pointer:'
                
            elif self.mem.section == ".data":
                self.ptype = DATA_PTR
                self.name  = 'Data Pointer:'
                
        
class DataTypes:
    def __init__(self, imm):
        """
        Data Discovery Class

        @type  imm: Debugger Object
        @param imm: Initialized debugged object
        """

        self.MemPages  = imm.getMemoryPages()
        self.imm = imm
        
        self.AllFunctions = [(self.isDoubleLinkedList, MEM), (self.isString, MEM),\
                          (self.isUnicode, MEM), (self.isPointer, DWORD) ]
        self.DiscoverWhat = {'all': self.AllFunctions,\
                             'pointers': [ (self.isPointer, DWORD) ],\
                             'strings': [(self.isString, MEM), (self.isUnicode, MEM)],\
                             'asciistrings': [ (self.isString, MEM)],\
                             'unicodestrings': [ (self.isUnicode, MEM) ],\
                             'doublelinkedlists': [ (self.isDoubleLinkedList, MEM) ],\
                             'exploitable': [ (self.isPointer, DWORD), (self.isDoubleLinkedList, MEM) ]
                         }

    def Get(self, address, size, iterate = 4, what = 'all'):
        """ 
        Discover types on Memory Space
        
        @type  address: DWORD
        @param address: RVA of the memory to analize
        
        @type  size: DWORD
        @param size: Size of memory to analize

        @type  iterate: Integer
        @param iterate: (Optional, Def: 4) Iterate through given bytes

        @type  what: STRING
        @param what: (Optional, Def: ALL) What to search for: all, pointers, strings, asciistrings, unicodestrings, doublelinkedlists, exploitable

        @rtype: List of Discovered Object
        @return: A list of Discovered Objects
        """        

        mem = self.imm.readMemory( address, size )
        if not mem:
            return []
        return self.Discover( mem, address, iterate, what )	

    def Discover(self, mem, address, iterate = 4, what = 'all'):
        """ 
        Discover types on Memory Space
        
        @type  mem: Buffer
        @param mem: Memory to discover
        
        @type  address: DWORD
        @param address: RVA of the memory
        
        @type  iterate: Integer
        @param iterate: (Optional, Def: 4) Iterate through given bytes

        @type  what: STRING
        @param what: (Optional, Def: ALL) What to search for: all, pointers, strings, asciistrings, unicodestrings, doublelinkedlists, exploitable

        @rtype: List of Discovered Object
        @return: A list of Discovered Objects
        """        
        # Discover types on memory space
        ndx = 0
        discovered = []

        try:
            Functions = self.DiscoverWhat[ what.lower() ]
        except KeyError:
            return []
        
        while ndx < len(mem):
            obj = None
            #self.imm.Log("Discovering... 0x%02x" % ndx, address = address + ndx)
            for discover_func, tipo in Functions:

                if tipo == MEM:
                    obj = discover_func(address + ndx, mem[ndx: ] )

                elif tipo == DWORD:
                    if len( mem[ndx:ndx+4] ) >= 4:
                        dword = struct.unpack("L", mem[ ndx : ndx+4 ] )[0] 
                        obj = discover_func(address + ndx, dword )
                        
                if obj:
                    break
            if obj:                    
                discovered.append( obj )
                ndx += obj.getSize() # align this address by iterate
                # round by iterate
                if ndx % iterate:
                    ndx = iterate + ndx & ~(iterate-1)
                    
            else:
                ndx += iterate
                
        return discovered    
    
    def isUnicode(self, address, mem, max_size = 4*2):
        ret = []
        for a in range(0, len(mem), 2):
            ndx = struct.unpack("H", mem[ a: a + 2 ] )[0]
            if ndx & 0xFF00:
                return False
            
            if not (ctable[ ndx & 0x00FF ] & PLAINASCII):
                break
            ret.append( chr( ndx & 0x00FF ) )

        if a < max_size:
            return None
        
        if ndx == 0x0000:
            ret.append(" ")
            
        return Unicode(address, "".join(ret) )
        
    def isString(self, address, mem, max_size = 4):
        
        for a in range(0, len(mem)):
            ndx = ord( mem[ a ] )
            if not (ctable[ ndx ] & PLAINASCII):
                break
            #if ( ndx < 0x20 or ndx > 0x7e) and ndx not in (0x9, 0xa, 0xd):
            #    break
            
        if a < max_size:
            return None
        if ndx == 0x0:
            a+=1
        return String(address,  mem[0 : a] )
    

    def isPointer(self, address, dword):
        try:
            ret = self.imm.readLong(dword)
        except Exception:
            return None
        p = Pointer( address, dword )
        mem = self.imm.getMemoryPagebyAddress(dword)
        if mem:
            p.setMemPage( mem )
        return p    
    
    def isDoubleLinkedList(self, address, mem):
        if len(mem) < 8:
            return False
        ptr1 = immutils.str2littleendian( mem[0 : 4] )
        ptr2 = immutils.str2littleendian( mem[4 : 8] )
        try:
            ptr1_dword  = self.imm.readLong( ptr1 )                
            ptr1_dword2 = self.imm.readLong( ptr1 + 4 )                
            ptr2_dword  = self.imm.readLong( ptr2 )                
            ptr2_dword2 = self.imm.readLong( ptr2 + 4 )                
        except Exception:
            return False
        
        if (address == ptr1_dword or address == ptr1_dword2) and\
           (address == ptr2_dword or address == ptr2_dword2):
            dl = DoubleLinkedList ( address, (ptr1, ptr2) )
            return dl
        
        return False
    
    def isFormatString(self):
        pass
    
    
            
if __name__ == '__main__':
    d = DataTypes()
    assert(d.isString("ho\nA\x01") == True)
    assert(d.isString("\x01COCA")  == False)

