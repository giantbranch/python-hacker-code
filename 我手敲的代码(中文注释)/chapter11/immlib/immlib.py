#!/usr/bin/env python
"""
    Immunity Debugger API for python

    (c) Immunity, Inc. 2004-2007


    U{Immunity Inc.<http://www.immunityinc.com>} Debugger API for python


    """

__VERSION__ = '1.3'


import debugger
import immutils
import string
import time
import struct
import pickle
import cPickle
import libheap

from libhook    import *
from libevent   import *
from debugtypes import *
from libanalize import *
from librecognition import FunctionRecognition


# CONSTANT
BpKeys        =  {"VK_F2": 0x71, "VK_F4" : 0x73}
BpFlags       = {"TY_STOPAN": 0x80L, "TY_SET": 0x100L, "TY_ACTIVE": 0x200L, "TY_DISABLED":0x400,\
                 "TY_ONESHOT": 0x800L, "TY_TEMP":0x1000L, "TY_KEEPCODE":0x2000L, "TY_KEEPCOND": 0x4000L,\
                 "TY_NOUPDATE":0x8000, "TY_RTRACE": 0x10000}

# Hardware breakpoint type flags

HB_FREE=0      # Breakpoint is not used
HB_CODE=1      # Active on command execution
HB_ACCESS=2    # Active on read/write access
HB_WRITE=3     # Active on write access
HB_IO=4        # Active on port I/O
HB_ONESHOT=5   # One-shot on command execution
HB_STOPAN=6    # One-shot on command and stop
HB_TEMP=7      # Temporary on command execution

DebugerStatus = { "NONE":0, "STOPPED":1, "EVENT":2, "RUNNING": 3, "FINISHED":4, "CLOSING":5 }

Register      = { "EAX" : 0 , "ECX" : 1, "EDX": 2, "EBX": 3, "ESP": 4, "EBP": 5, "ESI": 6, "EDI": 7, "EIP":8}

PageFlags     = {0x1 : "   ",0x2: "R  ", 0x4:"RW ", 0x8: "RW  COW", 0x10: "  E",\
                 0x20: "R E", 0x40: "RWE", 0x80: "RWE  COW"}

ImmFonts      =   {"fixed": 0, "terminal6": 1, "fixedsys":2, "courier":3, "lucida":4, "font5": 5,\
                   "font6": 6, "font7":7, "main": 8, "sys": 9, "info": 10}



BpMemFlags    = {"R": 0x1, "W":0x2, "S":0x1000L}

MemoryProtection = { "PAGE_EXECUTE" :0x10, "PAGE_EXECUTE_READ" :0x20 , "PAGE_EXECUTE_READWRITE": 0x40,\
                     "PAGE_EXECUTE_WRITECOPY":0x80,  "PAGE_NOACCESS":0x01, "PAGE_READONLY":0x02,\
                     "PAGE_READWRITE":0x04, "PAGE_WRITECOPY": 0x08 }



IgnoreSingleStep = {"DISABLE" : 0 , "FORCE" : 1 , "CONTINUE" : 2}



#define JT_JUMP        0               // Unconditional jump
#define JT_COND        1               // Conditional jump
#define JT_SWITCH      2               // Jump via switch table
#define JT_CALL        3               // Local (intramodular) call
#define CALL_INTER     4               // intermodular call
jmpTypeFlags = {"JUMP":0,\
                "JUMP_COND":1,\
                "JUMP_SWITCH":2,\
                "CALL":3,\
                "CALL_INTER":4}


NM_NONAME=0x00            # Undefined name
NM_MODSEARCH=0xFD
NM_ANYNAME=0xFF           # Name of any type
#Names saved in the data file of module they appear.
NM_PLUGCMD=0x30           # Plugin commands to execute at break
NM_LABEL=0x31             # User-defined label
NM_EXPORT=0x32            # Exported (global) name
NM_IMPORT=0x33            # Imported name
NM_LIBRARY=0x34           # Name from library or object file
NM_CONST=0x35             # User-defined constant
NM_COMMENT=0x36           # User-defined comment
NM_LIBCOMM=0x37           # Comment from library or object file
NM_BREAK=0x38             # Condition related with breakpoint
NM_ARG=0x39               # Arguments decoded by analyzer
NM_ANALYSE=0x3A           # Comment added by analyzer
NM_BREAKEXPR=0x3B         # Expression related with breakpoint
NM_BREAKEXPL=0x3C         # Explanation related with breakpoint
NM_ASSUME=0x3D            # Assume function with known arguments
NM_STRUCT=0x3E            # Code structure decoded by analyzer
NM_CASE=0x3F              # Case description decoded by analyzer
#Names saved in the data file of main module.
NM_INSPECT=0x40           # Several last inspect expressions
NM_WATCH=0x41             # Watch expressions
NM_ASM=0x42               # Several last assembled strings
NM_FINDASM=0x43           # Several last find assembler strings
NM_LASTWATCH=0x48         # Several last watch expressions
NM_SOURCE=0x49            # Several last source search strings
NM_REFTXT=0x4A            # Several last ref text search strings
NM_GOTO=0x4B              # Several last expressions to follow
NM_GOTODUMP=0x4C          # Several expressions to follow in Dump
NM_TRPAUSE=0x4D           # Several expressions to pause trace
#Names saved in the data file of debugged DLL.
NM_DLLPARMS=0x50          # (10 parms + 6 regs) x 10-line history
#Names that are not saved in the data file.
NM_DEBUG=0x80             # Names from debug data
NM_IMPLIB=0x81            # Names of import library files
NM_IMPNAME=0x82           # Names of import library entries
NM_FONT=0x83              # Names of fonts
NM_SCHEME=0x84            # Names of colour schemes
NM_GOTOSTACK=0x85         # Several expressions to follow in Stack
NM_HILITE=0x86            # Names of highlighting schemes
#Pseudonames.
NM_IMCALL=0xFE            # Intermodular call


import UserDict

# Dict that returns classess
class DictTypes(UserDict.IterableUserDict):
    def __init__(self):
        UserDict.IterableUserDict.__init__(self)
    def __iter__(self):
        for k in self.data.keys():
            yield self.data[k]


ImmDrawColors = {"Black":0,"Maroon":128,"Green":32768,"Olive":32896,"Navy":8388608,"Purple":8388736,"Teal":8421376,\
                 "Gray":8421504,"Silver":12632256,"Red":255,"Lime":65280,"Yellow":65535,"Blue":16711680,"Fuchsia":16711935,\
                 "Aqua":16776960,"LightGray":12632256,"DarkGray":8421504,"White":16777215,"MoneyGreen":12639424,\
                 "SkyBlue":15780518,"Cream":15793151,"MedGray":10789024,"red":255,"darkgreen":32768}

###########################    
###########################
### Debugger main class ###
###########################
###########################
class Debugger:
    def __init__(self):
        """ Initialize the Immunity Debugger API"""
        self.threadid  = 0
        os             = self.getOsInformation()
        self.ossystem  = os[ 0 ].lower()
        self.osversion = os[ 1 ].lower()
        self.osrelease = os[ 2 ].lower()

        # we want to distinguish Vista over other Windows.
        self.isVista = self.getOsRelease()[0] == '6'

        self.Eventndx  = { debugger.CREATE_PROCESS_DEBUG_EVENT : CreateProcessEvent,
                           debugger.CREATE_THREAD_DEBUG_EVENT  : CreateThreadEvent,
                           debugger.EXCEPTION_DEBUG_EVENT      : ExceptionEvent,
                           debugger.EXIT_PROCESS_DEBUG_EVENT   : ExitProcessEvent,
                           debugger.EXIT_THREAD_DEBUG_EVENT    : ExitThreadEvent,
                           debugger.LOAD_DLL_DEBUG_EVENT       : LoadDLLEvent,
                           debugger.OUTPUT_DEBUG_STRING_EVENT  : OutputDebugEvent,
                           debugger.UNLOAD_DLL_DEBUG_EVENT     : UnloadDLLEvent,
                           debugger.RIP_EVENT                  : RIPEvent }

        self.clearState()

    def clearState(self):
        self.Symbols = DictTypes()
        self.Handles = DictTypes()
        self.Threads = DictTypes()
        self.MemoryPages = DictTypes()
        self.Modules = DictTypes()
        self.BackTrace = []
        self.HeapsAddr = []
        self.Heaps = {}


    ### Get the ultimate solution ###
    def getShellcodeExecutionNoMatterWhat(self):
        return self.Error("%d" % (0x15 * 2))


    ### Immunity Debugger Knowledge ###
    #  Sharing information between scripts

    def addKnowledge(self, id, object, force_add = 0x0):
        """
            This function add a python object to the knowledge database.

            @type  id: STRING
            @param id: unique name tag of the object

            @type  object: Python object
            @param object: Object to be saved in the knowledge database
            """

        pickled_object=pickle.dumps(object)
        return debugger.AddKnowledge(pickled_object,id, force_add)

    def getKnowledge(self,id):
        """
            Gets python object from the knowledge database.

            @type  id: STRING
            @param id: unique name tag of the object

            @rtype:  PYTHON OBJECT
            @return: Object retrieved from the knowledge database
            """
        pickled_object=debugger.GetKnowledge(id)
        #try:
        if not pickled_object:
            return None
        return pickle.loads(pickled_object)

    def listKnowledge(self):
        """
            Gets the list of saved objects in the knowledge database.

            @rtype: TUPLE
            @return: List of String ids currently saved
            """
        return debugger.ListKnowledge()

    def findPacker(self, name, OnMemory = True):
        """ 
            Find possible Packer/Cryptors/etc on a Module

            @type name: STRING
            @param name: Module name

            @type  OnMemory: (Optional, Def: True) BOOLEAN
            @param OnMemory: Whether to look in memory or on a file.

            @rtype:  LIST of TUPLES in the form of (DWORD, LIST OF STRING)
            @return: A list of the Packer founded (Offset, List of Packer found in that address)
            """
        if OnMemory:
            mem = self.getMemoryPagebyOwner(name)
            if not mem:
                raise Exception, "Coudln't find a Memory Page belonging to %s" % name
            data = ""
            for a in mem:
                data+= a.getMemory()
        else:
            mod = self.getModule( name )
            if not mod:
                raise Exception, "Coudln't find the correct Module belonging to %s" % name
            data = mod.getPath()    

        import pefile
        import peutils
        if OnMemory:
            pe = pefile.PE( data = data )
        else:
            pe = pefile.PE( name = data )

        sig_db = peutils.SignatureDatabase('Data/UserDB.TXT')
        return sig_db.match( pe )

    def forgetKnowledge(self,id):
        """
            Remove python object from knowledge database.

            @type  id: STRING
            @param id: unique name tag of the object
            """
        return debugger.ForgetKnowledge(id)

    def cleanKnowledge(self):
        """ Clean ID memory from known objects
            """
        for ke in  self.listKnowledge():
            self.forgetKnowledge(ke)


    def addGenHook(self,object):
        """
            Add a hook to Immunity Debugger
            """

        import pickle
        try:
            rtype=object.type
        except:
            rtype=0
        try:
            label=object.label
        except:
            label="No Label specified for this hook"
        pickled_object=pickle.dumps(object)
        debugger.Addhook(pickled_object,label,rtype)


    def cleanHooks(self):
        """
            Clean ID memory from hook objects
            """
        for hk in self.listHooks():
            debugger.Removehook(hk)



    def cleanUP(self):
        """
            Clean ID memory for every kind of object saved in it
            """
        self.cleanHooks()
        self.cleanKnowledge()


    def getPEBaddress(self):
        """
            Gets PEB.
            @rtype:  DWORD
            @return: PEB address
            """
        return debugger.GetPEB()



    ### Disassembling / Analyzing Functions / etc ###

    def analyseCode(self,address):
        """
            Analyse module's code

            @type  Address: DWORD
            @param Address: Address from module to be analysed 
            """
        debugger.Analysecode(address)

    def isAnalysed(self,address):
        """
            Check if module is already analysed

            @type  Address: DWORD
            @param Address: Address from module

            @rtype: DWORD
            @return: 1 if module already analysed        
            """
        ret = debugger.IsAnalysed(address)

        if ret == -1:
            return 0
        else:
            return ret


    # Disasm tooks 0.00008130 usec/pass
    def Disasm(self, address, mode = DISASM_ALL):
        """
            Disasm address

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  Mode: (Optional, Def: DISASM_ALL)
            @param Mode: Disasm mode

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode
            """

        op= opCode( self, address )
        op._getfromtuple( debugger.Disasm( address, mode) )
        return op

        # Disasm tooks 0.00008130 usec/pass

    def disasm(self, address, mode = DISASM_ALL):
        return self.Disasm(address)


    # DisasmSize 0.00007515 usec/pass
    def disasmSizeOnly(self, address):
        """
            Determine command size only 

            @type  Address: DWORD
            @param Address: Address to disasm

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode
            """
        return self.Disasm(address, DISASM_SIZE)

    # DisasmData 0.00007375 usec/pass
    def disasmData(self, address):
        """ 
            Determine size and analysis data 

            @type  Address: DWORD
            @param Address: Address to disasm

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode        
            """
        return self.Disasm(address, DISASM_DATA)

    def disasmTrace(self, address):
        """ 
            Trace integer registers 

            @type  Address: DWORD
            @param Address: Address to disasm

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode        
            """
        return self.Disasm(address, DISASM_TRACE)

    # DisasmFile 0.00007934 usec/pass
    def disasmFile(self, address):
        """ 
            Disassembly, no symbols/registers 

            @type  Address: DWORD
            @param Address: Address to disasm

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode
            """
        return self.Disasm(address, DISASM_FILE)

    # DisasmCode 0.00008549 usec/pass
    def disasmCode(self, address):
        """ 
            Disassembly, registers undefined 

            @type  Address: DWORD
            @param Address: Address to disasm

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode        
            """
        return self.Disasm(address, DISASM_CODE)

    def disasmRTrace(self, address):
        """ 
            Disassemble with run-trace registers  

            @type  Address: DWORD
            @param Address: Address to disasm

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode        
            """
        return self.Disasm(address, DISASM_RTRACE)


    def disasmForward( self, address, nlines=1, mode = DISASM_ALL):
        """
            Disasm nlines forward of given address

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @type  Mode: (Optional, Def: DISASM_ALL)
            @param Mode: Disasm mode

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode
            """
        forward_address = debugger.Disasmforward( address, nlines )
        op=opCode( self, forward_address )
        op._getfromtuple( debugger.Disasm( forward_address, mode ) )
        return op



    def disasmForwardAddressOnly(self, address, nlines=1):
        """
            Disasm nlines forward to the given address

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @type  Mode: (Optional, Def: DISASM_ALL)
            @param Mode: Disasm mode

            @rtype:  DWORD
            @return: Address of the opcode
            """
        return debugger.Disasmforward(address,nlines)

    def disasmForwardSizeOnly(self, address, nlines=1):
        """
            Determine command size only 

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode
            """
        return self.disasmForward(address, nlines, DISASM_SIZE)

    def disasmForwardData(self, address, nlines=1):
        """ 
            Determine size and analysis data 

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode

            """
        return self.disasmForward(address, nlines, DISASM_DATA)

    def disasmForwardTrace(self, address, nlines=1):
        """ 
            Trace integer registers 

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode        
            """
        return self.disasmForward(address, nlines, DISASM_TRACE)

    def disasmForwardFile(self, address, nlines=1):
        """ 
            Disassembly, no symbols/registers 

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode        
            """
        return self.disasmForward(address, nlines, DISASM_FILE)

    def disasmForwardCode(self, address, nlines=1):
        """ 
            Disassembly, registers undefined 

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode        
            """
        return self.disasmForward(address, DISASM_CODE)

    def disasmForwardRTrace(self, address, nlines=1):
        """ 
            Disassemble with run-trace registers 

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode        
            """
        return self.disasmForward(address, nlines, DISASM_RTRACE)

    def disasmBackward( self, address, nlines = 1, mode = DISASM_ALL):
        """
            Disasm nlines backward from the given address

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode
            """
        backward_address = debugger.Disasmbackward( address, nlines )
        op = opCode( self, backward_address )
        op._getfromtuple( debugger.Disasm( backward_address, mode ) )
        return op

    def disasmBackwardAddressOnly(self,address,nlines=1):
        """
            Disasm nlines backward of given address

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  DWORD
            @return: Address of the Opcode"""
        return debugger.Disasmbackward(address,nlines)



    def disasmBackwardSizeOnly(self, address, nlines = 1):
        """
            Determine command size only 

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode                
            """
        return self.disasmBackward(address, nlines, DISASM_SIZE)

    def disasmBackwardData(self, address, nlines = 1):
        """ 
            Determine size and analysis data 

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode                
            """
        return self.disasmBackward(address, nlines, DISASM_DATA)

    def disasmBackwardTrace(self, address, nlines = 1):
        """ 
            Trace integer registers 

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode                
            """
        return self.disasmBackward(address, nlines, DISASM_TRACE)

    def disasmBackwardFile(self, address, nlines = 1):
        """ 
            Disassembly, no symbols/registers 

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode                
            """
        return self.disasmBackward(address, nlines, DISASM_FILE)

    def disasmBackwardCode(self, address, nlines = 1):
        """ 
            Disassembly, registers undefined 

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode                
            """
        return self.disasmBackward(address, nlines, DISASM_CODE)

    def disasmBackwardRTrace(self, address, nlines = 1):
        """ 
            Disassemble with run-trace registers  

            @type  Address: DWORD
            @param Address: Address to disasm

            @type  nlines: DWORD
            @param nlines: (Optional, Def: 1) Number of lines to disassemble forward

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode                
            """
        return self.disasmBackward(address, nlines, DISASM_RTRACE)

    def findDecode(self, address):
        """ 
            Get the internal decode information from an analysed module

            @type  Address: DWORD
            @param Address: Address in the range of the module page

            @rtype:  Decode OBJECT 
            @return: Decode Object containing the analized information
            """
        return  Decode( address )
        #return debugger.FindDecode( address )

    def goNextProcedure(self):
        """
            Go to next procedure

            @rtype: DWORD
            @return: Address of next procedure
            """
        return debugger.GoNextProcedure()

    def goPreviousProcedure(self):
        """
            Go to previous procedure

            @rtype:  DWORD
            @return: Address of previous procedure
            """
        return debugger.GoPreviousProcedure()

    def getOpcode(self,address):
        """
            Get address's Opcode

            @type  Address: DWORD
            @param Address: Address to disasm

            @rtype:  opCode Object (Check libanalize.py)
            @return: Disassmbled Opcode                
            """
        op=opCode(self, address)
        op._getfromtuple(debugger.Disasm(address))
        return op

    def Assemble(self, code,address=0x0):
        """
            Assemble code.

            @type  code: STRING
            @param code: Code to be assembled

            @rtype:  STRING
            @return: Opcodes of the assembled code
            """
        opcode = []
        for line in code.split("\n"):
            line = line.strip()
            if line:
                opcode.append( debugger.Assemble(line,address) )
        return string.joinfields( opcode, "")

    def decodeAddress(self,address):
        """
            Decode given address

            @rtype: STRING
            @return: decoded value        
            """
        return debugger.DecodeAddress(address)

    def undecorateName(self,decorated):
        """
            Undecorate given name

            @type decorated: STRING
            @param decorated: decorated name
            @rtype: STRING
            @return: undecorated name
            """
        return debugger.UndecorateName(decorated)

    def getTraceArgs(self, address, tracedarg, shownonusersupplied = False):
        """
            Trace Parameters of a function, return only when is user-supplied

            @type  Address: DWORD
            @param Address: Address of the function call

            @type  Tracedarg: DWORD
            @param Tracedarg: Parameter to trace

            @type  Shownonusersupplied: BOOLEAN
            @param Shownonusersupplied: (Optional, Def: False) Flag whether or not show user supplied param

            @rtype: TUPLES 
            @return: Returns a tuple of (Push Opcode, TABLE of OPCODES setting the PUSH)
            """
        t = TraceArgs( self, address, tracedarg, shownonusersupplied )
        return t.get()

    def getAllFunctions(self,address):
        """
            Gets all function of given module's address

            @rtype: LIST
            @return: Function start address
            """
        return debugger.Getallfunctions(address)

    def getFunction(self, address):
        """
            Get the Function information

            @type  Address: DWORD
            @param Address: Address of the function

            @rtype:  Function Object
            @return: Function Object containing information of the requested function

            """
        return Function(self, address)

    def getFunctionBegin(self,address):
        """ 
            Find start address of funcion

            @rtype:  DWORD
            @return: Start Address"""
        return debugger.Getfuncbegin(address)

    def getFunctionEnd(self, function_address):
        """
            Get all the possible ends of a Function
            
            @type  function_address: DWORD
            @param function_address: Address of the function
        
            @rtype:  LIST
            @return: List of Address of all the possible ret address
        """
        if type(function_address) in (type(1), type(1L)):
            func = self.getFunction( function_address )
            return func.getFunctionEnd()
        elif isinstance(function_address, Function):
            return function_address.getFunctionEnd()
        else:
            raise Exception, "Function type not recognized"
    
    #def getFunctionEnd(self,address):
        #""" 
            #Find end address of funcion (Deprecated, use Function)

            #@rtype: DWORD
            #@return: End address
            #"""
        #return debugger.Getfuncend(address)

    def getAllBasicBlocks(self,address):
        """
            Gets all basic blocks of given procedure (Deprecated, use Function)

            @rtype: LIST
            @return: (start,end) addresses of basic blocks
            """
        bblocks = debugger.Getallbasicblocks(address)
        basicblocks = []
        if bblocks:
            for block in bblocks:
                basicblocks.append(basicBlock(self,block[0],block[1]))
        return basicblocks

    def findDataRef(self,address):
        """
            Find data references to given address

            @rtype:  LIST
            @return: Table with found references
            """
        return debugger.FindDataRef(address)

    def getXrefFrom(self, address):
        """
            Get X Reference from a given address

            @type  Address: DWORD
            @param Address: Address

            @rtype:  LIST
            @return: List of X reference from the given address 
            """
        for mod in self.getAllModules():
            xref = mod.getXrefFrom(address)

            if xref: return xref
        return []

    def getXrefTo(self, address):
        """
            Get X Reference to a given address

            @type  Address: DWORD
            @param Address: Address

            @rtype:  LIST
            @return: List of X reference to the given address 
            """
        for mod in self.getAllModules():
            xref = mod.getXrefTo(address)

            if xref: return xref
        return []

    def getInterCalls(self,address):
        """
            Get intermodular calls

            @type  Address: DWORD
            @param Address: Address

            @rtype: DICTIONARY
            @return: Dict of intermodular calls to the given address
            """
        self.gotoDisasmWindow(address)
        return debugger.GetInterCalls(address)


    ### Gathering Information for the debugged process ###
    # All kind of information that can be gathered for the process (PEB, Heap, Events, Modules, etc)

    def getRegs(self):
        """
            Get CPU Context values.

            @rtype:  DICTIONARY
            @return: x86 Registers
            """
        return debugger.Getregs()

    def getRegsRepr(self):
        """
            We have to do this to handle the Long integers, which XML-RPC cannot do	

            @rtype: DICTIONARY
            @return: x86 registers in string format (repr)
            """
        regs=self.getRegs()

        for r in regs:
            regs[r]=repr(regs[r])
        return regs

    def setReg(self,reg,value):
        """
            Set REG value

            @type  reg: STRING
            @param reg: Register name

            @type  value: DWORD
            @param vale: Value to set the register
            """
        return debugger.Setreg(Register[reg],value)

    def getPEB(self):
        """
            Get the PEB information of the debugged process

            @rtype:  PEB OBJECT
            @return: PEB """

        return PEB(self)


    def getHeap(self, addr, restore = False):
        """
            Get Heap Information

            @type  addr: DWORD
            @param addr: Address of the heap

            @type  restore: BOOLEAN
            @param restore: (Optional, Def: False) Flag whether or not use a restore heap 

            @rtype: PHeap OBJECT
            @return: Heap
            """
        if self.Heaps.has_key(addr):
            return self.Heaps[addr]

        if self.isVista:
            pheap = libheap.VistaPHeap( self, addr, restore )
        else:
            pheap = libheap.PHeap( self, addr, restore )

        if pheap:
            self.Heaps[addr] = pheap
        return pheap

    def getDebuggedName(self):
        """
            Get debugged name

            @rtype:  STRING
            @return: Name of the Process been debugged
            """
        return debugger.getDebuggedName()

    def getDebuggedPid(self):
        """
            Get debugged pid

            @rtype:  DWORD
            @return: Process ID
            """
        return debugger.getPID()
    
    def isAdmin(self):
        """
        Is debugger running as admin?
        @rtype: INTEGER
        @return: 1 if running as admin
        """
        return debugger.IsAdmin()

    def getInfoPanel(self):
        """
            Get information displayed on Info Panel

            @rtype: TUPLE
            @return: Python Tuple with the 3 lines from InfoPanel
            """
        return debugger.Getinfopanel()

    def getCurrentAddress(self):
        """
            Get the current address been focus on the Disasm window

            @rtype:  DWORD
            @return: Address
            """
        return debugger.GetCurrentAddress()


    def getAllModules(self):
        """
            Get all loaded modules.

            @rtype:  DICTIONARY
            @return: Dict of Modules
            """

        if self.Modules:
            return self.Modules

        modulos = debugger.Getallmodules()
        symbol = 1
        for mod in modulos.keys():
            if not self.Modules.has_key(mod):
                # Modules are stable
                m = Module(mod, modulos[mod][0], modulos[mod][1], modulos[mod][2])
                mod_dict = self._getmoduleinfo(modulos[mod][0])
                m.setModuleExtension(mod_dict)
                if symbol:
                    self.getAllSymbols() #_getsymbols()
                    symbol = 0

                try:
                    m.setSymbols( self.Symbols[ mod.lower() ] ) 
                except KeyError:
                    pass
                self.Modules[mod] = m
        # XXX TODO: Here we must check between the modules that are loaded and the catched one on self.Modules
        #            so we know if a module is not there anymore

        return self.Modules

    def getModulebyAddress(self, address):

        modulos = debugger.Getallmodules()

        for name in modulos.keys():
            total_range = modulos[name][0] + modulos[name][1]
            if address > modulos[name][0] and address < total_range:
                if not self.Modules.has_key(name):
                    m = Module(name, modulos[name][0], modulos[name][1], modulos[name][2])
                    mod_dict = self._getmoduleinfo(modulos[name][0])
                    m.setModuleExtension(mod_dict)
                    self.Modules[name] = m
                    return m
                else:
                    return self.Modules[name]

    def getModule(self, name):
        """
            Get Module Information

            @type  name: STRING
            @param name: Name of the module

            @rtype:  Module OBJECT
            @return: A Module object
            """

        #self.getAllModules()

        modulos = debugger.Getallmodules()
        if modulos.has_key(name):
            if not self.Modules.has_key(name):
                # Modules are stable
                m = Module(name, modulos[name][0], modulos[name][1], modulos[name][2])
                mod_dict = self._getmoduleinfo(modulos[name][0])
                m.setModuleExtension(mod_dict)
                #if symbol:
                #    self.getAllSymbols() #_getsymbols()
                #    symbol = 0

                #try:
                #    m.setSymbols( self.Symbols[ mod.lower() ] ) 
                #except KeyError:
                #    pass
                self.Modules[name] = m
                return m
            else:
                return self.Modules[name]

        #if type(name) == type(''):
        #    try:
        #        return self.Modules[ name ]
        #    except KeyError:
        #        return None
        #else:
        #    for mod in self.Modules.keys():
        #        if self.Modules[ mod ].baseaddress == name:
        #            return self.Modules[ mod ]
        return None

    def _getmoduleinfo(self,base_address):
        return debugger.Getmodinfo(base_address)

    def getReferencedStrings(self,code_base):
        """
            Get all referenced string from module

            @type  name: DWORD
            @param name: Code Base Address
            @rtype: LIST
            @return: A list of tuples with referenced strings (address, string, comment)
            """
        return debugger.Getreferencedstrings(code_base)

    def Ps(self):
        """
            List all active processes.

            @rtype:  LIST
            @return: A list of tuples with process information (pid, name, path, services, tcp list, udp list)
            """
        return debugger.ps()        

    def ps(self):
        """
            List all active processes.

            @rtype:  LIST
            @return: A list of tuples with process information (pid, name, path, services, tcp list, udp list)
            """
        return self.Ps()

    def getSehChain(self):
        """
            Get the SEH chain.

            @rtype:  LIST
            @return: A list of tuples with SEH information (seh, handler)
            """
        return debugger.Getsehchain()

    def getEvent(self):
        """
            Get the current Event

            @rtype:  Event Object
            @return: Event
            """
        event = debugger.Getevent()
        EventCode = event[0][0]
        try:
            return self.Eventndx[ EventCode ]( event )
        except KeyError: # We cannot handle this event
            return None

    def getPage(self, addr):
        """
            Get a memory page.

            @type  addr: DWORD
            @param addr: Address of a beginning of the Page

            @rtype:  Page OBJECT
            @return: Memory Page
            """
        self.getMemoryPages()
        try:
            return self.MemoryPages[addr]
        except KeyError:
            return None

    def getMemoryPagebyOwner(self, owner):
        """
            Get the Memory Pages belonging to the given dll.

            @type  owner: STRING
            @param owner: Name of the dll

            @rtype:  LIST
            @return: LIST of Memory Pages belonging to the given dll
            """
        self.getMemoryPages()

        pages = []
        for a in self.MemoryPages.keys():
            mem = self.MemoryPages[a]
            if mem.getOwner() == owner:
                pages.append( mem )

        return pages

    def getMemoryPagebyAddress(self, address):
        """
            Get a memory page.

            @type  address: DWORD
            @param address: Address in the range of the Page

            @rtype:  Page OBJECT
            @return: Memory Page
            """

        self.getMemoryPages() 
        for a in self.MemoryPages.keys():
            mem = self.MemoryPages[a]
            if mem.baseaddress <= address and (mem.getBaseAddress() + mem.size) > address :
                return mem            
        return None

    def getMemoryPages(self):
        """
            Get All memory pages. 

            @rtype:  DICTIONARY
            @return: List of all memory pages
            """
        if self.MemoryPages:
            return self.MemoryPages

        pages = debugger.Getmemorypages()

        for addr in pages.keys():
            m = MemoryPage(addr, self)
            m._getfromtuple(pages[addr])
            self.MemoryPages[addr]  = m
        return self.MemoryPages

    def vmQuery(self,address):
        """
            Query Memory Page

            @type  address: DWORD
            @param address: Base Address of memory page

            @rtype:  Python List
            @return: List with memory page structure
            """
        return debugger.VmQuery(address)


    def getAllHandles(self):
        """
            Get all handles.

            @rtype:  DICTIONARY
            @return: All the process handles
            """
        if self.Handles:
            return self.Handles

        handles = debugger.Getallhandles()
        for h in handles.keys():
            H = Handle( h )
            H._getfromtuple( handles[h] )
            self.Handles[ h ] = H
        return self.Handles

    def getAllThreads(self):
        """
            Get all threads.
            @rtype: LIST
            @return: All process threads
            """
        threads = debugger.Getallthreads()
        for thread in threads:
            T = Thread(thread)
            T._getfromtuple(thread)
            self.Threads[T.getId()] = T
        return self.Threads




    def getAllSymbols(self):
        """
            Get All Symbols.

            @rtype:  DICTIONARY
            @return: All the symbols of the process
            """
        if self.Symbols:
            return self.Symbols

        names = debugger.Getallnames()
        # reorder it a little bit
        for a in names.keys():
            s=Symbol(a)
            s._getfromtuple( names[a] )

            module = s.getModule() + ".dll"

            if self.Symbols.has_key( module ):
                self.Symbols[ module ][ a ] = s
            else:
                self.Symbols[ module ] = { a : s } 

        return self.Symbols


    def callStack(self):
        """
            Get a Back Trace (Call stack).

            @rtype:  LIST of Stack OBJECT
            @return: list of all the stack trace
            """
        if self.BackTrace:
            return self.BackTrace

        callstack = debugger.Getcallstack()
        for a in callstack:
            s = Stack()
            s._setfromtuple(a)
            self.BackTrace.append(s)
        return self.BackTrace

    def getCallTree(self,address=0):
        """ 
            Get the call tree of given address.
            @rtype: LIST of Call tuples
            @return: list of all the call tree
            ulong          line;                 // Line number in column
            ulong          dummy;                // Must be 1
            ulong          type;                 // Type, set of TY_xxx
            ulong          entry;                // Address of function
            ulong          from;                 // Address of calling instruction
            ulong          calls;                // Address of called subfunction
            """

        return debugger.Getcalltree(address)


    def findModule(self, address):
        """
            Find which module an address belongs to.

            @type  address: DWORD
            @param address: Address

            @rtype: LIST 
            @return: Tuple of module information (name, base address)

            """
        mod = debugger.Findmodule( address )
        if mod == -1:
            mod = ()
        return mod

    def getHeapsAddress(self):
        """
            Get a the process heaps

            @rtype: LIST of DWORD
            @return: List of Heap Address
            """        
        self.HeapsAddr = []

        peb = self.getPEB()
        addr = peb.ProcessHeaps[0]
        for ndx in range(0, peb.NumberOfHeaps):
            l = self.readLong( addr + ndx * 4 )
            if l:
                self.HeapsAddr.append( l )

        return self.HeapsAddr

    def getAddressOfExpression(self, expression):
        """
            Get the address from an expression as ntdll.RtlAllocateHeap

            @type  expression: STRING
            @param expression: Expression to translate into an address

            @rtype:  DWORD
            @return: Address of the Expression 
            """
        return debugger.Getaddrfromexp(expression)


    def getAddress(self, expression):
        """
            Get the address from an expression as ntdll.RtlAllocateHeap

            @type  expression: STRING
            @param expression: Expression to translate into an address

            @rtype:  DWORD
            @return: Address of the Expression 

            """
        return debugger.Getaddrfromexp(expression)

    ### Displaying information ###
    # Error, Log, Creating new windows, etc 

    def Error(self, msg):
        """
            This function shows an Error dialog with a custom message.

            @type  msg: STRING
            @param msg: Message
            """
        return debugger.Error( msg )

    def openTextFile(self,path=""):
        """
            Opens text file in MDI windows. ( if no path is specified browsefile dialog will pop up )

            @type:  STRING
            @param: (Optional, Def= "") Path to file        
            """
        if (len(path) > 0):
            return debugger.Opentextfile(path)
        else:
            return debugger.Opentextfile()

    def setStatusBar(self, msg):
        """
            Sets the status bar message.

            @type  msg: STRING
            @param msg: Message        
            """
        return debugger.Infoline(msg)

    def clearStatusBar(self):
        """
            Removes the current status bar message.
            """
        return debugger.Infoline()   

    def logLines(self, data, address = 0, highlight = False, gray = False , focus = 0):
        """
            Adds multiple lines of ASCII text to the log window.  

            @type  msg: LIST of STRING
            @param msg: List of Message to add (max size of msg is 255 bytes)

            @type  address: DWORD
            @param address: Address associated with the message

            @type  highlight: BOOLEAN
            @param highlight: Set highlight text

            @type  gray: BOOLEAN
            @param gray: Set gray text
            """    
        return [ self.Log(d, address, highlight, gray, focus) for d in data.split("\n") ]

    def LogLines(self,data,address = 0, highlight = False, gray = False , focus = 0):
        return [ self.Log(d, address, highlight, gray, focus) for d in data.split("\n") ]


    def Log(self, msg, address = 0 ,highlight = False, gray = False , focus = 0):
        """
            Adds a single line of ASCII text to the log window.  

            @type  msg: STRING
            @param msg: Message (max size is 255 bytes)

            @type  address: DWORD
            @param address: Address associated with the message

            @type  highlight: BOOLEAN
            @param highlight: Set highlight text

            @type  gray: BOOLEAN
            @param gray: Set gray text
            """
        if gray and not highlight:
            highlight = -1
        return debugger.Addtolist( address, int(highlight), msg[:255],focus)

    def log(self, msg, address = 0 ,highlight = False, gray = False , focus = 0):
        """
            Adds a single line of ASCII text to the log window.  

            @type  msg: STRING
            @param msg: Message (max size is 255 bytes)

            @type  address: DWORD
            @param address: Address associated with the message

            @type  highlight: BOOLEAN
            @param highlight: Set highlight text

            @type  gray: BOOLEAN
            @param gray: Set gray text
            """
        if gray and not highlight:
            highlight = -1
        return debugger.Addtolist( address, int(highlight), msg[:255],focus)


    def updateLog(self):
        """
            Forces an immediate update of the log window.
            """
        debugger.Updatelist()

    def createLogWindow(self):
        """
            Creates or restores the log window. 
            """
        return debugger.Createlistwindow()

    def createWindow(self, title, col_titles):
        """
            Creates a custom window.

            @type  title: STRING
            @param title: Window title

            @type  col_titles: LIST OF STRING
            @param col_titles: Column titles list

            @return HWND: Handler of created table
            """
        return self.createTable( title, col_titles )

    def createTable(self,title,col_titles):
        """
            Creates a custom window.

            @type  title: STRING
            @param title: Window title

            @type  col_titles: LIST OF STRING
            @param col_titles: Column titles list

            """
        table=Table(self,title,col_titles)
        return table

    def setFocus(self,handler):
        """
            Set focus on window.

            @type handler: ULONG
            @param handler: Windows Handler

            @return phandler: Handle to the window that previously had the focus.
            """
        return debugger.SetFocus(handler)

    def isValidHandle(self,handler):
        """
            Does a window still exist?

            @type handler: ULONG
            @param handler: Windows to check handle

            @return: INT : 1 Exists, 0 Doesnt exist
            """
        return debugger.IsValidHandle(handler)

    def setStatusBarandLog(self, addr, msg):
        """
            Sets and logs a status bar message. 

            @type  addr: DWORD
            @param addr: Address related with the message

            @type  msg: STRING
            @param msg: Message
            """
        return debugger.Message(addr, msg)

    def flashMessage(self, msg):
        """
            Flashes a message at status bar. 

            @type  msg: STRING
            @param msg: Message
            """
        return debugger.Flash(msg)

    def setProgressBar(self, message, promille=100):
        """
            Displays a progress bar which can contain formatted text and a progress percentage.
            If the formatted text contains a dollar sign ('$') it will be replaced by the current progress percentage.

            @type  msg: STRING
            @param msg: Message

            @type  promille: DWORD
            @param promille: Progress. At 0 the progress bar is closed and the previous message restored.
            """
        return debugger.Progress(promille, message)

    def closeProgressBar(self):
        """
            Close Progress Bar.
            """
        return debugger.Progress(0, "")

    def getComment(self, address,type=0xFD):
        """
            Get the comment of the opcode line.

            @type  address: DWORD
            @param address: Address of the requested comment

            @rtype:  STRING
            @return: Requested comment
            """
        comment=None
        #First, try to fetch any comment
        if type == 0xFD:
            #alway look for user defined comments first
            comment=debugger.Getcomment(address,NM_COMMENT)
            if not comment:
                #try argument comment
                comment=debugger.Getcomment(address,NM_ARG)
                if not comment:
                    #try library comment
                    comment=debugger.Getcomment(address,NM_LIBCOMM)
                    if not comment:
                        #try Analyse comment
                        comment=debugger.Getcomment(address,NM_ANALYSE)
        else:
            #Let the user pick the comment type
            comment=debugger.Getcomment(address,type)

        return comment


    #If you are unsure about what kind of comment are you looking for,
    #dont use this methods, and go for the automatic one "getComment(address)"

    def getUserComment(self,address):
        return debugger.Getcomment(address,NM_COMMENT)

    def getArgumentsComment(self,address):
        return debugger.Getcomment(address,NM_ARG)

    def getAnalyseComment(self,address):
        return debugger.Getcomment(address,NM_ANALYSE)

    def getLibraryComment(self,address):
        return debugger.Getcomment(address,NM_LIBCOM)


    def setComment(self, address, comment):
        """
            Set a comment.

            @type  address: DWORD
            @param address: Address of the Comment

            @type  comment: STRING
            @param comment: Comment to add
            """
        return debugger.Setcomment(address, comment)

    def setLabel(self, address, label):
        """
            Set a label.

            @type  adresss: DWORD
            @param address: Address to the new label

            @type  label: STRING
            @param label: Label to add
            """
        return debugger.Setlabel(address, label)

    def markBegin(self):
        """ 
            Place a start mark for timming your script
            """
        self.timer=time.clock()

    def markEnd(self):
        """
            Place an End mark for timming your script

            @rtype  time: DWORD
            @return time: time in seconds
            """
        if self.timer >0:
            return time.clock() - self.timer
        else:
            return 0

    def findDependecies(self, lookfor):
        """
            Find exported function on the loaded dlls.  

            @type  lookfor: TABLE of DWORD
            @param lookfor: Table of functions to search

            @rtype: DICTIONARY
            @return: Dictionary 
            """
        #lookfor = ["rpcrt4.rpcserveruseprotseq","rpcrt4.rpcserveruseprotseqex","rpcrt4.rpcserveruseprotseqw", "rpcrt4.rpcserveruseprotseqEp", "rpcrt4.rpcserveruseprotseqif",\
        #           "rpcrt4.rpcserveruseallprotseqs", "rpcrt4.rpcserveruseallprotseqsif", "rpcrt4.rpcserveruseprotseqepw",\
        #           "rpcrt4.rpcserveruseprotseqepexw", "rpcrt4.rpcserveruseallprotseqsifw"]
        symbol = self.getAllSymbols()

        result = {}
        for modname in symbol.keys():
            modsym = symbol[modname]
            for modaddr in modsym.keys():
                mod = modsym[modaddr] 
                if mod.name.lower() in lookfor:
                    if mod.type == "Import":
                        if result.has_key(modname):
                            result[modname].append(mod)
                        else:
                            result[modname] = [mod]
        return result



    def isvmWare(self):
        """
            Check if debugger is running under a vmware machine

            @rtype:  DWORD
            @return: 1 if vmware machine exists
            """
        return debugger.checkvmWare()





    ### Breakpoint Functions ###
    # All kind of breakpoint functions

    # For manual breakpoints: 
    #     key     shiftkey                Action
    #    VK_F2   0                       Toggle unconditional breakpoint
    #    VK_F2   Pressed (not 0)         Set conditional breakpoint
    #    VK_F4   Pressed (not 0)         Set logging breakpoint

    def ManualBreakpoint(self, address, key, shiftkey, font):
        """
            Set a Manual Breakpoint.

            @type  address: DWORD
            @param address: Address of the breakpoint

            @type  key: DWORD
            @param key: VK_F2 (Conditional Breakpoint) or VK_F4 (Logging Breakpoint)

            @type  shiftkey: DWORD
            @param shiftkey: State of the shiftkey

            @type  font: STRING
            @param font: See ImmFonts
            """
        if not ImmFonts.has_key( font.lower() ):
            font = ImmFonts[ "fixed" ]
        else:
            font = ImmFonts[ font.lower() ]

        return debugger.Manualbreakpoint(address, key, int(shiftkey), font)

    def setUnconditionalBreakpoint(self, address, font="fixed"):
        """
            Set an Unconditional Breakpoint.

            @type  address: DWORD
            @param address: Address for the breakpoint

            @type  font: STRING
            @param font: (Optional, Def: fixed) Font for the breakpoint
            """
        return self.ManualBreakpoint(address, BpKeys["VK_F2"], False, font)

    def setConditionalBreakpoint(self, address, font="fixed"):
        """
            Set a Conditional Breakpoint.

            @type  address: DWORD
            @param address: Address for the breakpoint

            @type  font: STRING
            @param font: (Optional, Def: fixed) Font for the breakpoint
            """
        return self.ManualBreakpoint(address, BpKeys["VK_F2"], True, font)

    def setLoggingBreakpoint(self, address):
        """
            Set a Logging Breakpoint. (This breakpoint will not puase the execution, it will just act as a Watch point"

            @type  address: DWORD
            @param address: Address for the breakpoint
            """
        return debugger.Setloggingbreakpoint(address)

    def setWatchPoint(self,address):
        """
            Set a watching Breakpoint.

            @type  address: DWORD
            @param address: Address for the watchpoint        
            """
        return debugger.Setloggingbreakpoint(address)


#define    TY_SET         0x00000100      // Code INT3 is in memory
#define    TY_ACTIVE      0x00000200      // Permanent breakpoint
#define    TY_DISABLED    0x00000400      // Permanent disabled breakpoint
#define    TY_ONESHOT     0x00000800      // Temporary stop
#define    TY_TEMP        0x00001000      // Temporary breakpoint
#define    TY_KEEPCODE    0x00002000      // Set and keep command code
#define    TY_KEEPCOND    0x00004000      // Keep condition unchanged (0: remove)
#define    TY_NOUPDATE    0x00008000      // Don't redraw breakpoint window
#define    TY_RTRACE      0x00010000      // Pseudotype of run trace breakpoint

    def setTemporaryBreakpoint(self, address, continue_execution = False, stoptrace = False): 
        """
            Set a Temporary Breakpoint.

            @type  address: DWORD
            @param address: Address for the breakpoint

            @type  continue_execution: BOOLEAN
            @param continue_execution: Automatically removes temporary breakpoint when hit and continue execution

            @type  stoptrace: BOOLEAN
            @param stoptrace: Stop any kind of trace or animation when hit
            """
        if continue_execution:
            flags = BpFlags["TY_TEMP"] | BpFlags["TY_KEEPCOND"]
        else:
            flags = BpFlags["TY_ONESHOT"] | BpFlags["TY_KEEPCOND"]
            if stoptrace:
                flags |= BpFlags["TY_STOPAN"] 

        return debugger.Tempbreakpoint(address, flags)

    def setBreakpoint(self, address):
        """
            Set a Breakpoint.

            @type  address: DWORD
            @param address: Address for the breakpoint
            """
        flags = BpFlags["TY_ACTIVE"]
        return debugger.Setbreakpoint(address, flags, "")

    def setBreakpointOnName(self,name):
        """
            Set a Breakpoint.

            @type  Name: STRING
            @param Name: name of the function to bp

            @rtype:  DWORD
            @return: Address of name
            """
        return debugger.Setbreakpointonname(name)

    def disableBreakpoint(self, address):
        """
            Disable Breakpoint.

            @type  address: DWORD
            @param address: Address for the breakpoint
            """
        flags = BpFlags["TY_DISABLED"]
        return debugger.Setbreakpoint(address, flags, "")

    def deleteBreakpoint(self,address,address2=0):
        """
            Delete Breakpoint.

            @type address: DWORD
            @param address: Start range of addresses to delete breakpoints
            @type address2: DWORD
            @param Address: End range of addresses to delete breakpoints
            """
        return debugger.DeleteBreakpoints(address,address2)


    def getBreakpointType(self, address):
        """
            Get the Breakpoint type.

            @type  address: DWORD
            @param address: Address for the breakpoint

            @rtype: STRING
            @return: Breakpoint type
            """

        type = debugger.Getbreakpointtypecount(address)
        for a in BpFlags.keys():
            if BpFlags[a] == type:
                return a
        return ""

    def setMemBreakpoint(self,addr, type, size=4):
        """
            Modifies or removes a memory breakpoint.

            @type  address: DWORD
            @param address: Address for the breakpoint

            @type  type: DWORD
            @param type: Type of Memory Breakpoint (READ/WRITE/SFX)

            @type  size: DWORD
            @param size: (Optional, Def: 4) Size of Memory Breakpoint
            """
        ty = type.strip().split("|")
        flags = 0
        for a in ty:
            try:
                flags |= BpMemFlags[a]
            except KeyError:
                raise Exception("Bad Flags for setMembreakpoint: %s" % type)

        return debugger.Setmembreakpoint(flags, addr, size)

    def disableMemBreakpoint(self, addr):
        """
            Disable Memory Breakpoint.
            """
        return debugger.Setmembreakpoint(0, addr,0)


    def setHardwareBreakpoint(self,addr,type=HB_CODE,size=1):
        """ 
            Sets Hardware breakpoint
            """
        return debugger.Sethardwarebreakpoint(type,addr,size)


    ### Read/Write/Search ###
    # Read/Write from process memory

    def writeLong(self, address, dword):
        """
            Write long to memory address.

            @type  address: DWORD
            @param address: Address

            @type  dword: DWORD
            @param dword: long to write
            """
        return debugger.Writememory( immutils.intel_order( dword ), address, 4, 0x2 )

    def writeMemory(self, address, buf):
        """
            Write buffer to memory address.

            @type  address: DWORD
            @param address: Address

            @type  buf: BUFFER
            @param buf: Buffer
            """
        return debugger.Writememory(buf, address, len(buf), 0x2)

    def readMemory(self, address, size):
        """
            Read block of memory.

            @type  address: DWORD
            @param address: Address

            @type  size: DWORD
            @param size: Size

            @rtype:  BUFFER
            @return: Process memory
            """
        return debugger.Readmemory(address, size, 0x01|0x02)

    def readLong(self, address):
        """
            Read a Long from the debugged process

            @type  address: DWORD
            @param address: Address

            @rtype:  DWORD
            @return: Long
            """
        long = self.readMemory(address, 0x4)
        if len(long) == 4:
            try:
                return immutils.str2int32_swapped(long) 
            except ValueError:
                raise Exception, "readLong failed to gather a long at 0x%08x" % address
        else:
            raise Exception, "readLong failed to gather a long at 0x%08x" % address

    def readString(self, address):
        """
            Read a string from the remote process

            @type  address: DWORD
            @param address: Address of the string

            @rtype:  String
            @return: String
            """
        return self.readUntil(address, '\x00')

    def readWString(self,address):
        """
            Read a unicode string from the remote process

            @type  address: DWORD
            @param address: Address of the unicode string

            @rtype:  Unicode String
            @return: Unicode String
            """
        return self.readUntil(address,"\x00\x00")

    def readUntil(self, address, ending):
        """
            Read string until ending starting at given address

            @param Address: Start address
            @return Readed String
            """
        readed=[]
        while(1):
            read = self.readMemory( address, 16 )
            address += 16
            ndx = read.find(ending)
            if ndx != -1:
                readed.append( read[0:ndx] )
                break
            else:
                readed.append( read )

        return string.joinfields(readed, "")

    def readShort(self, address):
        """ 
            Read a short integer from the remote process

            @type  address: DWORD
            @param address: Address of the short

            @rtype:  Short Integer
            @return: Short
            """
        short = self.readMemory(address, 0x2)
        return immutils.str2int16_swapped(short)

    def searchShort(self, short , flag=None):
        """ 
            Search a short integer on the remote process memory

            @type  short: SHORT
            @param short: Short integer to search for
            
            @type flag: STRING
            @param flag: Memory Protection String Flag

            @rtype:  List
            @return: List of address of the short integer founded
            """
        return self.Search(immutils.int2str16_swapped(short),flag)

    def searchLong(self, long, flag=None):        
        """ 
            Search a short integer on the remote process memory

            @type  long: DWORD
            @param long: integer to search for
            @type flag: STRING
            @param flag: Memory Protection String Flag

            @rtype:  List
            @return: List of address of the integer founded
            """
        return self.Search( immutils.int2str32_swapped(long),flag)
    
    def searchOnExecute(self,buf):
        """
        Search string in executable memory.
        
        @param buf: Buffer to search for
        @return: A list of address where the string was found on memory
        """
        if not buf:
            return []
        self.getMemoryPages()
        find = []
        buf_size = len(buf)
        for a in self.MemoryPages.keys():
            if (MemoryProtection["PAGE_EXECUTE"] == self.MemoryPages[a].access\
                or MemoryProtection["PAGE_EXECUTE_READ"] == self.MemoryPages[a].access\
                or MemoryProtection["PAGE_EXECUTE_READWRITE"] == self.MemoryPages[a].access\
                or MemoryProtection["PAGE_EXECUTE_WRITECOPY"] == self.MemoryPages[a].access):
                mem = self.MemoryPages[a].getMemory()
                if not mem:
                    continue
                ndx = 0
                while 1:
                    f = mem[ndx:].find( buf )
                    if f == -1 : break
                    find.append( ndx + f + a )
                    ndx += f + buf_size
        return find
    
    def searchOnWrite(self,buf):
        """
        Search string in writable memory.
        
        @param buf: Buffer to search for
        @return: A list of address where the string was found on memory
        """
        if not buf:
            return []
        self.getMemoryPages()
        find = []
        buf_size = len(buf)
        for a in self.MemoryPages.keys():
            if (MemoryProtection["PAGE_READWRITE"] == self.MemoryPages[a].access\
                or MemoryProtection["PAGE_WRITECOPY"] == self.MemoryPages[a].access\
                or MemoryProtection["PAGE_EXECUTE_READWRITE"] == self.MemoryPages[a].access\
                or MemoryProtection["PAGE_EXECUTE_WRITECOPY"] == self.MemoryPages[a].access):
                mem = self.MemoryPages[a].getMemory()
                if not mem:
                    continue
                ndx = 0
                while 1:
                    f = mem[ndx:].find( buf )
                    if f == -1 : break
                    find.append( ndx + f + a )
                    ndx += f + buf_size
        return find
    
    def searchOnRead(self,buf):
        """
        Search string in readable memory.
        
        @param buf: Buffer to search for
        @return: A list of address where the string was found on memory
        """
        if not buf:
            return []
        self.getMemoryPages()
        find = []
        buf_size = len(buf)
        for a in self.MemoryPages.keys():
            if (MemoryProtection["PAGE_READONLY"] == self.MemoryPages[a].access\
                or MemoryProtection["PAGE_EXECUTE_READ"] == self.MemoryPages[a].access):
                mem = self.MemoryPages[a].getMemory()
                if not mem:
                    continue
                ndx = 0
                while 1:
                    f = mem[ndx:].find( buf )
                    if f == -1 : break
                    find.append( ndx + f + a )
                    ndx += f + buf_size
        return find



        

    def Search(self, buf,flag=None):
        """
            Search string in memory.

            @param buf: Buffer to search for
            @param flag: Memory Protection String Flag
            @return: A list of address where the string was found on memory

            
            """
        if not buf:
            return []

        self.getMemoryPages()
        find = []
        buf_size = len(buf)
        for a in self.MemoryPages.keys():
            if flag:
                if (MemoryProtection[flag] == self.MemoryPages[a].access):
                    mem = self.MemoryPages[a].getMemory()
                    if not mem:
                        continue
                    ndx = 0
                    while 1:
                        f = mem[ndx:].find( buf )
                        if f == -1 : break
                        find.append( ndx + f + a )
                        ndx += f + buf_size
            else:
                mem = self.MemoryPages[a].getMemory()
                if not mem:
                    continue
                ndx = 0
                while 1:
                    f = mem[ndx:].find( buf )
                    if f == -1 : break
                    find.append( ndx + f + a )
                    ndx += f + buf_size
        return find

    def searchCommands(self, cmd):
        """
            Search for a sequence of commands in all executable modules loaded.
            @type  cmd: STRING
            @param cmd: Assembly code to search for (Search using regexp is available. See Documentation)

            @rtype:  List
            @return: List of address of the command found

            NOTE: Since ImmunityDebugger 1.2 , the returning tuple[1] value is deprecated,
            if you need the opcode string of the resulted address, you'll have to do a immlib.Disasm(tuple[0]).

            """
        address=0 # all loaded modules
        return debugger.Searchregexp(address,cmd) 

    def searchCommandsOnModule(self,address,cmd):
        """
            Search for a sequence of commands in given executable module.
            @type  cmd: STRING
            @param cmd: Assembly code to search for (Search using regexp is available. See Documentation)

            @rtype:  List
            @return: List of address of the command found

            NOTE: Since ImmunityDebugger 1.2 , the returning tuple[1] value is deprecated,
            if you need the opcode string of the resulted address, you'll have to do a immlib.Disasm(tuple[0]).

            """
        return debugger.Searchregexp(address,cmd) 

    ### Execution control ###
    # All kind of functions that interact with code execution

    def Run(self, address=0):
        """Run Process untill address.
            @param address: Address"""
        self.clearState()
        return debugger.Run(address)

    def runTillRet(self):
        """Run Process till ret.
            """
        self.clearState()
        return debugger.Runtillret()


    def Pause(self):
        """Pause process"""
        return debugger.Pause()

    def stepOver(self, address=0):
        """
            Step-Over Process untill address.

            @type  address: DWORD
            @param address: (Optional, Def = 0) Address
            """
        self.clearState()
        return debugger.Stepover(address)

    def stepIn(self, address=0):
        """
            Step-in Process untill address.

            @type  address: DWORD
            @param address: (Optional, Def = 0) Address 
            """
        self.clearState()
        return debugger.Stepin(address)

    def quitDebugger(self):
        """
            Quits debugger
            """
        return debugger.exitID()


    def ignoreSingleStep(self,flag="CONTINUE"):
        """
            Ignore Single Step events
            @type flag: STRING
            @param flag: How to continue after a single event is catched
            flag = DISABLE : Disable ignoring
            flag = FORCE : Conventional Force continue method
            flag = CONTINUE : Transparent continue method

            CAUTION: This method overrides GUI option 'single-step break'
            """
        return debugger.IgnoreSingleStep(IgnoreSingleStep[flag])

    #Consider the following three methods of experimental nature.
    def openProcess(self, path,mode=0):
        """
            Open process for debugging
            @type path: STRING
            @param path: Path to file to debug
            @type mode: INTEGER
            @param mode: How to start: -2 SILENT, 0 NORMAL
            """
        return debugger.Open(path,mode)

    def restartProcess(self,mode=-1):
        """
            Restart debuggee
            @type mode: INTEGER
            @param mode: How to restart : -2 SILENT, -1 MSGBOX

            """
        return debugger.Open("",mode)


    def Attach(self, pid):
        """
            Attach to an active process
            @type pid: INTEGER
            @param pid: Process Id.
            """
        return debugger.Attach(pid)

    def Dettach(self):
        """
            Dettach from active process
            """
        #this methos is still very experimental
        return debugger.Dettach()


    def prepareForNewProcess(self):
        """
            Prepare Debugger for fresh debugging session
            NOTE: be sure to know what you are doing when
            calling this method
            """
        return debugger.Preparefornewps()












    ### GUI interaction ###
    # Whatever interaction on the gui

    def goSilent(self,silent):
        """ Set/Unset silent debugging flag
            @type silent: INTEGER
            @param silent: 1 to set silent, 0 to unset
            """
        return debugger.GoSilent(silent)

    def addHeader(self,address,header,color="Black"):
        """
            Add a header to given row.
            @type address: DWORD
            @param address: Address to add the header into
            @type header: STRING
            @param header: Header string to add into row
            @type color: STRING
            @param color: Color of text
            """
        return debugger.AddHeaderToRow(address,header,ImmDrawColors[color])

    def removeHeader(self,address):
        """
            Removes header from row.
            @type address: DWORD
            @param address: Address to remove the header from
            """
        return debugger.RemoveHeaderFromRow(address)

    def removeLine(self,address):
        """
            Removes header from row.
            @type address: DWORD
            @param address: Address to remove the header from
            """
        return debugger.RemoveHeaderFromRow(address)

    def getHeader(self,address):
        """
            Get Header from row.
            @type address: DWORD
            @param address: Address to get the headers from
            @return PYLIST: List of strings
            """
        return debugger.GetHeaderFromRow(address)




    def addLine(self,address,header,color="Black"):
        """
            Add a line to cpu window.
            @type address: DWORD
            @param address: Address to add line
            @type header: STRING
            @param header: Header string to add into row
            @type color: STRING
            @param color: Color of text
            """
        return debugger.AddHeaderToRow(address,header,ImmDrawColors[color])


    def gotoDisasmWindow(self, addr):
        """
            GoTo the Disassembler Window.

            @type  addr: DWORD
            @param addr: Address to show on the Disassembler Window
            """
        return debugger.Setcpu( self.threadid, addr, 0, 0, 0x8000L) # redraw

    def gotoDumpWindow(self, addr):
        """
            GoTo Dump Window.

            @type  addr: DWORD
            @param addr: Address to show on the Dump Window
            """
        return debugger.Setcpu( self.threadid, 0, addr, 0, 0x8000L) # redraw

    def gotoStackWindow(self, addr):
        """
            GoTo the Stack Window.
            @type  addr: DWORD
            @param addr: Address to show on the Stack Window
            """
        return debugger.Setcpu( self.threadid, 0, 0, addr, 0x8000L) # redraw

    def inputBox(self,title):
        """
            Creates Dialog with an Inputbox.

            @type  title: STRING
            @param title: Title for the Inputbox dialog

            @return: String from the inputbox
            """
        return debugger.Inputbox(title)

    def comboBox(self,title,combolist):
        """
            Creates Dialog with a Combobox.

            @type  title: STRING
            @param title: Title for the dialog

            @type  combolist: LIST
            @param combolist: List of items to add to combo dialog

            @return: Selected item
            """
        return debugger.Combobox(title,combolist,len(combolist))



    ### Debugger State ###
    # The state of the debugger

    def getStatus(self):
        """
            Get the status of the debugged process.

            @return: Status of the debugged process
            """
        return debugger.Getstatus()

    def isStopped(self):
        """
            Is the debugged process stopped?

            @rtype:  BOOL
            @return: Boolean (True/False)
            """
        return DebugerStatus["STOPPED"] == self.getStatus()

    def isEvent(self):
        """
            Is the debugged process in an event state?

            @rtype:  BOOL
            @return: Boolean (True/False)
            """
        return DebugerStatus["EVENT"] == self.getStatus()

    def isRunning(self):
        """
            Is the debugged process running?

            @rtype:  BOOL
            @return: Boolean (True/False)
            """
        return DebugerStatus["RUNNING"] == self.getStatus()

    def isFinished(self):
        """
            Is the debugged process finished?

            @rtype:  BOOL
            @return: Boolean (True/False)
            """
        return DebugerStatus["FINISHED"] == self.getStatus()

    def isClosing(self):
        """
            Is the debugged process closed?

            @rtype:  BOOL
            @return: Boolean (True/False)
            """
        return DebugerStatus["CLOSING"] == self.getStatus()



    ### Hooks ###

    def listHooks(self):
        """
            List of active hooks

            @rtype: LIST
            @return: List of active hooks
            """
        return debugger.Listhook()

    def removeHook(self,hook_str):
        """Unhook from memory
            """
        debugger.Removehook(hook_str)



    def _getHookEntry(self, entry):
        tbl = []
        # We need to use HOOK_REG, since some of the original register
        #  are saved on the stack
        try:
            reg = HOOK_REG[ entry[0] ]
            tbl.append( "MOV EAX, %s" % reg )
        except KeyError:
            if entry[0] == 'ESP':
                tbl.append("LEA EAX, [ESP+0x14]")
            elif type( entry[0] ) == type(0):
                tbl.append("MOV EAX, [0x%08x]" % entry[0] )
            else:
                return []


        if len(entry) == 2:
            tbl.append( "MOV EAX, [EAX + 0x%x]" % entry[1] )
        tbl.append( "STOSD" )

        return tbl

    # afterHookAddr = hookAddr + idx
    # ndx = function num
    # table = [ (reg), (reg, offset) ]
    def _createCodeforHook( self, memAddress, afterHookAddr, ndx, table, execute_prelude, alloc_size):
        # SAVING REGS, WE DONT WANT TO TOUCH ANYTHING!
        # XXX: Replace it with a PUSHA/POPA
        #      Add a global deadlock
        alloc_stub  = [ "PUSHAD" ]                          # Save all registers
        alloc_stub += [ "MOV   EBX, 0x%08x" % memAddress ]  #
        alloc_stub += [ "MOV   EDI, [EBX]"]                 # GETTING A POINTER to top of data
        alloc_stub += [ "CMP   DWORD DS:[EBX+4],1"]         # Check the deadlock
        alloc_stub += [ "JZ    -C" ]                        # If its in use, loop
        alloc_stub += [ "MOV   DWORD DS:[EBX+4],1"]         # Turn deadlock on
        alloc_stub += [ "MOV   EAX, EDI"]
        alloc_stub += [ "SUB   EAX, EBX"]
        alloc_stub += [ "ADD   EAX, 0x%08x" % (len(table) * 4 + 4) ] 
        alloc_stub += [ "CMP   EAX, 0x%08x" % alloc_size]   # Did we reach the end of memory?
                        # JE  -> JMP TO THE END OF THE FUNCTION
        alloc_stub_reg  = [ "MOV   EAX, 0x%x" % ndx]
        alloc_stub_reg += [ "STOSD"]                        # SAVE IN MEMORY THE FUNCTION NUMBER
        for entry in table:
            alloc_stub_reg += self._getHookEntry( entry )   # Get all the regs/mem and save them in data
        alloc_stub_reg += [ "MOV   [EBX], EDI"]             # Save the top of the data 
        alloc_stub_reg += [ "MOV   DWORD DS:[EBX+4],0"]     # Turn Lock OFF

        alloc_stub_pos = [ "POPAD"]                         # Restore register        
                                                            # Right here is where the 'saved' instruction
                                                            #  of the hook are executed                                                            
        alloc_ret = "PUSH 0x%08x\nRET" % afterHookAddr      # Back to the function

        code     = self.Assemble( "\n".join( alloc_stub ) )
        reg_code = self.Assemble( "\n".join( alloc_stub_reg ) )
        code    += "\x0f\x83" + struct.pack("L", len(reg_code) ) 
        code    += reg_code
        code    += self.Assemble( "\n".join( alloc_stub_pos ) )
        code    += execute_prelude
        code    += self.Assemble( alloc_ret )

        return code


    def addFastLogHook(self,  hook, alloc_size = 0x100000): 
        CODE_HOOK_START = 8
        flh = hook
        # Get the table of functions from the hook
        table = flh.get()
        # Allocate memory for the hook and the log
        memAddress = self.remoteVirtualAlloc( alloc_size )
        self.Log( "Logging at 0x%08x" % memAddress )

        # MEMORY LOOKS LIKE:
        # mem     [ ptr to data        ]
        # mem + 4 [ deadlock           ]
        # mem + 8 [ start of hook code ]
        # mem + n [ ...                ]
        # mem + n [ start of data      ]

        ptr = memAddress + CODE_HOOK_START

        fn_restore = []

        for fn_ndx in range( 0, len(table) ):
            hookAddress = table[ fn_ndx ][0]
            entry       = table[ fn_ndx ][1]

            idx = 0
            #patch_code = self.Assemble( "PUSH 0x%08x\nRET" % ptr )
            patch_code = self.Assemble( "JMP 0x%08x" % ptr, address = hookAddress)

            while idx < len(patch_code): 
                op = self.Disasm( hookAddress + idx )
                if op.isCall() or op.isJmp():
                    op = None
                    break

                idx += op.getOpSize()
            if not op:
                continue


            ex_prelude = self.readMemory( hookAddress, idx ) 

            code = self._createCodeforHook( memAddress, hookAddress + idx,\
                                            fn_ndx + 1, entry, ex_prelude, alloc_size)

            self.writeMemory( ptr , code )
            ptr+= len(code)
            self.writeMemory( hookAddress, patch_code )

            fn_restore.append( ex_prelude ) # Correspond in index with function address

        if ptr % 4:
            ptr = 4 + ptr & ~(4-1)
        hook.setMem( ptr )
        self.writeLong( memAddress, ptr )

        hook.setRestore( fn_restore )



    ### Remote Allocation/Deallocation ###

    def rVirtualAlloc(self, lpAddress, dwSize, flAllocationType, flProtect):
        """
            Virtual Allocation on the Debugged Process

            @type  lpAddress: DWORD
            @param lpAddress: Desired starting Address

            @type  dwSize: DWORD
            @param dwSize: Size of the memory to be allocated (in bytes)

            @type  flAllocationType: DWORD
            @param flAllocationType: Type of Memory Allocation (MEM_COMMIT, MEM_RESERVED, MEM_RESET, etc)

            @type  flProtect: DWORD
            @param flProtect: Flag protection of the memory allocated  

            @rtype:  DWORD
            @return: Address of the memory allocated
            """
        return debugger.pVirtualAllocEx( lpAddress, dwSize, flAllocationType, flProtect )

    # default dwFreetype == MEM_RELEASE
    def rVirtualFree(self, lpAddress, dwSize = 0x0, dwFreeType = 0x8000):
        """
            Virtual Free of memory on the Debugged Process

            @type  size: DWORD
            @param size: (Optional, Def: 0) Size of the memory to free

            @type  dwFreeType: DWORD
            @param dwFreeType: (Optional, Def: MEM_RELEASE) Type of Free operation

            @rtype:  DWORD
            @return: On Successful, returns a non zero value
            """
        return debugger.pVirtualFreeEx( lpAddress, dwSize, dwFreeType )

    def remoteVirtualAlloc(self, size = 0x10000, interactive = True):
        """
            Virtual Allocation on the Debugged Process

            @type  size: DWORD
            @param size: (Optional, Def: 0x10000) Size of the memory to allocated, in bytes

            @rtype:  DWORD
            @return: Address of the memory allocated
            """

        return self.rVirtualAlloc( 0x0, size, 0x1000, 0x40)

    ### OS information ###
    def getOsVersion(self):
        return self.osversion

    def getOsRelease(self):
        return self.osrelease	    

    def getOsInformation(self):
        """
            Get OS information 

            @rtype: TUPLE
            @return: List with ( system, release, version)
            """
        import platform
        return (platform.system(),platform.release(),platform.version())

    def getThreadId(self):
        """
            Return current debuggee thread id

            @trype: LONG
            @return: Thread ID
            """
        return debugger.GetThreadId()


    ### Accessing Recognition Routines ###

    def searchFunctionByName(self, name, heuristic = 90, module = None, version = None, data=""):
        """
            Look up into our dictionaries to find a function match.

            @type  name: STRING
            @param name: Name of the function to search

            @type  module: STRING
            @param module: name of a module to restrict the search

            @type  version: STRING
            @param version: restrict the search to the given version

            @type  heuristic: INTEGER
            @param heuristic: heuristic threasold to consider a real function match

            @type  data: STRING|LIST
            @param data: Name (or list of names) of the .dat file inside the Data folder, where're stored the function 
            patterns. Use an empty string to use all the files in the Data folder.

            @rtype: DWORD|None
            @return: the address of the function or None if we can't find it
            """
        recon = FunctionRecognition(self, data)
        return recon.searchFunctionByName(name, heuristic , module, version )

    def searchFunctionByHeuristic(self, csvline, heuristic = 90, module = None, data=""):
        """
            Search memory to find a function that fullfit the options.

            @type  csvline: STRING
            @param csvline: A line of a Data CSV file. This's a simple support for copy 'n paste from a CSV file.        

            @type  heuristic: INTEGER
            @param heuristic: heuristic threasold to consider a real function match

            @type  module: STRING
            @param module: name of a module to restrict the search

            @type  data: STRING|LIST
            @param data: Name (or list of names) of the .dat file inside the Data folder, where're stored the function 
            patterns. Use an empty string to use all the files in the Data folder.

            @rtype: DWORD|None
            @return: the address of the function or None if we can't find it
            """

        recon = FunctionRecognition(self, data)
        return recon.searchFunctionByHeuristic(csvline, heuristic , module )

    def resolvFunctionByAddress(self, address, heuristic=90,data=""):
        """
            Look up into our dictionaries to find a function match.

            @type  address: DWORD
            @param address: Address of the function to search

            @type  heuristic: INTEGER
            @param heuristic: heuristic threasold to consider a real function match

            @type  data: STRING|LIST
            @param data: Name (or list of names) of the .dat file inside the Data folder, where're stored the function 
            patterns. Use an empty string to use all the files in the Data folder.

            @rtype: STRING
            @return: a STRING with the function's real name or the given address if there's no match
            """
        recon = FunctionRecognition(self,data)
        return recon.resolvFunctionByAddress(address, heuristic,data)

    def makeFunctionHashHeuristic(self, address, compressed = False, followCalls = True, data=""):
        """
            @type  address: DWORD
            @param address: address of the function to hash

            @type  compressed: Boolean
            @param compressed: return a compressed base64 representation or the raw data

            @type  followCalls: Boolean
            @param followCalls: follow the first call in a single basic block function

            @type  data: STRING|LIST
            @param data: Name (or list of names) of the .dat file inside the Data folder, where're stored the function 
            patterns. Use an empty string to use all the files in the Data folder.

            @rtype: LIST
            @return: the first element is described below and the second is the result of this same function but over the first
            call of a single basic block function (if applies), each element is like this:
            a base64 representation of the compressed version of each bb hash:
            [4 bytes BB(i) start][4 bytes BB(i) 1st edge][4 bytes BB(i) 2nd edge]
            0 <= i < BB count
            or the same but like a LIST with raw data.
            """
        recon = FunctionRecognition(self, data)
        return FunctionRecognition.makeFunctionHashHeuristic(address, compressed, followCalls)

    def makeFunctionHashExact(self, address,data=""):
        """
            Return a SHA-1 hash of the function, taking the raw bytes as data.

            @type  address: DWORD
            @param address: address of the function to hash

            @type  data: STRING|LIST
            @param data: Name (or list of names) of the .dat file inside the Data folder, where're stored the function 
            patterns. Use an empty string to use all the files in the Data folder.

            @rtype: STRING
            @return: SHA-1 hash of the function
            """

        recon = FunctionRecognition(self,data)
        return recon.makeFunctionHashExact(address)

    def makeFunctionHash(self, address, compressed = False,data=""):
        """
            Return a list with the best BB to use for a search and the heuristic hash
            of the function. This two components are the function hash.

            @type  address: DWORD
            @param address: address of the function to hash

            @type  compressed: Boolean
            @param compressed: return a compressed base64 representation or the raw data

            @type  data: STRING|LIST
            @param data: Name (or list of names) of the .dat file inside the Data folder, where're stored the function 
            patterns. Use an empty string to use all the files in the Data folder.

            @rtype: LIST
            @return: 1st element is the generalized instructions to use with searchCommand
            2nd element is the heuristic function hash (makeFunctionHashHeuristic)
            3rd element is an exact hash of the function (makeFunctionHashExact)
            """
        recon = FunctionRecognition(self,data)
        return recon.makeFunctionHash(address, compressed)


    def sleep_till_stopped(self, timeout):
        """
            timeout is in seconds. this function will sleep 1 second at a time until timeout is reached
            or the debugger has stopped (probably due to AV)
            returns True if we were stopped before timeout happened
            """
        for i in xrange(timeout):
            #sleep 1 second at a time
            if self.isStopped():
                return True
            if self.isEvent():
                return True

            time.sleep(1)
        return False 











