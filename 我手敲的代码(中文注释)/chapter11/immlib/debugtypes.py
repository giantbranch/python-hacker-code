#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}


"""

__version__ = '1.0'

import debugger
import struct

###ulong
#    handle = handle
#    handles[handle][0]=type
#    handles[handle][1]=access
#    handles[handle][2]=data1
#    handles[handle][3]=data2
### int
#    handles[handle][4]=refcount
###char
#    handles[handle][5]=htype
#    handles[handle][6]=username   
#    handles[handle][7]=nativename

class Handle:
    def __init__(self, handle):
        self.handle     = handle
        self.type       = 0
        self.access     = 0 
        self.data1      = 0
        self.data2      = 0
        self.refcount   = 0
        self.htype      = ""
        self.username   = ""
        self.nativename = ""
        
    def _getfromtuple(self, mem):
        self.type       = mem[0]
        self.access     = mem[1] 
        self.data1      = mem[2]
        self.data2      = mem[3]
        self.refcount   = mem[4]
        self.htype      = mem[5]
        self.username   = mem[6]
        self.nativename = mem[7]

    def getHandle(self):
        return self.handle
    
    def getType(self):
        return self.type

    def getAccess(self):
        return self.access

    def getData1(self):
        return self.data1

    def getData2(self):
        return self.data2

    def getRefCount(self):
        return self.refcount

    def getHtype(self):
        return self.htype

    def getUserName(self):
        return self.username

    def getNativeName(self):
        return self.nativename

class Thread:
    def __init__(self, thread):
        self.thread        = thread
        self.entry         = 0
        self.threadid      = 0
        self.datablock     = 0 
        self.stacktop      = 0
        self.stackbottom   = 0
        self.status        = 0
        
        
    def _getfromtuple(self, thread):
        self.threadid      = thread[0]
        self.entry         = thread[1]
        self.datablock     = thread[2]
        self.stacktop      = thread[3]
        self.stackbottom   = thread[4]
        self.status        = thread[5]


    def getEntry(self):
        return self.entry
    
    def getId(self):
        return self.threadid

    def getdatablock(self):
        return self.datablock

    def getStackTop(self):
        return self.stacktop

    def getStackBottom(self):
        return self.stackbottom

    def getStatus(self):
        return self.status


class Symbol:
    def __init__(self, addr):
        self.address = addr
        self.section = ""
        self.type = ""
        self.name = ""
        self.comment = ""
        self.module = ""
        
    def _getfromtuple(self, tup):
        self.module  = tup[0].strip()
        self.module  = self.module.lower()
        
        self.section = tup[1]
        self.type    = tup[2]
        self.name    = tup[3]
        self.comment = tup[4]

    def getAddress(self):
        return self.address
    
    def getModule(self):
        return self.module

    def getSection(self):
        return self.section

    def getType(self):
        return self.type

    def getName(self):
        return self.name

    def getComment(self):
        return self.comment

    
#Base address of module:                base
#Size occupied by module:               size
#service information, TY_xxx:           type
#base address of module code block:     codebase
#size of module code block:             codesize
#Base address of resources:             resbase
#Size of resources:                     ressize
#Address of <ModuleEntryPoint> or NULL: entry
#Base address of module data block:     database
#Base address of import data table:     idatatable
#Base address of import data block:     idatabase
#Base address of export data table:     edatatable
#Size of export data table:             edatasize
#Base address of relocation table:      reloctable
#Size of relocation table:              relocsize
#Short name of the module:              name
#Full name of the module:               path
#Number of sections in the module:      nsect
#Total size of headers in executable:   headersize
#Base of image in executable file:      fixupbase
#Decoded code features or NULL:         codedec
#Code CRC for actual decoding:          codecrc
#Hit tracing data or NULL:              hittrace
#Decoded data features or NULL:         datadec
#Global types from debug info:          globaltypes
#Address of WinMain() etc. in dbg data: mainentry
#Entry of packed code or NULL:          realsfxentry
#Original size of module code block:    origcodesize
#Base of memory block with SFX:         sfxbase
#Size of memory block with SFX:         sfxsize
#Whether system DLL:                    issystemdll
#Version of executable file:            version
class Module:
    def __init__(self, name, baseaddress, size, entrypoint):
        """
        Module Information
        
        @type  name: STRING
        @param name: Name of the module
        
        @type  baseaddress: DWORD
        @param baseaddress: Base Address of the Module
        
        @type  size: DWORD
        @param size: Size of the Module
        
        @type  entrypoint: DWORD
        @param entrypoint: Entry Point
        """
        # for modulos in mods.keys():
        #    name     : modulos
        #    base addy: mods[modulos][0]
        #    size     : mods[modulos][1]
        #    entry    : mods[modulos][2]
        #    full path: mods[modulos][3]
        
        self.name        = name.lower()
        self.baseaddress = baseaddress
        self.size        = size
        self.entrypoint  = entrypoint
        self.modDict     = None
        self.symbols     = []
        self.XREFto      = {}
        self.XREFfrom    = {}

    def getFunctions(self):
        """
        Get the all the functions from Module
        
        @rtype:  LIST of DWORD
        @return: A List of the address of all function
        """
        return debugger.Getallfunctions(self.baseaddress)
        
    def _xrefs(self, address, XREF, debugger_callback):
        code = self.getCodebase()
        codesize = self.getCodesize()
        
        # We first check check if address is inside this module code
        if address >= code and address <= (code+codesize):
            return []
        
        # If we didn't get the whole xref list from debugger, we get it
        if not XREF:
            XREF = debugger_callback(address)

        # returning the xrefs as a list of (addy, type)
        try:
            return XREF[address]
        except KeyError:
            return []
        
    def getXrefTo(self, address):
        """
        Get the Xreference to the given address
        
        @type  address: DWORD
        @param address: Address in the Module to get Xref to
        
        @rtype:  LIST of DWORD
        @return: List of Address
        """
        return self._xrefs(address, self.XREFto, debugger.Getxref_to)
                    
    def getXrefFrom(self, address):
        """
        Get the Xreference from the given address
        
        @type  address: DWORD
        @param address: Address in the Module to get Xref from
        
        @rtype:  LIST of DWORD
        @return: List of Address
        """
        return self._xrefs(address, self.XREFfrom, debugger.Getxref_from)
        
    def getBaseAddress(self):
        """
        Get the Base Address
        
        @rtype:  DWORD
        @return: Base Address
        """
        return self.baseaddress
    
    def getReferencedStrings(self):
        return debugger.Getreferencedstrings(self.entrypoint)
    
    def setModuleExtension(self, mod_dict):
        self.modDict = mod_dict

    def setSymbols(self, symbol):
        self.symbols = symbol

    def Analyse(self):
        """
        Analize the Current Module
        """
        return debugger.Analysecode(self.baseaddress)
    
    def get(self, name):
        name = name.lower()
        if not self.modDict.has_key(name):
            return None
        return self.modDict[name][0]
    
    def getSymbols(self):
        return self.symbols
    
    def getBase(self):
        """
        Get Base from module
        
        @rtype:  DWORD
        @return: Base from the module
        """
        try:
            return self.modDict['base'][0]
        except KeyError:
            return None
    
    def getSize(self):
        """
        Get Size from module
        """
        try:
            return self.modDict['size'][0]
        except KeyError:
            return None
    
    def getType(self):
        """
        Get Type from module
        """
        try:
            return self.modDict['type'][0]
        except KeyError:
            return None
    
    def getCodebase(self):
        """
        Get Codebase from module
        """
        try:
            return self.modDict['codebase'][0]
        except KeyError:
            return None
    
    def getCodesize(self):
        """
        Get Codesize from module
        
        @rtype:  DWORD
        @return: Code Size
        """
        try:
            return self.modDict['codesize'][0]
        except KeyError:
            return None
    
    def getResbase(self):
        """
        Get Resbase from module
        
        @rtype:  DWORD
        @return: Res Base

        """
        try:
            return self.modDict['resbase'][0]
        except KeyError:
            return None
    
    def getRessize(self):
        """
        Get Ressize from module

        @rtype:  DWORD
        @return: Res Size
        """
        try:
            return self.modDict['ressize'][0]
        except KeyError:
            return None
    
    def getEntry(self):
        """
        Get Entry from module
        
        @rtype:  DWORD
        @return: Entry        
        """
        try:
            return self.modDict['entry'][0]
        except KeyError:
            return None
    
    def getDatabase(self):
        """
        Get Database from module

        @rtype:  DWORD
        @return: Database
        """
        try:
            return self.modDict['database'][0]
        except KeyError:
            return None
    
    def getIdatatable(self):
        """
        Get Idatatable from module
        """
        try:
            return self.modDict['idatatable'][0]
        except KeyError:
            return None
    
    def getIdatabase(self):
        """Get Idatabase from module"""
        try:
            return self.modDict['idatabase'][0]
        except KeyError:
            return None
    
    def getEdatatable(self):
        """
        Get Edatatable from module
        """
        try:
            return self.modDict['edatatable'][0]
        except KeyError:
            return None
    
    def getEdatasize(self):
        """
        Get Edatasize from module
        """
        try:
            return self.modDict['edatasize'][0]
        except KeyError:
            return None
    
    def getReloctable(self):
        """
        Get Reloctable from module
        """
        try:
            return self.modDict['reloctable'][0]
        except KeyError:
            return None
    
    def getRelocsize(self):
        """
        Get Relocsize from module
        """
        try:
            return self.modDict['relocsize'][0]
        except KeyError:
            return None
    
    def getName(self):
        """
        Get Name from module
        """
        try:
            return self.modDict['name'][0]
        except KeyError:
            return None
    
    def getPath(self):
        """
        Get Path from module
        """
        try:
            return self.modDict['path'][0]
        except KeyError:
            return None
    
    def getNsect(self):
        """
        Get Nsect from module
        """
        try:
            return self.modDict['nsect'][0]
        except KeyError:
            return None
    
    def getHeadersize(self):
        """
        Get Headersize from module
        """
        try:
            return self.modDict['headersize'][0]
        except KeyError:
            return None
    
    def getFixupbase(self):
        """
        Get Fixupbase from module
        """
        try:
            return self.modDict['fixupbase'][0]
        except KeyError:
            return None
    
    def getCodedec(self):
        """
        Get Codedec from module
        """
        try:
            return self.modDict['codedec'][0]
        except KeyError:
            return None
    
    def getCodecrc(self):
        """
        Get Codecrc from module
        """
        try:
            return self.modDict['codecrc'][0]
        except KeyError:
            return None
    
    def getHittrace(self):
        """
        Get Hittrace from module
        """
        try:
            return self.modDict['hittrace'][0]
        except KeyError:
            return None
    
    def getDatadec(self):
        """
        Get Datadec from module
        """
        try:
            return self.modDict['datadec'][0]
        except KeyError:
            return None
    
    def getGlobaltypes(self):
        """
        Get Globaltypes from module
        """
        try:
            return self.modDict['globaltypes'][0]
        except KeyError:
            return None
    
    def getMainentry(self):
        """
        Get Mainentry from module
        """
        try:
            return self.modDict['mainentry'][0]
        except KeyError:
            return None
    
    def getRealsfxentry(self):
        """
        Get Realsfxentry from module
        """
        try:
            return self.modDict['realsfxentry'][0]
        except KeyError:
            return None
    
    def getOrigcodesize(self):
        """
        Get Origcodesize from module
        """
        try:
            return self.modDict['origcodesize'][0]
        except KeyError:
            return None
    
    def getSfxbase(self):
        """
        Get Sfxbase from module
        """
        try:
            return self.modDict['sfxbase'][0]
        except KeyError:
            return None
    
    def getSfxsize(self):
        """
        Get Sfxsize from module
        """
        try:
            return self.modDict['sfxsize'][0]
        except KeyError:
            return None
    
    def getIssystemdll(self):
        """
        Get Issystemdll from module
        """
        try:
            return self.modDict['issystemdll'][0]
        except KeyError:
            return None
    
    def getVersion(self):
        """
        Get Version from module
        """
        try:
            return self.modDict['version'][0]
        except KeyError:
            return None
        
    def isAnalysed(self):
        """
        Check if module was analysed
        """
        # we should check every time, cause the module might be analysed. Since modules are cached sometimes
        return debugger.IsAnalysed(self.baseaddress)
    
    def getJumpList(self):
        """
        get jump list from analysed module
        """
        #jumplist[0] = from
        #jumplist[1] = to
        #jumplist[2] = type
        #type is one of
        #define JT_JUMP        0               // Unconditional jump
        #define JT_COND        1               // Conditional jump
        #define qJT_SWITCH      2               // Jump via switch table
        #define JT_CALL        3               // Local (intramodular) call
        #define CALL_INTER     4               // intermodular call
        #jmpTypeFlags = {"JUMP":0,\
                #"JUMP_COND":1,\
                #"JUMP_SWITCH":2,\
                #"CALL":3,\
                #"CALL_INTER":4}
        try:
            return self.modDict['jumplist'][0]
        except KeyError:
            return None
        
    
class Stack:
    def __init__(self):
        self.address    = 0 # stack pointer
        self.stack      = 0
        self.procedure  = ""
        self.calledfrom = 0
        self.frame      = 0 # frame pointer
        # args
        self.stackdump1 = 0
        self.stackdump2 = 0
        self.stackdump3 = 0
        
    def _setfromtuple(self, s):
        self.address    = s[0]     # stack pointer
        self.stack      = s[1]
        self.procedure  = str(s[2])
        self.calledfrom = s[3]
        self.frame      = s[4]     # frame pointer
        self.stackdump1 = s[5]
        self.stackdump2 = s[6]
        self.stackdump3 = s[7]
        

    def getStackDump(self):
        return (self.stackdump1,self.stackdump2,self.stackdump3)
                
    def getAddress(self):
        return self.address
    
    def getStack(self):
        return self.stack
    
    def getProcedure(self):
        return self.procedure
    
    def getFrame(self):
        return self.frame
    
    def getCalledFrom(self):
        return self.calledfrom


class Table:
    def __init__(self,imm,title,col_titles):
        """
        Create a GUI Window Table
        
        @type   imm: Debugger Object
        @param  imm: Debugger
        
        @type  title: STRING
        @param title: Title for the Window
        
        @type  col_titles: LIST of STRINGs
        @param col_titles: List of the Column's Name
        """
        self.imm = imm
        self.instance=self.createTable(title,col_titles)
        
    def createTable(self,title,col_titles):
        title1=""
        title2=""
        title3=""
        title4=""
        title5=""
        if len(col_titles) > 5:
            maxcol=5
        else:
            maxcol=len(col_titles)
        try:
            title1=col_titles[0]
        except:
            pass
        try:
            title2=col_titles[1]
        except:
            pass
        try:
            title3=col_titles[2]
        except:
            pass
        try:
            title4=col_titles[3]
        except:
            pass
        try:
            title5=col_titles[4]
        except:
            pass
        return debugger.Createtable(title,maxcol,title1,title2,title3,title4,title5)
    
    # Focus not implemented yet
    def Log(self, data, address=0, focus = False):
        """
        Add a message into a column
        
        @type  data: STRING
        @param data: Message for the column
        
        @type  address: DWORD
        @param address: (Optional, Default: 0) Address related to the message
        
        @type  focus: BOOLEAN
        @param focus: (Optional, Default: False) Whether or not give focus to the window
        """
        return debugger.Addtotable(self.instance,address,"0x%08x" % address, data,"","","")

    
    def isValidHandle(self):
        return debugger.IsValidHandle(self.instance)
    
    
    def add(self,address,data):
        """
        Add Data to the Window
        
        @type  address: DWORD
        @param address: Address related to the Data
        
        @type  data: LIST OF STRING
        @param data: Data to add on the different columns        
        """
        col1=""
        col2=""
        col3=""
        col4=""
        col5=""
        if not address:
            address=0x0
        try:
            col1=data[0]
        except:
            pass
        try:
            col2=data[1]
        except:
            pass
        try:
            col3=data[2]
        except:
            pass
        try:
            col4=data[3]
        except:
            pass
        try:
            col5=data[4]
        except:
            pass
        return debugger.Addtotable(self.instance,address,col1,col2,col3,col4,col5)
        
    
MemoryProtection = { 0x10 : "PAGE_EXECUTE", 0x20 : "PAGE_EXECUTE_READ", 0x40: "PAGE_EXECUTE_READWRITE",\
                     0x80 : "PAGE_EXECUTE_WRITECOPY", 0x01: "PAGE_NOACCESS", 0x02: "PAGE_READONLY",\
                     0x04 : "PAGE_READWRITE", 0x08: "PAGE_WRITECOPY" }

class MemoryPage:
    def __init__(self, baseaddress, imm):
        """
        Memory Page Information
        
        @type  baseaddress: DWORD
        @param baseaddress: Base Address of the Memory Page
        
        @type  imm: Debugger OBJECT
        @param imm: Debugger
        """
        self.baseaddress = baseaddress
        self.imm = imm
        self.size = 0
        self.type  = 0
        self.owner = 0
        self.initaccess = 0
        self.access = 0
        self.threadid = 0
        self.section = ""
        self.mem = ""
        
    def _getfromtuple(self, mem):
        requery = debugger.VmQuery(self.baseaddress)
        self.size       = mem[0]
        self.type       = mem[1]
        self.owner      = mem[2]
        self.initaccess = requery[4]
        self.access     = requery[3]
        self.threadid   = mem[5]
        self.section   = mem[6]

    def getBaseAddress(self):
        return self.baseaddress
    
    def getSize(self):
        return self.size       

    def getType(self):
        """
        Get Type of Memory Page
        
        @rtype:  DWORD
        @return: Type of Page
        """
        return self.type       

    def getOwner(self):
        """ 
        Get the Owner of the Memory Page
        
        @rtype:  STRING
        @return: Owner of the Page
        """
        # use to use getModulebyAddress
        mod = self.imm.findModule(self.owner)
        if not mod:
            return "0x%08x" %  self.owner      
        else:
            return mod[0]
        
    def _getflags(self, page):
        try:
            return PageFlags[page]
        except KeyError:
            return "   "
        
    def getInitAccess(self,human=0):
        """
        Get the Intial Access Flag of the Memory Page

        @type  human: Human Readable String Flag
        @param human: Boolean
        
        @rtype:  DWORD
        @return: Initial Access Flag
        
        
        """
        if human == 0:
            return self.initaccess
        else:
            return MemoryProtection[self.initaccess & 0xFF]

    def getAccess(self,human=0):
        """
        Get the Access Flag of the Memory Page
        
        @type  human: Human Readable String Flag
        @param human: Boolean
        
        @rtype:  DWORD
        @return: Access Flag
        """
        if human == 0:
            return self.access
        else:
            return MemoryProtection[self.access & 0xFF]



    def getThreadID(self):
        """
        Get the ID of the Thread
        
        @rtype:  DWORD
        @return: Thread ID
        """
        return self.threadid   

    def getMemory(self):
        """
        Get the Memory of the Page
        
        @rtype:  BUFFER
        @return: Page Memory
        """
        if not self.mem:
            self.mem = self.imm.readMemory(self.baseaddress, self.size) 
        return self.mem

    def getBaseAddress(self):
        """
        Get the Base Address of the Memory Page
        
        @rtype:  DWORD
        @return: Base Address
        """
        return self.baseaddress

    def getSection(self):
        """
        Get the Section from the Memory Page
        
        @rtype:  STRING
        @return: Section
        """
        return self.section
    

            

#PEB class (taken for bas's PDB)
class PEB:
    def __init__(self, imm):
        """ 
        Process Environment Block
        
        @type  imm: Debugger OBJECT
        @param imm: Debugger        
        """
        # PEB struct is 488 bytes (win2k) located at 0x7ffdf000
        # can also use NTQueryProcessInformation to locate PEB base
        self.base = imm.getPEBaddress()

        try:
            self.PEB = imm.readMemory(self.base, 488)
        except:
            error = "can't read PEB struct"
            raise Exception, error

        """
        0:000> !kdex2x86.strct PEB
        Loaded kdex2x86 extension DLL
        struct   _PEB (sizeof=488)
        +000 byte     InheritedAddressSpace
        +001 byte     ReadImageFileExecOptions
        +002 byte     BeingDebugged
        +003 byte     SpareBool
        +004 void     *Mutant
        +008 void     *ImageBaseAddress
        +00c struct   _PEB_LDR_DATA *Ldr
        +010 struct   _RTL_USER_PROCESS_PARAMETERS *ProcessParameters
        +014 void     *SubSystemData
        +018 void     *ProcessHeap
        +01c void     *FastPebLock
        +020 void     *FastPebLockRoutine
        +024 void     *FastPebUnlockRoutine
        +028 uint32   EnvironmentUpdateCount
        +02c void     *KernelCallbackTable
        +030 uint32   SystemReserved[2]
        +038 struct   _PEB_FREE_BLOCK *FreeList
        +03c uint32   TlsExpansionCounter
        +040 void     *TlsBitmap
        +044 uint32   TlsBitmapBits[2]
        +04c void     *ReadOnlySharedMemoryBase
        +050 void     *ReadOnlySharedMemoryHeap
        +054 void     **ReadOnlyStaticServerData
        +058 void     *AnsiCodePageData
        +05c void     *OemCodePageData
        +060 void     *UnicodeCaseTableData
        +064 uint32   NumberOfProcessors
        +068 uint32   NtGlobalFlag
        +070 union    _LARGE_INTEGER CriticalSectionTimeout
        +070 uint32   LowPart
        +074 int32    HighPart
        +070 struct   __unnamed3 u
        +070 uint32   LowPart
        +074 int32    HighPart
        +070 int64    QuadPart
        +078 uint32   HeapSegmentReserve
        +07c uint32   HeapSegmentCommit
        +080 uint32   HeapDeCommitTotalFreeThreshold
        +084 uint32   HeapDeCommitFreeBlockThreshold
        +088 uint32   NumberOfHeaps
        +08c uint32   MaximumNumberOfHeaps
        +090 void     **ProcessHeaps
        +094 void     *GdiSharedHandleTable
        +098 void     *ProcessStarterHelper
        +09c uint32   GdiDCAttributeList
        +0a0 void     *LoaderLock
        +0a4 uint32   OSMajorVersion
        +0a8 uint32   OSMinorVersion
        +0ac uint16   OSBuildNumber
        +0ae uint16   OSCSDVersion
        +0b0 uint32   OSPlatformId
        +0b4 uint32   ImageSubsystem
        +0b8 uint32   ImageSubsystemMajorVersion
        +0bc uint32   ImageSubsystemMinorVersion
        +0c0 uint32   ImageProcessAffinityMask
        +0c4 uint32   GdiHandleBuffer[34]
        +14c function *PostProcessInitRoutine
        +150 void     *TlsExpansionBitmap
        +154 uint32   TlsExpansionBitmapBits[32]
        +1d4 uint32   SessionId
        +1d8 void     *AppCompatInfo
        +1dc struct   _UNICODE_STRING CSDVersion
        +1dc uint16   Length
        +1de uint16   MaximumLength
        +1e0 uint16   *Buffer
        """
        # init PEB struct
        index = 0x000
        self.InheritedAddressSpace = struct.unpack("B",self.PEB[index])
        index = 0x001
        self.ReadImageFileExecOptions = struct.unpack("B",self.PEB[index])
        index = 0x002
        self.BeingDebugged = struct.unpack("B",self.PEB[index])
        index = 0x003
        self.SpareBool = struct.unpack("B",self.PEB[index])
        index = 0x004
        self.Mutant = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x008
        self.ImageBaseAddress = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x00c
        self.Ldr = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x010
        self.ProcessParameters = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x014
        self.SubSystemData = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x018
        self.ProcessHeap = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x01c
        self.FastPebLock = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x020
        self.FastPebLockRoutine = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x024
        self.FastPebUnlockRoutine = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x028
        self.EnviromentUpdateCount = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x02c
        self.KernelCallbackTable = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x030
        self.SystemReserved = []
        for i in range(0,2):
            self.SystemReserved.append(struct.unpack("<L",self.PEB[index:index+4]))
            index += 4
        index = 0x038
        self.FreeList = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x03c
        self.TlsExpansionCounter = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x040
        self.TlsBitmap = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x044
        self.TlsBitmapBits = []
        for i in range(0,2):
            self.TlsBitmapBits.append(struct.unpack("<L",self.PEB[index:index+4]))
            index += 4
        index = 0x04c
        self.ReadOnlySharedMemoryBase = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x050
        self.ReadOnlySharedMemoryheap = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x054
        self.ReadOnlyStaticServerData = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x058
        self.AnsiCodePageData = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x05c
        self.OemCodePageData = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x060
        self.UnicodeCaseTableData = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x064
        self.NumberOfProcessors = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x068
        self.NtGlobalFlag = struct.unpack("<L",self.PEB[index:index+4])

        # ??? WHAT HAPPENS TO THE 4 bytes here ?

        index = 0x070
        self.CriticalSectionTimeout_LowPart = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x074
        self.CriticalSectionTimeout_HighPart = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x078
        self.HeapSegmentReserve = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x07c
        self.HeapSegmentCommit = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x080
        self.HeapDeCommitTotalFreeThreshold = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x084
        self.HeapDeCommitFreeBlockThreshold = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x088
        self.NumberOfHeaps = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x08c
        self.MaximumNumberOfHeaps = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x090
        self.ProcessHeaps = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x094
        self.GdiSharedHandleTable = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x098
        self.ProcessStarterHelper = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x09c
        self.GdiDCAttributeList = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x0a0
        self.LoaderLock = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x0a4
        self.OSMajorVersion = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x0a8
        self.OSMinorVersion = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x0ac
        self.OSBuildNumber = struct.unpack("<H",self.PEB[index:index+2])
        index = 0x0ae
        self.OSCSDVersion = struct.unpack("<H",self.PEB[index:index+2])
        index = 0x0b0
        self.OSPlatformId = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x0b4
        self.ImageSubsystem = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x0b8
        self.ImageSubsystemMajorVersion = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x0bc
        self.ImageSubsystemMinorVersion = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x0c0
        self.ImageProcessAffinityMask = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x0c4
        # uint32 GdiHandleBuffer[34]
        self.GdiHandleBuffer = []
        for i in range(0,34):
            self.GdiHandleBuffer.append(struct.unpack("<L",self.PEB[index:index+4]))
            index += 4
        index = 0x14c
        self.PostProcessInitRoutine = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x150
        self.TlsExpansionBitmap = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x154
        # uint32 TlsExpansionBitmapBits[32]
        self.TlsExpansionBitmapBits = []
        for i in range(0,32):
            self.TlsExpansionBitmapBits.append(struct.unpack("<L",self.PEB[index:index+4]))
            index += 4
        index = 0x1d4
        self.SessionId = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x1d8
        self.AppCompatInfo = struct.unpack("<L",self.PEB[index:index+4])
        index = 0x1dc
        # struct _UNICODE_STRING CSDVersion
        self.CSDVersion_Length = struct.unpack("<H",self.PEB[index:index+2])
        index += 2
        self.CSDVersion_MaximumLength = struct.unpack("<H",self.PEB[index:index+2])
        index += 2
        self.CSDVersion_Buffer = struct.unpack("<H",self.PEB[index:index+2])
        index += 2

