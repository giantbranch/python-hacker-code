#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}


"""

__VERSION__ = '1.1'

import struct
import debugger 
import pickle

FS_UNHOOK  = 0  
FS_HOOK    = 1 # hooked and running
FS_PAUSE   = 2

HookTypes  = {"ORDINARY_BP_HOOK" : 3900, "LOG_BP_HOOK" : 3909,\
              "EVERY_EXCEPTION_HOOK" : 3901,\
              "POST_ANALYSIS_HOOK" : 3902, "ACCESS_VIOLATION_HOOK": 3910,\
              "LOAD_DLL_HOOK" : 3903, "UNLOAD_DLL_HOOK" : 3904,\
              "CREATE_THREAD_HOOK" : 3905, "EXIT_THREAD_HOOK" : 3906,\
              "CREATE_PROCESS_HOOK" : 3907, "EXIT_PROCESS_HOOK" : 3908,\
              "PRE_BP_HOOK" : 3911}

HOOK_REG = {'ESI': '[ESP+4   ]',  'EDI': '[ESP]',\
            'EBX': '[ESP+0x10]',  'EAX': '[ESP+0x1C]',\
            'ECX': '[ESP+0x18]',  'EDX': '[ESP+0x14]',\
            'EBP': '[ESP+0x8 ]',  'ESP': '[ESP+0xC ]'}


class FastLogHook:
    def __init__(self, imm):
        self.address = None
        self.tbl   = []
        self.list  = []
        self.entry = []
        self.hooked = False
        self.mem = None
        self.imm = imm
        self.restore = []       
        self.status = FS_UNHOOK

    def isHooked(self):
        return self.status == FS_HOOK       
    
    def isPause(self):
        return self.status == FS_PAUSE

    def Pause(self):
        if not self.isHooked():
            return False
    
        # Removing Hook on every function
        for ndx in range(0, len(self.tbl) ):    
            self.imm.writeMemory( self.tbl[ndx][0], self.restore[ndx][0] )

        self.status = FS_PAUSE
        return True
        
    def Continue(self):
        if not self.isPause():
            return False

        for ndx in range(0, len(self.tbl) ):
            self.imm.writeMemory( self.tbl[ndx][0], self.restore[ndx][1] )
        self.status = FS_HOOK       
        return True

    def unHook(self):
        if not self.isHooked(): 
            return False                
         
        # Removing Hook on every function
        for ndx in range(0, len(self.tbl) ):    
            self.imm.writeMemory( self.tbl[ndx][0], self.restore[ndx][0] )                 # Cleaning up Hook Memory
        self.imm.rVirtualFree( self.mem )           
        self.status = FS_UNHOOK
        return True
            
    def setRestore(self, restore): 
        self.restore = restore
        
    def Hook(self):
        self.addFastLogHook()
        self.status = FS_HOOK
        return True     

    def setMem(self, mem):
        self.mem = mem

    def logFunction(self, address):
        if self.address:
            self.tbl.append( (self.address,  self.entry) )
            self.entry = []
        self.address = address

    def logRegister(self, REG):
        self.entry.append( (REG,) )

    def logDirectMemory(self, address):
        self.entry.append( (address,) )

    def logBaseDisplacement(self, REG, offset = 0 ):
        self.entry.append( ( REG, offset) )

    def getAllUniqueFunctions(self):
        ndx      = 0
        addr     = self.mem
        self._fn = {}
        self.ret = []

        while ndx != -1 :
            mem   = self.imm.readMemory( addr, 0x1000)
            ndx   = self._parseUniqueFn( mem )
            addr += ndx
            
        return self._fn
        
    def getAllLog(self):
        mem      = ""
        ndx      = 0
        self.ret = []
        flag     = False
        addr     = self.mem

        while ndx != -1 :
            mem   = self.imm.readMemory( addr, 0x1000)
            ndx   = self._parseMem( mem )
            addr += ndx

        return self.ret

    def _parseUniqueFn(self, mem):
        mem_size = len(mem)         
        ndx = 0
        while ndx < len(mem):
            index = struct.unpack("L", mem[ ndx : ndx+4 ] )[0]
            if index == 0:
                return -1 # Finished correctly
            if index > (len(self.tbl) + 1) :
                return -1
            
            entry   = self.tbl[ index -1 ][1]
            ndx    += 4
            size_e  = len(entry) 
            if (size_e*4 + ndx) > ( mem_size):
                return ndx - 4 # REQUEST MORE MEM 
            ndx += size_e * 4 
            
            addr = self.tbl[ index -1 ][0]
            if self._fn.has_key( addr ):
                self._fn[ addr ] += 1
            else:
                self._fn[ addr ]  = 1
        return ndx

        
    def _parseMem(self, mem):
        mem_size = len(mem)
        ndx = 0 
        #self.imm.Log("table: %d" % len(self.tbl) )
        while ndx < len(mem) :
            index = struct.unpack("L", mem[ ndx : ndx+4 ] )[0]
            #self.imm.Log("Index: %d" % index)
            if index == 0:
                return -1 # Finished correctly
            if index > (len(self.tbl) + 1) :
                return -1
            
            entry   = self.tbl[ index -1 ][1]
            ndx    += 4
            size_e  = len(entry) 
            if (size_e*4 + ndx) > ( mem_size):
                return ndx - 4 # REQUEST MORE MEM 
            ret     = struct.unpack( "L" * size_e, mem[ ndx : ndx + size_e *4 ] )
            ndx += size_e * 4 
            self.ret.append( ( self.tbl[ index - 1 ][0], ret) )
        return ndx

    def get(self):
        self.logFunction(None)
        return self.tbl 

    def setTable(self, tbl):
        self.tbl = tbl
        
    def addFastLogHook(self, alloc_size = 0x100000, memAddress = 0x0): 
        CODE_HOOK_START = 8
        #flh = hook
        # Get the table of functions from the hook
        table = self.get()
        self.imm.Log("TABLE SIZE: %d" % len(table) )
        # Allocate memory for the hook and the log
        if not memAddress: 
            memAddress = self.imm.remoteVirtualAlloc( alloc_size )

        self.memAddress = memAddress

        self.imm.Log( "Logging at 0x%08x" % memAddress )

        # MEMORY LOOKS LIKE:
        # mem     [ ptr to data        ]
        # mem + 4 [ deadlock           ]
        # mem + 8 [ start of hook code ]
        # mem + n [ ...                ]
        # mem + n [ start of data      ]

        ptr = memAddress + CODE_HOOK_START
        
        fn_restore = []

#        for fn_ndx in range( 0, len(table) ):
        fn_ndx = 0
        while fn_ndx < len(table) :
            hookAddress = table[ fn_ndx ][0]
            entry       = table[ fn_ndx ][1]

            idx         = 0
            #patch_code  = self.imm.Assemble( "PUSH 0x%08x\nRET" % ptr )
            patch_code  = self.imm.Assemble( "JMP 0x%08x" % ptr, address = hookAddress )
            
            while idx < len(patch_code): 
                op   = self.imm.Disasm( hookAddress + idx )
                idx += op.getOpSize()
                if op.isCall() or op.isJmp():
                    op = None
                    break
                
            # Removing the BP from the table
            if not op:
                self.imm.Log("deleting: %d" % fn_ndx)
                del table[ fn_ndx ]
                continue
            
            ex_prelude = self.imm.readMemory( hookAddress, idx ) 
                     
            code = self.imm._createCodeforHook( memAddress, hookAddress + idx,\
                            fn_ndx + 1, entry, ex_prelude, alloc_size)
        
            self.imm.writeMemory( ptr , code )
            ptr += len(code)
            self.imm.writeMemory( hookAddress, patch_code )

            fn_restore.append( (ex_prelude, patch_code ) ) # Correspond in index with function address
            fn_ndx += 1
            
        self.setTable( table )
        if ptr % 4:
            ptr = 4 + ptr & ~(4-1)
        self.setMem( ptr )
        self.imm.writeLong( memAddress, ptr )
        self.setRestore( fn_restore )
        

    
class STDCALLFastLogHook(FastLogHook):
    def __init__(self, imm):
        FastLogHook.__init__(self, imm)
    def logFunction(self, address, args = 0 ):
        if self.address:
            self.tbl.append( (self.address,  self.entry) )
            self.entry = []
    
        self.address = address
        for ndx in range(0, args):
            self.logBaseDisplacement( "ESP", ndx*4 + 4 )

#HOOK class
class Hook:
    def __init__(self):
        self.type=0
        self.msg=""
        self.string=""
        self.address=0
        self.enabled=True # by default hook is enabled
        
    def enable(self):
        """Enable hook execution"""
        self.enabled=True
    
    def disable(self):
        """Disable hook execution"""
        self.enabled=False
        
    def UnHook(self):
        """Remove the hook"""
        debugger.Removehook(self.desc)
        
    def add(self,description,address=0,force=0,timeout=0,mode=0):
        """Add hook to Immunity Debugger hook database
        @param type: Type of hook
        @param desc: Descriptive string
        @param force: Force hook adding
        @param timeout: time to live in memory
        @param mode: thread mode of ttl execution
        """
        
        self.desc = description
        self.address = address
        self.force=force
        self.timeout=timeout
        # mode = 1 then, execute ttl hook in the same thread enviroment as the python command/script
        # mode = 0 use your own thread enviroment to place and execute the ttl hook 
        # you'll be using mode = 0 at least you really know what you are doing.
        
        self.mode=mode
        if self.type == HookTypes["ORDINARY_BP_HOOK"]:
            debugger.Setbreakpoint(self.address,0x200L,"")
        elif self.type == HookTypes["LOG_BP_HOOK"]:
            debugger.Setloggingbreakpoint(self.address)
        pickled_object = pickle.dumps(self)
        return debugger.Addhook( pickled_object , self.desc , self.type, self.address,self.force,self.timeout,self.mode)
    
    def _run(self,regs):
        """regs is the actual cpu context, be sure of using this values
        and not the ones from imm.getRegs() at hook time"""
        self.regs=regs
        self.run(regs)
        
    def _runTimeout(self,regs):
        """regs is the actual cpu context, be sure of using this values
        and not the ones from imm.getRegs() at hook time"""
        self.regs=regs
        self.runTimeout(regs)

    
    # function that will be runned once the hook is triggered
    def run(self,regs):
        debugger.Error("Your hook doesnt seem to have run() defined")
        return
    
    def runTimeout(self,regs):
        debugger.Error("Your hook doesnt seem to have runTimeout() defined")
        return
        
    
class BpHook(Hook):
    def __init__(self):
        Hook.__init__(self)
        self.type = HookTypes["ORDINARY_BP_HOOK"] 
        self.desc = "BreakpointHook"
        
class LogBpHook(Hook):
    def __init__(self):
        Hook.__init__(self)
        self.type = HookTypes["LOG_BP_HOOK"] 
        self.desc = "LoggingPointHook"
        
class PreBpHook(Hook):
    def __init__(self):
        Hook.__init__(self)
        self.type = HookTypes["PRE_BP_HOOK"] 
        self.desc = "PreBreakpointHook"
        
class AllExceptHook(Hook):
    def __init__(self):
        Hook.__init__(self)
        self.type = HookTypes["EVERY_EXCEPTION_HOOK"] 
        self.desc = "EveryExceptionHook"
        
class PostAnalysisHook(Hook):
    def __init__(self):
        Hook.__init__(self)
        self.type = HookTypes["POST_ANALYSIS_HOOK"] 
        self.desc = "PostAnalysisHook"
        
class AccessViolationHook(Hook):
    def __init__(self):
        Hook.__init__(self)
        self.type = HookTypes["ACCESS_VIOLATION_HOOK"] 
        self.desc = "AcessViolationHook"

class RunUntilAV(Hook):
    def __init__(self,imm):
        Hook.__init__(self)
        self.type = HookTypes["ACCESS_VIOLATION_HOOK"] 
        self.desc = "AcessViolationHook"
        imm.Run()
        

class LoadDLLHook(Hook):
    def __init__(self):
        Hook.__init__(self)
        self.type = HookTypes["LOAD_DLL_HOOK"] 
        self.desc = "LoadDLLHook"

class UnloadDLLHook(Hook):
    def __init__(self):
        Hook.__init__(self)
        self.type = HookTypes["UNLOAD_DLL_HOOK"] 
        self.desc = "UnloadDLLHook"

class CreateThreadHook(Hook):
    def __init__(self):
        Hook.__init__(self)
        self.type = HookTypes["CREATE_THREAD_HOOK"] 
        self.desc = "CreateThreadHook"

class ExitThreadHook(Hook):
    def __init__(self):
        Hook.__init__(self)
        self.type = HookTypes["EXIT_THREAD_HOOK"] 
        self.desc = "ExitThreadHook"

class CreateProcessHook(Hook):
    def __init__(self):
        Hook.__init__(self)
        self.type = HookTypes["CREATE_PROCESS_HOOK"] 
        self.desc = "CreateProcessHook"

class ExitProcessHook(Hook):
    def __init__(self):
        Hook.__init__(self)
        self.type = HookTypes["EXIT_PROCESS_HOOK"] 
        self.desc = "ExitProcessHook"
