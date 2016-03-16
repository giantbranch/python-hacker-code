#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}


"""

__VERSION__ = '1.3'

import UserList
import debugger

# REGISTER STATUS
RST_INVALID  =  0               # Register undefined
RST_VALUE    =  1               # Register contains regdata
RST_VFIXUP   =  2               # Reg contains regdata that is fixup
RST_INDIRECT =  3               # Register contains [regdata]


# DISASM MODE
DISASM_SIZE   = 0              # Determine command size only
DISASM_DATA   = 1              # Determine size and analysis data
DISASM_TRACE  = 2              # Trace integer registers
DISASM_FILE   = 3              # Disassembly, no symbols/registers
DISASM_CODE   = 4              # Disassembly, registers undefined
DISASM_ALL    = 5              # Completely disassembly
DISASM_RTRACE = 6              # Disassemble with run-trace registers

# Types for Opcode
C_TYPEMASK =  0xF0            # Mask for command type
C_CMD =       0x00            # Ordinary instruction
C_PSH =       0x10            # PUSH instruction
C_POP =       0x20            # POP instruction
C_MMX =       0x30            # MMX instruction
C_FLT =       0x40            # FPU instruction
C_JMP =       0x50            # JUMP instruction
C_JMC =       0x60            # Conditional JUMP instruction
C_CAL =       0x70            # CALL instruction
C_RET =       0x80            # RET instruction
C_FLG =       0x90            # Changes system flags
C_RTF =       0xA0            # C_JMP and C_FLG simultaneously
C_REP =       0xB0            # Instruction with REPxx prefix
C_PRI =       0xC0            # Privileged instruction
C_SSE =       0xD0            # SSE instruction
C_NOW =       0xE0            # 3DNow! instruction
C_BAD =       0xF0            # Unrecognized command

# Decode type
DEC_TYPEMASK = 0x1F     # Type of memory byte
DEC_UNKNOWN  = 0x00     # Unknown type
DEC_BYTE     = 0x01     # Accessed as byte
DEC_WORD     = 0x02     # Accessed as short
DEC_NEXTDATA = 0x03     # Subsequent byte of data
DEC_DWORD    = 0x04     # Accessed as long
DEC_FLOAT4   = 0x05     # Accessed as float
DEC_FWORD    = 0x06     # Accessed as descriptor/long pointer
DEC_FLOAT8   = 0x07     # Accessed as double
DEC_QWORD    = 0x08     # Accessed as 8-byte integer
DEC_FLOAT10  = 0x09     # Accessed as long double
DEC_TBYTE    = 0x0A     # Accessed as 10-byte integer
DEC_STRING   = 0x0B     # Zero-terminated ASCII string
DEC_UNICODE  = 0x0C     # Zero-terminated UNICODE string
DEC_3DNOW    = 0x0D     # Accessed as 3Dnow operand
DEC_SSE      = 0x0E     # Accessed as SSE operand
DEC_TEXT     = 0x10     # For use in t_result only
DEC_BYTESW   = 0x11     # Accessed as byte index to switch
DEC_NEXTCODE = 0x13     # Subsequent byte of command
DEC_COMMAND  = 0x1D     # First byte of command
DEC_JMPDEST  = 0x1E     # Jump destination
DEC_CALLDEST = 0x1F     # Call (and maybe jump) destination

DEC_PROCMASK = 0x60     # Procedure analysis
DEC_PROC     = 0x20     # Start of procedure
DEC_PBODY    = 0x40     # Body of procedure
DEC_PEND     = 0x60     # End of procedure

DEC_CHECKED  = 0x80     # Byte was analysed
DEC_SIGNED   = 0x100    # For use in t_result only

DECR_TYPEMASK = 0x3F    # Type of register or memory
DECR_BYTE     = 0x21    # Byte register
DECR_WORD     = 0x22    # Short integer register
DECR_DWORD    = 0x24    # Long integer register
DECR_QWORD    = 0x28    # MMX register
DECR_FLOAT10  = 0x29    # Floating-point register
DECR_SEG      = 0x2A    # Segment register
DECR_3DNOW    = 0x2D    # 3Dnow! register
DECR_SSE      = 0x2E    # SSE register

DECR_ISREG    = 0x20    # Mask to check that operand is register
DEC_CONST     = 0x40    # Immediate constant, used by Analyser

RegisterName = { (0,0,0,0,0,0,0,0):"", (1,0,0,0,0,0,0,0):"EAX",(0,1,0,0,0,0,0,0):"ECX",\
                 (0,0,1,0,0,0,0,0):"EDX", (0,0,0,1,0,0,0,0):"EBX",(0,0,0,0,1,0,0,0):"ESP",\
                 (0,0,0,0,0,1,0,0):"EBP", (0,0,0,0,0,0,1,0):"ESI", (0,0,0,0,0,0,0,1):"EDI"}

COUNT = 100
class opCode:
    def __init__(self, imm, addr):
        self.imm = imm
        self.address = addr
        self.operand = []


    def _getfromtuple(self, opcode):
        self.ip=opcode[0]            # Instruction pointer
        self.dump=opcode[1]          # Hexadecimal dump of the command
        self.result=opcode[2]        # Disassembled command
        self.comment=opcode[3]       # Brief comment
        self.opinfo=opcode[4]        # Comments to command's operands (tuple[3])
        self.cmdtype=opcode[5]       # One of C_xxx
        self.memtype=opcode[6]       # Type of addressed variable in memory
        self.nprefix=opcode[7]       # Number of prefixes
        self.indexed=opcode[8]       # Address contains register(s)
        self.jmpconst=opcode[9]      # Constant jump address
        self.jmptable=opcode[10]      # Possible address of switch table
        self.adrconst=opcode[11]     # Constant part of address
        self.immconst=opcode[12]     # Immediate constant
        self.zeroconst=opcode[13]    # Whether contains zero constant
        self.fixupoffset=opcode[14]  # Possible offset of 32-bit fixups
        self.fixupsize=opcode[15]    # Possible total size of fixups or 0
        self.jmpaddr=opcode[16]      # Destination of jump/call/return
        self.condition=opcode[17]    # 0xFF:unconditional, 0:false, 1:true
        self.error=opcode[18]        # Error while disassembling command
        self.warnings=opcode[19]     # Combination of DAW_xxx
        self.optype=opcode[20]       # Type of operand (extended set DEC_xxx) (tuple[3])
        self.operandsize=opcode[21]  # Size of operand, bytes (tuple[3])
        self.opsize=opcode[22]       #common opsize in bytes (this is the one you want, almost sure)
        self.opgood=opcode[23]       # Whether address and data valid (tuple[3])
        self.opaddr=opcode[24]       # Address if memory, index if register (tuple[3])
        self.opdata=opcode[25]       # Actual value (only integer operands) (tuple[3])
        #NOTE ABOUT self.operand:
        #self.operand[n][0] = operand type DEC_xxx (mem) or DECR_xxx (reg,const)
        #self.operand[n][1] = operand size
        #self.operand[n][2][x] = where x any reg value from 0 to 7 = scales of registers
        #self.operand[n][3] segment register
        #self.operand[n][4] Constant
        self.operand=opcode[26]      # Full description of operand (tuple[3])


        self.regdata=opcode[27]       # Registers after command is executed / status of registers list[(reg,status)]
        self.addrdata=opcode[28]      # Traced memory address
        self.addrstatus=opcode[29]    # Status of addrdata, one of RST_xxx
        self.regstack=opcode[30]      # Stack tracing buffer / status of stack items list[(stack,status)]
        #self.nregstack=opcode[32]    # Number of items in stack trace buffer        

    # We need to include more than one register
    # ex: [EAX+EDI+2]
    def getOperandRegister(self, num):
        try:
            return RegisterName[ self.operand[num][2] ]
        except KeyError:
            return "[]"

    def getIP(self):
        return self.ip

    def getAddress(self):
        return self.address

    def getDump(self):
        return self.dump

    def getResult(self):
        return self.result

    def getDisasm(self):
        return self.result

    def getComment(self):
        return self.comment

    def getOpInfo(self):
        return self.opinfo

    def isCmd(self):
        return self.getCmdType() == C_CMD

    def isPush(self):
        return self.getCmdType() == C_PSH

    def isPop(self):
        return self.getCmdType() == C_POP

    def isCall(self):
        return self.getCmdType() == C_CAL

    def isJmp(self):
        return self.getCmdType() == C_JMP

    def isConditionalJmp(self):
        return self.getCmdType() == C_JMC

    def isRet(self):
        return self.getCmdType() == C_RET

    def isRep(self):
        return self.getCmdType() == C_REP

    def getCmd(self):
        return self.cmdtype

    def getCmdType(self):
        # types are defined as C_*
        return self.cmdtype & C_TYPEMASK

    def getMemType(self):
        return self.memtype

    def getnPrefix(self):
        return self.nprefix

    def getIndexed(self):
        return self.indexed

    def getJmpConst(self):
        return self.jmpconst

    def getJmpTable(self):
        return self.jmptable

    def getAddrConst(self):
        return self.adrconst

    def getImmConst(self):
        return self.immconst

    def getZeroConst(self):
        return self.zeroconst

    def getFixUpOffset(self):
        return self.fixupoffset

    def getFixUpSize(self):
        return self.fixupsize

    def getJmpAddr(self):
        return self.jmpaddr

    def getCondition(self):
        return self.condition

    def getError(self):
        return self.error

    def getWarnings(self):
        return self.warnings

    def getOpType(self):
        return self.optype

    def getOpSize(self):
        return self.opsize

    def getSize(self):
        return self.opsize

    def getOpGood(self):
        return self.opgood

    def getOpAddr(self):
        return self.opaddr

    def getOpData(self):
        return self.opdata

    def getRegData(self):
        return self.regdata

    def getRegStatus(self):
        return self.regdata

    def getAddrData(self):
        return self.addrdata

    def getAddrStatus(self):
        return self.addrstatus

    def getRegStack(self):
        return self.regstack

    def getRstStatus(self):
        return self.regstack

    def getnRegStack(self):
        return "deprecated"

    #NOTE: info panel is runtime information, no matter which opcode you use to fetch it
    #      you'll have the info IP linked.

    def getInfoPanel(self):
        return debugger.Getinfopanel()

class Decode(UserList.UserList):
    def __init__(self, address):
        """
        Internal Information of the Analyzed Code

        @type  address: DWORD
        @param address: Address in the range of the analized code you want to retrieve
        """
        UserList.UserList.__init__(self)
        self.address = address
        self.data = debugger.FindDecode( address )

    def __getitem__(self, i):
        try:
            return ord( self.data[ i - self.address  ] )
        except IndexError:
            raise IndexError, "Address 0x%08x not in this Decode" % i

    def __setitem__(self, i, item):
        self.data[ i - self.address ] = item

    def isJmpDestination(self, i):
        """
        Check Whether or not the provided address is a destination for a jmp instruction

        @type  i: DWORD
        @param i: Address to check

        @rtype:  BOOLEAN
        @return: Whether or not the provided address is a destination for a jmp instruction
        """
        return ( self.__getitem__( i ) & DEC_TYPEMASK ) == DEC_JMPDEST

    def isCallDestination(self, i):
        """
        Check Whether or not the provided address is a destination for a call instruction

        @type  i: DWORD
        @param i: Address to check

        @rtype:  BOOLEAN
        @return: Whether or not the provided address is a destination for a call instruction        
        """
        return ( self.__getitem__( i ) & DEC_TYPEMASK ) == DEC_CALLDEST

    def isCommand(self, i):
        """
        Check Whether or not the provided address has a command (regular opcode)

        @type  i: DWORD
        @param i: Address to check

        @rtype:  BOOLEAN
        @return: Whether or not the provided address a command (regular opcode)
        """
        return ( self.__getitem__( i ) & DEC_TYPEMASK ) == DEC_COMMAND

    def isFunctionStart(self, i):
        """
        Check Whether or not the provided address is the begging of a Function

        @type  i: DWORD
        @param i: Address to check

        @rtype:  BOOLEAN
        @return: Whether or not the provided address is the begging of a Function        
        """
        return ( self.__getitem__( i ) & DEC_PROCMASK ) == DEC_PROC

    def isFunctionBody(self, i):
        """
        Check Whether or not the provided address is part of a Function

        @type  i: DWORD
        @param i: Address to check

        @rtype:  BOOLEAN
        @return: Check Whether or not the provided address is part of a Function
        """
        return ( self.__getitem__( i ) & DEC_PROCMASK ) == DEC_PBODY


class Function:
    """
    Class that contains information about a Function
    """    
    def __init__(self, imm, start):
        """
        Class that contains information about a Function

        @type  imm: Debbuger OBJECT
        @param imm: Debbuger

        @type  start: DWORD
        @param start: Address of the begging of the function
        """
        if not start:
            raise Exception, "Wrong Function Address: 0x%08x" % start

        self.start  = start
        self.imm    = imm
        self.bb     = []
        self.bbhash = {} # Hash that contains the visited Blocks

    def setStart(self,address):
        """
        Change the start of a Function

        @type  address: DWORD
        @param address: New address of the function
        """
        self.start = address


    def getStart(self):
        """
        Get the Address of the Function

        @rtype:  DWORD
        @return: Address of the function
        """
        return self.start

    def getName(self):
        """
        Get the name of the Function

        @rtype:  STRING
        @return: Name of the Function
        """
        return self.imm.decodeAddress(self.start)

    def getFunctionEnd(self):
        ret = []
        endblocks = self.getEnd() 
        for bb in endblocks:
            op = self.imm.disasmBackward( bb.getEnd() )
            ret.append( op.getAddress() )
        return ret

    def getEnd(self):
        """
        Get the end of the Function (Understanding end as the Basic Block with a ret inside)

        @rtype:  LIST of BasicBlock
        @return: A list of all the basic block that end the function
        """
        ret = []
        bb  = self.getBasicBlocks()
        for a in bb:
            if a.isRet():
                ret.append( a )
        return ret

    def findRetValue(self):
        """
        Find all the possible ret values on a function (Beta)
        Note: This function only check the modifiers on a Ret BasicBlock, so the result might not be precise.

        @type  start: LIST OF OPCODE
        @param start: Return all the possible modifiers of EAX
        """
        ret = []
        endblocks = self.getEnd() # Grab all the Blocks with "Ret" on it.
        for bb in endblocks:
            opcodes = bb.getInstructions(self.imm)
            # We are gonna loop over the instruction on the block backwardly, in order to
            # find who is modifying eax before the ret.
            for a in range( len(opcodes)-1, 0, -1): 
                op = opcodes[a]
                if op.getOperandRegister(0) == "EAX" and op.optype[0] == 36:
                    ret.append( op )
                    break
        return ret


    def hasAddress(self, address):
        """ 
        Check if the given address is part of the Function

        @type  address: DWORD
        @param force: Address of the instruction to check

        @rtype:  BasicBlock object
        @return: If true, returns the corresponding Basic block else returns None
        """
        bb = self.getBasicBlocks()
        for b in bb:
            if address >= b.start and address <= b.end:
                return b
        return None

    def getBasicBlocks(self, force = False):
        """ 
        Get basic block from the current Function

        @type  force: BOOLEAN
        @param force: (Optional, Def: False) Force to Function to reparse the basic blocks

        @rtype:  LIST of BasicBlock objects
        @return: Basic blocks of the current function


        TODO: Recursion here is bad - we need to make this an iterative process with a work queue
        """
        if self.bb and not force:
            return self.bb

        op = None
        if not self.imm.isAnalysed( self.start ):
            self.imm.analyseCode( self.start )

        #self.decode = self.imm.findDecode( self.start )
        #self.imm.Log("Decode Len: %d" % len(self.decode))
        #if not self.decode:
        #    raise Exception, "Couldn't find a proper Decode"
        self._getBB(self.start)

        return self.bb

    # Depth First construction of Basic block 
    # This is the real recursive function that iterates over the function code flow creating basic block.
    # The function iterate over every assembly code always following first the jmp/jmc
    def _getBB(self, address):
        decode = self.imm.findDecode( address )
        if not decode:
            raise Exception, "Couldn't find a proper Decode for address 0x%08x" % address
        start = address
        calls = []
        while 1:            
            # XREF BASIC BLOCK:
            #  If we find our address has an xref, we know is the end the basic block
            if decode.isJmpDestination( address ) and start != address:

                if self.bbhash.has_key(start):
                    return
                #self.imm.Log("BB created (xref): %08x %08x" % ( start, address ) )
                op = self.imm.Disasm( address )
                bb = XREFBasicBlock( start, address )
                bb.setFunction( self )
                bb.addTrueEdge( address )
                bb.setCalls( calls )
                if calls:
                    bb.setCalls( calls )
                    calls = [] # cleaning calls
                self.bb.append( bb )
                self.bbhash[ start ] = 1
                start = address
                if self.bbhash.has_key( address ):
                    return

            #op = self.imm.disasmData( address )   XXX: change it for this one
            op = self.imm.Disasm( address )
            #self.imm.Log( op.getResult(), address = address)

            # JMC Basic block:
            #  If we find a conditional jmp, its the end of a basic block. We recursively follow the jmp
            if op.isConditionalJmp():
                #self.imm.Log("BB conditional (JMC): %08x %08x" % ( start, address ) )
                self.bbhash[ start ] = 1
                bb    = JMCBasicBlock( start, address + op.getSize() )
                if calls:
                    bb.setCalls( calls )
                    calls = [] # cleaning calls
                start = address + op.getSize()
                bb.setFunction( self )
                bb.addTrueEdge( op.getJmpConst() )
                bb.addFalseEdge( start ) # the next instruction
                self.bb.append( bb )

                # if the jmp address is not on our current basic block list, we follow that leaf
                if not self.bbhash.has_key( op.getJmpConst() ):
                    self._getBB( op.getJmpConst() )    
                    op = self.imm.Disasm( address )

                if self.bbhash.has_key( start ) :
                    return

            # JMP Basic Block:
            #  If we find a jmp, we create a new basic block.
            elif op.isJmp():
                if not self.bbhash.has_key( address):
                    #self.imm.Log("BB conditional (JMP): %08x %08x" % ( start, address ) )
                    self.bbhash[ start ] = 1
                    bb = JMPBasicBlock( start, address + op.getSize() )
                    bb.setFunction( self )
                    bb.addTrueEdge( op.getJmpConst() )  
                    if calls:
                        bb.setCalls( calls )
                        calls = [] # cleaning calls
                    self.bb.append( bb )
                    start = address + op.getSize()  
                    if not self.bbhash.has_key( op.getJmpConst() ):
                        # We limit the jmp only on a decode we control.
                        # That means, it has to jmp into our own dll
                        try:
                            decode[op.getJmpConst()] 
                            self._getBB( op.getJmpConst() )
                        except Exception:
                            pass
                return

            # RET Basic Block
            #  Whenever we find a ret, its the end of the tree. We create a Basic Block and return
            elif op.isRet():
                #self.imm.Log("BB conditional (RET): %08x %08x\n" % ( start, address ) )            
                self.bbhash[ start ] = 1
                bb = RETBasicBlock( start, address + op.getSize() )
                bb.setFunction( self )
                if calls:
                    bb.setCalls( calls )
                    calls = [] # cleaning calls
                self.bb.append( bb )
                return
            elif op.isCall():
                calls.append( address )

            address += op.getSize()



class BasicBlock:
    def __init__(self, start, end):
        """ 
        Basic Block class

        @type  start: DWORD
        @param start: Address of the begging of the Basic Block

        @type  end: DWORD
        @param end: Address of the end of the Basic Block
        """
        self.edgeamount  = 0
        self.start       = start
        self.end         = end
        self.calls       = []
        #self.Function is a pointer to our parent so we always have it available
        self.Function    = None
        #TODO: Flesh this out - let's store as much information as possible in the basic blocks 
        #for example, if we write to the stack or heap or if we have various macros in us, etc

    def setFunction(self, function):
        self.Function = function

    def getFunction(self):
        return self.Function

    def setCalls(self, calls):
        self.calls = calls 

    def getCalls(self):
        return self.calls

    def __cmp__(self, other):
        """
        Comparision by the start address of the BB
        """
        return cmp(self.start, other.start)

    def setStart(self, address):
        """
        Change the start of a Basic Block

        @type  address: DWORD
        @param address: New address of the Basic Block
        """
        self.start = address

    def addTrueEdge(self, addr):
        self.trueedge = addr

    def addFalseEdge(self, addr):
        self.falseedge = addr

    def getEdges(self):
        if not self.edgeamount:
            return (0,0)
        elif self.edgeamount == 1:
            if self.trueedge == 0:
                return (0,0)
            else:
                return (self.trueedge,0)
        else:
            return ( self.trueedge, self.falseedge )

    def getTrueEdge(self):
        """
        Get the 'true' Edge

        @rtype:  DWORD
        @return: 'True' Edge of the Basic Block
        """
        if not self.edgeamount:
            return None
        elif self.edgeamount != 1:
            return self.trueedge

    def getFalseEdge(self):
        """
        Get the 'false' Edge

        @rtype:  DWORD
        @return: 'False' Edge of the Basic Block (The 'false' edge, is not always present. Depends of the Basic Block)
        """
        if not self.edgeamount:
            return None
        elif self.edgeamount != 1:
            return self.falseedge

    def getDirectEdge(self):
        """
        Get the Edges of a Basic Block

        @rtype:  TUPLE of DWORD
        @return: The Edge of the Basic Block (Might change depending of the basic block type)
        """
        if not self.edgeamount:
            return ()
        elif self.edgeamount == 1:
            if self.trueedge == 0:
                return ()
            else:
                return self.trueedge

    def getSize(self):
        """
        Return the Size of the Basic Block

        @rtype:  DWORD
        @return: Size of the Basic Block
        """
        return self.end - self.start

    def setEnd(self, address):
        """
        Change the end of a Basic Block

        @type  address: DWORD
        @param address: New address of the Basic Block end
        """

        self.end   = address
    def getLimits(self):
        """
        Get the limits of the basic block

        @rtype: TUPLE OF DWORD
        @return: (Beginning of BB, End of BB)
        """
        return ( self.start,self.end )

    def getStart(self):
        """ 
        Get the begging of a Basic Block

        @rtype:  DWORD
        @return: Beginning of the Basic Block
        """
        return self.start

    def getEnd(self):
        """ 
        Get the End of a Basic Block

        @rtype:  DWORD
        @return: End of the Basic Block
        """
        return self.end
    

    def getInstructions(self, imm):
        """
        Get the disassembled instructions from a Basic Block

        @type  imm: Debugger OBJECT
        @param imm: Debugger

        @rtype: LIST of opCode OBJECT
        @return: List of disassembled instructions
        """
        addr         = self.start
        instructions = [] 

        while addr < self.end:
            op    = imm.Disasm( addr )
            instructions.append( op )
            addr += op.getSize()

        return instructions

    def isXref(self):
        """
        Check if a Basic Block was created from an XREF

        @rtype:  BOOLEAN
        @return: Whether the Basic Block was created from an XREF
        """
        return isinstance(self, XREFBasicBlock)

    def isConditionalJmp(self):
        """
        Check if a Basic Block was created from a Conditional Jump instruction

        @rtype:  BOOLEAN
        @return: Whether the Basic Block was created from a Conditional Jump instruction
        """
        return isinstance(self, JMCBasicBlock)

    def isJmp(self):
        """
        Check if a Basic Block was created from a Jump instruction

        @rtype:  BOOLEAN
        @return: Whether the Basic Block was created from a Jump instruction
        """
        return isinstance(self, JMPBasicBlock)

    def isRet(self):
        """
        Check if a Basic Block was created from a RET instruction

        @rtype:  BOOLEAN
        @return: Whether the Basic Block was created from a RET instruction
        """
        return isinstance(self, RETBasicBlock)

class XREFBasicBlock(BasicBlock):
    def __init__(self, start, end):
        """ 
        XREF Basic Block, Basic Block created from a code reference

        @type  start: DWORD
        @param start: Address of the begging of the Basic Block

        @type  end: DWORD
        @param end: Address of the end of the Basic Block
        """
        BasicBlock.__init__(self, start, end)
        self.edgeamount = 1

class JMCBasicBlock(BasicBlock):
    def __init__(self, start, end):
        """ 
        Conditional Jump Basic Block, Basic Block created from a conditional jump instruction (branch node)

        @type  start: DWORD
        @param start: Address of the begging of the Basic Block

        @type  end: DWORD
        @param end: Address of the end of the Basic Block
        """
        BasicBlock.__init__(self, start, end)
        self.edgeamount = 2

# Important Note:
#  Keep in mind, that the Edge of a JMP Basic block could be 0x0
#  (For example, in case like jmp [...]), we still don't take care of this special cases
class JMPBasicBlock(BasicBlock):
    def __init__(self, start, end):
        """ 
        Jump Basic Block, Basic Block created from a jump instruction 

        @type  start: DWORD
        @param start: Address of the begging of the Basic Block

        @type  end: DWORD
        @param end: Address of the end of the Basic Block
        """
        BasicBlock.__init__(self, start, end)
        self.edgeamount = 1

class RETBasicBlock(BasicBlock):
    def __init__(self, start, end):
        """ 
        RET Basic Block, Basic Block created from a RET instruction (exit node)

        @type  start: DWORD
        @param start: Address of the begging of the Basic Block

        @type  end: DWORD
        @param end: Address of the end of the Basic Block
        """
        BasicBlock.__init__(self, start, end)
        self.edgeamount = 0

class TraceArgs():
    def __init__(self, imm, func_address, tracedarg, shownonusersupplied = False):
        self.imm = imm
        self.func_address = func_address
        self.tracedarg = tracedarg
        self.shownonusersupplied  = shownonusersupplied

    def get(self):
        idx = 0
        stack =[]
        address = self.func_address

        # Find the corresponding PUSH
        while idx < COUNT:
            op = self.imm.disasmBackward( address )
            if op.isPush():
                stack.append(1)
                if len(stack) == self.tracedarg:
                    break
            elif op.isPop():
                if len(stack):
                    stack.pop(0)
                else:
                    return
            address = op.getAddress()
            del op
            idx += 1

        # Is this a PUSH?    
        if idx < COUNT:
            # Double check, just in case
            dotraceback = True
            if not op.isPush():
                #imm.Log("XXX: Error, Opcode should be a Push")
                return ()

            # If the PUSH has no register, its a PUSH CONSTANT
            # PUSH 0x400
            if op.getOperandRegister(0) == "":
                if not self.shownonusersupplied:
                    return ()
                else:
                    return (op, [])

            # If the Operand of the push is EBP, no need to get the traceback.
            # Cause is probably a PUSH of arguments or a local variable.
            # (At least, not now)
            # PUSH [EBP+C]
            elif op.getOperandRegister(0) == "EBP" and op.operand[0][3]:
                dotraceback = False
                #return (op, [])

            show = []

            # DOING THE TRACEBACK
            if dotraceback:
                self.modarg = []            
                self.visited = []

                try:
                    self.traceArgBackWithDecode( op.getAddress(), op.operand[0][2] )
                except IndexError:
                    op = self.traceArgBack( op.getAddress(), op.operand[0][2])
                    if op:
                        self.modarg.append(op)

                newop = None

                type = ""
                for newop in self.modarg:
                    newop.type = ""
                    # If the second argument is a constant, then is not user-supplied
                    # MOV ESI, 0x200 
                    if newop.getOperandRegister(1) == "":
                        if self.shownonusersupplied or newop.isCall():
                            show.append( newop )
                        else:
                            return ()
                    else:
                        type = ""
                        # op.operand[1][3] constante
                        if newop.getOperandRegister(1) == "EBP":
                            if newop.operand[1][3] < 0x80000000: 
                                newop.type = "VARS"
                            else:
                                newop.type = "ARGS"

                        show.append( newop )

            op.type = ""
            # op.operand[1][3] constant
            # 
            if op.getOperandRegister(0) == "EBP":
                if op.operand[0][3] < 0x80000000 and op.operand[0][3] != 0: 
                    op.type = "<VARS>"
                elif op.operand[0][3] > 0x80000000:
                    op.type = "<ARGS>"

                #imm.Log("Found user-supplied for arg_%d in %s"  % ( tracedarg, imm.disasm(ref[0]).result) , address = ref[0])
                #imm.Log( "%s %s" % (op.getDisasm(), type), address = op.getAddress()  )
                #for msg in show:
                #    imm.Log( msg[0], address = msg[1] )
                #imm.Log("------")
            return (op, show)

        return ()

    # Note:
    #  We just trace for MOV (We skip arymethic and lea opcodes)
    #  This function search backward linearly, we should change it into changing using
    #   xrefs and probably detecting more than one traceBack
    def traceArgBackWithDecode(self, address, register):
        idx = 0
        decode = self.imm.findDecode( address )

        while idx < COUNT:
            if address in self.visited:
                return 0
            op = self.imm.disasmBackward( address )
            #imm.Log("> %s" % op.result, address = op.getAddress())
            self.visited.append( address )
            if op.isJmp():
                return 0
            if op.getResult()[:3] in ("MOV", "XOR"):
                # Register is the source
                # ex: MOV EAX, ...
                if op.operand[0][2] == register:
                    self.modarg.append( op )
                    return 0
            # If the register we are looking for is EAX, a CALL would be the one
            #  the modifier
            # CALL ntdll.67225328
            elif register == (1,0,0,0,0,0,0,0) and op.isCall():
                self.modarg.append( op )
                return 0

            if decode.isJmpDestination(address):
                for ref in self.imm.getXrefFrom( address ):
                    self.traceArgBackWithDecode(ref[0], register)    

            address = op.getAddress()
            idx += 1
            if decode:
                # Finish looking if we reach the begging of the address
                if decode.isFunctionStart( address ):
                    del decode
                    return None
            del op

        del decode
        return None


    # Note:
    #  We just trace for MOV (We skip arymethic and lea opcodes)
    #  This function search backward linearly, we should change it into changing using
    #   xrefs and probably detecting more than one traceBack
    def traceArgBack(self, address, register):
        idx = 0
        decode = self.imm.findDecode( address )

        while idx < COUNT:
            op = self.imm.disasmBackward( address )
            if op.getResult()[:3] == "MOV":
                # Register is the source
                # ex: MOV EAX, ...
                if op.operand[0][2] == register:
                    return op
            # If the register we are looking for is EAX, a CALL would be the one
            #  the modifier
            # CALL ntdll.67225328
            elif register == (1,0,0,0,0,0,0,0) and op.isCall():
                return op

            address = op.getAddress()
            idx += 1
            if decode:
                # Finish looking if we reach the begging of the address
                if decode.isFunctionStart( address ):
                    del decode
                    return None
            del op

        del decode
        return None
