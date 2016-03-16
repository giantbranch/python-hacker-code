#!/usr/bin/env python
"""
Immunity Debugger Stack Analysis Lib

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>} Stack Analysis Lib

"""

__VERSION__ = "1.1"

from libanalize import *
from libdatatype import *

class StackFunction(Function):
    """
    This is an inherited class from Function that add stack analysis capabilities.
    
    The params are the same as the Function class.
    """
    
    def analyzeStack(self, base = None):
        """
        Analyze the stack of a function, searching frame-based local variables.
        
        @type  base: StackFunction OBJECT | None
        @param base: represent the object where we want to do the searchHits (for cache reasons), it can be "self".
        
        @rtype: LIST
        @return: in order:
          - calls:   (dictionary) key: caller addy,    value: (list) callee addy and args
          - myVarHits: (dictionary) key: stack constant, value: (list) hits addresses
          - myArgHits: (dictionary) key: stack constant, value: (list) hits addresses
          - varsSize:(dictionary) key: stack constant, value: size of the variable
        """

        if not base:
            base = self
        
        if not self.imm.isAnalysed( self.getStart() ):
            self.imm.analyseCode( self.getStart() )
        
        #Search the function start using an alternative method or normal method or 
        #use the given address
        start = self.getFunctionBegin(self.getStart())
        if not start:
            start = self.imm.getFunctionBegin(self.getStart())
        if start:
            self.setStart(start)
        
        self.calls = {}
        for bb in self.getBasicBlocks(force = True):
            for addy,dest in self.searchCalls(bb):
                args = self.searchArgs(addy, bb)
                self.calls[addy] = [dest, args]

        #we make the searchHits all in the same object, to cache the results
        self.argHits = {}
        self.varHits = {}
        
        myVarHits, myArgHits = base.searchHits(self.getStart())
        
        self.getVarsSize(myVarHits.keys())
        
        return ( self.calls, myVarHits, myArgHits, self.varsSize )
    
    def searchCalls(self, bb):
        """
        Search all the calls inside a BB and find the real dest address
        
        @type  bb: BasicBlock OBJECT
        @param bb: BasicBlock to search into
        
        @rtype: LIST
        @return: A list of tuples of the form: from_address, to_address
        """
        ret = []
        for op in bb.getInstructions(self.imm):
            if op.isCall() or (op.isJmp() and not op.getIndexed() and op.getAddrConst() and op.getOpData()[0]):
                #CALL CONST, CALL DWORD PTR DS:[CONST], JMP DWORD PTR DS:[CONST]
                dest = self.hopJump(op.getAddress(), includecall=True)
                if dest:
                    #hop JMP tables
                    tmp = self.hopJump(dest)
                    if tmp: 
                        dest = tmp
                    ret.append( (op.getAddress(), dest) )
        return ret
    
    def searchArgs(self, addy, bb):
        """
        Search possible arguments inside the function, following the PUSHes before a call
        
        @type  addy: DWORD
        @param addy: Start address to begin searching backward for arguments
        
        @type    bb: BasicBlock OBJECT
        @param   bb: Find arguments just inside this BB
        
        @rtype: DICTIONARY
        @return:  the key is the argument number and the value is another dictionary:
                  { 'type' : const|lvar|gvar|arg|call|other,
                    'ref'  : TRUE|FALSE (is a reference or not),
                    'value': DWORD,
                    'addy' : DWORD }
        """
        op = self.imm.disasm(addy)
        args = {}
        argc = 1
        
        while True:
            op = self.imm.disasmBackward(op.getAddress(),1)
            
            #search only inside the BB and stop on any call
            if op.getAddress() < self.getBBStart(addy) or op.isCall():
                break
            
            asm = op.getDisasm()
            if "PUSH " in asm:
                if op.operand[0][0] == DEC_CONST:
                    #PUSH CONST
                    args[argc] = { 'type':'const',
                                   'ref':False,
                                   'value':op.getImmConst(),
                                   'addy' :op.getAddress() }
                    argc += 1
                elif " PTR " in asm:
                    #PUSH a direct arg/local var/global var
                    const = asm.split("[")[1][:-1]
                    try:
                        if "EBP" in const:
                            if   "-" in const:
                                type="lvar"
                                try:
                                    const = int(const.split('-')[1], 16)
                                except:
                                    argc += 1
                                    continue
                            elif "+" in const:
                                type="arg"
                                try:
                                    const = int(const.split('+')[1], 16)
                                except:
                                    argc += 1
                                    continue
                        elif not op.getIndexed() and op.getAddrConst():
                            type = "gvar"
                            const = int(const, 16)
                        else:
                            argc += 1
                            continue
                            
                        args[argc] = { 'type' :type,
                                       'ref'  :False,
                                       'value':const,
                                       'addy' :op.getAddress() }
                        argc += 1
                    except:
                        self.imm.Log("error possible var: %08X -> %s" % (op.getAddress(), asm))
                else:
                    #PUSH REG
                    reg = asm.split(" ")[1]
                    #get the opCode where the reg it's set to his actual value
                    regop = self.followRegBack(op.getAddress(), reg)
                    if regop == None:
                        argc += 1
                        continue
                    regasm = regop.getDisasm()
                    #by default is "other"
                    type   = "other"
                    const  = regop.getAddress()
                    #stack fun
                    if "[EBP-" in regasm:
                        type="lvar"
                        try:
                            const = int(regasm.split('-')[1][:-1], 16)
                        except:
                            argc += 1
                            continue
                    elif "[EBP+" in regasm:
                        type="arg"
                        try:
                            const = int(regasm.split('+')[1][:-1], 16)
                        except:
                            argc += 1
                            continue
                    #is this a pointer?
                    if "MOV" in regasm:
                        pRef = True
                    else:
                        pRef = False
                    #the value comes from the return of another call (save the address of the call)
                    if regop.isCall():
                        type="call"
                        const=regop.getAddress()
                        pRef=False
                        
                    args[argc] = { 'type' :type,
                                   'ref'  :pRef,
                                   'value':const,
                                   'addy' :op.getAddress() }
                    argc += 1
        return args

    def getBBStart(self, addy):
        """
        Get the begining of a BB using a given address
        
        @type  addy: DWORD
        @param addy: Address of reference to find the BB start
        
        @rtype: DWORD | None
        @return: Address of the Basic Block's begining
        """
        for bb in self.getBasicBlocks():
            limits = bb.getLimits()
            if addy >= limits[0] and addy <= limits[1]:
                return limits[0]
        return None

    def hopJump(self, address, includecall=False):
        """
        Hop to the real destination address from a FAR CALL or may be a JMP Table
        
        @type  address: DWORD
        @param address: Address of JMP/CALL
        
        @type  address: Boolean
        @param address: Accept a Call instruction as a possible hop

        @rtype: DWORD
        @return: Address of the decoded jump/call or the given address if it can't be decoded
        """
        op = self.imm.disasm(address)
        dest = None

        if (includecall and op.isCall()) or op.isJmp() or op.isConditionalJmp():
            if   op.getJmpConst():
                dest = op.getJmpConst()
            elif not op.getIndexed() and op.getAddrConst() and op.getOpData()[0]:
                #Check that isn't indexed ([REG32+xxx])
                #Check that have an address constant ([CONST])
                #Check that address goes to somewhere inside the code
                dest = op.getOpData()[0]
        return dest

    def followRegBack(self, followAddress, reg):
        """
        Follow back a reg inside a BB until we get a MOV/LEA REG
        
        @type  followAddress: DWORD
        @param followAddress: Start address to begin searching backward
        
        @type  reg: STRING
        @param reg: Register to follow
        
        @rtype: opCode OBJECT | None
        @return: the opcode instance where the reg is defined
        """
        
        op = self.imm.disasmBackward(followAddress,1)
        while op.getAddress() >= self.getBBStart(followAddress):
            #self.imm.Log("followRegBack addy: %08X - asm: %s" % \
                         #(op.getAddress(), op.getDisasm()))
            
            #check if we found a winner
            if "MOV %s," % reg in op.getDisasm() or "LEA %s," % reg in op.getDisasm():
                return op
            
            #if it's a REG32, look for the REG16 version too
            if "E" in reg:
                if "MOV %s," % reg.strip("E") in op.getDisasm() or "LEA %s," % reg.strip("E") in op.getDisasm():
                    return op
            
            #if We found a call before a MOV and the reg is EAX/AX, it could be the return of another function
            if op.isCall() and reg.strip("E") == "AX":
                return op
            
            op = self.imm.disasmBackward(op.getAddress(), 1)
        
        return None

    def isInsideFunction(self, address):
        """
        Check if an address is inside the function limits.
        
        @type  address: DWORD
        @param address: Address to check
        
        @rtype: Boolean
        @return: return if is inside or not
        """
        
        for bb in self.getBasicBlocks():
            limits = bb.getLimits()
            if address >= limits[0] and address <= limits[1]:
                return True
        return False
    
    def getStackSize(self):
        """
        Read the CONST on the function init sequence to get the stack size.
        
        @rtype: INTEGER | None
        @return: The constant from the function's prolog, normally associated
                 to the total size of the local variables.
        """

        if "SUB ESP," in self.imm.disasmForward(self.getStart(), 2).getDisasm():
            return size_op.getImmConst()
        if "SUB ESP," in self.imm.disasmForward(self.getStart(), 3).getDisasm():
            return size_op.getImmConst()
        if "SUB ESP," in self.imm.disasmForward(self.getStart(), 4).getDisasm():
            return size_op.getImmConst()
        
        return None
    
    def searchHits(self, address):
        """
        Look for instructions that use args or local vars.
        
        @type  address: DWORD
        @param address: Function start
        
        @rtype: TUPLE
        @return: A 2-tuple of dictionaries, one with the vars and one with the args for this function.
                 Each dictionary use the stack constant as key and a list of hit addresses as value.
        """

        mod = self.imm.getModulebyAddress(address)
        base = mod.getBaseAddress()
        
        if not base:
            return ( {}, {} )
        
        #we do this just one time for all the execution and save only the part we need, cleaning the rest
        if not self.argHits.has_key(base) and not self.varHits.has_key(base):
            for asm in ("LEA R32,[EBP-CONST]", "MOV R32,[EBP-CONST]", "LEA R16,[EBP-CONST]", "MOV R16,[EBP-CONST]", "LEA R8,[EBP-CONST]", \
                        "MOV R8,[EBP-CONST]", "PUSH DWORD PTR SS:[EBP-CONST]", "LEA R32,[EBP+CONST]", "MOV R32,[EBP+CONST]", \
                        "PUSH DWORD PTR SS:[EBP+CONST]"):
                hits  = self.imm.searchCommandsOnModule(address, asm)
                self.__saveHits(hits, base)
                del hits
        
        #here we select only the function specific hits
        myVars = {}
        for hit in self.varHits[base]:
            #use only the hits inside the function
            if self.isInsideFunction(hit):
                const = self.varHits[base][hit]
                if not myVars.has_key(const):
                    myVars[const] = []
                myVars[const].append(hit)

        myArgs = {}
        for hit in self.argHits[base]:
            #use only the hits inside the function
            if self.isInsideFunction(hit):
                const = self.argHits[base][hit]
                if not myArgs.has_key(const):
                    myArgs[const] = []
                myArgs[const].append(hit)
        
        return ( myVars, myArgs )

    def __saveHits(self, hits, base):
        """
        save the hits separating args from vars and using the address as key (inside a dictionary by module).
        """
        if not self.varHits.has_key(base):
            self.varHits[base] = {}
        if not self.argHits.has_key(base):
            self.argHits[base] = {}
            
        for hit in hits:
            op = self.imm.disasm(hit[0])
            asm = op.getDisasm()
            if '-' in asm:
                #local var
                const = int(asm.split('-')[1][:-1], 16)
                self.varHits[base][hit[0]] = const
            elif '+' in asm:
                #argument
                const = int(asm.split('+')[1][:-1], 16)
                self.argHits[base][hit[0]] = const
            del asm
            del op
    
    def getVarsSize(self, offsets):
        """
        Get the size of the local vars, checking the difference between the offset
        of two consecutives vars.
        
        XXX:An unused local var can make this check unreliable.
        
        @type  offsets: LIST
        @param offsets: a list of stack's constants
        
        @rtype: DICTIONARY
        @return: the key is the stack's constant, value is the size
        """
        
        self.varsSize = {}
        offsets.sort()
        last = 0
        for off in offsets:
            size = off - last
            last = off
            self.varsSize[off] = size
        return self.varsSize
    
    def getFunctionBranches(self):
        """
        Make an acyclic tree of all possible execution branches
        
        @rtype: LIST
        @return: a list with one or more lists of Basic Block's addresses.
        """
        
        tree = {}
        for bb in self.getBasicBlocks():
            tree[bb.getStart()] = bb.getEdges()
        branches = FunctionBranches(tree, self.getStart())
        self.Branches = branches.getBranches()
        return self.Branches
    
    def getFunctionBegin(self, beginAddress, maxsteps = 500):
        """
        Walk back the code until we get a PUSH EBP/MOV EBP,ESP/SUB ESP, CONST
        XXX: there're better ways to do this (BB-like)
        
        @type  beginAddress: DWORD
        @param beginAddress: an address of reference to start the searching
        
        @type  maxsteps: INTEGER
        @param maxsteps: max steps to search backward
           
        @rtype: DWORD | None
        @return: Function Begin's address or None if we are outside the scope of
                 search
        """
        
        #we can position ourself some steps forward, before start searching backward
        #to avoid be in the middle of a "MOV EDI,EDI/PUSH EBP/MOV EBP,ESP/SUB ESP, CONST"
        instr = 0
        while instr < 10:
            op = self.imm.disasmForward(beginAddress, instr)
            instr += 1
            
            #Stop if something is going to change the course of action
            if op.isCall() or op.isJmp() or op.isConditionalJmp() or op.isRet():
                break
        address = op.getAddress()
        
        instr = 1
        ret = None
        while instr < maxsteps:
            op = self.imm.disasmBackward(address, 1)

            if "PUSH EBP" in op.getDisasm():
                #check a second instr of a stack initialization (could have some instr in the middle)
                if "MOV EBP,ESP" in self.imm.disasmForward(address, 0).getDisasm() or \
                   "MOV EBP,ESP" in self.imm.disasmForward(address, 1).getDisasm() or \
                   "MOV EBP,ESP" in self.imm.disasmForward(address, 2).getDisasm():
                    ret = op.getAddress()
                    break

            address = op.getAddress()
            instr += 1

        if ret:
            #check if there is a MOV before the start, if so, use that address
            if "MOV " in self.imm.disasmBackward(ret, 1).getDisasm():
                ret = self.imm.disasmBackward(ret, 1).getAddress()
        return ret
    
    def getCalls(self):
        return self.calls
    def getvarHits(self):
        return self.varHits
    def getargHits(self):
        return self.argHits
    def getvarsSize(self):
        return self.varsSize
    def getBranches(self):
        return self.Branches
 
class FunctionBranches:
    """
    Traverse a tree to get all possible branches (execution flows)
    The class don't follow cycles.
    """
    
    def __init__(self, tree, startnode):
        """
        @type  tree: DICTIONARY
        @param tree: a dictionary of BBs the key is the BB Start and the value is a
                     list of out-edges.
           
        @type  startnode: DWORD
        @param startnode: The base node where the tree begin
        """
        self.branches = []
        self.tree = tree
        self.start = startnode
        self.TraverseTree(self.start, [self.start])
        
    def getBranches(self):
        """
        Get the function branches processed by the TraverseTree function.
        
        @rtype: LIST
        @return: a list of branches, each one is a list of Basic Block start address
        """
        return self.branches
        
    def TraverseTree(self, node, branch):
        if not self.tree.has_key(node):
            return None
        
        if self.tree[node][0] == 0 and self.tree[node][1] == 0:
            #End Node
            self.branches.append(branch)
        
        if self.tree[node][0] != 0:
            #True Edge
            if self.tree[node][0] in branch:
                #Loop found
                self.branches.append(branch)
            else:
                tmp = branch[:]
                tmp.append(self.tree[node][0])
                self.TraverseTree(self.tree[node][0],tmp)
        
        if self.tree[node][1] != 0:
            #False Edge
            if self.tree[node][1] in branch:
                #Loop found
                self.branches.append(branch)
            else:
                tmp = branch[:]
                tmp.append(self.tree[node][1])
                self.TraverseTree(self.tree[node][1],tmp)

class FlowAnalyzer:
    def __init__(self, imm, address, steps=1, __base=None):
        """
        Try to figure out the relation of local variables and arguments between 
        different functions.

        @type  imm: Debugger OBJECT
        @param imm: a debugger object to interact with the debugger
           
        @type  address: DWORD
        @param address: a reference address to start the function analysis
        
        @type  steps: INTEGER
        @param steps: How many steps (functions) forward it has to analyze

        @type  __base: StackFunction OBJECT | None
        @param __base: instance used to make all the searchCommands calls, used internally
        """
        
        self.imm = imm
        self.address = address
        self.steps = steps
        self.calls = {}
        self.varHits = {}
        self.argHits = {}
        self.varsSize = {}
        
        self.function = StackFunction(self.imm, self.address)

        #setup the base Function at the first execution
        if "base" not in dir(self):
            if __base:
                self.base = __base
            else:
                self.base = self.function
        
        ret = self.function.analyzeStack(self.base)
        
        self.functionBegin = self.function.getStart()
        self.calls[self.functionBegin] = ret[0]
        self.varHits[self.functionBegin] = ret[1]
        self.argHits[self.functionBegin] = ret[2]
        self.varsSize[self.functionBegin] = ret[3]

        if self.steps > 0:
            self.analyzeFunction()
        
    def analyzeFunction(self):
        """
        Analyze the function's calls to collect information
        """
        
        for addy,data in self.function.getCalls().iteritems():
            flow = FlowAnalyzer(self.imm, data[0], self.steps-1, self.base)
            
            calls, vars, args, varsize = flow.getFlowInformation()
            for functstart,_calls in calls.iteritems():
                if not self.calls.has_key(functstart):
                    self.calls[functstart] = _calls
            for functstart,_vars in vars.iteritems():
                if not self.varHits.has_key(functstart):
                    self.varHits[functstart] = _vars
            for functstart,_args in args.iteritems():
                if not self.argHits.has_key(functstart):
                    self.argHits[functstart] = _args
            for functstart,_varsize in varsize.iteritems():
                if not self.varsSize.has_key(functstart):
                    self.varsSize[functstart] = _varsize
    
    def getFlowInformation(self):
        """
        Returns all the information collected, the format of each variable is the same
        of the StackFunction, but allocated inside a dictionary where the key is
        the Funcion Start.
        """
        return [ self.calls, self.varHits, self.argHits, self.varsSize ]
    
    def getFunctionBegin(self):
        return self.functionBegin
    
    def decodeConstant(self, addy, size=4096):
        """
        decode a constant value trying to find a string.
        
        @type  addy: DWORD
        @param addy: Address to decode
        
        @type  size: INTEGER
        @param size: Max size of the memory chunk that it decode, default=4096
        
        @rtype: LIST | None
        @return: a list with the string value decoded and length of it
        """

        if self.imm.getMemoryPagebyAddress(addy) != None:
            datatype = DataTypes(self.imm)
            posstype = datatype.Discover(self.imm.readMemory(addy, size), addy, what='strings')
            if posstype:
                return [ posstype[0].Print()[1:-1], len(posstype[0].Print()[1:-1]) ]
        return None

    def argInfo(self,function,callfrom,argc):
        """
        Show argument information in a more suitable way
        
        @type  function: DWORD
        @param function: Address of the function begin
        
        @type  callfrom: DWORD
        @param callfrom: Address of the call related to the arguments we need to decode
        
        @type  argc: INTEGER
        @param argc: argument count of the arg we want to decode
        
        @rtype: STRING
        @return: a string with useful information about the argument
        """
        
        try:
            info = self.calls[function][callfrom][1][argc]
        except KeyError:
            self.imm.Log("can't decode arg info for function %08X - call: %08X - argc: %d" % \
                         (function,callfrom,argc))
            return ""
        
        value = "%08X" % info['value']
        tmp = ""
        if   info['type'] == "const":
            const = self.decodeConstant(info['value'])
            if const:
                value = "%s - size: %d" % (const[0][:30], const[1])
        elif info['type'] == "arg":
            value = "%s->arg[%d]" % ( self.imm.decodeAddress(function), (info['value']-4)/4 )
        elif info['type'] == "lvar":
            try:
                size = self.varsSize[function][info['value']]
                tmp += " size: %X" % size
            except:
                pass
        if info['ref']: tmp += " [REF]"
        
        return "arg[%d] (%5s) value: %s%s" % (argc, info['type'], value, tmp)
