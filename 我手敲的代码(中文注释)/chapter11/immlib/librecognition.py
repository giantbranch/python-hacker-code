"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}


Library for function recognizing

"""
__VERSION__ = '1.2'


from libanalize import *
from libdatatype import *
from libstackanalyze import *
import binascii
import struct
import hashlib
import re
import string
import debugger
import csv
import os

class MultiCSVIterator:
    def __init__(self, dictionaries):
        if not isinstance(dictionaries, list):
            dictionaries = [ dictionaries ]

        self.iterators = []
        self.fds = []
        self.idx = 0
        for d in dictionaries:
            try:
                fd = open(d, "rb")
            except:
                fd = open(d, "w+b")
            self.iterators.append(csv.reader(fd))
            self.fds.append(fd)
    def __iter__(self):
        for i in range(0, self.idx+1):
            self.fds[i].seek(0)
        self.idx = 0
        return self

    def __del__(self):
        while self.iterators:
            self.iterators.pop()
        for fd in self.fds:
            fd.close()
        del self.fds
    
    def next(self):
        try:
            data = self.iterators[self.idx].next()
        except StopIteration:
            if len(self.iterators) > self.idx+1:
                self.idx += 1
                return self.next()
            else:
                raise StopIteration
        #append the filename to each line
        data.append(self.fds[self.idx].name)
        return data

class FunctionRecognition:
    def __init__(self, imm, dictionaryfiles=None):
        """
        This class try to recognize a function using different methods 
        (address/signature/heuristic).
        
        @type  imm: Debbuger OBJECT
        @param imm: Debbuger instance
        
        @type  dictionaryfiles: STRING|LIST
        @param dictionaryfiles: Name, or list of names, of .dat files inside the Data folder, where're stored the function 
                               patterns. Use an empty string to use all .dat files in Data folder.
        """
        self.imm = imm
        self.heuristicReferencesCache = {}
        self.heuristicCache = {}
        self.resolvCache = {}
        
        if not dictionaryfiles:
            dictionaryfiles = []
            for file in os.listdir("Data"):
                if file[-4:] == ".dat":
                    dictionaryfiles.append(os.path.join("Data", file))
        self.dictionaries = MultiCSVIterator(dictionaryfiles)
    
    def resolvFunctionByAddress(self, address, heuristic=90):
        """
        Look up into our dictionaries to find a function match.
        
        @type  address: DWORD
        @param address: Address of the function to search
        
        @type  heuristic: INTEGER
        @param heuristic: heuristic threasold to consider a real function match
        
        @rtype: STRING
        @return: a STRING with the function's real name or the given address if there's no match
        """
        
        #cache the answers
        if self.resolvCache.has_key(address):
            return self.resolvCache[address]
        
        #try the exact hash method
        exact = self.makeFunctionHashExact(address)
        for data in self.dictionaries:
            if exact == data[4]:
                self.resolvCache[address] = data[0]
                break
                
        #try the heuristic method
        if not self.resolvCache.has_key(address):
            ref = self.selectBasicBlock(address)
            posThreshold = 0
            posName = ""
            for data in self.dictionaries:
                #cut down the possibilities, because the performance, reproducing the BB selection and comparing the result
                #XXX: it's not a perfect way, thinking of supporting version changes
                if ref == data[1]:
                    perc = self.checkHeuristic(address, data[2], data[3])
                    #self.imm.Log("similar to function %s in %d%%" % (data[0], perc))
                    if  perc >= heuristic and perc > posThreshold:
                        posThreshold = perc
                        posName = data[0]
            if posName:
                self.resolvCache[address] = posName

        #cache the negative answer
        if not self.resolvCache.has_key(address):
            self.resolvCache[address] = "%08X" % address

        return self.resolvCache[address]
    
    def checkHeuristic(self, address, reference, refFirstCall=[]):
        """
        Check a given address with a precomputed hash of a function.
        Return a percentage of match (you can use a threasold to consider a real match)
        
        @type  address: DWORD
        @param address: Address of the function to compare
        
        @type  reference: STRING
        @param reference: base64 representation of the compressed information about the function

        @type  refFirstCall: STRING
        @param refFirstCall: the same, but following the function pointed by the first call in the first BB.
                             (OPTIONAL)
        
        @rtype: INTEGER
        @return: heuristic threasold to consider a real function match
        """
        
        #self.imm.Log("checking heuristically: %08X" % address)
        
        #do the hard work just one time
        if self.heuristicCache.has_key(address):
            cfg = self.heuristicCache[address]
        else:
            cfg = self.makeFunctionHashHeuristic(address)
            self.heuristicCache[address] = cfg
        
        #check reference against our cache
        sha1 = hashlib.sha1(reference+refFirstCall).digest()
        if self.heuristicReferencesCache.has_key(sha1):
            refcfg = self.heuristicReferencesCache[sha1]
        else:
            #This's the reference hash to compare with (uncompress just once and cache the results)
            #Decode each BB-hash
            refcfg = []
            refcfg.append([])
            refcfg.append([])
            data = binascii.a2b_base64(reference)
            for o in range(0,len(data),12):
                (start, left, right) = struct.unpack("LLL",data[o:o+12])
                refcfg[0].append([ start, left, right ])
            if refFirstCall:
                data = binascii.a2b_base64(refFirstCall)
                for o in range(0,len(data),12):
                    (start, left, right) = struct.unpack("LLL",data[o:o+12])
                    refcfg[1].append([ start, left, right ])
            self.heuristicReferencesCache[sha1] = refcfg

        perc1 = self.compareHeuristic(cfg[0][:], refcfg[0][:])
        if cfg[1] or refcfg[1]:
            perc2 = self.compareHeuristic(cfg[1][:], refcfg[1][:])
            #use the average
            perc = (perc1 + perc2) / 2
        else:
            perc = perc1
            
        return perc

    def compareHeuristic(self, cfg, refcfg):
        #for tmp in cfg:
            #self.imm.Log("check start: %08X - left: %08X - right: %08X" % (tmp[0],tmp[1],tmp[2]))
        
        #for tmp in refcfg:
            #self.imm.Log("ref start: %08X - left: %08X - right: %08X" % (tmp[0],tmp[1],tmp[2]))
            
        diff = eq = 0
        checked = []
        #Compare each BB-hash
        for info in cfg:
            bbeq = value = 0
            for rinfo in refcfg:
                tmp = 0
                if info[0] == rinfo[0]: tmp += 1
                if info[1] == rinfo[1]: tmp += 1
                if info[2] == rinfo[2]: tmp += 1
                if tmp > bbeq:
                    bbeq = tmp
                    value = rinfo
                if bbeq == 3: break
            try:
                idx=refcfg.index(value)
                refcfg.pop(idx)
            except ValueError:
                pass
                #self.imm.Log("value %s not found in refcfg" % value)
            eq += bbeq
            diff += 3 - bbeq
        
        #crossed check
        for rinfo in refcfg:
            bbeq = value = 0
            for info in cfg:
                tmp = 0
                if info[0] == rinfo[0]: tmp += 1
                if info[1] == rinfo[1]: tmp += 1
                if info[2] == rinfo[2]: tmp += 1
                if tmp > bbeq:
                    bbeq = tmp
                    value = rinfo
                if bbeq == 3: break
            try:
                idx=cfg.index(value)
                cfg.pop(idx)
            except ValueError:
                pass
                #self.imm.Log("value %s not found in cfg" % value)
            eq += bbeq
            diff += 3 - bbeq
        
        #self.imm.Log("eq=%d, diff=%d" % (eq,diff))
        return eq * 100 / (eq + diff)
        
    def makeFunctionHashHeuristic(self, address, compressed = False, followCalls = True):
        """
        Consider:
        - Control Flow Graph
        - generalized instructions that:
            access memory/write memory/use registers/use constant/call/jmp/jmc
            and all his combinations.
        - special case of functions with just 1 BB and a couple of calls (follow the first call)
        
        @type  address: DWORD
        @param address: address of the function to hash
        
        @type  compressed: Boolean
        @param compressed: return a compressed base64 representation or the raw data

        @type  followCalls: Boolean
        @param followCalls: follow the first call in a single basic block function
        
        @rtype: LIST
        @return: the first element is described below and the second is the result of this same function but over the first
                 call of a single basic block function (if applies), each element is like this:
            a base64 representation of the compressed version of each bb hash:
            [4 bytes BB(i) start][4 bytes BB(i) 1st edge][4 bytes BB(i) 2nd edge]
            0 <= i < BB count
            or the same but like a LIST with raw data.
        """
        
        f = self.imm.getFunction(address)
        bbs = f.getBasicBlocks()
        bbmap = {}
        cfg = {}
        
        #Make a control flow graph
        for bb in bbs:
            cfg[bb.getStart()] = bb.getEdges()
        
        #Make a hash of each BB
        for bb in bbs:
            bbhash_data = []
            for op in bb.getInstructions(self.imm):
                #take into account just information about the opcode
                instr = []
                instr.append(op.getMemType())
                instr.append(op.indexed)
                instr.append(op.getCmdType())
                instr.append(op.optype[0])
                instr.append(op.optype[1])
                instr.append(op.optype[2])
                instr.append(op.getSize())
                bbhash_data.append(self.hash_a_list(instr))
            bbhash = self.hash_a_list(bbhash_data)
            bbmap[bb.getStart()] = bbhash
            
        #Replace BB addresses with hashes
        rcfg = []
        for start,edges in cfg.iteritems():
            rstart = 0
            redges = [0, 0]
            rstart = bbmap[start]
            if bbmap.has_key(edges[0]):
                redges[0] = bbmap[edges[0]]
            if bbmap.has_key(edges[1]):
                redges[1] = bbmap[edges[1]]
            rcfg.append([ rstart,redges[0],redges[1] ])
        
        #special case for functions with just one basic block and one or more calls
        firstcall = []
        if followCalls and len(bbs) == 1 and len(bbs[0].getCalls()) > 0:
            #we follow the first call and do the same work there, but avoiding recursion
            #XXX: why the first?
            op = self.imm.Disasm(bbs[0].getCalls()[0])
            if op.getJmpConst():
                firstcall = self.makeFunctionHashHeuristic(op.getJmpConst(), compressed, followCalls=False)[0]
                #self.imm.Log("following first call to: %08X" % op.getJmpConst())
            del op
        
        del bbs
        del f
        rcfg.sort()
        
        if compressed:
            #make the final hash
            fhash = ""
            for data in rcfg:
                #[4 bytes BB(i) start][4 bytes BB(i) 1st edge][4 bytes BB(i) 2nd edge]
                fhash += struct.pack("LLL", data[0], data[1], data[2])
            return [ binascii.b2a_base64(fhash)[:-1], firstcall ]
        else:
            return [ rcfg, firstcall ]
    
    def hash_a_list(self,data):
        """
        Take a list and return a binary representation of his CRC32.
        
        @type  data: LIST
        @param data: a list of elements to make the hash
        
        @rtype: UNSIGNED LONG
        @return: a hash of the given values
        """
        
        ret = 0
        for elem in data:
            ret = binascii.crc32(str(elem), ret)
        return struct.unpack("L", struct.pack("l",ret))[0]

    def searchFunctionByHeuristic(self, csvline, heuristic = 90, module = None):
        """
        Search memory to find a function that fullfit the options.
        
        @type  csvline: STRING
        @param csvline: A line of a Data CSV file. This's a simple support for copy 'n paste from a CSV file.        
        
        @type  heuristic: INTEGER
        @param heuristic: heuristic threasold to consider a real function match
        
        @type  module: STRING
        @param module: name of a module to restrict the search

        @rtype: LIST
        @return: a list of tuples with possible function's addresses and the heauristic match percentage 
        """
        
        line = csv.reader([csvline]).next()
        if len(line) < 9: line[7] = "" #support for older entries
        return self._searchFunctionByHeuristic(line[1], line[2], line[3], line[4], heuristic, module, string.split(line[7],"|"))
    
    def _searchFunctionByHeuristic(self, search, functionhash=None, firstcallhash=None, exact=None, heuristic = 90, module = None, firstbb = None):
        """
        Search memory to find a function that fullfit the options.
        
        @type  search: STRING
        @param search: searchCommand string to make the first selection
        
        @type  functionhash: STRING
        @param functionhash: the primary function hash (use makeFunctionHash to generate this value)

        @type  firstcallhash: STRING
        @param firstcallhash: the hash of the first call on single BB functions (use makeFunctionHash to generate this value)

        @type  exact: STRING
        @param exact: an exact function hash, this's a binary byte-per-byte hash (use makeFunctionHash to generate this value)
        
        @type  heuristic: INTEGER
        @param heuristic: heuristic threasold to consider a real function match
        
        @type  module: STRING
        @param module: name of a module to restrict the search

        @type  firstbb: STRING
        @param firstbb: generalized assembler of the first BB (to search function begin)

        @rtype: LIST
        @return: a list of tuples with possible function's addresses and the heauristic match percentage 
        """

        #if the first argument is a LIST, decode it to each real argument of the function, following the order in the CSV file.
        #this give us a simple support for copy 'n paste from the CSV file.
        if isinstance(search, list):
            search.reverse()
            tmp = search[:]
            if tmp: search = tmp.pop()
            if tmp: functionhash = tmp.pop()
            if tmp: firstcallhash = tmp.pop()
            if tmp: exact = tmp.pop()
            if tmp: version = tmp.pop()
            if tmp: file = tmp.pop()
            if tmp: firstbb = tmp.pop()
        
        #this arguments are mandatory
        if not search or not functionhash:
            return None
        
        if not firstcallhash:
            firstcallhash = ""
        
        heu_addy = None
        heu_perc = 0
        poss_functions = []
        poss_return = []
        search = string.replace(search, "\\n","\n")
        if search:
            if module:
                #XXX: access directly  isn't the best way to do this
                for key,mod in debugger.Getallmodules().iteritems():
                    if module.lower() in key.lower():
                        poss_functions += self.imm.searchCommandsOnModule(mod[0], search)
            else:
                poss_functions = self.imm.searchCommands(search)
        if poss_functions:
            for poss in poss_functions:
                #self.imm.Log("possible funct: %08X" % poss[0])
                addy = self.imm.getFunctionBegin(poss[0])
                if not addy:
                    #check entrypoint routine
                    for mod in self.imm.getAllModules().values():
                        if mod.getMainentry():
                            #self.imm.Log("mainentry: %08X" % mod.getMainentry())
                            f = StackFunction(self.imm, mod.getMainentry())
                            if f.isInsideFunction(poss[0]):
                                addy = mod.getMainentry()
                                break
                if not addy and firstbb:
                    #self.imm.Log("Trying with the new firstbb")
                    addy = self.findBasicBlockHeuristically(poss[0], firstbb)
                if not addy and firstbb:
                    tmp = self.findFirstBB(poss[0])
                    if tmp:
                        #self.imm.Log("Trying with the new firstbb 2nd try:%X"%tmp,tmp)
                        addy = self.findBasicBlockHeuristically(tmp, firstbb)
                if not addy:
                    addy = poss[0]
                #self.imm.Log("possible start: %08X" % addy)
                
                #Make a comparision using an Exact Hash
                if exact:
                    test = self.makeFunctionHashExact(addy)
                    if exact ==  test and not firstcallhash:
                        #self.imm.Log("EXACT match")
                        #when we find an exact match, we don't need to search anymore
                        return [ (addy, 100) ]
                
                perc = self.checkHeuristic(addy, functionhash, firstcallhash)
                #self.imm.Log("function %08X similar in %d%%" % (addy, perc))
                if  perc >= heuristic:
                    poss_return.append( (addy,perc) )
                    #self.imm.Log("HEURISTIC match")
        return poss_return
    
    def searchFunctionByName(self, name, heuristic = 90, module = None, version = None):
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
        
        @rtype: LIST
        @return: a list of tuples with possible function's addresses and the heauristic match percentage 
        """
        #the name is case insensitive
        name = name.lower()
        
        #Heuristic search
        poss_return = []
        for data in self.dictionaries:
            if name == data[0].lower():
                #support version matching
                if version and version.lower() != data[6].lower():
                    continue
                
                #self.imm.Log("trying with: %s, version: %s" % ( data[0], data[5]))
                if len(data) < 9: data[7] = "" #support for older entries
                poss_return += self._searchFunctionByHeuristic(data[1], data[2], data[3], data[4], heuristic, module, string.split(data[7],"|"))
        return poss_return

    def makeFunctionHashExact(self, address):
        """
        Return a SHA-1 hash of the function, taking the raw bytes as data.
        
        @type  address: DWORD
        @param address: address of the function to hash
        
        @rtype: STRING
        @return: SHA-1 hash of the function
        """
        
        f = self.imm.getFunction(address)
        bbs = f.getBasicBlocks()
        bucket = ""
        data = {}
        
        for bb in bbs:
            data[bb.getStart()] = self.imm.readMemory(bb.getStart(), bb.getSize())

        keys = data.keys()
        keys.sort()
        
        for key in keys:
            bucket += data[key]
        
        hash = hashlib.sha1(bucket).hexdigest()
        del bucket
        del bbs
        del f
        return hash
    
    def makeFunctionHash(self, address, compressed = False):
        """
        Return a list with the best BB to use for a search and the heuristic hash
        of the function. This two components are the function hash.
        
        @type  address: DWORD
        @param address: address of the function to hash
        
        @type  compressed: Boolean
        @param compressed: return a compressed base64 representation or the raw data
        
        @rtype: LIST
        @return: 1st element is the generalized instructions to use with searchCommand
                 2nd element is the heuristic function hash (makeFunctionHashHeuristic)
                 3rd element is an exact hash of the function (makeFunctionHashExact)
                 4th element is a LIST of generalized instructions of the first BB (to find the function begin)
        """
        
        ret = []
        ret.append(self.selectBasicBlock(address))
        ret.append(self.makeFunctionHashHeuristic(address, compressed))
        ret.append(self.makeFunctionHashExact(address))
        ret.append(self.generalizeFunction(address)[1][1])
        return ret

    def selectBasicBlock(self, address):
        bbs = self.generalizeFunction(address)
        
        #make some punctuation to get the BB with major diversity and 
        #quantity of instructions
        hpoints = bb = 0
        for id, instrs in bbs[1].iteritems():
            map = {}
            sum = 0
            for instr in instrs:
                sum += 1
                base = instr.split(" ")
                if "REP" in base[0]:
                    base = base[0] + " " + base[1]
                else:
                    base = base[0]
                map[base] = True
                if sum > 7: break
            
            #it's four times more important diversity than quantity
            #We can use 8 instructions to search, so priorize diversity
            points = sum + len(map)*4
            if points > hpoints:
                #self.imm.Log("new hpoint (%d, last %d): %s" % (points,hpoints,instrs[0:8]))
                #self.imm.Log("sum: %d diver: %d" % (sum, len(map)))
                hpoints = points
                bb = id
        ret = ""
        if bb:
            ret = string.join(bbs[1][bb][0:8],"\\n")
        del bbs
        return ret
    
    def generalizeFunction(self, address):
        """
        Take an address an return a generalized version of the function, dismissing
        address and register dependant information.
        
        @type  address: DWORD
        @param address: address to the function begin
        
        @rtype: LIST
        @return: the 1st value is a DICTIONARY of a Control Flow Graph of the 
                 BB conexions (each BB have an arbitrary ID)
                 the 2nd value is a DICTIONARY using this arbitrary BB ID as the key
                 and a LIST of searchCommand suitable, generalized instructions.
        """
        bbcount = 1
        bbmap = {}
        cfg = {}
        bbinfo = {}
        
        f = self.imm.getFunction(address)
        bbs = f.getBasicBlocks()
        
        #Make a control flow graph
        for bb in bbs:
            if not bbmap.has_key(bb.getStart()):
                bbmap[bb.getStart()] = bbcount
                bbcount += 1
            if not bbmap.has_key(bb.getEdges()[0]):
                bbmap[bb.getEdges()[0]] = bbcount
                bbcount += 1
            if not bbmap.has_key(bb.getEdges()[1]):
                bbmap[bb.getEdges()[1]] = bbcount
                bbcount += 1
            
            cfg[bbmap[bb.getStart()]] = [ bbmap[bb.getEdges()[0]], bbmap[bb.getEdges()[1]] ]
            
            regex = []
            for op in bb.getInstructions(self.imm):
                asm = self.generalizeInstruction(op)
                regex.append(asm)
                #self.imm.Log("%s --> %s" % (op.getDisasm(), asm))
            bbinfo[bbmap[bb.getStart()]] = regex
        
        del bbs
        del f
        del regex
        return [ cfg, bbinfo ]
    
    def generalizeInstruction(self, inp):
        """
        Generalize an instruction given an address or an opCode instance
        
        @type  inp: DWORD|OpCode OBJECT
        @param inp: address to generalize or opcode to generalize
        
        @rtype: STRING
        @return: a generalized assembler instruction
        """
        if not isinstance(inp, opCode):
            op = self.imm.Disasm(inp)
        else: op = inp
        
        asm = op.getDisasm()
        
        #replace the constants inside the opcode to the word CONST
        if op.isConditionalJmp():
            asm = "JCC CONST"
        if op.getImmConst() or op.operand[0][0] == DEC_CONST:
            #self.imm.Log("const part:%X"%op.getImmConst())
            r = re.compile("(?<=[ ,\[])[a-z0-9_\.\@\-]*%X" % op.getImmConst(), re.I)
            asm = r.sub('CONST', asm)
            if op.getImmConst() > 0xFFFFBFFF:
                #self.imm.Log("neg part!. %X: %X"%(op.getImmConst(),op.getImmConst()-0x100000000))
                r = re.compile("(?<=[ ,\[])[a-z0-9_\.\@\-]*\%X" % (op.getImmConst()-0x100000000), re.I)
                asm = r.sub('CONST', asm)
        if op.getAddrConst():
            if not op.indexed:
                asm = asm.split("[")[0]+"[CONST]"+asm.split("]")[1]
            else:
                tmp = "%+X" % struct.unpack("l", struct.pack("L", op.getAddrConst()))
                asm = asm.replace(tmp,"+CONST")
        if op.getJmpConst():
            r = re.compile("(?<=[ ,\[])[a-z0-9_\.\-\@]*%X" % op.getJmpConst(), re.I)
            asm = r.sub('CONST', asm)
        
        #<JMP &msvcrt._initterm> --> CONST
        asm = re.sub(r'(?i)<[a-z\.&_0-9\@\-]+>', "CONST", asm)
        
        #CALL schannel._SetWrapNoEncrypt@12 --> CONST
        asm = re.sub(r'(?i)[a-z\.&_0-9\@\-]+\.[a-z\.&_0-9\@\-]+',"CONST", asm)
        
        #generalize registers
        if not op.getAddrConst() or not op.indexed:
            asm = re.sub(r'(?i)(?<![A-Z])E([ABCD]X|[SD]I)(?![A-Z])', 'R32', asm)
        else:
            #this's a workaround until we fix wildcard searching
            asm = re.sub(r'(?i)(?<![A-Z\+\-\[])E([ABCD]X|[SD]I)(?![A-Z])', 'R32', asm)
        asm = re.sub(r'(?i)(?<![A-Z])([ABCD]X|[SD]I)(?![A-Z])', 'R16', asm)
        asm = re.sub(r'(?i)(?<![A-Z])[ABCD][HL](?![A-Z])', 'R8', asm)
        
        #XXX: we can decide to forget some opcodes using ANY n
        #XXX: we can support replacing registers with RA and RB

        return asm
    
    def findBasicBlockHeuristically(self, address, firstbb, maxsteps=20):
        """
        Try to match a generalized BB with an address range (moving backward).
        
        @type  address: DWORD
        @param address: address used to match with the generalized BB
        
        @type  firstbb: LIST
        @param firstbb: a list of generalized assembler instructions
        
        @type  maxsteps: INTEGER
        @param maxsteps: max amount of steps to go backward looking for a BB
        
        @rtype: DWORD|None
        @return: starting address of the BB that match with the generalized version or None if we don't find it
        """
        #self.imm.Log("whole firstbb: %s" % firstbb)
        index = address
        instr = 0
        while instr < maxsteps:
            num = 0
            notmatch = False
            #compare the whole BB
            for cmp in firstbb:
                gen = self.generalizeInstruction(self.imm.disasmForward(index, num))
                if gen != cmp:
                    notmatch = True
                    #self.imm.Log("%s != %s. idx=%08X - num=%d" % (gen,cmp,index,num))
                    break
                num += 1
            
            if notmatch:
                index = self.imm.disasmBackward(index, 1).getAddress()
                instr += 1
            else:
                #self.imm.Log("BB found using heuristic", index)
                return index
        
        return None
    
    def findFirstBB(self, address, recursive=False):
        """
        The main idea is traverse a function backward following Xrefs until we reach a point where there's no more Xrefs other than CALLs
        
        @type  address: DWORD
        @param address: address used find the first BB
        
        @rtype: DWORD|None
        @return: Address of the first BB of the function or None if we don't find it
        """
        
        poss = []
        
        xref = self.imm.getXrefFrom(address)
        for info in xref:
            if info[1] != 3:
                #not a CALL xref
                poss.append(info[0])
        
        if not xref and not recursive:
            return None
        if not poss:
            return address
        
        for addy in poss:
            tmp = self.findFirstBB(addy, True)
            if tmp:
                return addy
        
        return None
