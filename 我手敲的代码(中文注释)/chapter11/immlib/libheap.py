#!/usr/bin/env python
"""
Immunity Heap API for Immunity Debugger

(c) Immunity, Inc. 2004-2006


U{Immunity Inc.<http://www.immunityinc.com>} Debugger Heap Library for python


"""

__VERSION__ = '1.3'

import immutils
import struct
import string
from UserList import UserList
HEAP_MAX_FREELIST = 0x80



class PHeap:
    def __init__(self, imm, heapddr = 0, restore = False):
        """
        Windows 32 Heap Class
       
        @rtype: PHEAP object
        """   
        self.imm = imm
        self.address  = heapddr
        self.chunks = []
        self.restore = restore
        self.Segments = []
        if heapddr:
            self._grabHeap()

            

    def _grabHeap(self):
            try:
                    heaps = self.imm.readMemory( self.address, 0x588 )
            except WindowsError, msg:
                    raise Exception, "Failed to get heap at address : 0x%08x" % heapaddr
            
            index = 0x8
            (self.Signature, self.Flags, self.ForceFlags, self.VirtualMemoryThreshold,\
             self.SegmentReserve, self.SegmentCommit, self.DeCommitFreeBlockThreshold, self.DeCommitTotalBlockThreshold,\
             self.TotalFreeSize, self.MaximumAllocationSize, self.ProcessHeapListIndex, self.HeaderValidateLength,\
             self.HeaderValidateCopy,self.NextAvailableTagIndex, self.MaximumTagIndex, self.TagEntries, \
             self.UCRSegments, self.UnusedUnCommittedRanges, self.AlignRound, self.AlignMask) =\
                struct.unpack("LLLLLLLLLLHHLHHLLLLL", heaps[ index : index + (0x50-8) ])
    
            index+= 0x50-8
            self.VirtualAllocedBlock  = struct.unpack("LL", heaps[ index : index + 8 ])
            index+=8
            self._Segments = struct.unpack("L" * 64, heaps[ index: index+ 64*4 ])
            index+=64*4
            self.FreeListInUseLong = struct.unpack("LLLL" , heaps[ index : index + 16 ])
            index+=16
            (self.FreeListInUseTerminate,self.AllocatorBackTraceIndex) = struct.unpack("HH", heaps[ index : index + 4 ])
            index+=4
            self.Reserved1= struct.unpack("LL", heaps[ index : index + 8 ])
            index+=8
            self.PseudoTagEntries= struct.unpack("L", heaps[ index : index + 4])
            index+=4
            self.FreeList=[]
            
            # Getting the FreeList
            for a in range(0, 128):
                    free_entry = []
                    # Previous and Next Chunk of the head of the double linked list
                    (prev, next) = struct.unpack("LL", heaps[ index + a*8 : index + a*8 + 8 ])
                    
                    free_entry.append((self.address + index+ a * 8, prev, next))
                    base_entry = self.address + index + a * 8
    
                    # Loop over the Double Linked List until next == to the begging of the list.
                    while next != base_entry:
                            tmp = next
                            try:
                                    (prev,next) = struct.unpack("LL",  self.imm.readMemory(next, 0x8))
                            except:
                                break
                            
                            free_entry.append( (tmp, prev,next) )
                            
                    self.FreeList.append(free_entry)
                    
            index+=256*4
            (self.LockVariable, self.CommitRoutine, self.Lookaside, self.LookasideLockCount)=\
             struct.unpack("LLLL", heaps[index:index+16])                     
    
            # the first segment is the heap on the base address (the 2nd chunk)
            #self.Segments.
            for a in range(0, 64):
                    if self._Segments[a] == 0x0:
                            break
		    s = Segment( self.imm,  self._Segments[a] )
                    self.Segments.append( s )		    
                    #imm.Log("Segment[%d]:      0x%08x" % (a, self.Segments[a]))
		    # BaseAddress
                    if self.restore:
                        self.getRestoredChunks( s.BaseAddress )
                    else:
                        self.getChunks( s.BaseAddress )
                    for idx in s.Pages:
                        self.imm.Log("> 0x%08x" % idx)			    
                        if self.restore:
                            self.getRestoredChunks( idx )
                        else:
                            self.getChunks( idx )
                   
    def printFreeListInUse(self, uselog=None):
        """ 
        Print the Heap's FreeListInUse bitmask
        
        @type  uselog: Log Function
        @param uselog: (Optional, Def: Log Window) Log function that display the information
        """
        tbl= ["FreeListInUse %s %s"%  (immutils.decimal2binary(self.FreeListInUseLong[0]), immutils.decimal2binary(self.FreeListInUseLong[1])),\
                "              %s %s" % (immutils.decimal2binary(self.FreeListInUseLong[2]), immutils.decimal2binary(self.FreeListInUseLong[3]))]
        if uselog:
            for a in tbl:
                uselog(a)
        return tbl
    
    def printFreeList(self, uselog = None):
        """ 
        Print the Heap's FreeList
        
        @type  uselog: Log Function
        @param uselog: (Optional, Def: Log Window) Log function that display the information
        """
        log = self.imm.Log
        if uselog:
            log = uselog
        for a in range(0, 128):
            entry= self.FreeList[a]
            e=entry[0]
            
            log("[%03x]   0x%08x -> [ 0x%08x |  0x%08x ] " % (a, e[0], e[1], e[2]), address = e[0])
            for e in entry[1:]:
                    try:
                        sz = self.get_chunk( e[0] - 8 ).size
                    except:
                        sz = 0
                    log("        0x%08x -> [ 0x%08x |  0x%08x ] (%08x)" % (e[0], e[1], e[2], sz), address= e[0])
        return 0x0

    # Get Chunnks restored
    def getRestoredChunks(self,  address):
        """
        Enumerate Chunks of the current heap using a restore heap

        @type  address: DWORD
        @param address: Address where to start getting chunks

        @rtype:  List of win32heapchunks
        @return: Chunks
        """

        imm = self.imm
        
        oldheap = imm.getKnowledge("saved_heap_%08x" % self.address) #retriving the heap
        if not oldheap:
            imm.Log("Coudln't use restore mode: No saved Heap")
            return self.getChunks(address)
        
        ptr = address
        # null chunk
        backchunk = self.get_chunk(imm, ptr, self.address)

        backchunk.size = backchunk.psize
        backchunk.usize = backchunk.upsize
        
        while 1:
             
            try:
                c = self.get_chunk(imm, ptr, self.address)
            except:
                return self.chunks

            #ptr+= c.size * 8
            next = ptr + c.usize
            
            try:
                sizes = imm.readLong( next )
                previous = (sizes>>16) & 0xffff
            except Exception:
                previous = 0 # unable to read

            # When to restore?
            #  o Chunk size is zero
            #  o Chunk previous size is zero
            #  o When Size is different from next chunk previous size
            #  o Next chunk previous size is zero (means, readLong fails) and the chunk is not a top chunk
            #  o When the size of the backward chunk is different for the chunk Size
            if (not c.size) or (c.size != previous and not c.istop()) or (not previous and not c.istop()) or (backchunk.size != c.psize) :
                restoredchunk = oldheap.findChunkByAddress(ptr)
                
                if restoredchunk:
                    c = restoredchunk
                    c.setRestored()
                    next = ptr + c.usize
            ptr = next            
            self.chunks.append(c)
            backchunk = c
            
            
            if c.istop() or c.size == 0:
                break
            
            backchunk = c
            
        return self.chunks

    def findChunkByAddress(self, addr):
        """
        Find a Chunks by its address

        @type  address: DWORD
        @param address: Address to search for

        @rtype:  win32heapchunks
        @return: Chunk
        """

        for a in self.chunks:
            if a.addr == addr:
                return a
        return None
            
    def getChunks(self, address, size = 0xffffffffL):
        """
        Enumerate Chunks of the current heap
        
        @type  address: DWORD
        @param address: Address where to start getting chunks

        @type  size: DWORD
        @param size: (Optional, Def: All) Amount of chunks

        @rtype:  List of win32heapchunks
        @return: Chunks
        """
        imm = self.imm
        
        ptr = address

        while size:
            
            try:
                 c = self.get_chunk( ptr )
            except Exception, msg:   
                imm.Log("Failed to grab chunks> " + str(msg) )
                return self.chunks
            
            self.chunks.append(c)
            
            #c.printchunk()
            ptr+= c.usize
            if c.istop() or c.size == 0:
                break
            size -= 1 

        return self.chunks

    def get_chunk(self,  addr):   
        return win32heapchunk(self.imm,  addr, self)

class Segment:
    def __init__(self, imm, addr):
        self.address = addr
        addr += 8 # AVOID THE ENTRY ITSELF
        mem = imm.readMemory(addr, 0x34)

	(self.Signature, self.Flags, self.Heap, self.LargestUnCommitedRange, self.BaseAddress,\
         self.NumberOfPages, self.FirstEntry, self.LastValidEntry, self.NumberOfUnCommittedPages,\
         self.NumberOfUnCommittedRanges, self.UnCommittedRanges, self.AllocatorBackTraceIndex,\
         self.Reserved, self.LastEntryInSegment) = struct.unpack("LLLLLLLLLLLHHL", mem)
	imm.Log("SEGMENT: 0x%08x Sig: %x" % (self.address, self.Signature), address = self.address )
        imm.Log("Heap: %08x LargetUncommit %08x Base: %08x" % (self.Heap, self.LargestUnCommitedRange, self.BaseAddress))
        imm.Log("NumberOfPages %08x FirstEntry: %08x LastValid: %08x" %  (self.NumberOfPages, self.FirstEntry, self.LastValidEntry))
	imm.Log("Uncommited: %08x" % self.UnCommittedRanges)
        self.Pages = [] 
	if self.UnCommittedRanges:
            i = 0		
            addr = self.UnCommittedRanges
	    while addr != 0: 
                mem = imm.readMemory( addr,  0x10 )
                ( C_Next, C_Addr, C_Size, C_Filler) = struct.unpack( "LLLL", mem )
		#imm.Log( ">> Memory: 0x%08x Address: 0x%08x (a: %08x) Size: %x" % ( addr, C_Next, C_Addr,C_Size) )
		self.Pages.append( C_Addr + C_Size )
                addr = C_Next

class VistaPHeap(PHeap):
    def __init__(self,  imm, heapddr = 0, restore = False):
        PHeap.__init__(self, imm, heapddr, restore)

    def _grabHeap(self):
        try:
            heapmem = self.imm.readMemory( self.address + 8 , 0x120 )        
        except WindowsError, msg:
            raise Exception, "Failed to get heap at address : 0x%08x" % heapaddr
        index = 8           
        (self.SegmentSignature, self.SegmentFlags, self.SegmentListEntry_Flink, self.SegmentListEntry_Blink, self.Heap, self.BaseAddress, self.NumberOfPages, self.FirstEntry, self.LastValidEntry, self.NumberofUncommitedPages, self.NumberofUncommitedRanges, self.SegmentAllocatorBackTraceIndex, self.Reserved, self.UCRSegmentList_Flink, self.UCRSegmentList_Blink, self.Flags, self.ForceFlags, self.CompatibilityFlags, self.EncodeFlagMask, self.EncodingKey, self.EncodingKey2, self.PointerKey, self.Interceptor_debug, self.VirtualMemoryThreshold, self.Signature, self.SegmentReserve, self.SegmentCommit, self.DeCommitThresholdBlock, self.DeCommitThresholdTotal, self.TotalFreeSize, self.MaxAllocationSize, self.ProcessHeapsListIndex, self.HeaderValidateLength, self.HeaderValidateCopy, self.NextAvailableTagIndex, self.MaximumTagIndex, self.TagEntries, self.UCRList_Flink, self.UCRList_Blink, self.AlignRound, self.AlignMask, self.VirtualAlloc_Flink, self.VirtualAlloc_Blink, self.SegmentList_Flink, self.SegmentList_Blink, self.AllocatorBackTraceIndex, self.NonDedicatedListLenght, self.BlocksIndex, self.UCRIndex, self.PseudoTagEntries, self.FreeList_Flink, self.FreeList_Blink, self.LockVariable, self.CommitRoutine, self.FrontEndHeap, self.FrontHeapLockCount, self.FrontEndHeapType, self.TotalMemoryReserved, self.TotalMemoryCommited, self.TotalMemoryLargeUCR, self.TotalSizeInVirtualBlocks, self.TotalSegments, self.TotalUCRs, self.CommitOps, self.DecommitOps, self.LockAcquires, self.LockCollisions, self.CommitRate, self.DeCommitRate, self.CommitFailures, self.InBlockCommitFailures, self.CompactHeapCalls, self.CompactedUCRs, self.InBlockDecommits, self.InBlockDecommitSize, self.TunningParameters) = struct.unpack("L" * 11 + "HH" + "L" *18 + "HHLHH" + "L" * 19 + "HH" + "L" * 19, heapmem)
        # XXX: TODO Loop over the Segments 
        self.imm.Log("FreeList: 0x%08x | 0x%08x" % (self.FreeList_Flink, self.FreeList_Blink) )
        head = self.address +0x10
        addr = self.SegmentList_Blink 
        self.Segments.append( self.address )
        self.getChunks( self.address )
        self.imm.Log("segment: 0x%08x 0x%08x" % (self.SegmentList_Flink, self.SegmentList_Blink) )
        while head != addr:
            self.Segments.append( addr - 0x10 )
            self.getChunks( addr - 0x10 )
            addr = self.imm.readLong( addr )
                        
        #self.FreeList_Flink
        
        self.getBlocks( self.BlocksIndex )
        if self.FrontEndHeap:
            self.LFH = LFHeap( self.imm, self.FrontEndHeap )

    def getBlocks(self, startaddr):
        self.blocks = []
        addr = startaddr

        while addr:
            block = Blocks( self.imm, addr )
            self.blocks.append( block )
            block.FreeList=[]
            memory = self.imm.readMemory( block.Buckets, 0x80*8 )
            if block.FreeListInUsePtr:      
                block.setFreeListInUse( struct.unpack("LLLL", self.imm.readMemory( block.FreeListInUsePtr, 4*4 )) )

            # Getting the FreeList
            for a in range(0, 128):
                    free_entry = []
                    # Previous and Next Chunk of the head of the double linked list
                    (fwlink, heap_bucket) = struct.unpack("LL", memory[a *8 : a *8 + 8] )
                    if fwlink:
                        try:
                          (next, prev) = struct.unpack("LL", self.imm.readMemory( fwlink, 8) )
                        except: 
                          next, prev = (0,0)
                          self.imm.Log("Error with 0x%x" % fwlink)
                        free_entry.append( (fwlink, next, prev) )               
                        base_entry = fwlink

                        while next and next != base_entry:
                            tmp = next
                            chunk = win32vistaheapchunk( self.imm,  next - 8, self )

                            if a == 127:    
                                if chunk.size <= a:
                                    break
                            else:
                                if chunk.size != a:
                                    break                                       

                            next = chunk.nextchunk
                            free_entry.append( (tmp, chunk.nextchunk, chunk.prevchunk) )

                    else:
                        free_entry = [ (fwlink, 0x0, 0x0) ]

                    #if heap_bucket & 1:
                    #    bucket = self.getBucket( heap_bucket - 1 )                                         
                    block.FreeList.append(free_entry)

            addr = block.FwLink 

    def get_chunk(self,  addr):   
        return win32vistaheapchunk(self.imm,  addr, self)
    
    def printFreeList(self, uselog = None):
        """ 
        Print the Heap's FreeList
        
        @type  uselog: Log Function
        @param uselog: (Optional, Def: Log Window) Log function that display the information
        """
        log = self.imm.Log
        if uselog:
            log = uselog
        for block in self.blocks:    
            f = block.FreeListInUse
            log("** Block 0x%08x StartSize: %d MaxSize: %d CtrZone: %d **" % ( block.address, block.StartSize, block.MaxSize, block.CtrZone ) )
            log("FreeListInUse: %s %s" % (immutils.decimal2binary(f[0]),\
                            immutils.decimal2binary(f[1]) ) )
            log("               %s %s" % (immutils.decimal2binary(f[2]),\
                            immutils.decimal2binary(f[3]) ) )
            
            for a in range(0, 128):
                entry= block.FreeList[a]
                e=entry[0]
                if e[0]:
                    log("[%03d]   0x%08x -> [ 0x%08x |  0x%08x ] " % (a, e[0], e[1], e[2]), address = e[0])
                    for e in entry[1:]:
                        log("        0x%08x -> [ 0x%08x |  0x%08x ] " % (e[0], e[1], e[2]), address= e[0])
        return 0x0


class LFHeap:
    def __init__(self, imm, addr):
        mem = imm.readMemory( addr, 0x300 )
        if not mem:
            raise Exception, "Can't read Low Fragmentation Heap at 0x%08x" % addr
        index = 0
        self.address = addr
        imm.Log("Low Fragmented Heap: 0x%08x" % addr)
        (self.Lock, self.field_4, self.field_8, self.field_c,\
         self.field_10, field_14, self.SubSegmentZone_Flink, 
         self.SubSegmentZone_Blink, self.ZoneBlockSize,\
         self.Heap, self.SegmentChange, self.SegmentCreate,\
         self.SegmentInsertInFree, self.SegmentDelete, self.CacheAllocs,\
         self.CacheFrees) = struct.unpack("L" * 0x10, mem[ index : index +0x40 ])
        index += 0x40
        self.UserBlockCache = []
        for a in range(0,12):
            umc = UserMemoryCache( addr + index, mem[ index : index + 0x10] )   
            index+= 0x10
            self.UserBlockCache.append( umc )
        self.Buckets = []
        for a in range(0, 128):
            entry = mem[ index  : index  + 4 ]
            b = Bucket( addr + index,  entry)
            index = index + 4
            self.Buckets.append( b )

        self.LocalData = LocalData(imm, addr + index )

class LocalData:
    def __init__(self, imm, addr):
        self.address = addr

        mem = imm.readMemory( addr, 0x18 + 0x68*128 )
        (self.Next, self.Depth, self.Seq, self.CtrZone, self.LowFragHeap,\
         self.Sequence1, self.Sequence2) = struct.unpack("LHHLLLL", mem[:0x18])
        index = 0x18
        self.SegmentInfo = []
        for a in range(0, 128):
            l = LocalSegmentInfo( imm, self.address + index,\
                mem[ index  : index + 0x68] )               
            index+= 0x68
            self.SegmentInfo.append( l )

# What the real size of this, it is 0x64 or 0x68?
class LocalSegmentInfo:
    def __init__(self, imm, addr, mem = ""):
        self.address = addr         
        self.SubSegment = []
        self.imm = imm
        if not mem:
            mem = imm.readMemory( self.address, 0x68 )

        (self.Hint, self.ActiveSubsegment) = struct.unpack("LL", mem[0:8] )
        index = 8
        self.CachedItems = struct.unpack("L" * 0x10, mem[ index : index + 0x10*4])
        index += 0x10*4
        (self.Next, self.Depth, self.Seq, self.TotalBlocks,\
        self.SubSegmentCounts, self.LocalData, self.LastOpSequence,\
        self.BucketIndex, self.LastUsed, self.Reserved) = struct.unpack("LHHLLLLHHL", mem[index: index + 0x20])

        if self.Hint:
            self.SubSegment.append( self.getSubSegment( self.Hint, "Hint" ) )
        if self.ActiveSubsegment and self.ActiveSubsegment != self.Hint:
            self.SubSegment.append( self.getSubSegment( self.ActiveSubsegment, "ActiveSS") )
	for a in range( 0, len(self.CachedItems) ):
            item = self.CachedItems[a]		
            if item and item not in (self.Hint, self.ActiveSubsegment):
                self.SubSegment.append( self.getSubSegment( item, "Cache_%02x" % a) )		    
                        
        
                
    def getSubSegment(self, address, type = ""):
        return SubSegment(self.imm, address, type)         

class SubSegment:
    def __init__(self, imm, address, type=""):
        self.address = address      
        self.type = type
        self.chunks = []
        mem = imm.readMemory( address, 0x20 )
        (self.LocalInfo, self.UserBlocks, self.AggregateExchg,\
         self.Aggregate_Sequence, self.BlockSize, self.Flags,\
         self.BlockCount, self.SizeIndex, self.AffinityIndex, 
         self.Next, self.Lock) = struct.unpack("LLLLHHHBBLL", mem)
        self.Offset = self.AggregateExchg >> 0xD 
        self.Offset = self.Offset & 0x7FFF8
        self.Depth  = self.AggregateExchg & 0xFFFF
        #imm.Log("UserBlock %s: 0x%08x size: %x offset: %x Depth: %x (0x%08x)" % ( self.type, self.UserBlocks, self.BlockSize, self.Offset, self.Depth,  self.Next), address = self.UserBlocks)
        if self.UserBlocks:
            self.UserDataHeader = self.getUserData( imm,  self.UserBlocks )

            # XXX: We need to check the "Next" for more chunks 
            list = self.grabBusyList( imm, self.UserBlocks, self.Offset, self.Depth)
            self.chunks = self.getChunks( imm, self.UserBlocks + self.UserDataHeader.getSize(), list ) 
        
    def grabBusyList(self, imm, base_addr, offset, depth):
        list = {}           
        i = 1
        for a in range(0, depth):
            address = base_addr + offset                
            dword   = imm.readLong( address + 8 )       
            offset = dword & 0xFFFF
            offset *=8
            list[ address ] = a + 1   
        return list
        
    def getUserData(self, imm, addr):
        return UserData( imm, addr )        

    def getChunks(self, imm, address, list):
        #mem = imm.readMemory( self.UserBlocks, self.BlockSize * self.BlockCount)
        addr = address
        chunks = []
        for a in range(0, self.BlockCount):
            c = win32vistaheapchunk(imm, addr, BlockSize = self.BlockSize)
            s = "B"
            if list.has_key(addr):
                c.setFreeOrder( list[addr] )		    
                s = "F(%02d)" % list[addr]                  
            #imm.Log("Chunk  size: 0x%x lfhflag: 0x%x %s" % ( self.BlockSize,  c.lfhflags, s ), address = addr)
            addr += self.BlockSize*8
            chunks.append( c )
        return chunks

class UserData:
    def __init__(self, imm, addr):
        self.address = addr
        mem = imm.readMemory(addr, 0x10)
        (self.SubSegment, self.Reserved, self.SizeIndex, self.Signature) =\
         struct.unpack("LLLL", mem)
    def getSize(self):
        return 0x10         

class Bucket:
    def __init__(self, addr, mem):      
        self.address = addr
        (self.BlockUnits, self.SizeIndex, Flag) =\
        struct.unpack("HBB", mem[:4])
        # Theoretically, this is how the Flag are separated:
        self.UseAffinity = Flag & 0x1
        self.DebugFlags  = (Flag >1) & 0x3 
                                
class UserMemoryCache:
    def __init__(self, addr, mem):
        self.address = addr         
        (self.Next, self.Depth, self.Sequence, self.AvailableBlocks,\
         self.Reserved) = struct.unpack("LHHLL", mem[ 0 : 16 ])
        
class Blocks:
    def __init__(self, imm, addr):
        mem = imm.readMemory( addr, 0x24 )
        if not mem:
            raise Exception, "Can't read Block at 0x%08x" % addr
        self.address = addr    
        self.FreeListInUse = None
        self.FreeList = []
        (self.FwLink, self.MaxSize, self.CtrZone, self.field_c, 
         self.field_10, self.StartSize, self.FreeListPtr,\
         self.FreeListInUsePtr, self.Buckets) =\
         struct.unpack( "L" * 9, mem )   
    def setFreeListInUse(self, inuse):
        self.FreeListInUse = inuse
   
    def setFreeList(self, flist):
        self.FreeList = flist       

SHOWCHUNK_FULL = 0x1
CHUNK_ANALIZE  = 0x2
class win32heapchunk:
    FLAGS = { 'EXTRA PRESENT':('E', 0x2), 'FILL PATTERN':('FP', 0x4),\
             'VIRTUAL ALLOC': ('V', 0x8), 'TOP': ('T', 0x10), 
             'FFU1':('FFU1',0x20), 'FFU2': ('FFU2', 0x40),\
             'NO COALESCE':('NC', 0x80) }
    BUSY = ('BUSY', ('B', 0x1))
    def __init__(self, imm, addr, heap = None):
        """ Win32 Chunk """
        self.imm = imm # later replace it with heap.imm

        self.restored = False

        if heap:
            self.heap_addr = heap.address
        else:
            self.heap_addr = 0
        self.nextchunk=0
        self.prevchunk=0
        self.addr = addr
         
        try:
                dword1 = self.imm.readLong(addr)
                dword2 = self.imm.readLong(addr+4)
        except Exception:
                raise Exception, "Failed to read chunk at address: 0x%08x" % addr

        self._get( dword1, dword2, addr )


    def _get(self, size, flags, addr):
        self.size   = size & 0xffff
        self.usize  = self.size * 8 # unpacked

        self.psize  = ( size >> 16 ) & 0xffff
        self.upsize = self.psize * 8
       
        self.field4 = flags & 0xff         
        self.flags  = (flags >> 8) & 0xff
        self.other  = (flags >> 16) & 0xffff
        mem_addr = addr + 8
        if not (self.flags & self.BUSY[1][1] ):
            if self.flags & self.FLAGS['VIRTUAL ALLOC'][1]:
                pass
            else:
                try:
                        self.nextchunk= self.imm.readLong(addr+8)
                        self.prevchunk= self.imm.readLong(addr+12)
                except WindowsError:
                        raise Exception, "Failed to read chunk at address: 0x%08x" % addr

                mem_addr +=8

        self.data_addr = mem_addr
        self.data_size = self.upsize - (addr - mem_addr)

        try:
                self.sample = self.imm.readMemory(self.data_addr, 0x10)
        except WindowsError:
                raise Exception, "Failed to read chunk at address: 0x%08x" % addr

        self.properties= {'size': self.usize, 'prevsize': self.upsize, 'field4': self.field4,\
                          'flags':self.flags, 'other':self.other, 'address':self.addr,\
                          'next': self.nextchunk, 'prev': self.prevchunk}
    
    def setRestored(self):
        self.restored = True

    def isRestore(self):
        return self.restored
    
    def get(self, what):
        try:
            return self.properties[string.lower(what)]
        except KeyError:
            return None

    def printchunk(self, uselog= None, option=0, dt= None):
        ret = []
        if self.isRestore():
            restore = "<R>"
        else:
            restore = ""
        ret.append((self.addr, "0x%08x> " % self.addr + "size:    0x%08x  (%04x)  prevsize: 0x%08x (%04x) %s" % (self.usize, self.size, \
                                                                    self.upsize, self.psize, restore) ))
        ret.append((self.addr, "            heap:   *0x%08x*         flags:    0x%08x (%s)" % (self.heap_addr, self.flags,\
                                                             self.getflags(self.flags))))
        #print "unused:  0x%08x          flags: 0x%08x (%s)" % (self.field4, self.flags,\
        #                                                     self.getflags(self.flags))
        if not (self.flags & self.BUSY[1][1]):
            ret.append((self.addr, "            next:    0x%08x          prev:     0x%08x" % (self.nextchunk, self.prevchunk)))
        if option & SHOWCHUNK_FULL:
            dump = immutils.hexdump(self.sample)
            for a in range(0, len(dump)):
                if not a:
                    ret.append((self.addr, "           (%s  %s)" % (dump[a][0], dump[a][1])))
        if dt:
            result = dt.Discover(self.imm.readMemory(self.data_addr, self.data_size), self.data_addr)
            #self.imm.Log( str(ret ))
            for obj in result:
                msg = obj.Print()
                ret.append((obj.address, " > %s: %s " % (obj.name, msg) ))
            #imm.Log( "obj: %s: %s %d" % (obj.name, msg, obj.getSize() ), address = obj.address)

        if uselog:
            for adr, msg in ret:
                uselog(msg, address = adr)        
                
        return ret
    
    def getflags(self, flag):
        f=""
        if self.flags & self.BUSY[1][1]:
            f+=self.BUSY[1][0]
        else:
            f+="F"

        for a in self.FLAGS.keys():
            if self.FLAGS[a][1] & self.flags:
                f+="|" + self.FLAGS[a][0]
        return f

    def istop(self):
        if self.flags & self.FLAGS['TOP'][1]:
            return 1
        return 0

    def isfirst(self):
        if self.psize == 0:
            return 1
        return 0


class win32vistaheapchunk(win32heapchunk):
    FLAGS    = { 'FILL PATTERN':('FP', 0x4), 'DEBUG': ('D', 0x8),\
             'TOP': ('T', 0x10), 'FFU1':('FFU1',0x20),\
             'FFU2': ('FFU2', 0x40), 'NO COALESCE':('NC', 0x80) }
    LFHMASK  = 0x3F 
    LFHFLAGS = { 'TOP': ('T', 0x3), 'BUSY': ('B', 0x18) }

    def __init__(self, imm, addr, heap = None, BlockSize = 0):
        self.heap = heap
        self.freeorder = -1
        self.isLFH = False
	if BlockSize:
            self.isLFH = True
            self.size = BlockSize	    
        win32heapchunk.__init__(self, imm, addr, heap)

    def setFreeOrder(self, freeorder):
        self.freeorder = freeorder

    def _get(self, dword1, dword2, addr):
        heap = self.heap            
        self.nextchunk= 0
        self.prevchunk= 0
        if heap and heap.EncodeFlagMask:
            dword1 ^= heap.EncodingKey
            dword2 = dword2 ^ heap.EncodingKey2         
          
        self.subsegmentcode = self.SubSegmentCode = dword1
	if self.isLFH:
            self.upsize = self.usize = self.size << 3
	    self.psize = self.size
        else:		
            self.size  = dword1 & 0xffff
            self.usize = self.size << 3	
            self.psize  = dword2 & 0xffff
            self.upsize = self.psize << 3   
        
        self.flags         = (dword1 >> 16 & 0xff)
        self.smalltagindex  = (dword1 >> 24 & 0xff)

        self.segmentoffset = (dword2 >> 16 & 0xff)
        self.unused        = (dword2 >> 24 & 0xff)
        self.flags2      = self.unused # LOW FRAGMENTATION HEAP FLAGS
        self.lfhflags = self.flags2

        
        self.data_addr = addr + 8

        self.properties= {'size': self.usize, 'prevsize': self.upsize, 'smalltagindex': self.smalltagindex,\
                          'flags':self.flags, 'subsegmentcode':self.subsegmentcode, 'address':self.addr,\
                          'next': self.nextchunk, 'prev': self.prevchunk, 'lfhflags': self.flags2,\
                          'segmentoffset': self.segmentoffset }
        self.data_size = self.usize - (self.addr - self.data_addr)
        #self.imm.Log("datasize: 0x%d" % self.data_size, address = self.addr)	
        try:
                self.sample = self.imm.readMemory(self.data_addr, 0x10)
        except WindowsError:
                raise Exception, "Failed to read chunk at address: 0x%08x" % addr

    def getflags(self, flag):
        f=""
        if not self.isLFH:          
            if self.flags & self.BUSY[1][1]:
                f+=self.BUSY[1][0]
            else:
                f+="F"

            for a in self.FLAGS.keys():
                if self.FLAGS[a][1] & self.flags:
                    f+="|" + self.FLAGS[a][0]
        else:
            for k in self.LFHFLAGS.keys():
                if self.flags2 == self.LFHFLAGS[k][1]:
                    return self.LFHFLAGS[k][0]
        return f
        
    def istop(self):
        if self.flags2 == self.LFHFLAGS['TOP'][1] : 
            return 1
        else:
            return 0    

    def printchunk(self, uselog= None, option=0, dt= None):
        ret = []
        if self.isRestore():
            restore = "<R>"
        else:
            restore = ""
	if self.isLFH:
            s = "B"
	    if self.freeorder != -1:
                s="F(%02x)" % self.freeorder		
	    ret.append( (self.addr, "Chunk  size: 0x%x lfhflag: 0x%x %s" % ( self.psize,  self.lfhflags, s )) )
        else:	
            ret.append((self.addr, "0x%08x> " % self.addr + "size:    0x%08x  (%04x)  prevsize: 0x%08x (%04x) %s" % (self.usize, self.size, \
                                                                    self.upsize, self.psize, restore) ))
            ret.append((self.addr, "            heap:   *0x%08x*         flags:    0x%02x  0x%02x (%s)" % (self.heap_addr, self.flags, self.flags2,\
                                                             self.getflags(self.flags))))
            if not self.isLFH and not (self.flags2 & self.BUSY[1][1]):
                ret.append((self.addr, "            next:    0x%08x          prev:     0x%08x" % (self.nextchunk, self.prevchunk)))
        if option & SHOWCHUNK_FULL:
            dump = immutils.hexdump(self.sample)
            for a in range(0, len(dump)):
                if not a:
                    ret.append((self.addr, "           (%s  %s)" % (dump[a][0], dump[a][1])))
        if dt:
            if not self.isLFH or (self.isLFH and self.freeorder == -1) :
                result = dt.Discover(self.imm.readMemory(self.data_addr, self.data_size), self.data_addr)
                for obj in result:
                    msg = obj.Print()
                    ret.append((obj.address, " > %s: %s " % (obj.name, msg) ))

        if uselog:
            for adr, msg in ret:
                uselog(msg, address = adr)        
                
        return ret


class PHeapLookaside(UserList):
    def __init__(self, imm, addr, heap = 0x0, log = None ): 
       """ Win32 Heap Lookaside list """
       UserList.__init__(self)
       if not log:
          log  = imm.Log
       self.log = log
       self.imm = imm
       self.heap = heap
       self.Lookaside = []
      
       LookSize = PLook(self.imm, 0x0).getSize()
       mem = imm.readMemory(addr, LookSize * HEAP_MAX_FREELIST)

       for ndx in range(0, HEAP_MAX_FREELIST):
           base_addr = addr + ndx * LookSize
           l = PLook(self.imm,  base_addr, mem[ ndx * LookSize : ndx * LookSize + LookSize ], self.heap ) 

           self.data.append(l)
           next = l.ListHead
           while next and next != base_addr:
              l.append( next )
              try:
                  next = self.imm.readLong(next)
              except:
                  break
                 
                   
class PLook:
    def __init__(self, imm, addr, data = None, heap = 0x0, log= None):
        self.log = log
        self.addr = addr
        self.List = []
        self.fmt = "LLHHLLLLLL12s"
        self.imm = imm
        self.heap = heap

        # XXX: This need some check, cause my calculation might be wrong
        if data:
                (self.ListHead, none, self.Depth, self.MaxDepth, self.TotalAlloc, self.AllocMiss, self.TotalFrees,
                self.FreeMiss, self.AllocLastTotal, self.LastAllocateMiss, self.Unknown) = \
                 struct.unpack(self.fmt, data[:struct.calcsize(self.fmt)])
        elif addr:
            data = self.imm.readMemory(addr, self.getSize() )
            (self.ListHead, none, self.Depth, self.MaxDepth, self.TotalAlloc, self.AllocMiss, self.TotalFrees,
                self.FreeMiss, self.AllocLastTotal, self.LastAllocateMiss, self.Unknown1, self.Unknown2) = \
                 struct.unpack(self.fmt, data[:struct.calcsize(self.fmt)])

    def isEmpty(self):
        return self.ListHead == 0x0
        
    def getSize(self):
        return struct.calcsize(self.fmt)

    def append(self, andres):
        self.List.append(andres)

    def getList(self):
        """get a the single linked list of the Lookaside entry
        @return: A list of the address of the linked list"""
        return self.List
    
    def getChunks(self):
        """get a the single linked list of the Lookaside entry
        @return: A list of the Chunks on the linked list"""

        chunks = []
        for addr in self.List:
            # The Address of the Single Linked list of the Lookaside points to the data of the chunk.
            # so, we need to increase 8 bytes to get into the begging of the header
            chunks.append( win32heapchunk(self.imm, addr - 8, self.heap ) )

        return chunks
    
class SearchHeap:
    def __init__(self, imm, what, action, value, heap = 0x0, restore = False, option = 0):
        """
        Search the Heap for specific Chunks

        @type  imm: Debugger Object
        @param imm: Initialized debugged object

        @type  what: STRING 
        @param what: Chunk property to search from (size, prevsize, field4, flags, other, address, next, prev)
       
        @type  action: STRING
        @param action: Type of search ( =, >, <, >=, <=, &, not, !=)

        @type  value: DWORD
        @param value: Value to search for
 
        @type  heap: DWORD
        @param heap: (Optional, Def=None) Filter by Heap
 
        @type  restore: BOOLEAN
        @param restore: (Optional, Def: False) Flag whether or not use a restore heap (Useful if you want to search on a broken heap)
  
        @type  option: DWORD
        @param option: (Optional, Def: None) Chunk's display option        
        """
        self.functions = { '=': lambda a, b: a==b,
                           '>': lambda a,b : a>b,
                           '<': lambda a,b : a<b,
                           '>=': lambda a,b : a>=b,
                           '<=': lambda a,b : a<=b,
                           '&': lambda a,b : a&b,
                           'not': lambda a,b: a & ~b,
                           #'find': lambda a,b: a.find(b) > -1,
                           '!=': lambda a,b : a!=b
                       }
        for a in imm.getHeapsAddress():
            if a==heap or not heap:
                #imm.Log("Dumping heap:    0x%08x" % a, address = a, focus = 1 )
                p = imm.getHeap( a, restore )
                if not what or not action:
                    for c in p.chunks:
                        c.printchunk(uselog = imm.Log, option = option)
                else:
                    for c in p.chunks:
                        if self.functions[action](c.get(what) , value):
                            c.printchunk(uselog = imm.Log, option = option)
