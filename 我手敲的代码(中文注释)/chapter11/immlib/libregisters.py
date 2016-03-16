#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}


"""
#
__version__ = '1.0'

import _winreg

# Documentation
#  http://msdn2.microsoft.com/en-us/library/cc265944.aspx
#  http://msdn2.microsoft.com/en-us/library/cc265944.aspx


#Systemwide settings ("Registry") 	HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\GlobalFlag
#Program-specific settings ("Image file") for all users of the computer. 	HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ImageFileName\GlobalFlag
#Program-specific settings ("Image file") for a specified user of the computer. 	HKEY_USERS\SID\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ImageFileName\GlobalFlag
#Page heap options for an image file for all users of the computer 	HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ImageFileName\PageHeapFlags
#Page heap options for an image file for a specified user of the computer 	HKEY_USERS\SID\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ImageFileName\PageHeapFlags
#User mode stack trace database size (tracedb) 	HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ImageFileName\StackTraceDatabaseSizeInMbz

GFlagsTags = ['ddp', 'kst', 'ust', 'dic', 'dwl', 'dhc', 'dps', 'dpd', 'dse', 'cse', 'vrf', 'bhd', 'ece', 'd32', 'eel', 'hfc', 'hpc', 'htg', 'htd', 'htc', 'hvc', 'ksl', 'eot', 'hpa', 'ptg', 'scb', 'ltd', 'otl', 'sls', 'soe', 'shg']

GFlagsRef = {}
GFlagsRef['ddp'] = ('Buffer DbgPrint output', 0x08000000, 'FLG_DISABLE_DBGPRINT', ['Systemwide registry entry', 'kernel mode.'], """Suppresses debugger output from DbgPrint(), DbgPrintEx(), KdPrint(), and KdPrintEx() calls. When this output is suppressed, it does not automatically appear in the kernel debugger. However, it can still be accessed by using the !dbgprint debugger extension. """)
GFlagsRef['kst'] = ('Create kernel mode stack trace database', 0x2000, 'FLG_KERNEL_STACK_TRACE_DB', ['Systemwide registry entry.'], """Creates a run-time stack trace database of kernel operations, such as resource objects and object management operations. This feature works only when using a "checked build," that is, an internal debugging build of the operating system. """)
GFlagsRef['ust'] = ('Create user mode stack trace database', 0x1000, 'FLG_USER_STACK_TRACE_DB', ['Systemwide registry entry', 'kernel mode', 'image file registry entry.'], """Creates a run-time stack trace database in the address space of a particular process (image file mode) or all processes (systemwide). """)
GFlagsRef['dic'] = ('Debug initial command', 0x4, 'FLG_DEBUG_INITIAL_COMMAND', ['Systemwide registry entry', 'kernel mode.'], """Runs Winlogon in the Windows Symbolic Debugger (Ntsd.exe) with the -d parameter, which directs its output to the kernel debugger console. """)
GFlagsRef['dwl'] = ('Debug Winlogon', 0x04000000, 'FLG_DEBUG_INITIAL_COMMAND_EX', ['Systemwide registry entry', 'kernel mode.'], """Runs Winlogon in the Windows Symbolic Debugger (Ntsd.exe) with the following options: """)
GFlagsRef['dhc'] = ('Disable heap coalesce on free', 0x00200000, 'FLG_HEAP_DISABLE_COALESCING', ['Systemwide registry entry', 'kernel mode', 'image file registry entry.'], """Leaves adjacent blocks of heap memory separate when they are freed. By default, the system combines ("coalesces") newly freed adjacent blocks into a single block. Combining the blocks takes time, but reduces fragmentation that might force the heap to allocate additional memory when it can't find contiguous memory. """)
GFlagsRef['dps'] = ('Disable paging of kernel stacks', 0x80000, 'FLG_DISABLE_PAGE_KERNEL_STACKS', ['Systemwide registry entry', 'kernel mode.'], """Prevents paging of the kernel mode stacks of inactive threads. Generally, the kernel mode stack cannot be paged; it is guaranteed to be resident in memory. However, the system occasionally pages the kernel stacks of inactive threads. This flag prevents these occurrences. """)
GFlagsRef['dpd'] = ('Disable protected DLL verification', 0x80000000, 'FLG_DISABLE_PROTDLLS', ['Systemwide registry entry', 'kernel mode', 'image file registry entry.'], """""")
GFlagsRef['dse'] = ('Disable stack extension', 0x10000, 'FLG_DISABLE_STACK_EXTENSION', ['image file registry entry.'], """Prevents the kernel from extending the stacks of the threads in the process beyond the initial memory committed. This is used to simulate low memory conditions (where stack extensions fail) and to test the strategic system processes that are expected to run well even with low memory. """)
GFlagsRef['cse'] = ('Early critical section event creation', 0x10000000, 'FLG_CRITSEC_EVENT_CREATION', ['Systemwide registry entry', 'kernel mode', 'image file registry entry.'], """Creates event handles when a critical section is initialized, rather than waiting until the event is needed. When the system cannot create an event, it generates the exception during initialization and the calls to enter and leave the critical section do not fail. """)
GFlagsRef['vrf'] = ('Enable application verifier', 0x100, 'FLG_APPLICATION_VERIFIER', ['Systemwide registry entry', 'kernel mode', 'image file registry entry.'], """""")
GFlagsRef['bhd'] = ('Enable bad handles detection', 0x40000000, 'FLG_ENABLE_HANDLE_EXCEPTIONS', ['Systemwide registry entry', 'kernel mode.'], """Raises a user mode exception (STATUS_INVALID_HANDLE) whenever a user mode process passes an invalid handle to the Object Manager. """)
GFlagsRef['ece'] = ('Enable close exception', 0x00400000, 'FLG_ENABLE_CLOSE_EXCEPTIONS', ['Systemwide registry entry', 'kernel mode.'], """Raises a user mode exception whenever an invalid handle is passed to the CloseHandle() interface or related interfaces, such as SetEvent(), that take handles as arguments. """)
GFlagsRef['d32'] = ('Enable debugging of Win32 subsystem', 0x20000, 'FLG_ENABLE_CSRDEBUG', ['Systemwide registry entry', 'kernel mode.'], """""")
GFlagsRef['eel'] = ('Enable exception logging', 0x00800000, 'FLG_ENABLE_EXCEPTION_LOGGING', ['Systemwide registry entry', 'kernel mode.'], """Creates a log of exception records in the kernel run-time library. You can access the log from the kernel debugger. """)
GFlagsRef['hfc'] = ('Enable heap free checking', 0x20, 'FLG_HEAP_ENABLE_FREE_CHECK', ['Systemwide registry entry', 'kernel mode', 'image file registry entry.'], """Validates the heap when it is freed. """)
GFlagsRef['hpc'] = ('Enable heap parameter checking', 0x40, 'FLG_HEAP_VALIDATE_PARAMETERS', ['Systemwide registry entry', 'kernel mode', 'image file registry entry.'], """Verifies some aspects of the heap whenever a heap API is called. """)
GFlagsRef['htg'] = ('Enable heap tagging', 0x800, 'FLG_HEAP_ENABLE_TAGGING', ['Systemwide registry entry', 'kernel mode', 'image file registry entry.'], """Assigns unique tags to heap allocations. You can display the tag by using the !heap debugger extension with the -t parameter. """)
GFlagsRef['htd'] = ('Enable heap tagging by DLL', 0x8000, 'FLG_HEAP_ENABLE_TAG_BY_DLL', ['Systemwide registry entry', 'kernel mode', 'image file registry entry.'], """Assigns a unique tag to heap allocations created by the same DLL. You can display the tag by using the !heap debugger extension with the -t parameter. """)
GFlagsRef['htc'] = ('Enable heap tail checking', 0x10, 'FLG_HEAP_ENABLE_TAIL_CHECK', ['Systemwide registry entry', 'kernel mode', 'image file registry entry.'], """Checks for buffer overruns when the heap is freed. This flag adds a short pattern to the end of each allocation. The Windows heap manager detects the pattern when the block is freed and, if the block was modified, the heap manager breaks into the debugger. """)
GFlagsRef['hvc'] = ('Enable heap validation on call', 0x80, 'FLG_HEAP_VALIDATE_ALL', ['Systemwide registry entry', 'kernel mode', 'image file registry entry.'], """Validates the entire heap each time a heap API is called. """)
GFlagsRef['ksl'] = ('Enable loading of kernel debugger symbols', 0x40000, 'FLG_ENABLE_KDEBUG_SYMBOL_LOAD', ['Systemwide registry entry', 'kernel mode.'], """Loads kernel symbols into the kernel memory space the next time the system starts. The kernel symbols are used in kernel profiling and by advanced kernel debugging tools. """)
GFlagsRef['eot'] = ('Enable object handle type tagging', 0x01000000, 'FLG_ENABLE_HANDLE_TYPE_TAGGING', ['Systemwide registry entry', 'kernel mode.'], """This flag appears in Gflags, but it has no effect on the operating system. """)
GFlagsRef['hpa'] = ('Enable page heap', 0x02000000, 'FLG_HEAP_PAGE_ALLOCS', ['Systemwide registry entry', 'kernel mode', 'image file registry entry.'], """Turns on page heap debugging, which verifies dynamic heap memory operations, including allocations and frees, and causes a debugger break when it detects a heap error. """)
GFlagsRef['ptg'] = ('Enable pool tagging', 0x400, 'FLG_POOL_ENABLE_TAGGING', ['Systemwide registry entry.'], """Collects data and calculates statistics about pool memory allocations. The data is grouped by pool tag value. Several tools that diagnose memory leaks and other kernel pool errors use the resulting data. """)
GFlagsRef['scb'] = ('Enable system critical breaks', 0x100000, 'FLG_ENABLE_SYSTEM_CRIT_BREAKS', ['Systemwide registry entry', 'kernel mode', 'image file registry entry.'], """For per-process (image file) only: Forces a system breakpoint into the debugger whenever the specified process stops abnormally. This flag is effective only when the process calls the RtlSetProcessBreakOnExit() and RtlSetThreadBreakOnExit() interfaces. """)
GFlagsRef['ltd'] = ('Load DLLs top-down', 0x20000000, 'FLG_LDR_TOP_DOWN', ['Systemwide registry entry', 'kernel mode', 'image file registry entry.'], """Loads DLLs at the highest possible address. This flag is used to test 64-bit code for pointer truncation errors, because the most significant 32 bits of the pointers are not zeroes. It is designed for code running on the 64-bit versions of the Windows Server 2003. """)
GFlagsRef['otl'] = ('Maintain a list of objects for each type', 0x4000, 'FLG_MAINTAIN_OBJECT_TYPELIST', ['Systemwide registry entry', 'kernel mode.'], """Collects and maintains a list of active objects by object type (for example, event, mutex, and semaphore). """)
GFlagsRef['sls'] = ('Show loader snaps', 0x2, 'FLG_SHOW_LDR_SNAPS', ['Systemwide registry entry', 'kernel mode', 'image file registry entry.'], """Captures detailed information about the loading and unloading of executable images and their supporting library modules. """)
GFlagsRef['soe'] = ('Stop on exception', 0x1, 'FLG_STOP_ON_EXCEPTION', ['Systemwide registry entry', 'kernel mode', 'image file registry entry.'], """The kernel breaks into the kernel debugger whenever a kernel mode exception occurs. The system passes all first chance exceptions (except for STATUS_PORT_DISCONNECT) with a severity of Warning or Error to the debugger before passing them to a local exception handler. """)
GFlagsRef['shg'] = ('Stop on hung GUI', 0x8, 'FLG_STOP_ON_HUNG_GUI', ['kernel mode'], """""")


# For a complete usage of this Class, check the Pycommand 'gflags.py'
class GFlags:
    def __init__(self, processname = ""):
        """ 
        GFlags class  enable and disable Windows global flags
        
        @type  processname: STRING
        @param processname: (Optional) Process name (If is unset, it will use the system global flags)
        """
        self.processname = processname
        
        if self.processname:
            self.subkey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s" % self.processname
        else:
            self.subkey = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\"
            
       
    def _query(self):
        try:
            hkey = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, self.subkey)
        except WindowsError:
            raise Exception, "Cannot Openkey for Query (%s)" % self.subkey
        
        try:
            return _winreg.QueryValueEx(hkey, "GlobalFlag")[0]
        except WindowsError:
            raise Exception, "Cannot Query value (%s\\%s)" % (self.subkey, "GlobalFlag")

    def GetReferencebyName(self, val):
        """
        Get Flag information by its shorcut name
        
        @type  val: STRING
        @param val: Shortcut Name
        
        @rtype:  TUPLE
        @return: A tuple containning all the internal information of a Flag
        """
        val = val.lower()
        try:
            r = GFlagsRef[val]
        except KeyError:
            raise Exception, "'%s' is not a gflag value" % val
        if self.processname:
            if 'image file registry entry.' not in r[3]:
                raise Exception, "Flag '%s' is not available for Image file (only for: %s)" % (val, str(r[3]))
            
        return r
    
    def SetbyName(self, val):
        """
        Set a Flag by its shorcut name
        
        @type  val: STRING
        @param val: Shortcut Name
        """
        r = self.GetReferencebyName( val )
        return self.Set( r[1] )
    
    def Set(self, val):
        """
        Set a Flag
        
        @type  val: DWORD
        @param val: Value of the flag to set
        """
        
        try:
            current = self._query()
        except Exception:
            # Key is not created, set will automatically do it
            current = 0L

        self._set( current | val ) 
        
        return current | val

    def UnSetbyName(self, val): 
        """
        Unset a Flag by its shorcut name
        
        @type  val: STRING
        @param val: Shortcut Name
        """
        r = self.GetReferencebyName( val )
        return self.UnSet( r[1] )
        
    def UnSet(self, val):
        """
        Set a Flag
        
        @type  val: DWORD
        @param val: Value of the flag to set
        """
        
        current = self._query()
        self._set( current &~ val )
        
        return current &~ val 

    def isSet(self, val):
        """
        Whether a Flag is set
        
        @type  val: STRING
        @param val: Shortcut name
        """

        r = self.GetReferencebyName( val )
        current = self._query()
        
        return bool( r[1] & current )
        
    def Print(self):
        """
        Print all the current setted GFlags 
        
        @rtype:  LIST OF TUPLES
        @return: A list of a tuple with two elements: Shortcut Name and flag information
        """
        current = self._query()
        ret = []
        for a in GFlagsRef.keys():
            r = GFlagsRef[a]
            if r[1] & current:
                ret.append ( (a, r) )
        return ret
    
    def Clear(self):
        """
        Clear the Flags
        """
        if self.processname:
            _winreg.DeleteKey(_winreg.HKEY_LOCAL_MACHINE, self.subkey)
        else:
            self._set( 0 )
            
    def _set(self, flag):
        try:
            hkey = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, self.subkey, 0, _winreg.KEY_SET_VALUE )
        except WindowsError:
            try:
                hkey = _winreg.CreateKey(_winreg.HKEY_LOCAL_MACHINE, self.subkey)
            except WindowsError:
                raise Exception, "Cannot Open/Create key (%s)" % self.subkey
            
        try:
            _winreg.SetValueEx(hkey, "GlobalFlag", 0, _winreg.REG_DWORD, int(flag) )
        except WindowsError:
            raise Exception, "Cannot SetValue key (%s\\%s)" % ( self.subkey, "GlobalFlag")
        except ValueError:
            raise Exception, "Cannot SetValue key  (%s\\%s) %s %s" % ( self.subkey, "GlobalFlag", str(flag), type(flag))
        
        try:
            _winreg.CloseKey(hkey)
        except WindowsError:
            raise Exception, "Cannot Close key (%s)" % self.subkey
        
if __name__ == "__main__":
    g = GFlags("notepad.exe")
    g.Set( 'htc' )
    g.Clear()
    