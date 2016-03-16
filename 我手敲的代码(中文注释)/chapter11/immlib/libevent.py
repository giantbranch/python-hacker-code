#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}



"""

__VERSION__ = '1.0'
import debugger

class Event:
    def __init__( self, event ):
            self.dwDebugEventCode = event[0][0]
            self.dwProcessId = event[0][1]
            self.dwThreadId  = event[0][2]
            self._GetValues(event)
            
    def isCreateProcess(self):
        return self.dwDebugEventCode == debugger.CREATE_PROCESS_DEBUG_EVENT

    def isCreateThread(self):
        return self.dwDebugEventCode == debugger.CREATE_THREAD_DEBUG_EVENT

    def isException(self):
        return self.dwDebugEventCode == debugger.EXCEPTION_DEBUG_EVENT

    def isExitProcess(self):
        return self.dwDebugEventCode == debugger.EXIT_PROCESS_DEBUG_EVENT

    def isExitThread(self):
        return self.dwDebugEventCode == debugger.EXIT_THREAD_DEBUG_EVENT

    def isLoadDll(self):
        return self.dwDebugEventCode == debugger.LOAD_DLL_DEBUG_EVENT

    def isOutputDebugString(self):
        return self.dwDebugEventCode == debugger.OUTPUT_DEBUG_STRING_EVENT

    def isUnloadDll(self):
        return self.dwDebugEventCode == debugger.UNLOAD_DLL_DEBUG_EVENT

    def isRipEvent(self):
        return self.dwDebugEventCode == debugger.RIP_EVENT
    
    def _GetValues(self, event):
        return 

class CreateProcessEvent(Event):
    def __init__(self, event):
        Event.__init__(self, event)
    
    def _GetValues(self, event):
        self.hFile                 = event[1][0] 
        self.hProcess              = event[1][1] 
        self.hThread               = event[1][2] 
        self.lpBaseOfImage         = event[1][3] 
        self.dwDebugInfoFileOffset = event[1][4] 
        self.nDebugInfoSize        = event[1][5] 
        self.lpThreadLocalBase     = event[1][6] 
        self.lpStartAddress        = event[1][7] 
        self.lpImageName           = event[1][8] 
        self.fUnicode              = event[1][9] 

class CreateThreadEvent(Event):
    def __init__(self, event):
        Event.__init__(self, event)
        
    def _GetValues(self, event):
        self.hThread           = [1][0]
        self.lpStartAddress    = event[1][1]
        self.lpThreadLocalBase = event[1][2]

EXCEPTION_CODE = {debugger.EXCEPTION_BREAKPOINT: "Breakpoint",
                  debugger.EXCEPTION_SINGLE_STEP:"SingleStep",
                  debugger.EXCEPTION_ACCESS_VIOLATION:"AccessViolation",
                  debugger.EXCEPTION_GUARD_PAGE: "GuardPage",
                  debugger.EXCEPTION_ARRAY_BOUNDS_EXCEEDED: "ArrayBoundsExceeded",
                  debugger.EXCEPTION_FLT_DENORMAL_OPERAND: "FltDenormalOperand",
                  debugger.EXCEPTION_FLT_DIVIDE_BY_ZERO: "FltDivideByZero",
                  debugger.EXCEPTION_FLT_INEXACT_RESULT: "FltInexactResult",
                  debugger.EXCEPTION_FLT_INVALID_OPERATION: "FltInvalidOperation",
                  debugger.EXCEPTION_FLT_OVERFLOW: "FltOverflow",
                  debugger.EXCEPTION_FLT_STACK_CHECK: "FltStackCheck",
                  debugger.EXCEPTION_FLT_UNDERFLOW: "FltUnderflow",
                  debugger.EXCEPTION_INT_DIVIDE_BY_ZERO: "IntDivideByZero",
                  debugger.EXCEPTION_INT_OVERFLOW: "IntOverflow",
                  debugger.EXCEPTION_PRIV_INSTRUCTION: "PrivInstruction",
                  debugger.EXCEPTION_ILLEGAL_INSTRUCTION: "IllegalInstruction",
                  debugger.EXCEPTION_NONCONTINUABLE_EXCEPTION: "NonContinuableException",
                  debugger.EXCEPTION_STACK_OVERFLOW: "StackOverflow" 
              }

class ExceptionRecord:
    def __init__(self, er):
        self.ExceptionCode        = er [0]
        self.ExceptionFlags       = er [1]
        self.ExceptionAddress     = er [2]
        self.NumberParameters     = er [3]
        self.ExceptionInformation = er [4]
        self.ExceptionRecord      = er [5]

    def isAccessViolationOnExecute(self):
        return self.isAccessViolation() and self.ExceptionInformation[0] != 1 and self.ExceptionInformation[0] == self.ExceptionAddress
    
    def isAccessViolationOnWrite(self):
        return self.isAccessViolation() and self.ExceptionInformation[0] == 1
    
    def isAccessViolationOnRead(self):
        return self.isAccessViolation() and self.ExceptionInformation[0] != 1 and self.ExceptionInformation[0] != self.ExceptionAddress 
        
    def isBreakpoint(self):
        return self.ExceptionCode == debugger.EXCEPTION_BREAKPOINT

    def isSingleStep(self):
        return self.ExceptionCode == debugger.EXCEPTION_SINGLE_STEP

    def isAccessViolation(self):
        return self.ExceptionCode == debugger.EXCEPTION_ACCESS_VIOLATION

    def isGuardPage(self):
        return self.ExceptionCode == debugger.EXCEPTION_GUARD_PAGE

    def isArrayBoundsExceeded(self):
        return self.ExceptionCode == debugger.EXCEPTION_ARRAY_BOUNDS_EXCEEDED

    def isFltDenormalOperand(self):
        return self.ExceptionCode == debugger.EXCEPTION_FLT_DENORMAL_OPERAND

    def isFltDivideByZero(self):
        return self.ExceptionCode == debugger.EXCEPTION_FLT_DIVIDE_BY_ZERO

    def isFltInexactResult(self):
        return self.ExceptionCode == debugger.EXCEPTION_FLT_INEXACT_RESULT

    def isFltInvalidOperation(self):
        return self.ExceptionCode == debugger.EXCEPTION_FLT_INVALID_OPERATION

    def isFltOverflow(self):
        return self.ExceptionCode == debugger.EXCEPTION_FLT_OVERFLOW

    def isFltStackCheck(self):
        return self.ExceptionCode == debugger.EXCEPTION_FLT_STACK_CHECK

    def isFltUnderflow(self):
        return self.ExceptionCode == debugger.EXCEPTION_FLT_UNDERFLOW

    def isIntDivideByZero(self):
        return self.ExceptionCode == debugger.EXCEPTION_INT_DIVIDE_BY_ZERO

    def isIntOverflow(self):
        return self.ExceptionCode == debugger.EXCEPTION_INT_OVERFLOW

    def isPrivInstruction(self):
        return self.ExceptionCode == debugger.EXCEPTION_PRIV_INSTRUCTION

    def isIllegalInstruction(self):
        return self.ExceptionCode == debugger.EXCEPTION_ILLEGAL_INSTRUCTION

    def isNonContinuableException(self):
        return self.ExceptionCode == debugger.EXCEPTION_NONCONTINUABLE_EXCEPTION

    def isExceptionStackOverflow(self):
        return self.ExceptionCode == debugger.EXCEPTION_STACK_OVERFLOW
    
    def getType(self):
        try:
            return EXCEPTION_CODE[self.ExceptionCode]
        except KeyError:
            return "UknownException"
        
    def __str__(self):
        return self.getType()
    
    
class ExceptionEvent(Event):
    def __init__(self, event):
        Event.__init__(self, event)
        
    def _GetValues(self, event):
        self.dwFirstChance = event[1][0]
        self.Exception = []
        for er in range(1, len(event[1])):
            self.Exception.append( ExceptionRecord(event[1][er]) )
            
class ExitProcessEvent(Event):
    def __init__(self, event):
        Event.__init__(self, event)
        
    def _GetValues(self, event):
        self.dwExitCode = event[1][0]
 
class ExitThreadEvent(Event):
    def __init__(self, event):
        Event.__init__(self, event)
        
    def _GetValues(self, event):
        self.dwExitCode = event[1][0]

class LoadDLLEvent(Event):
    def __init__(self, event):
        Event.__init__(self, event)
        
    def _GetValues(self, event):
        self.hFile                 = event[1][0]
        self.lpBaseOfDll           = event[1][1]
        self.dwDebugInfoFileOffset = event[1][2]
        self.nDebugInfoSize        = event[1][3]
        self.lpImageName           = event[1][4]
        self.fUnicode              = event[1][5]

class OutputDebugEvent(Event):
    def __init__(self, event):
        Event.__init__(self, event)
        
    def _GetValues(self, event):
        self.lpDebugStringData  = event[1][0]
        self.fUnicode           = event[1][1]
        self.nDebugStringLength = event[1][2]

class RIPEvent(Event):
    def __init__(self, event):
        Event.__init__(self, event)
        
    def _GetValues(self, event):
        self.dwError = event[1][0]
        self.dwType  = event[1][1]

class UnloadDLLEvent(Event):
    def __init__(self, event):
        Event.__init__(event)
        
    def _GetValues(self, event):
        self.lpBaseOfDll = event[1][0]
