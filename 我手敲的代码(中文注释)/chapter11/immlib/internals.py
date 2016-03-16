#!/usr/bin/env python
"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}


Internal libs


"""

__VERSION__ = '1.0'

import pickle
import immlib




def hookmain(pickled_hook,regs):
    """Auxiliar hook function
    get pickled hook instance and execute run()"""
    imm= immlib.Debugger()
    hook=pickle.loads(pickled_hook)
    if hook.enabled==True: #only enabled hooks will execute
        hook._run(regs) #be sure this method is actually the one you want executed with your hook


def hookmaintimeout(pickled_hook,regs):
    """Auxiliar hook function
    get pickled hook instance and execute runtimeout()"""
    imm= immlib.Debugger()
    hook=pickle.loads(pickled_hook)
    if hook.enabled==True: #only enabled hooks will execute
        hook._runTimeout(regs) #be sure this method is actually the one you want executed with your hook
    

    
    
def addGenHook(object):
    imm=immlib.Debugger()
    imm.addGenHook(object)
    del imm
        
   
    
    
    
    
    


