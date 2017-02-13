## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Run commands when the Scapy interpreter starts.
"""

import code,sys
from scapy.config import conf
from scapy.themes import *
from scapy.error import Scapy_Exception
from scapy.utils import tex_escape


#########################
##### Autorun stuff #####
#########################

class StopAutorun(Scapy_Exception):
    code_run = ""

class ScapyAutorunInterpreter(code.InteractiveInterpreter):
    def __init__(self, *args, **kargs):
        code.InteractiveInterpreter.__init__(self, *args, **kargs)
        self.error = 0
    def showsyntaxerror(self, *args, **kargs):
        self.error = 1
        return code.InteractiveInterpreter.showsyntaxerror(self, *args, **kargs)
    def showtraceback(self, *args, **kargs):
        self.error = 1
        exc_type, exc_value, exc_tb = sys.exc_info()
        if isinstance(exc_value, StopAutorun):
            raise exc_value
        return code.InteractiveInterpreter.showtraceback(self, *args, **kargs)


def autorun_commands(cmds,my_globals=None,verb=0):
    sv = conf.verb
    import __builtin__
    try:
        try:
            if my_globals is None:
                my_globals = __import__("scapy.all").all.__dict__
            conf.verb = verb
            interp = ScapyAutorunInterpreter(my_globals)
            cmd = ""
            cmds = cmds.splitlines()
            cmds.append("") # ensure we finish multi-line commands
            cmds.reverse()
            __builtin__.__dict__["_"] = None
            while 1:
                if cmd:
                    sys.stderr.write(sys.__dict__.get("ps2","... "))
                else:
                    sys.stderr.write(str(sys.__dict__.get("ps1",ColorPrompt())))
                    
                l = cmds.pop()
                print l
                cmd += "\n"+l
                if interp.runsource(cmd):
                    continue
                if interp.error:
                    return 0
                cmd = ""
                if len(cmds) <= 1:
                    break
        except SystemExit:
            pass
    finally:
        conf.verb = sv
    return _

def autorun_get_interactive_session(cmds, **kargs):
    class StringWriter:
        def __init__(self):
            self.s = ""
        def write(self, x):
            self.s += x
        def flush(self):
            pass
            
    sw = StringWriter()
    sstdout,sstderr = sys.stdout,sys.stderr
    try:
        try:
            sys.stdout = sys.stderr = sw
            res = autorun_commands(cmds, **kargs)
        except StopAutorun,e:
            e.code_run = sw.s
            raise
    finally:
        sys.stdout,sys.stderr = sstdout,sstderr
    return sw.s,res

def autorun_get_text_interactive_session(cmds, **kargs):
    ct = conf.color_theme
    try:
        conf.color_theme = NoTheme()
        s,res = autorun_get_interactive_session(cmds, **kargs)
    finally:
        conf.color_theme = ct
    return s,res

def autorun_get_ansi_interactive_session(cmds, **kargs):
    ct = conf.color_theme
    try:
        conf.color_theme = DefaultTheme()
        s,res = autorun_get_interactive_session(cmds, **kargs)
    finally:
        conf.color_theme = ct
    return s,res

def autorun_get_html_interactive_session(cmds, **kargs):
    ct = conf.color_theme
    to_html = lambda s: s.replace("<","&lt;").replace(">","&gt;").replace("#[#","<").replace("#]#",">")
    try:
        try:
            conf.color_theme = HTMLTheme2()
            s,res = autorun_get_interactive_session(cmds, **kargs)
        except StopAutorun,e:
            e.code_run = to_html(e.code_run)
            raise
    finally:
        conf.color_theme = ct
    
    return to_html(s),res

def autorun_get_latex_interactive_session(cmds, **kargs):
    ct = conf.color_theme
    to_latex = lambda s: tex_escape(s).replace("@[@","{").replace("@]@","}").replace("@`@","\\")
    try:
        try:
            conf.color_theme = LatexTheme2()
            s,res = autorun_get_interactive_session(cmds, **kargs)
        except StopAutorun,e:
            e.code_run = to_latex(e.code_run)
            raise
    finally:
        conf.color_theme = ct
    return to_latex(s),res


