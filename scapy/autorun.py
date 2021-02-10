# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Run commands when the Scapy interpreter starts.
"""

from __future__ import print_function
import code
import sys
import importlib
import logging

from scapy.config import conf
from scapy.themes import NoTheme, DefaultTheme, HTMLTheme2, LatexTheme2
from scapy.error import log_scapy, Scapy_Exception
from scapy.utils import tex_escape
import scapy.modules.six as six


#########################
#     Autorun stuff     #
#########################

class StopAutorun(Scapy_Exception):
    code_run = ""


class ScapyAutorunInterpreter(code.InteractiveInterpreter):
    def __init__(self, *args, **kargs):
        code.InteractiveInterpreter.__init__(self, *args, **kargs)
        self.error = 0

    def showsyntaxerror(self, *args, **kargs):
        self.error = 1
        return code.InteractiveInterpreter.showsyntaxerror(self, *args, **kargs)  # noqa: E501

    def showtraceback(self, *args, **kargs):
        self.error = 1
        exc_type, exc_value, exc_tb = sys.exc_info()
        if isinstance(exc_value, StopAutorun):
            raise exc_value
        return code.InteractiveInterpreter.showtraceback(self, *args, **kargs)


def autorun_commands(cmds, my_globals=None, ignore_globals=None, verb=None):
    sv = conf.verb
    try:
        try:
            if my_globals is None:
                my_globals = importlib.import_module(".all", "scapy").__dict__
                if ignore_globals:
                    for ig in ignore_globals:
                        my_globals.pop(ig, None)
            if verb is not None:
                conf.verb = verb
            interp = ScapyAutorunInterpreter(my_globals)
            cmd = ""
            cmds = cmds.splitlines()
            cmds.append("")  # ensure we finish multi-line commands
            cmds.reverse()
            six.moves.builtins.__dict__["_"] = None
            while True:
                if cmd:
                    sys.stderr.write(sys.__dict__.get("ps2", "... "))
                else:
                    sys.stderr.write(str(sys.__dict__.get("ps1", sys.ps1)))

                line = cmds.pop()
                print(line)
                cmd += "\n" + line
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
    return _  # noqa: F821


class StringWriter(object):
    """Util to mock sys.stdout and sys.stderr, and
    store their output in a 's' var."""
    def __init__(self, debug=None):
        self.s = ""
        self.debug = debug

    def write(self, x):
        # Object can be in the middle of being destroyed.
        if getattr(self, "debug", None):
            self.debug.write(x)
        if getattr(self, "s", None) is not None:
            self.s += x

    def flush(self):
        if getattr(self, "debug", None):
            self.debug.flush()


def autorun_get_interactive_session(cmds, **kargs):
    """Create an interactive session and execute the
    commands passed as "cmds" and return all output

    :param cmds: a list of commands to run
    :returns: (output, returned) contains both sys.stdout and sys.stderr logs
    """
    sstdout, sstderr = sys.stdout, sys.stderr
    sw = StringWriter()
    h_old = log_scapy.handlers[0]
    log_scapy.removeHandler(h_old)
    log_scapy.addHandler(logging.StreamHandler(stream=sw))
    try:
        try:
            sys.stdout = sys.stderr = sw
            res = autorun_commands(cmds, **kargs)
        except StopAutorun as e:
            e.code_run = sw.s
            raise
    finally:
        sys.stdout, sys.stderr = sstdout, sstderr
        log_scapy.removeHandler(log_scapy.handlers[0])
        log_scapy.addHandler(h_old)
    return sw.s, res


def autorun_get_interactive_live_session(cmds, **kargs):
    """Create an interactive session and execute the
    commands passed as "cmds" and return all output

    :param cmds: a list of commands to run
    :returns: (output, returned) contains both sys.stdout and sys.stderr logs
    """
    sstdout, sstderr = sys.stdout, sys.stderr
    sw = StringWriter(debug=sstdout)
    try:
        try:
            sys.stdout = sys.stderr = sw
            res = autorun_commands(cmds, **kargs)
        except StopAutorun as e:
            e.code_run = sw.s
            raise
    finally:
        sys.stdout, sys.stderr = sstdout, sstderr
    return sw.s, res


def autorun_get_text_interactive_session(cmds, **kargs):
    ct = conf.color_theme
    try:
        conf.color_theme = NoTheme()
        s, res = autorun_get_interactive_session(cmds, **kargs)
    finally:
        conf.color_theme = ct
    return s, res


def autorun_get_live_interactive_session(cmds, **kargs):
    ct = conf.color_theme
    try:
        conf.color_theme = DefaultTheme()
        s, res = autorun_get_interactive_live_session(cmds, **kargs)
    finally:
        conf.color_theme = ct
    return s, res


def autorun_get_ansi_interactive_session(cmds, **kargs):
    ct = conf.color_theme
    try:
        conf.color_theme = DefaultTheme()
        s, res = autorun_get_interactive_session(cmds, **kargs)
    finally:
        conf.color_theme = ct
    return s, res


def autorun_get_html_interactive_session(cmds, **kargs):
    ct = conf.color_theme
    to_html = lambda s: s.replace("<", "&lt;").replace(">", "&gt;").replace("#[#", "<").replace("#]#", ">")  # noqa: E501
    try:
        try:
            conf.color_theme = HTMLTheme2()
            s, res = autorun_get_interactive_session(cmds, **kargs)
        except StopAutorun as e:
            e.code_run = to_html(e.code_run)
            raise
    finally:
        conf.color_theme = ct

    return to_html(s), res


def autorun_get_latex_interactive_session(cmds, **kargs):
    ct = conf.color_theme
    to_latex = lambda s: tex_escape(s).replace("@[@", "{").replace("@]@", "}").replace("@`@", "\\")  # noqa: E501
    try:
        try:
            conf.color_theme = LatexTheme2()
            s, res = autorun_get_interactive_session(cmds, **kargs)
        except StopAutorun as e:
            e.code_run = to_latex(e.code_run)
            raise
    finally:
        conf.color_theme = ct
    return to_latex(s), res
