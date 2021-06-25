# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Run commands when the Scapy interpreter starts.
"""

from __future__ import print_function
import code
import importlib
import logging
import sys
import traceback

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

    def write(self, data):
        pass


def autorun_commands(cmds, my_globals=None, verb=None):
    sv = conf.verb
    try:
        try:
            interp = ScapyAutorunInterpreter()
            if my_globals is None:
                my_globals = importlib.import_module(".all", "scapy").__dict__
            interp.locals = my_globals
            try:
                del six.moves.builtins.__dict__["scapy_session"]["_"]
            except KeyError:
                pass
            if verb is not None:
                conf.verb = verb
            cmd = ""
            cmds = cmds.splitlines()
            cmds.append("")  # ensure we finish multi-line commands
            cmds.reverse()
            while True:
                if cmd:
                    sys.stderr.write(sys.__dict__.get("ps2", "... "))
                else:
                    sys.stderr.write(sys.__dict__.get("ps1", ">>> "))

                line = cmds.pop()
                print(line)
                cmd += "\n" + line
                sys.last_value = None
                if interp.runsource(cmd):
                    continue
                if sys.last_value:  # An error occurred
                    traceback.print_exception(sys.last_type,
                                              sys.last_value,
                                              sys.last_traceback.tb_next,
                                              file=sys.stdout)
                    sys.last_value = None
                    return None
                cmd = ""
                if len(cmds) <= 1:
                    break
        except SystemExit:
            pass
    finally:
        conf.verb = sv
    try:
        return six.moves.builtins.__dict__["scapy_session"]["_"]
    except KeyError:
        return six.moves.builtins.__dict__.get("_", None)


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
    sstdout, sstderr, sexcepthook = sys.stdout, sys.stderr, sys.excepthook
    sw = StringWriter()
    h_old = log_scapy.handlers[0]
    log_scapy.removeHandler(h_old)
    log_scapy.addHandler(logging.StreamHandler(stream=sw))
    try:
        try:
            sys.stdout = sys.stderr = sw
            sys.excepthook = sys.__excepthook__
            res = autorun_commands(cmds, **kargs)
        except StopAutorun as e:
            e.code_run = sw.s
            raise
    finally:
        sys.stdout, sys.stderr, sys.excepthook = sstdout, sstderr, sexcepthook
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
