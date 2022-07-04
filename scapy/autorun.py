# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Run commands when the Scapy interpreter starts.
"""

from __future__ import print_function
import code
import logging
import sys
import threading
import traceback

from scapy.config import conf
from scapy.themes import NoTheme, DefaultTheme, HTMLTheme2, LatexTheme2
from scapy.error import log_scapy, Scapy_Exception
from scapy.utils import tex_escape

from scapy.compat import (
    Any,
    Optional,
    TextIO,
    Dict,
    Tuple,
)

from scapy.libs.six.moves import queue
import scapy.libs.six as six


#########################
#     Autorun stuff     #
#########################

class StopAutorun(Scapy_Exception):
    code_run = ""


class StopAutorunTimeout(StopAutorun):
    pass


class ScapyAutorunInterpreter(code.InteractiveInterpreter):
    def __init__(self, *args, **kargs):
        # type: (*Any, **Any) -> None
        code.InteractiveInterpreter.__init__(self, *args, **kargs)

    def write(self, data):
        # type: (str) -> None
        pass


def autorun_commands(_cmds, my_globals=None, verb=None):
    # type: (str, Optional[Dict[str, Any]], Optional[int]) -> Any
    sv = conf.verb
    try:
        try:
            if my_globals is None:
                from scapy.main import _scapy_builtins
                my_globals = _scapy_builtins()
            interp = ScapyAutorunInterpreter(locals=my_globals)
            try:
                del six.moves.builtins.__dict__["scapy_session"]["_"]
            except KeyError:
                pass
            if verb is not None:
                conf.verb = verb
            cmd = ""
            cmds = _cmds.splitlines()
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
                    return False
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


def autorun_commands_timeout(cmds, timeout=None, **kwargs):
    # type: (str, Optional[int], **Any) -> Any
    """
    Wraps autorun_commands with a timeout that raises StopAutorunTimeout
    on expiration.
    """
    if timeout is None:
        return autorun_commands(cmds, **kwargs)

    q = queue.Queue()

    def _runner():
        # type: () -> None
        q.put(autorun_commands(cmds, **kwargs))
    th = threading.Thread(target=_runner)
    th.daemon = True
    th.start()
    th.join(timeout)
    if th.is_alive():
        raise StopAutorunTimeout
    return q.get()


class StringWriter(six.StringIO):
    """Util to mock sys.stdout and sys.stderr, and
    store their output in a 's' var."""
    def __init__(self, debug=None):
        # type: (Optional[TextIO]) -> None
        self.s = ""
        self.debug = debug
        six.StringIO.__init__(self)

    def write(self, x):
        # type: (str) -> int
        # Object can be in the middle of being destroyed.
        if getattr(self, "debug", None) and self.debug:
            self.debug.write(x)
        if getattr(self, "s", None) is not None:
            self.s += x
        return len(x)

    def flush(self):
        # type: () -> None
        if getattr(self, "debug", None) and self.debug:
            self.debug.flush()


def autorun_get_interactive_session(cmds, **kargs):
    # type: (str, **Any) -> Tuple[str, Any]
    """Create an interactive session and execute the
    commands passed as "cmds" and return all output

    :param cmds: a list of commands to run
    :param timeout: timeout in seconds
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
            sys.excepthook = sys.__excepthook__  # type: ignore
            res = autorun_commands_timeout(cmds, **kargs)
        except StopAutorun as e:
            e.code_run = sw.s
            raise
    finally:
        sys.stdout, sys.stderr, sys.excepthook = sstdout, sstderr, sexcepthook
        log_scapy.removeHandler(log_scapy.handlers[0])
        log_scapy.addHandler(h_old)
    return sw.s, res


def autorun_get_interactive_live_session(cmds, **kargs):
    # type: (str, **Any) -> Tuple[str, Any]
    """Create an interactive session and execute the
    commands passed as "cmds" and return all output

    :param cmds: a list of commands to run
    :param timeout: timeout in seconds
    :returns: (output, returned) contains both sys.stdout and sys.stderr logs
    """
    sstdout, sstderr = sys.stdout, sys.stderr
    sw = StringWriter(debug=sstdout)
    try:
        try:
            sys.stdout = sys.stderr = sw
            res = autorun_commands_timeout(cmds, **kargs)
        except StopAutorun as e:
            e.code_run = sw.s
            raise
    finally:
        sys.stdout, sys.stderr = sstdout, sstderr
    return sw.s, res


def autorun_get_text_interactive_session(cmds, **kargs):
    # type: (str, **Any) -> Tuple[str, Any]
    ct = conf.color_theme
    try:
        conf.color_theme = NoTheme()
        s, res = autorun_get_interactive_session(cmds, **kargs)
    finally:
        conf.color_theme = ct
    return s, res


def autorun_get_live_interactive_session(cmds, **kargs):
    # type: (str, **Any) -> Tuple[str, Any]
    ct = conf.color_theme
    try:
        conf.color_theme = DefaultTheme()
        s, res = autorun_get_interactive_live_session(cmds, **kargs)
    finally:
        conf.color_theme = ct
    return s, res


def autorun_get_ansi_interactive_session(cmds, **kargs):
    # type: (str, **Any) -> Tuple[str, Any]
    ct = conf.color_theme
    try:
        conf.color_theme = DefaultTheme()
        s, res = autorun_get_interactive_session(cmds, **kargs)
    finally:
        conf.color_theme = ct
    return s, res


def autorun_get_html_interactive_session(cmds, **kargs):
    # type: (str, **Any) -> Tuple[str, Any]
    ct = conf.color_theme

    def to_html(s):
        # type: (str) -> str
        return s.replace("<", "&lt;").replace(">", "&gt;").replace("#[#", "<").replace("#]#", ">")  # noqa: E501
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
    # type: (str, **Any) -> Tuple[str, Any]
    ct = conf.color_theme

    def to_latex(s):
        # type: (str) -> str
        return tex_escape(s).replace("@[@", "{").replace("@]@", "}").replace("@`@", "\\")  # noqa: E501
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
