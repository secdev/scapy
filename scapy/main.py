# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Main module for interactive startup.
"""

from __future__ import absolute_import
from __future__ import print_function

import sys
import os
import getopt
import code
import gzip
import glob
import importlib
import io
import logging
import types
import warnings
from random import choice

# Never add any global import, in main.py, that would trigger a warning message  # noqa: E501
# before the console handlers gets added in interact()
from scapy.error import log_interactive, log_loading, log_scapy, \
    Scapy_Exception, ScapyColoredFormatter
import scapy.modules.six as six
from scapy.themes import DefaultTheme, BlackAndWhite, apply_ipython_style
from scapy.consts import WINDOWS

IGNORED = list(six.moves.builtins.__dict__)

GLOBKEYS = []

LAYER_ALIASES = {
    "tls": "tls.all"
}

QUOTES = [
    ("Craft packets like it is your last day on earth.", "Lao-Tze"),
    ("Craft packets like I craft my beer.", "Jean De Clerck"),
    ("Craft packets before they craft you.", "Socrate"),
    ("Craft me if you can.", "IPv6 layer"),
    ("To craft a packet, you have to be a packet, and learn how to swim in the "  # noqa: E501
     "wires and in the waves.", "Jean-Claude Van Damme"),
    ("We are in France, we say Skappee. OK? Merci.", "Sebastien Chabal"),
    ("Wanna support scapy? Rate it on sectools! http://sectools.org/tool/scapy/", "Satoshi Nakamoto"),  # noqa: E501
]


def _probe_config_file(cf):
    cf_path = os.path.join(os.path.expanduser("~"), cf)
    try:
        os.stat(cf_path)
    except OSError:
        return None
    else:
        return cf_path


def _read_config_file(cf, _globals=globals(), _locals=locals(), interactive=True):  # noqa: E501
    """Read a config file: execute a python file while loading scapy, that may contain  # noqa: E501
    some pre-configured values.

    If _globals or _locals are specified, they will be updated with the loaded vars.  # noqa: E501
    This allows an external program to use the function. Otherwise, vars are only available  # noqa: E501
    from inside the scapy console.

    params:
    - _globals: the globals() vars
    - _locals: the locals() vars
    - interactive: specified whether or not errors should be printed using the scapy console or  # noqa: E501
    raised.

    ex, content of a config.py file:
        'conf.verb = 42\n'
    Manual loading:
        >>> _read_config_file("./config.py"))
        >>> conf.verb
        42
    """
    log_loading.debug("Loading config file [%s]", cf)
    try:
        with open(cf) as cfgf:
            exec(
                compile(cfgf.read(), cf, 'exec'),
                _globals, _locals
            )
    except IOError as e:
        if interactive:
            raise
        log_loading.warning("Cannot read config file [%s] [%s]", cf, e)
    except Exception:
        if interactive:
            raise
        log_loading.exception("Error during evaluation of config file [%s]", cf)  # noqa: E501


def _validate_local(x):
    """Returns whether or not a variable should be imported.
    Will return False for any default modules (sys), or if
    they are detected as private vars (starting with a _)"""
    global IGNORED
    return x[0] != "_" and x not in IGNORED


DEFAULT_PRESTART_FILE = _probe_config_file(".scapy_prestart.py")
DEFAULT_STARTUP_FILE = _probe_config_file(".scapy_startup.py")
SESSION = None


def _usage():
    print(
        "Usage: scapy.py [-s sessionfile] [-c new_startup_file] "
        "[-p new_prestart_file] [-C] [-P] [-H]\n"
        "Args:\n"
        "\t-H: header-less start\n"
        "\t-C: do not read startup file\n"
        "\t-P: do not read pre-startup file\n"
    )
    sys.exit(0)


######################
#  Extension system  #
######################


def _load(module, globals_dict=None, symb_list=None):
    """Loads a Python module to make variables, objects and functions
available globally.

    The idea is to load the module using importlib, then copy the
symbols to the global symbol table.

    """
    if globals_dict is None:
        globals_dict = six.moves.builtins.__dict__
    try:
        mod = importlib.import_module(module)
        if '__all__' in mod.__dict__:
            # import listed symbols
            for name in mod.__dict__['__all__']:
                if symb_list is not None:
                    symb_list.append(name)
                globals_dict[name] = mod.__dict__[name]
        else:
            # only import non-private symbols
            for name, sym in six.iteritems(mod.__dict__):
                if _validate_local(name):
                    if symb_list is not None:
                        symb_list.append(name)
                    globals_dict[name] = sym
    except Exception:
        log_interactive.error("Loading module %s", module, exc_info=True)


def load_module(name, globals_dict=None, symb_list=None):
    """Loads a Scapy module to make variables, objects and functions
    available globally.

    """
    _load("scapy.modules." + name,
          globals_dict=globals_dict, symb_list=symb_list)


def load_layer(name, globals_dict=None, symb_list=None):
    """Loads a Scapy layer module to make variables, objects and functions
    available globally.

    """
    _load("scapy.layers." + LAYER_ALIASES.get(name, name),
          globals_dict=globals_dict, symb_list=symb_list)


def load_contrib(name, globals_dict=None, symb_list=None):
    """Loads a Scapy contrib module to make variables, objects and
    functions available globally.

    If no contrib module can be found with the given name, try to find
    a layer module, since a contrib module may become a layer module.

    """
    try:
        importlib.import_module("scapy.contrib." + name)
        _load("scapy.contrib." + name,
              globals_dict=globals_dict, symb_list=symb_list)
    except ImportError as e:
        # if layer not found in contrib, try in layers
        try:
            load_layer(name,
                       globals_dict=globals_dict, symb_list=symb_list)
        except ImportError:
            raise e  # Let's raise the original error to avoid confusion


def list_contrib(name=None, ret=False, _debug=False):
    """Show the list of all existing contribs.
    Params:
     - name: filter to search the contribs
     - ret: whether the function should return a dict instead of printing it
    """
    # _debug: checks that all contrib modules have correctly defined:
    # # scapy.contrib.description = [...]
    # # scapy.contrib.status = [...]
    # # scapy.contrib.name = [...] (optional)
    # or set the flag:
    # # scapy.contrib.description = skip
    # to skip the file
    if name is None:
        name = "*.py"
    elif "*" not in name and "?" not in name and not name.endswith(".py"):
        name += ".py"
    results = []
    dir_path = os.path.join(os.path.dirname(__file__), "contrib")
    if sys.version_info >= (3, 5):
        name = os.path.join(dir_path, "**", name)
        iterator = glob.iglob(name, recursive=True)
    else:
        name = os.path.join(dir_path, name)
        iterator = glob.iglob(name)
    for f in iterator:
        mod = f.replace(os.path.sep, ".").partition("contrib.")[2]
        if mod.startswith("__"):
            continue
        if mod.endswith(".py"):
            mod = mod[:-3]
        desc = {"description": None, "status": None, "name": mod}
        with io.open(f, errors="replace") as fd:
            for l in fd:
                if l[0] != "#":
                    continue
                p = l.find("scapy.contrib.")
                if p >= 0:
                    p += 14
                    q = l.find("=", p)
                    key = l[p:q].strip()
                    value = l[q + 1:].strip()
                    desc[key] = value
                if desc["status"] == "skip":
                    break
                if desc["description"] and desc["status"]:
                    results.append(desc)
                    break
        if _debug:
            if desc["status"] == "skip":
                pass
            elif not desc["description"] or not desc["status"]:
                raise Scapy_Exception("Module %s is missing its "
                                      "contrib infos !" % mod)
    results.sort(key=lambda x: x["name"])
    if ret:
        return results
    else:
        for desc in results:
            print("%(name)-20s: %(description)-40s status=%(status)s" % desc)


##############################
#  Session saving/restoring  #
##############################

def update_ipython_session(session):
    """Updates IPython session with a custom one"""
    try:
        global get_ipython
        get_ipython().user_ns.update(session)
    except Exception:
        pass


def save_session(fname=None, session=None, pickleProto=-1):
    """Save current Scapy session to the file specified in the fname arg.

    params:
     - fname: file to save the scapy session in
     - session: scapy session to use. If None, the console one will be used
     - pickleProto: pickle proto version (default: -1 = latest)"""
    from scapy import utils
    from scapy.config import conf, ConfClass
    if fname is None:
        fname = conf.session
        if not fname:
            conf.session = fname = utils.get_temp_file(keep=True)
    log_interactive.info("Use [%s] as session file" % fname)

    if session is None:
        try:
            session = get_ipython().user_ns
        except Exception:
            session = six.moves.builtins.__dict__["scapy_session"]

    to_be_saved = session.copy()
    if "__builtins__" in to_be_saved:
        del(to_be_saved["__builtins__"])

    for k in list(to_be_saved):
        i = to_be_saved[k]
        if hasattr(i, "__module__") and (k[0] == "_" or i.__module__.startswith("IPython")):  # noqa: E501
            del(to_be_saved[k])
        if isinstance(i, ConfClass):
            del(to_be_saved[k])
        elif isinstance(i, (type, type, types.ModuleType)):
            if k[0] != "_":
                log_interactive.error("[%s] (%s) can't be saved.", k, type(to_be_saved[k]))  # noqa: E501
            del(to_be_saved[k])

    try:
        os.rename(fname, fname + ".bak")
    except OSError:
        pass

    f = gzip.open(fname, "wb")
    six.moves.cPickle.dump(to_be_saved, f, pickleProto)
    f.close()
    del f


def load_session(fname=None):
    """Load current Scapy session from the file specified in the fname arg.
    This will erase any existing session.

    params:
     - fname: file to load the scapy session from"""
    from scapy.config import conf
    if fname is None:
        fname = conf.session
    try:
        s = six.moves.cPickle.load(gzip.open(fname, "rb"))
    except IOError:
        try:
            s = six.moves.cPickle.load(open(fname, "rb"))
        except IOError:
            # Raise "No such file exception"
            raise

    scapy_session = six.moves.builtins.__dict__["scapy_session"]
    scapy_session.clear()
    scapy_session.update(s)
    update_ipython_session(scapy_session)

    log_loading.info("Loaded session [%s]" % fname)


def update_session(fname=None):
    """Update current Scapy session from the file specified in the fname arg.

    params:
     - fname: file to load the scapy session from"""
    from scapy.config import conf
    if fname is None:
        fname = conf.session
    try:
        s = six.moves.cPickle.load(gzip.open(fname, "rb"))
    except IOError:
        s = six.moves.cPickle.load(open(fname, "rb"))
    scapy_session = six.moves.builtins.__dict__["scapy_session"]
    scapy_session.update(s)
    update_ipython_session(scapy_session)


def init_session(session_name, mydict=None):
    from scapy.config import conf
    global SESSION
    global GLOBKEYS

    scapy_builtins = {k: v for k, v in six.iteritems(importlib.import_module(".all", "scapy").__dict__) if _validate_local(k)}  # noqa: E501
    six.moves.builtins.__dict__.update(scapy_builtins)
    GLOBKEYS.extend(scapy_builtins)
    GLOBKEYS.append("scapy_session")
    scapy_builtins = None

    if session_name:
        try:
            os.stat(session_name)
        except OSError:
            log_loading.info("New session [%s]" % session_name)
        else:
            try:
                try:
                    SESSION = six.moves.cPickle.load(gzip.open(session_name, "rb"))  # noqa: E501
                except IOError:
                    SESSION = six.moves.cPickle.load(open(session_name, "rb"))
                log_loading.info("Using session [%s]" % session_name)
            except EOFError:
                log_loading.error("Error opening session [%s]" % session_name)
            except AttributeError:
                log_loading.error("Error opening session [%s]. Attribute missing" % session_name)  # noqa: E501

        if SESSION:
            if "conf" in SESSION:
                conf.configure(SESSION["conf"])
                conf.session = session_name
                SESSION["conf"] = conf
            else:
                conf.session = session_name
        else:
            conf.session = session_name
            SESSION = {"conf": conf}
    else:
        SESSION = {"conf": conf}

    six.moves.builtins.__dict__["scapy_session"] = SESSION

    if mydict is not None:
        six.moves.builtins.__dict__["scapy_session"].update(mydict)
        update_ipython_session(mydict)
        GLOBKEYS.extend(mydict)

################
#     Main     #
################


def scapy_delete_temp_files():
    from scapy.config import conf
    for f in conf.temp_files:
        try:
            os.unlink(f)
        except Exception:
            pass
    del(conf.temp_files[:])


def _prepare_quote(quote, author, max_len=78):
    """This function processes a quote and returns a string that is ready
to be used in the fancy prompt.

    """
    quote = quote.split(' ')
    max_len -= 6
    lines = []
    cur_line = []

    def _len(line):
        return sum(len(elt) for elt in line) + len(line) - 1
    while quote:
        if not cur_line or (_len(cur_line) + len(quote[0]) - 1 <= max_len):
            cur_line.append(quote.pop(0))
            continue
        lines.append('   | %s' % ' '.join(cur_line))
        cur_line = []
    if cur_line:
        lines.append('   | %s' % ' '.join(cur_line))
        cur_line = []
    lines.append('   | %s-- %s' % (" " * (max_len - len(author) - 5), author))
    return lines


def interact(mydict=None, argv=None, mybanner=None, loglevel=logging.INFO):
    """Starts Scapy's console."""
    global SESSION
    global GLOBKEYS

    try:
        if WINDOWS:
            # colorama is bundled within IPython.
            # logging.StreamHandler will be overwritten when called,
            # We can't wait for IPython to call it
            import colorama
            colorama.init()
        # Success
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            ScapyColoredFormatter(
                "%(levelname)s: %(message)s",
            )
        )
    except ImportError:
        # Failure: ignore colors in the logger
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            logging.Formatter(
                "%(levelname)s: %(message)s",
            )
        )
    log_scapy.addHandler(console_handler)

    # We're in interactive mode, let's throw the DeprecationWarnings
    warnings.simplefilter("always")

    from scapy.config import conf
    conf.interactive = True
    conf.color_theme = DefaultTheme()
    if loglevel is not None:
        conf.logLevel = loglevel

    STARTUP_FILE = DEFAULT_STARTUP_FILE
    PRESTART_FILE = DEFAULT_PRESTART_FILE

    session_name = None

    if argv is None:
        argv = sys.argv

    try:
        opts = getopt.getopt(argv[1:], "hs:Cc:Pp:d:H")
        for opt, parm in opts[0]:
            if opt == "-h":
                _usage()
            elif opt == "-H":
                conf.fancy_prompt = False
                conf.verb = 30
            elif opt == "-s":
                session_name = parm
            elif opt == "-c":
                STARTUP_FILE = parm
            elif opt == "-C":
                STARTUP_FILE = None
            elif opt == "-p":
                PRESTART_FILE = parm
            elif opt == "-P":
                PRESTART_FILE = None
            elif opt == "-d":
                conf.logLevel = max(1, conf.logLevel - 10)

        if len(opts[1]) > 0:
            raise getopt.GetoptError("Too many parameters : [%s]" % " ".join(opts[1]))  # noqa: E501

    except getopt.GetoptError as msg:
        log_loading.error(msg)
        sys.exit(1)

    # Reset sys.argv, otherwise IPython thinks it is for him
    sys.argv = sys.argv[:1]

    init_session(session_name, mydict)

    if STARTUP_FILE:
        _read_config_file(STARTUP_FILE, interactive=True)
    if PRESTART_FILE:
        _read_config_file(PRESTART_FILE, interactive=True)

    if not conf.interactive_shell or conf.interactive_shell.lower() in [
            "ipython", "auto"
    ]:
        try:
            import IPython
            from IPython import start_ipython
        except ImportError:
            log_loading.warning(
                "IPython not available. Using standard Python shell "
                "instead.\nAutoCompletion, History are disabled."
            )
            if WINDOWS:
                log_loading.warning(
                    "On Windows, colors are also disabled"
                )
                conf.color_theme = BlackAndWhite()
            IPYTHON = False
        else:
            IPYTHON = True
    else:
        IPYTHON = False

    if conf.fancy_prompt:
        from scapy.utils import get_terminal_width
        mini_banner = (get_terminal_width() or 84) <= 75

        the_logo = [
            "                                      ",
            "                     aSPY//YASa       ",
            "             apyyyyCY//////////YCa    ",
            "            sY//////YSpcs  scpCY//Pp  ",
            " ayp ayyyyyyySCP//Pp           syY//C ",
            " AYAsAYYYYYYYY///Ps              cY//S",
            "         pCCCCY//p          cSSps y//Y",
            "         SPPPP///a          pP///AC//Y",
            "              A//A            cyP////C",
            "              p///Ac            sC///a",
            "              P////YCpc           A//A",
            "       scccccp///pSP///p          p//Y",
            "      sY/////////y  caa           S//P",
            "       cayCyayP//Ya              pY/Ya",
            "        sY/PsY////YCc          aC//Yp ",
            "         sc  sccaCY//PCypaapyCP//YSs  ",
            "                  spCPY//////YPSps    ",
            "                       ccaacs         ",
            "                                      ",
        ]

        # Used on mini screens
        the_logo_mini = [
            "      .SYPACCCSASYY  ",
            "P /SCS/CCS        ACS",
            "       /A          AC",
            "     A/PS       /SPPS",
            "        YP        (SC",
            "       SPS/A.      SC",
            "   Y/PACC          PP",
            "    PY*AYC        CAA",
            "         YYCY//SCYP  ",
        ]

        the_banner = [
            "",
            "",
            "   |",
            "   | Welcome to Scapy",
            "   | Version %s" % conf.version,
            "   |",
            "   | https://github.com/secdev/scapy",
            "   |",
            "   | Have fun!",
            "   |",
        ]

        if mini_banner:
            the_logo = the_logo_mini
            the_banner = [x[2:] for x in the_banner[3:-1]]
            the_banner = [""] + the_banner + [""]
        else:
            quote, author = choice(QUOTES)
            the_banner.extend(_prepare_quote(quote, author, max_len=39))
            the_banner.append("   |")
        the_banner = "\n".join(
            logo + banner for logo, banner in six.moves.zip_longest(
                (conf.color_theme.logo(line) for line in the_logo),
                (conf.color_theme.success(line) for line in the_banner),
                fillvalue=""
            )
        )
    else:
        the_banner = "Welcome to Scapy (%s)" % conf.version
    if mybanner is not None:
        the_banner += "\n"
        the_banner += mybanner

    if IPYTHON:
        banner = the_banner + " using IPython %s\n" % IPython.__version__
        try:
            from traitlets.config.loader import Config
        except ImportError:
            log_loading.warning(
                "traitlets not available. Some Scapy shell features won't be "
                "available."
            )
            try:
                start_ipython(
                    display_banner=False,
                    user_ns=SESSION,
                    exec_lines=["print(\"\"\"" + banner + "\"\"\")"]
                )
            except Exception:
                code.interact(banner=the_banner, local=SESSION)
        else:
            cfg = Config()
            try:
                get_ipython
            except NameError:
                # Set "classic" prompt style when launched from run_scapy(.bat) files  # noqa: E501
                # Register and apply scapy color+prompt style
                apply_ipython_style(shell=cfg.TerminalInteractiveShell)
                cfg.TerminalInteractiveShell.confirm_exit = False
                cfg.TerminalInteractiveShell.separate_in = u''
            if int(IPython.__version__[0]) >= 6:
                cfg.TerminalInteractiveShell.term_title_format = "Scapy v%s" % conf.version  # noqa: E501
            else:
                cfg.TerminalInteractiveShell.term_title = False
            cfg.HistoryAccessor.hist_file = conf.histfile
            cfg.InteractiveShell.banner1 = banner
            # configuration can thus be specified here.
            try:
                start_ipython(config=cfg, user_ns=SESSION)
            except (AttributeError, TypeError):
                code.interact(banner=the_banner, local=SESSION)
    else:
        code.interact(banner=the_banner, local=SESSION)

    if conf.session:
        save_session(conf.session, SESSION)

    for k in GLOBKEYS:
        try:
            del(six.moves.builtins.__dict__[k])
        except Exception:
            pass


if __name__ == "__main__":
    interact()
