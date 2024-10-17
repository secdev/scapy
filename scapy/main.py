# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Main module for interactive startup.
"""


import builtins
import pathlib
import sys
import os
import getopt
import code
import gzip
import glob
import importlib
import io
from itertools import zip_longest
import logging
import pickle
import types
import warnings
from random import choice

# Never add any global import, in main.py, that would trigger a
# warning message before the console handlers gets added in interact()
from scapy.error import (
    log_interactive,
    log_loading,
    Scapy_Exception,
)
from scapy.themes import DefaultTheme, BlackAndWhite, apply_ipython_style
from scapy.consts import WINDOWS

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Union,
    overload,
)
from scapy.compat import (
    Literal,
)

LAYER_ALIASES = {
    "tls": "tls.all",
    "msrpce": "msrpce.all",
}

QUOTES = [
    ("Craft packets like it is your last day on earth.", "Lao-Tze"),
    ("Craft packets like I craft my beer.", "Jean De Clerck"),
    ("Craft packets before they craft you.", "Socrate"),
    ("Craft me if you can.", "IPv6 layer"),
    ("To craft a packet, you have to be a packet, and learn how to swim in "
     "the wires and in the waves.", "Jean-Claude Van Damme"),
    ("We are in France, we say Skappee. OK? Merci.", "Sebastien Chabal"),
    ("Wanna support scapy? Star us on GitHub!", "Satoshi Nakamoto"),
    ("I'll be back.", "Python 2"),
]


def _probe_xdg_folder(var, default, *cf):
    # type: (str, str, *str) -> Optional[pathlib.Path]
    path = pathlib.Path(os.environ.get(var, default))
    if not path.exists():
        # ~ folder doesn't exist. Create according to spec
        # https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
        # "If, when attempting to write a file, the destination directory is
        # non-existent an attempt should be made to create it with permission 0700."
        try:
            path.mkdir(mode=0o700, exist_ok=True)
        except Exception:
            # There is a gazillion ways this can fail. Most notably,
            # a read-only fs.
            return None
    return path.joinpath(*cf).resolve()


def _probe_config_folder(*cf):
    # type: (str) -> Optional[pathlib.Path]
    return _probe_xdg_folder(
        "XDG_CONFIG_HOME",
        os.path.join(os.path.expanduser("~"), ".config"),
        *cf
    )


def _probe_cache_folder(*cf):
    # type: (str) -> Optional[pathlib.Path]
    return _probe_xdg_folder(
        "XDG_CACHE_HOME",
        os.path.join(os.path.expanduser("~"), ".cache"),
        *cf
    )


def _read_config_file(cf, _globals=globals(), _locals=locals(),
                      interactive=True, default=None):
    # type: (str, Dict[str, Any], Dict[str, Any], bool, Optional[str]) -> None
    """Read a config file: execute a python file while loading scapy, that
    may contain some pre-configured values.

    If _globals or _locals are specified, they will be updated with
    the loaded vars.  This allows an external program to use the
    function. Otherwise, vars are only available from inside the scapy
    console.

    Parameters:

    :param _globals: the globals() vars
    :param _locals: the locals() vars
    :param interactive: specified whether or not errors should be printed
    using the scapy console or raised.
    :param default: if provided, set a default value for the config file

    ex, content of a config.py file:
        'conf.verb = 42\n'
    Manual loading:
        >>> _read_config_file("./config.py"))
        >>> conf.verb
        2

    """
    cf_path = pathlib.Path(cf)
    if not cf_path.exists():
        log_loading.debug("Config file [%s] does not exist.", cf)
        if default is None:
            return
        # We have a default ! set it
        try:
            if not cf_path.parent.exists():
                cf_path.parent.mkdir(parents=True, exist_ok=True)
                if (
                    not WINDOWS and
                    "SUDO_UID" in os.environ and
                    "SUDO_GID" in os.environ
                ):
                    # Was started with sudo. Still, chown to the user.
                    try:
                        os.chown(
                            cf_path.parent,
                            int(os.environ["SUDO_UID"]),
                            int(os.environ["SUDO_GID"]),
                        )
                    except Exception:
                        pass
            with cf_path.open("w") as fd:
                fd.write(default)
            if (
                not WINDOWS and
                "SUDO_UID" in os.environ and
                "SUDO_GID" in os.environ
            ):
                # Was started with sudo. Still, chown to the user.
                try:
                    os.chown(
                        cf_path,
                        int(os.environ["SUDO_UID"]),
                        int(os.environ["SUDO_GID"]),
                    )
                except Exception:
                    pass
            log_loading.debug("Config file [%s] created with default.", cf)
        except OSError:
            log_loading.warning("Config file [%s] could not be created.", cf,
                                exc_info=True)
            return
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
        log_loading.exception("Error during evaluation of config file [%s]",
                              cf)


def _validate_local(k):
    # type: (str) -> bool
    """Returns whether or not a variable should be imported."""
    return k[0] != "_" and k not in ["range", "map"]


# This is ~/.config/scapy
SCAPY_CONFIG_FOLDER = _probe_config_folder("scapy")
SCAPY_CACHE_FOLDER = _probe_cache_folder("scapy")

if SCAPY_CONFIG_FOLDER:
    DEFAULT_PRESTART_FILE: Optional[str] = str(SCAPY_CONFIG_FOLDER / "prestart.py")
    DEFAULT_STARTUP_FILE: Optional[str] = str(SCAPY_CONFIG_FOLDER / "startup.py")
else:
    DEFAULT_PRESTART_FILE = None
    DEFAULT_STARTUP_FILE = None

# Default scapy prestart.py config file

DEFAULT_PRESTART = """
# Scapy CLI 'pre-start' config file
# see https://scapy.readthedocs.io/en/latest/api/scapy.config.html#scapy.config.Conf
# for all available options

# default interpreter
conf.interactive_shell = "auto"

# color theme (DefaultTheme, BrightTheme, ColorOnBlackTheme, BlackAndWhite, ...)
conf.color_theme = DefaultTheme()

# disable INFO: tags related to dependencies missing
# log_loading.setLevel(logging.WARNING)

# force-use libpcap
# conf.use_pcap = True
""".strip()


def _usage():
    # type: () -> None
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
    # type: (str, Optional[Dict[str, Any]], Optional[List[str]]) -> None
    """Loads a Python module to make variables, objects and functions
available globally.

    The idea is to load the module using importlib, then copy the
symbols to the global symbol table.

    """
    if globals_dict is None:
        globals_dict = builtins.__dict__
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
            for name, sym in mod.__dict__.items():
                if _validate_local(name):
                    if symb_list is not None:
                        symb_list.append(name)
                    globals_dict[name] = sym
    except Exception:
        log_interactive.error("Loading module %s", module, exc_info=True)


def load_module(name, globals_dict=None, symb_list=None):
    # type: (str, Optional[Dict[str, Any]], Optional[List[str]]) -> None
    """Loads a Scapy module to make variables, objects and functions
    available globally.

    """
    _load("scapy.modules." + name,
          globals_dict=globals_dict, symb_list=symb_list)


def load_layer(name, globals_dict=None, symb_list=None):
    # type: (str, Optional[Dict[str, Any]], Optional[List[str]]) -> None
    """Loads a Scapy layer module to make variables, objects and functions
    available globally.

    """
    _load("scapy.layers." + LAYER_ALIASES.get(name, name),
          globals_dict=globals_dict, symb_list=symb_list)


def load_contrib(name, globals_dict=None, symb_list=None):
    # type: (str, Optional[Dict[str, Any]], Optional[List[str]]) -> None
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


def list_contrib(name=None,  # type: Optional[str]
                 ret=False,  # type: bool
                 _debug=False  # type: bool
                 ):
    # type: (...) -> Optional[List[Dict[str, str]]]
    """Show the list of all existing contribs.

    :param name: filter to search the contribs
    :param ret: whether the function should return a dict instead of
        printing it
    :returns: None or a dictionary containing the results if ret=True
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
    results = []  # type: List[Dict[str, str]]
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
        desc = {"description": "", "status": "", "name": mod}
        with io.open(f, errors="replace") as fd:
            for line in fd:
                if line[0] != "#":
                    continue
                p = line.find("scapy.contrib.")
                if p >= 0:
                    p += 14
                    q = line.find("=", p)
                    key = line[p:q].strip()
                    value = line[q + 1:].strip()
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
        return None


##############################
#  Session saving/restoring  #
##############################

def update_ipython_session(session):
    # type: (Dict[str, Any]) -> None
    """Updates IPython session with a custom one"""
    if "_oh" not in session:
        session["_oh"] = session["Out"] = {}
        session["In"] = {}
    try:
        from IPython import get_ipython
        get_ipython().user_ns.update(session)
    except Exception:
        pass


def _scapy_prestart_builtins():
    # type: () -> Dict[str, Any]
    """Load Scapy prestart and return all builtins"""
    return {
        k: v
        for k, v in importlib.import_module(".config", "scapy").__dict__.copy().items()
        if _validate_local(k)
    }


def _scapy_builtins():
    # type: () -> Dict[str, Any]
    """Load Scapy and return all builtins"""
    return {
        k: v
        for k, v in importlib.import_module(".all", "scapy").__dict__.copy().items()
        if _validate_local(k)
    }


def _scapy_exts():
    # type: () -> Dict[str, Any]
    """Load Scapy exts and return their builtins"""
    from scapy.config import conf
    res = {}
    for modname, spec in conf.exts.all_specs.items():
        if spec.default:
            mod = sys.modules[modname]
            res.update({
                k: v
                for k, v in mod.__dict__.copy().items()
                if _validate_local(k)
            })
    return res


def save_session(fname="", session=None, pickleProto=-1):
    # type: (str, Optional[Dict[str, Any]], int) -> None
    """Save current Scapy session to the file specified in the fname arg.

    params:
     - fname: file to save the scapy session in
     - session: scapy session to use. If None, the console one will be used
     - pickleProto: pickle proto version (default: -1 = latest)"""
    from scapy import utils
    from scapy.config import conf, ConfClass
    if not fname:
        fname = conf.session
        if not fname:
            conf.session = fname = utils.get_temp_file(keep=True)
    log_interactive.info("Saving session into [%s]", fname)

    if not session:
        if conf.interactive_shell in ["ipython", "ptipython"]:
            from IPython import get_ipython
            session = get_ipython().user_ns
        else:
            session = builtins.__dict__["scapy_session"]

    if not session:
        log_interactive.error("No session found ?!")
        return

    ignore = session.get("_scpybuiltins", [])
    hard_ignore = ["scapy_session", "In", "Out", "open"]
    to_be_saved = session.copy()

    for k in list(to_be_saved):
        i = to_be_saved[k]
        if k[0] == "_":
            del to_be_saved[k]
        elif hasattr(i, "__module__") and i.__module__.startswith("IPython"):
            del to_be_saved[k]
        elif isinstance(i, ConfClass):
            del to_be_saved[k]
        elif k in ignore or k in hard_ignore:
            del to_be_saved[k]
        elif isinstance(i, (type, types.ModuleType, types.FunctionType)):
            if k[0] != "_":
                log_interactive.warning("[%s] (%s) can't be saved.", k, type(i))
            del to_be_saved[k]
        else:
            try:
                pickle.dumps(i)
            except Exception:
                log_interactive.warning("[%s] (%s) can't be saved.", k, type(i))

    try:
        os.rename(fname, fname + ".bak")
    except OSError:
        pass

    f = gzip.open(fname, "wb")
    pickle.dump(to_be_saved, f, pickleProto)
    f.close()


def load_session(fname=None):
    # type: (Optional[Union[str, None]]) -> None
    """Load current Scapy session from the file specified in the fname arg.
    This will erase any existing session.

    params:
     - fname: file to load the scapy session from"""
    from scapy.config import conf
    if fname is None:
        fname = conf.session
    try:
        s = pickle.load(gzip.open(fname, "rb"))
    except IOError:
        try:
            s = pickle.load(open(fname, "rb"))
        except IOError:
            # Raise "No such file exception"
            raise

    scapy_session = builtins.__dict__["scapy_session"]
    s.update({k: scapy_session[k] for k in scapy_session["_scpybuiltins"]})
    scapy_session.clear()
    scapy_session.update(s)
    update_ipython_session(scapy_session)

    log_loading.info("Loaded session [%s]", fname)


def update_session(fname=None):
    # type: (Optional[Union[str, None]]) -> None
    """Update current Scapy session from the file specified in the fname arg.

    params:
     - fname: file to load the scapy session from"""
    from scapy.config import conf
    if fname is None:
        fname = conf.session
    try:
        s = pickle.load(gzip.open(fname, "rb"))
    except IOError:
        s = pickle.load(open(fname, "rb"))
    scapy_session = builtins.__dict__["scapy_session"]
    scapy_session.update(s)
    update_ipython_session(scapy_session)


@overload
def init_session(session_name,  # type: Optional[Union[str, None]]
                 mydict,  # type: Optional[Union[Dict[str, Any], None]]
                 ret,  # type: Literal[True]
                 ):
    # type: (...) -> Dict[str, Any]
    pass


@overload
def init_session(session_name,  # type: Optional[Union[str, None]]
                 mydict=None,  # type: Optional[Union[Dict[str, Any], None]]
                 ret=False,  # type: Literal[False]
                 ):
    # type: (...) -> None
    pass


def init_session(session_name,  # type: Optional[Union[str, None]]
                 mydict=None,  # type: Optional[Union[Dict[str, Any], None]]
                 ret=False,  # type: bool
                 ):
    # type: (...) -> Union[Dict[str, Any], None]
    from scapy.config import conf
    SESSION = {}  # type: Optional[Dict[str, Any]]

    # Load Scapy
    scapy_builtins = _scapy_builtins()

    # Load exts
    scapy_builtins.update(_scapy_exts())

    if session_name:
        try:
            os.stat(session_name)
        except OSError:
            log_loading.info("New session [%s]", session_name)
        else:
            try:
                try:
                    SESSION = pickle.load(gzip.open(session_name, "rb"))
                except IOError:
                    SESSION = pickle.load(open(session_name, "rb"))
                log_loading.info("Using existing session [%s]", session_name)
            except ValueError:
                msg = "Error opening Python3 pickled session on Python2 [%s]"
                log_loading.error(msg, session_name)
            except EOFError:
                log_loading.error("Error opening session [%s]", session_name)
            except AttributeError:
                log_loading.error("Error opening session [%s]. "
                                  "Attribute missing", session_name)

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

    SESSION.update(scapy_builtins)
    SESSION["_scpybuiltins"] = scapy_builtins.keys()
    builtins.__dict__["scapy_session"] = SESSION

    if mydict is not None:
        builtins.__dict__["scapy_session"].update(mydict)
        update_ipython_session(mydict)
    if ret:
        return SESSION
    return None

################
#     Main     #
################


def _prepare_quote(quote, author, max_len=78):
    # type: (str, str, int) -> List[str]
    """This function processes a quote and returns a string that is ready
to be used in the fancy banner.

    """
    _quote = quote.split(' ')
    max_len -= 6
    lines = []
    cur_line = []  # type: List[str]

    def _len(line):
        # type: (List[str]) -> int
        return sum(len(elt) for elt in line) + len(line) - 1
    while _quote:
        if not cur_line or (_len(cur_line) + len(_quote[0]) - 1 <= max_len):
            cur_line.append(_quote.pop(0))
            continue
        lines.append('   | %s' % ' '.join(cur_line))
        cur_line = []
    if cur_line:
        lines.append('   | %s' % ' '.join(cur_line))
        cur_line = []
    lines.append('   | %s-- %s' % (" " * (max_len - len(author) - 5), author))
    return lines


def get_fancy_banner(mini: Optional[bool] = None) -> str:
    """
    Generates the fancy Scapy banner

    :param mini: if set, force a mini banner or not. Otherwise detect
    """
    from scapy.config import conf
    from scapy.utils import get_terminal_width
    if mini is None:
        mini_banner = (get_terminal_width() or 84) <= 75
    else:
        mini_banner = mini

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
    return "\n".join(
        logo + banner for logo, banner in zip_longest(
            (conf.color_theme.logo(line) for line in the_logo),
            (conf.color_theme.success(line) for line in the_banner),
            fillvalue=""
        )
    )


def interact(mydict=None, argv=None, mybanner=None, loglevel=logging.INFO):
    # type: (Optional[Any], Optional[Any], Optional[Any], int) -> None
    """
    Starts Scapy's console.
    """
    # We're in interactive mode, let's throw the DeprecationWarnings
    warnings.simplefilter("always")

    # Set interactive mode, load the color scheme
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
        for opt, param in opts[0]:
            if opt == "-h":
                _usage()
            elif opt == "-H":
                conf.fancy_banner = False
                conf.verb = 1
                conf.logLevel = logging.WARNING
            elif opt == "-s":
                session_name = param
            elif opt == "-c":
                STARTUP_FILE = param
            elif opt == "-C":
                STARTUP_FILE = None
            elif opt == "-p":
                PRESTART_FILE = param
            elif opt == "-P":
                PRESTART_FILE = None
            elif opt == "-d":
                conf.logLevel = max(1, conf.logLevel - 10)

        if len(opts[1]) > 0:
            raise getopt.GetoptError(
                "Too many parameters : [%s]" % " ".join(opts[1])
            )

    except getopt.GetoptError as msg:
        log_loading.error(msg)
        sys.exit(1)

    # Reset sys.argv, otherwise IPython thinks it is for him
    sys.argv = sys.argv[:1]

    if PRESTART_FILE:
        _read_config_file(
            PRESTART_FILE,
            interactive=True,
            _locals=_scapy_prestart_builtins(),
            default=DEFAULT_PRESTART,
        )

    SESSION = init_session(session_name, mydict=mydict, ret=True)

    if STARTUP_FILE:
        _read_config_file(
            STARTUP_FILE,
            interactive=True,
            _locals=SESSION
        )

    if conf.fancy_banner:
        banner_text = get_fancy_banner()
    else:
        banner_text = "Welcome to Scapy (%s)" % conf.version
    if mybanner is not None:
        banner_text += "\n"
        banner_text += mybanner

    # Configure interactive terminal

    if conf.interactive_shell not in [
            "ipython",
            "python",
            "ptpython",
            "ptipython",
            "bpython",
            "auto"]:
        log_loading.warning("Unknown conf.interactive_shell ! Using 'auto'")
        conf.interactive_shell = "auto"

    # Auto detect available shells.
    # Order:
    # 1. IPython
    # 2. bpython
    # 3. ptpython

    _IMPORTS = {
        "ipython": ["IPython"],
        "bpython": ["bpython"],
        "ptpython": ["ptpython"],
        "ptipython": ["IPython", "ptpython"],
    }

    if conf.interactive_shell == "auto":
        # Auto detect
        for imp in ["IPython", "bpython", "ptpython"]:
            try:
                importlib.import_module(imp)
                conf.interactive_shell = imp.lower()
                break
            except ImportError:
                continue
        else:
            log_loading.warning(
                "No alternative Python interpreters found ! "
                "Using standard Python shell instead."
            )
            conf.interactive_shell = "python"

    if conf.interactive_shell in _IMPORTS:
        # Check import
        for imp in _IMPORTS[conf.interactive_shell]:
            try:
                importlib.import_module(imp)
            except ImportError:
                log_loading.warning("%s requested but not found !" % imp)
                conf.interactive_shell = "python"

    # Default shell
    if conf.interactive_shell == "python":
        disabled = ["History"]
        if WINDOWS:
            disabled.append("Colors")
            conf.color_theme = BlackAndWhite()
        else:
            try:
                # Bad completer.. but better than nothing
                import rlcompleter
                import readline
                readline.set_completer(
                    rlcompleter.Completer(namespace=SESSION).complete
                )
                readline.parse_and_bind('tab: complete')
            except ImportError:
                disabled.insert(0, "AutoCompletion")
        # Display warning when using the default REPL
        log_loading.info(
            "Using the default Python shell: %s %s disabled." % (
                ",".join(disabled),
                "is" if len(disabled) == 1 else "are"
            )
        )

    # ptpython configure function
    def ptpython_configure(repl):
        # type: (Any) -> None
        # Hide status bar
        repl.show_status_bar = False
        # Complete while typing (versus only when pressing tab)
        repl.complete_while_typing = False
        # Enable auto-suggestions
        repl.enable_auto_suggest = True
        # Disable exit confirmation
        repl.confirm_exit = False
        # Show signature
        repl.show_signature = True
        # Apply Scapy color theme: TODO
        # repl.install_ui_colorscheme("scapy",
        #                             Style.from_dict(_custom_ui_colorscheme))
        # repl.use_ui_colorscheme("scapy")

    # Extend banner text
    if conf.interactive_shell in ["ipython", "ptipython"]:
        import IPython
        if conf.interactive_shell == "ptipython":
            banner = banner_text + " using IPython %s" % IPython.__version__
            try:
                from importlib.metadata import version
                ptpython_version = " " + version('ptpython')
            except ImportError:
                ptpython_version = ""
            banner += " and ptpython%s" % ptpython_version
        else:
            banner = banner_text + " using IPython %s" % IPython.__version__
    elif conf.interactive_shell == "ptpython":
        try:
            from importlib.metadata import version
            ptpython_version = " " + version('ptpython')
        except ImportError:
            ptpython_version = ""
        banner = banner_text + " using ptpython%s" % ptpython_version
    elif conf.interactive_shell == "bpython":
        import bpython
        banner = banner_text + " using bpython %s" % bpython.__version__

    # Start IPython or ptipython
    if conf.interactive_shell in ["ipython", "ptipython"]:
        banner += "\n"
        if conf.interactive_shell == "ptipython":
            from ptpython.ipython import embed
        else:
            from IPython import embed
        try:
            from traitlets.config.loader import Config
        except ImportError:
            log_loading.warning(
                "traitlets not available. Some Scapy shell features won't be "
                "available."
            )
            try:
                embed(
                    display_banner=False,
                    user_ns=SESSION,
                    exec_lines=["print(\"\"\"" + banner + "\"\"\")"]
                )
            except Exception:
                code.interact(banner=banner_text, local=SESSION)
        else:
            cfg = Config()
            try:
                from IPython import get_ipython
                if not get_ipython():
                    raise ImportError
            except ImportError:
                # Set "classic" prompt style when launched from
                # run_scapy(.bat) files Register and apply scapy
                # color+prompt style
                apply_ipython_style(shell=cfg.InteractiveShellEmbed)
                cfg.InteractiveShellEmbed.confirm_exit = False
                cfg.InteractiveShellEmbed.separate_in = u''
            if int(IPython.__version__[0]) >= 6:
                cfg.InteractiveShellEmbed.term_title = True
                cfg.InteractiveShellEmbed.term_title_format = ("Scapy %s" %
                                                               conf.version)
                # As of IPython 6-7, the jedi completion module is a dumpster
                # of fire that should be scrapped never to be seen again.
                # This is why the following defaults to False. Feel free to hurt
                # yourself (#GH4056) :P
                cfg.Completer.use_jedi = conf.ipython_use_jedi
            else:
                cfg.InteractiveShellEmbed.term_title = False
            cfg.HistoryAccessor.hist_file = conf.histfile
            cfg.InteractiveShell.banner1 = banner
            # configuration can thus be specified here.
            _kwargs = {}
            if conf.interactive_shell == "ptipython":
                _kwargs["configure"] = ptpython_configure
            try:
                embed(config=cfg, user_ns=SESSION, **_kwargs)
            except (AttributeError, TypeError):
                code.interact(banner=banner_text, local=SESSION)
    # Start ptpython
    elif conf.interactive_shell == "ptpython":
        # ptpython has special, non-default handling of __repr__ which breaks Scapy.
        # For instance: >>> IP()
        log_loading.warning("ptpython support is currently partially broken")
        from ptpython.repl import embed
        # ptpython has no banner option
        banner += "\n"
        print(banner)
        embed(
            locals=SESSION,
            history_filename=conf.histfile,
            title="Scapy %s" % conf.version,
            configure=ptpython_configure
        )
    # Start bpython
    elif conf.interactive_shell == "bpython":
        from bpython.curtsies import main as embed
        embed(
            args=["-q", "-i"],
            locals_=SESSION,
            banner=banner,
            welcome_message=""
        )
    # Start Python
    elif conf.interactive_shell == "python":
        code.interact(banner=banner_text, local=SESSION)
    else:
        raise ValueError("Invalid conf.interactive_shell")

    if conf.session:
        save_session(conf.session, SESSION)


if __name__ == "__main__":
    interact()
