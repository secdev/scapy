## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Main module for interactive startup.
"""

from __future__ import absolute_import
from __future__ import print_function


import glob
import gzip
import importlib
import os
from random import choice
import sys
import types


import scapy.modules.six as six
from scapy.error import *


ignored = list(six.moves.builtins.__dict__.keys())


LAYER_ALIASES = {
    "tls": "tls.all"
}

QUOTES = [
    ("Craft packets like it is your last day on earth.", "Lao-Tze"),
    ("Craft packets like I craft my beer.", "Jean De Clerck"),
    ("Craft packets before they craft you.", "Socrate"),
    ("Craft me if you can.", "IPv6 layer"),
    ("To craft a packet, you have to be a packet, and learn how to swim in the "
     "wires and in the waves.", "Jean-Claude Van Damme"),
]

def _probe_config_file(cf):
    cf_path = os.path.join(os.path.expanduser("~"), cf)
    try:
        os.stat(cf_path)
    except OSError:
        return None
    else:
        return cf_path

def _read_config_file(cf):
    log_loading.debug("Loading config file [%s]" % cf)
    try:
        exec(compile(open(cf).read(), cf, 'exec'))
    except IOError as e:
        log_loading.warning("Cannot read config file [%s] [%s]" % (cf,e))
    except Exception as e:
        log_loading.exception("Error during evaluation of config file [%s]" % cf)
        
def _validate_local(x):
    """Returns whether or not a variable should be imported.
    Will return False for any default modules (sys), or if
    they are detected as private vars (starting with a _)"""
    global ignored
    return x[0] != "_" and not x in ignored

DEFAULT_PRESTART_FILE = _probe_config_file(".scapy_prestart.py")
DEFAULT_STARTUP_FILE = _probe_config_file(".scapy_startup.py")
session = None

def _usage():
    print("""Usage: scapy.py [-s sessionfile] [-c new_startup_file] [-p new_prestart_file] [-C] [-P]
    -C: do not read startup file
    -P: do not read pre-startup file""")
    sys.exit(0)


from scapy.config import conf
from scapy.themes import DefaultTheme


######################
## Extension system ##
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

def load_module(name):
    """Loads a Scapy module to make variables, objects and functions
    available globally.

    """
    _load("scapy.modules."+name)

def load_layer(name, globals_dict=None, symb_list=None):
    """Loads a Scapy layer module to make variables, objects and functions
    available globally.

    """
    _load("scapy.layers." + LAYER_ALIASES.get(name, name),
          globals_dict=globals_dict, symb_list=symb_list)

def load_contrib(name):
    """Loads a Scapy contrib module to make variables, objects and
    functions available globally.

    If no contrib module can be found with the given name, try to find
    a layer module, since a contrib module may become a layer module.

    """
    try:
        importlib.import_module("scapy.contrib." + name)
        _load("scapy.contrib." + name)
    except ImportError:
        # if layer not found in contrib, try in layers
        load_layer(name)

def list_contrib(name=None):
    if name is None:
        name="*.py"
    elif "*" not in name and "?" not in name and not name.endswith(".py"):
        name += ".py"
    name = os.path.join(os.path.dirname(__file__), "contrib", name)
    for f in sorted(glob.glob(name)):
        mod = os.path.basename(f)
        if mod.startswith("__"):
            continue
        if mod.endswith(".py"):
            mod = mod[:-3]
        desc = { "description":"-", "status":"?", "name":mod }
        for l in open(f):
            p = l.find("scapy.contrib.")
            if p >= 0:
                p += 14
                q = l.find("=", p)
                key = l[p:q].strip()
                value = l[q+1:].strip()
                desc[key] = value
        print("%(name)-20s: %(description)-40s status=%(status)s" % desc)

                        


    

##############################
## Session saving/restoring ##
##############################


def save_session(fname=None, session=None, pickleProto=-1):
    from scapy import utils
    if fname is None:
        fname = conf.session
        if not fname:
            conf.session = fname = utils.get_temp_file(keep=True)
            log_interactive.info("Use [%s] as session file" % fname)
    if session is None:
        session = six.moves.builtins.__dict__["scapy_session"]

    to_be_saved = session.copy()
        
    if "__builtins__" in to_be_saved:
        del(to_be_saved["__builtins__"])

    for k in to_be_saved.keys():
        if type(to_be_saved[k]) in [type, type, types.ModuleType]:
             log_interactive.error("[%s] (%s) can't be saved." % (k, type(to_be_saved[k])))
             del(to_be_saved[k])

    
    try:
         os.rename(fname, fname+".bak")
    except OSError:
         pass
    
    f=gzip.open(fname,"wb")
    six.moves.cPickle.dump(to_be_saved, f, pickleProto)
    f.close()
    del f

def load_session(fname=None):
    if fname is None:
        fname = conf.session
    try:
        s = six.moves.cPickle.load(gzip.open(fname,"rb"))
    except IOError:
        try:
            s = six.moves.cPickle.load(open(fname,"rb"))
        except IOError:
            # Raise "No such file exception"
            raise

    scapy_session = six.moves.builtins.__dict__["scapy_session"]
    scapy_session.clear()
    scapy_session.update(s)
    log_loading.info("Loaded session [%s]" % conf.session)
    
def update_session(fname=None):
    if fname is None:
        fname = conf.session
    try:
        s = six.moves.cPickle.load(gzip.open(fname,"rb"))
    except IOError:
        s = six.moves.cPickle.load(open(fname,"rb"))
    scapy_session = six.moves.builtins.__dict__["scapy_session"]
    scapy_session.update(s)

def init_session(session_name, mydict=None):
    global session
    global globkeys
    
    scapy_builtins = {k: v for k, v in six.iteritems(importlib.import_module(".all", "scapy").__dict__) if _validate_local(k)}
    six.moves.builtins.__dict__.update(scapy_builtins)
    globkeys = list(scapy_builtins.keys())
    globkeys.append("scapy_session")
    scapy_builtins=None # XXX replace with "with" statement
    if mydict is not None:
        six.moves.builtins.__dict__.update(mydict)
        globkeys += list(mydict.keys())
    
    if session_name:
        try:
            os.stat(session_name)
        except OSError:
            log_loading.info("New session [%s]" % session_name)
        else:
            try:
                try:
                    session = six.moves.cPickle.load(gzip.open(session_name,"rb"))
                except IOError:
                    session = six.moves.cPickle.load(open(session_name,"rb"))
                log_loading.info("Using session [%s]" % session_name)
            except EOFError:
                log_loading.error("Error opening session [%s]" % session_name)
            except AttributeError:
                log_loading.error("Error opening session [%s]. Attribute missing" %  session_name)

        if session:
            if "conf" in session:
                conf.configure(session["conf"])
                session["conf"] = conf
        else:
            conf.session = session_name
            session={"conf":conf}
    else:
        session={"conf": conf}

    six.moves.builtins.__dict__["scapy_session"] = session

################
##### Main #####
################

def scapy_delete_temp_files():
    for f in conf.temp_files:
        try:
            os.unlink(f)
        except:
            pass

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

def scapy_write_history_file(readline):
    from scapy import utils
    if conf.histfile:
        try:
            readline.write_history_file(conf.histfile)
        except IOError as e:
            try:
                warning("Could not write history to [%s]\n\t (%s)" % (conf.histfile,e))
                tmp = utils.get_temp_file(keep=True)
                readline.write_history_file(tmp)
                warning("Wrote history to [%s]" % tmp)
            except:
                warning("Could not write history to [%s]. Discarded" % tmp)


def interact(mydict=None,argv=None,mybanner=None,loglevel=20):
    global session
    global globkeys
    import code,sys,os,getopt,re
    from scapy.config import conf
    conf.interactive = True
    if loglevel is not None:
        conf.logLevel=loglevel

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    log_scapy.addHandler(console_handler)

    conf.color_theme = DefaultTheme()

    STARTUP_FILE = DEFAULT_STARTUP_FILE
    PRESTART_FILE = DEFAULT_PRESTART_FILE

    session_name = None

    if argv is None:
        argv = sys.argv

    try:
        opts = getopt.getopt(argv[1:], "hs:Cc:Pp:d")
        for opt, parm in opts[0]:
            if opt == "-h":
                _usage()
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
                conf.logLevel = max(1, conf.logLevel-10)

        if len(opts[1]) > 0:
            raise getopt.GetoptError("Too many parameters : [%s]" % " ".join(opts[1]))


    except getopt.GetoptError as msg:
        log_loading.error(msg)
        sys.exit(1)

    if STARTUP_FILE:
        _read_config_file(STARTUP_FILE)
    if PRESTART_FILE:
        _read_config_file(PRESTART_FILE)

    init_session(session_name, mydict)

    if conf.fancy_prompt:

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

    import atexit
    try:
        import rlcompleter,readline
    except ImportError:
        log_loading.info("Can't load Python libreadline or completer")
        READLINE=0
    else:
        READLINE=1
        class ScapyCompleter(rlcompleter.Completer):
            def global_matches(self, text):
                matches = []
                n = len(text)
                for lst in [dir(six.moves.builtins), session]:
                    for word in lst:
                        if word[:n] == text and word != "__builtins__":
                            matches.append(word)
                return matches


            def attr_matches(self, text):
                m = re.match(r"(\w+(\.\w+)*)\.(\w*)", text)
                if not m:
                    return []
                expr, attr = m.group(1, 3)
                try:
                    object = eval(expr)
                except:
                    try:
                        object = eval(expr, session)
                    except (NameError, AttributeError):
                        return []
                from scapy.packet import Packet, Packet_metaclass
                if isinstance(object, Packet) or isinstance(object, Packet_metaclass):
                    words = [x for x in dir(object) if x[0] != "_"]
                    words += [x.name for x in object.fields_desc]
                else:
                    words = dir(object)
                    if hasattr( object,"__class__" ):
                        words = words + rlcompleter.get_class_members(object.__class__)
                matches = []
                n = len(attr)
                for word in words:
                    if word[:n] == attr and word != "__builtins__":
                        matches.append("%s.%s" % (expr, word))
                return matches
    
        readline.set_completer(ScapyCompleter().complete)
        readline.parse_and_bind("C-o: operate-and-get-next")
        readline.parse_and_bind("tab: complete")

    if READLINE:
        if conf.histfile:
            try:
                readline.read_history_file(conf.histfile)
            except IOError:
                pass
        atexit.register(scapy_write_history_file,readline)
    
    atexit.register(scapy_delete_temp_files)
    
    IPYTHON=False
    if conf.interactive_shell.lower() == "ipython":
        try:
            import IPython
            IPYTHON=True
        except ImportError as e:
            log_loading.warning("IPython not available. Using standard Python shell instead.")
            IPYTHON=False
        
    if IPYTHON:
        banner = the_banner + " using IPython %s" % IPython.__version__

        # Old way to embed IPython kept for backward compatibility
        try:
          args = ['']  # IPython command line args (will be seen as sys.argv)
          ipshell = IPython.Shell.IPShellEmbed(args, banner = banner)
          ipshell(local_ns=session)
        except AttributeError as e:
          pass

        # In the IPython cookbook, see 'Updating-code-for-use-with-IPython-0.11-and-later'
        IPython.embed(user_ns=session, banner2=banner)

    else:
        code.interact(banner=the_banner, local=session, readfunc=conf.readfunc)

    if conf.session:
        save_session(conf.session, session)


    for k in globkeys:
        try:
            del(six.moves.builtins.__dict__[k])
        except:
            pass

if __name__ == "__main__":
    interact()
