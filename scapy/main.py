## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Main module for interactive startup.
"""

import os,sys
import glob
import types
import gzip
import cPickle
import __builtin__

from scapy.error import *
from scapy import utils
    

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
        execfile(cf)
    except IOError,e:
        log_loading.warning("Cannot read config file [%s] [%s]" % (cf,e))
    except Exception,e:
        log_loading.exception("Error during evaluation of config file [%s]" % cf)
        

DEFAULT_PRESTART_FILE = _probe_config_file(".scapy_prestart.py")
DEFAULT_STARTUP_FILE = _probe_config_file(".scapy_startup.py")

def _usage():
    print """Usage: scapy.py [-s sessionfile] [-c new_startup_file] [-p new_prestart_file] [-C] [-P]
    -C: do not read startup file
    -P: do not read pre-startup file"""
    sys.exit(0)


from scapy.config import conf
from scapy.themes import DefaultTheme


######################
## Extension system ##
######################


def _load(module):
    try:
        mod = __import__(module,globals(),locals(),".")
        if '__all__' in mod.__dict__:
            # import listed symbols
            for name in mod.__dict__['__all__']:
                __builtin__.__dict__[name] = mod.__dict__[name]
        else:
            # only import non-private symbols
            for name, sym in mod.__dict__.iteritems():
                if name[0] != '_':
                    __builtin__.__dict__[name] = sym
    except Exception,e:
        log_interactive.error(e)

def load_module(name):
    _load("scapy.modules."+name)

def load_layer(name):
    _load("scapy.layers."+name)

def load_contrib(name):
    try:
        __import__("scapy.contrib." + name)
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
    for f in glob.glob(name):
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
        print "%(name)-20s: %(description)-40s status=%(status)s" % desc

                        


    

##############################
## Session saving/restoring ##
##############################


def save_session(fname=None, session=None, pickleProto=-1):
    if fname is None:
        fname = conf.session
        if not fname:
            conf.session = fname = utils.get_temp_file(keep=True)
            log_interactive.info("Use [%s] as session file" % fname)
    if session is None:
        session = __builtin__.__dict__["scapy_session"]

    to_be_saved = session.copy()
        
    if to_be_saved.has_key("__builtins__"):
        del(to_be_saved["__builtins__"])

    for k in to_be_saved.keys():
        if type(to_be_saved[k]) in [types.TypeType, types.ClassType, types.ModuleType]:
             log_interactive.error("[%s] (%s) can't be saved." % (k, type(to_be_saved[k])))
             del(to_be_saved[k])

    try:
        os.rename(fname, fname+".bak")
    except OSError:
        pass
    f=gzip.open(fname,"wb")
    cPickle.dump(to_be_saved, f, pickleProto)
    f.close()

def load_session(fname=None):
    if fname is None:
        fname = conf.session
    try:
        s = cPickle.load(gzip.open(fname,"rb"))
    except IOError:
        s = cPickle.load(open(fname,"rb"))
    scapy_session = __builtin__.__dict__["scapy_session"]
    scapy_session.clear()
    scapy_session.update(s)

def update_session(fname=None):
    if fname is None:
        fname = conf.session
    try:
        s = cPickle.load(gzip.open(fname,"rb"))
    except IOError:
        s = cPickle.load(open(fname,"rb"))
    scapy_session = __builtin__.__dict__["scapy_session"]
    scapy_session.update(s)


################
##### Main #####
################

def scapy_delete_temp_files():
    for f in conf.temp_files:
        try:
            os.unlink(f)
        except:
            pass

def scapy_write_history_file(readline):
    if conf.histfile:
        try:
            readline.write_history_file(conf.histfile)
        except IOError,e:
            try:
                warning("Could not write history to [%s]\n\t (%s)" % (conf.histfile,e))
                tmp = utils.get_temp_file(keep=True)
                readline.write_history_file(tmp)
                warning("Wrote history to [%s]" % tmp)
            except:
                warning("Cound not write history to [%s]. Discarded" % tmp)


def interact(mydict=None,argv=None,mybanner=None,loglevel=20):
    global session
    import code,sys,os,getopt,re
    from scapy.config import conf
    conf.interactive = True
    if loglevel is not None:
        conf.logLevel=loglevel

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    log_scapy.addHandler(console_handler)

    the_banner = "Welcome to Scapy (%s)"
    if mybanner is not None:
        the_banner += "\n"
        the_banner += mybanner

    if argv is None:
        argv = sys.argv

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
                for lst in [dir(__builtin__), session]:
                    for word in lst:
                        if word[:n] == text and word != "__builtins__":
                            matches.append(word)
                return matches


            def attr_matches(self, text):
                m = re.match(r"(\w+(\.\w+)*)\.(\w*)", text)
                if not m:
                    return
                expr, attr = m.group(1, 3)
                try:
                    object = eval(expr)
                except:
                    object = eval(expr, session)
                from scapy.packet import Packet, Packet_metaclass
                if isinstance(object, Packet) or isinstance(object, Packet_metaclass):
                    words = filter(lambda x: x[0]!="_",dir(object))
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
    
    
    session=None
    session_name=""
    STARTUP_FILE = DEFAULT_STARTUP_FILE
    PRESTART_FILE = DEFAULT_PRESTART_FILE


    iface = None
    try:
        opts=getopt.getopt(argv[1:], "hs:Cc:Pp:d")
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
                conf.logLevel = max(1,conf.logLevel-10)
        
        if len(opts[1]) > 0:
            raise getopt.GetoptError("Too many parameters : [%s]" % " ".join(opts[1]))


    except getopt.GetoptError, msg:
        log_loading.error(msg)
        sys.exit(1)

    if PRESTART_FILE:
        _read_config_file(PRESTART_FILE)

    scapy_builtins = __import__("all",globals(),locals(),".").__dict__
    for name, sym in scapy_builtins.iteritems():
        if name [0] != '_':
            __builtin__.__dict__[name] = sym
    globkeys = scapy_builtins.keys()
    globkeys.append("scapy_session")
    scapy_builtins=None # XXX replace with "with" statement
    if mydict is not None:
        __builtin__.__dict__.update(mydict)
        globkeys += mydict.keys()
    

    conf.color_theme = DefaultTheme()
    if STARTUP_FILE:
        _read_config_file(STARTUP_FILE)
        
    if session_name:
        try:
            os.stat(session_name)
        except OSError:
            log_loading.info("New session [%s]" % session_name)
        else:
            try:
                try:
                    session = cPickle.load(gzip.open(session_name,"rb"))
                except IOError:
                    session = cPickle.load(open(session_name,"rb"))
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

    __builtin__.__dict__["scapy_session"] = session


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
        except ImportError, e:
            log_loading.warning("IPython not available. Using standard Python shell instead.")
            IPYTHON=False
        
    if IPYTHON:
        banner = the_banner % (conf.version) + " using IPython %s" % IPython.__version__

        # Old way to embed IPython kept for backward compatibility
        try:
          args = ['']  # IPython command line args (will be seen as sys.argv)
          ipshell = IPython.Shell.IPShellEmbed(args, banner = banner)
          ipshell(local_ns=session)
        except AttributeError, e:
          pass

        # In the IPython cookbook, see 'Updating-code-for-use-with-IPython-0.11-and-later'
        IPython.embed(user_ns=session, banner2=banner)

    else:
        code.interact(banner = the_banner % (conf.version),
                      local=session, readfunc=conf.readfunc)

    if conf.session:
        save_session(conf.session, session)


    for k in globkeys:
        try:
            del(__builtin__.__dict__[k])
        except:
            pass

if __name__ == "__main__":
    interact()
