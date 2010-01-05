## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license


from __future__ import generators
import os,sys
import __builtin__
from error import *
import utils
    

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


from config import conf
from themes import DefaultTheme


######################
## Extension system ##
######################


def _load(module):
    try:
        mod = __import__(module,globals(),locals(),".")
        __builtin__.__dict__.update(mod.__dict__)
    except Exception,e:
        log_interactive.error(e)
        
def load_module(name):
    _load("scapy.modules."+name)

def load_layer(name):
    _load("scapy.layers."+name)

    

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
    import code,sys,cPickle,os,getopt,re
    from config import conf
    conf.interactive = True
    if loglevel is not None:
        conf.logLevel=loglevel

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
                for lst in [dir(__builtin__), session.keys()]:
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
    __builtin__.__dict__.update(scapy_builtins)
    globkeys = scapy_builtins.keys()
    globkeys.append("scapy_session")
    scapy_builtins=None # XXX replace with "with" statement
    if mydict is not None:
        __builtin__.__dict__.update(mydict)
        globkeys += mydict.keys()
    

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
    conf.color_theme = DefaultTheme()
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
