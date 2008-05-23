
from __future__ import generators
import os,sys

VERSION = "1.2.0.2"

DEFAULT_CONFIG_FILE = os.path.join(os.environ["HOME"], ".scapy_startup.py")

try:
    os.stat(DEFAULT_CONFIG_FILE)
except OSError:
    DEFAULT_CONFIG_FILE = None

def usage():
    print """Usage: scapy.py [-s sessionfile] [-c new_startup_file] [-C]
    -C: do not read startup file"""
    sys.exit(0)


from config import conf
from themes import ColorPrompt


######################
## Extension system ##
######################


def load_extension(filename):
    import imp
    paths = conf.extensions_paths
    if type(paths) is not list:
        paths = [paths]

    name = os.path.realpath(os.path.expanduser(filename))
    thepath = os.path.dirname(name)
    thename = os.path.basename(name)
    if thename.endswith(".py"):
        thename = thename[:-3]

    paths.insert(0, thepath)
    cwd=syspath=None
    try:
        cwd = os.getcwd()
        os.chdir(thepath)
        syspath = sys.path[:]
        sys.path += paths
        try:
            extf = imp.find_module(thename, paths)
        except ImportError:
            log_runtime.error("Module [%s] not found. Check conf.extensions_paths ?" % filename)
        else:
            ext = imp.load_module(thename, *extf)
            import __builtin__
            __builtin__.__dict__.update(ext.__dict__)
    finally:
        if syspath:
            sys.path=syspath
        if cwd:
            os.chdir(cwd)
    

################
##### Main #####
################

def scapy_write_history_file(readline):
    if conf.histfile:
        try:
            readline.write_history_file(conf.histfile)
        except IOError,e:
            try:
                warning("Could not write history to [%s]\n\t (%s)" % (conf.histfile,e))
                tmp = os.tempnam("","scapy")
                readline.write_history_file(tmp)
                warning("Wrote history to [%s]" % tmp)
            except:
                warning("Cound not write history to [%s]. Discarded" % tmp)


def interact(mydict=None,argv=None,mybanner=None,loglevel=1):
    global session
    import code,sys,cPickle,types,os,imp,getopt,logging,re

    logging.getLogger("scapy").setLevel(loglevel)

    the_banner = "Welcome to Scapy (%s)"
    if mybanner is not None:
        the_banner += "\n"
        the_banner += mybanner

    if argv is None:
        argv = sys.argv

#    scapy_module = argv[0][argv[0].rfind("/")+1:]
#    if not scapy_module:
#        scapy_module = "scapy"
#    else:
#        if scapy_module.endswith(".py"):
#            scapy_module = scapy_module[:-3]
#
#    scapy=imp.load_module("scapy",*imp.find_module(scapy_module))
    
    
#    __builtin__.__dict__.update(scapy.__dict__)
    import __builtin__
    scapy_builtins = {}
    for m in [ "ansmachine","arch","automaton","autorun","config","dadict","data","error","fields","main",
               "mib","packet","plist","route","sendrecv","supersocket","themes","utils","volatile","asn1","asn1fields","asn1packet" ]:
        mod = __import__("scapy."+m,globals(),locals(),".")
        scapy_builtins.update(mod.__dict__)
    for m in ["l2","inet","dot11","dhcp","dns","ip6","isakmp","l2tp","mgcp","netbios","ntp","ppp","radius","rip",
              "skinny","smb","rtp","tftp","snmp","x509" ]: # "ir","bluetooth","hsrp","gprs"
        mod = __import__("scapy.layers."+m,globals(),locals(),".")
        scapy_builtins.update(mod.__dict__)
    __builtin__.__dict__.update(scapy_builtins)
    globkeys = scapy_builtins.keys()
    globkeys.append("scapy_session")
    scapy_builtins=None # XXX replace with "with" statement
    if mydict is not None:
        __builtin__.__dict__.update(mydict)
        globkeys += mydict.keys()
    
    import re, atexit
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
    CONFIG_FILE = DEFAULT_CONFIG_FILE

    iface = None
    try:
        opts=getopt.getopt(argv[1:], "hs:Cc:")
        for opt, parm in opts[0]:
            if opt == "-h":
                usage()
            elif opt == "-s":
                session_name = parm
            elif opt == "-c":
                CONFIG_FILE = parm
            elif opt == "-C":
                CONFIG_FILE = None
        
        if len(opts[1]) > 0:
            raise getopt.GetoptError("Too many parameters : [%s]" % " ".join(opts[1]))


    except getopt.GetoptError, msg:
        log_loading.error(msg)
        sys.exit(1)


    if CONFIG_FILE:
        read_config_file(CONFIG_FILE)
        
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
    
    sys.ps1 = ColorPrompt()
    code.interact(banner = the_banner % (VERSION), local=session)

    if conf.session:
        save_session(conf.session, session)


    for k in globkeys:
        try:
            del(__builtin__.__dict__[k])
        except:
            pass

def read_config_file(configfile):
    try:
        execfile(configfile)
    except IOError,e:
        log_loading.warning("Cannot read config file [%s] [%s]" % (configfile,e))
    except Exception,e:
        log_loading.exception("Error during evaluation of config file [%s]" % configfile)
        

if __name__ == "__main__":
    interact()
else:
    if DEFAULT_CONFIG_FILE:
        read_config_file(DEFAULT_CONFIG_FILE)
