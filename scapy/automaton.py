## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## Copyright (C) Gabriel Potter <gabriel@potter.fr>
## This program is published under a GPLv2 license

"""
Automata with states, transitions and actions.
"""

from __future__ import absolute_import
import types,itertools,time,os,sys,socket,traceback
from select import select
from collections import deque
import threading
from scapy.config import conf
from scapy.utils import do_graph
from scapy.error import log_interactive
from scapy.plist import PacketList
from scapy.data import MTU
from scapy.supersocket import SuperSocket
from scapy.consts import WINDOWS
from scapy.compat import *
import scapy.modules.six as six

if WINDOWS:
    from scapy.error import Scapy_Exception
    recv_error = Scapy_Exception
else:
    recv_error = ()

""" In Windows, select.select is not available for custom objects. Here's the implementation of scapy to re-create this functionnality
# Passive way: using no-ressources locks
               +---------+             +---------------+      +-------------------------+
               |  Start  +------------->Select_objects +----->+Linux: call select.select|
               +---------+             |(select.select)|      +-------------------------+
                                       +-------+-------+
                                               |
                                          +----v----+               +--------+
                                          | Windows |               |Time Out+----------------------------------+
                                          +----+----+               +----+---+                                  |
                                               |                         ^                                      |
      Event                                    |                         |                                      |
        +                                      |                         |                                      |
        |                              +-------v-------+                 |                                      |
        |                       +------+Selectable Sel.+-----+-----------------+-----------+                    |
        |                       |      +-------+-------+     |           |     |           v              +-----v-----+
+-------v----------+            |              |             |           |     |        Passive lock<-----+release_all<------+
|Data added to list|       +----v-----+  +-----v-----+  +----v-----+     v     v            +             +-----------+      |
+--------+---------+       |Selectable|  |Selectable |  |Selectable|   ............         |                                |
         |                 +----+-----+  +-----------+  +----------+                        |                                |
         |                      v                                                           |                                |
         v                 +----+------+   +------------------+               +-------------v-------------------+            |
   +-----+------+          |wait_return+-->+  check_recv:     |               |                                 |            |
   |call_release|          +----+------+   |If data is in list|               |  END state: selectable returned |        +---+--------+
   +-----+--------              v          +-------+----------+               |                                 |        | exit door  |
         |                    else                 |                          +---------------------------------+        +---+--------+
         |                      +                  |                                                                         |
         |                 +----v-------+          |                                                                         |
         +--------->free -->Passive lock|          |                                                                         |
                           +----+-------+          |                                                                         |
                                |                  |                                                                         |
                                |                  v                                                                         |
                                +------------------Selectable-Selector-is-advertised-that-the-selectable-is-readable---------+
"""

class SelectableObject:
    """DEV: to implement one of those, you need to add 2 things to your object:
    - add "check_recv" function
    - call "self.call_release" once you are ready to be read

    You can set the __selectable_force_select__ to True in the class, if you want to
    force the handler to use fileno(). This may only be useable on sockets created using
    the builtin socket API."""
    __selectable_force_select__ = False
    def check_recv(self):
        """DEV: will be called only once (at beginning) to check if the object is ready."""
        raise OSError("This method must be overwriten.")

    def _wait_non_ressources(self, callback):
        """This get started as a thread, and waits for the data lock to be freed then advertise itself to the SelectableSelector using the callback"""
        self.trigger = threading.Lock()
        self.was_ended = False
        self.trigger.acquire()
        self.trigger.acquire()
        if not self.was_ended:
            callback(self)

    def wait_return(self, callback):
        """Entry point of SelectableObject: register the callback"""
        if self.check_recv():
            return callback(self)
        _t = threading.Thread(target=self._wait_non_ressources, args=(callback,))
        _t.setDaemon(True)
        _t.start()
        
    def call_release(self, arborted=False):
        """DEV: Must be call when the object becomes ready to read.
           Relesases the lock of _wait_non_ressources"""
        self.was_ended = arborted
        try:
            self.trigger.release()
        except (threading.ThreadError, AttributeError):
            pass

class SelectableSelector(object):
    """
    Select SelectableObject objects.
    
    inputs: objects to process
    remain: timeout. If 0, return [].
    customTypes: types of the objects that have the check_recv function.
    """
    def _release_all(self):
        """Releases all locks to kill all threads"""
        for i in self.inputs:
            i.call_release(True)
        self.available_lock.release()

    def _timeout_thread(self, remain):
        """Timeout before releasing every thing, if nothing was returned"""
        time.sleep(remain)
        if not self._ended:
            self._ended = True
            self._release_all()

    def _exit_door(self, _input):
        """This function is passed to each SelectableObject as a callback
        The SelectableObjects have to call it once there are ready"""
        self.results.append(_input)
        if self._ended:
            return
        self._ended = True
        self._release_all()
    
    def __init__(self, inputs, remain):
        self.results = []
        self.inputs = list(inputs)
        self.remain = remain
        self.available_lock = threading.Lock()
        self.available_lock.acquire()
        self._ended = False

    def process(self):
        """Entry point of SelectableSelector"""
        if WINDOWS:
            select_inputs = []
            for i in self.inputs:
                if not isinstance(i, SelectableObject):
                    warning("Unknown ignored object type: %s", type(i))
                elif i.__selectable_force_select__:
                    # Then use select.select
                    select_inputs.append(i)
                elif not self.remain and i.check_recv():
                    self.results.append(i)
                else:
                    i.wait_return(self._exit_door)
            if select_inputs:
                # Use default select function
                self.results.extend(select(select_inputs, [], [], self.remain)[0])
            if not self.remain:
                return self.results

            threading.Thread(target=self._timeout_thread, args=(self.remain,)).start()
            if not self._ended:
                self.available_lock.acquire()
            return self.results
        else:
            r,_,_ = select(self.inputs,[],[],self.remain)
            return r

def select_objects(inputs, remain):
    """
    Select SelectableObject objects. Same than:
        select.select([inputs], [], [], remain)
    But also works on Windows, only on SelectableObject.
    
    inputs: objects to process
    remain: timeout. If 0, return [].
    """
    handler = SelectableSelector(inputs, remain)
    return handler.process()

class ObjectPipe(SelectableObject):
    def __init__(self):
        self.rd,self.wr = os.pipe()
        self.queue = deque()
    def fileno(self):
        return self.rd
    def check_recv(self):
        return len(self.queue) > 0
    def send(self, obj):
        self.queue.append(obj)
        os.write(self.wr,b"X")
        self.call_release()
    def write(self, obj):
        self.send(obj)
    def recv(self, n=0):
        os.read(self.rd, 1)
        return self.queue.popleft()
    def read(self, n=0):
        return self.recv(n)

class Message:
    def __init__(self, **args):
        self.__dict__.update(args)
    def __repr__(self):
        return "<Message %s>" % " ".join("%s=%r"%(k,v)
                                         for (k,v) in six.iteritems(self.__dict__)
                                         if not k.startswith("_"))

class _instance_state:
    def __init__(self, instance):
        self.__self__ = instance.__self__
        self.__func__ = instance.__func__
        self.__self__.__class__ = instance.__self__.__class__
    def __getattr__(self, attr):
        return getattr(self.__func__, attr)
    def __call__(self, *args, **kargs):
        return self.__func__(self.__self__, *args, **kargs)
    def breaks(self):
        return self.__self__.add_breakpoints(self.__func__)
    def intercepts(self):
        return self.__self__.add_interception_points(self.__func__)
    def unbreaks(self):
        return self.__self__.remove_breakpoints(self.__func__)
    def unintercepts(self):
        return self.__self__.remove_interception_points(self.__func__)
        

##############
## Automata ##
##############

class ATMT:
    STATE = "State"
    ACTION = "Action"
    CONDITION = "Condition"
    RECV = "Receive condition"
    TIMEOUT = "Timeout condition"
    IOEVENT = "I/O event"

    class NewStateRequested(Exception):
        def __init__(self, state_func, automaton, *args, **kargs):
            self.func = state_func
            self.state = state_func.atmt_state
            self.initial = state_func.atmt_initial
            self.error = state_func.atmt_error
            self.final = state_func.atmt_final
            Exception.__init__(self, "Request state [%s]" % self.state)
            self.automaton = automaton
            self.args = args
            self.kargs = kargs
            self.action_parameters() # init action parameters
        def action_parameters(self, *args, **kargs):
            self.action_args = args
            self.action_kargs = kargs
            return self
        def run(self):
            return self.func(self.automaton, *self.args, **self.kargs)
        def __repr__(self):
            return "NewStateRequested(%s)" % self.state

    @staticmethod
    def state(initial=0,final=0,error=0):
        def deco(f,initial=initial, final=final):
            f.atmt_type = ATMT.STATE
            f.atmt_state = f.__name__
            f.atmt_initial = initial
            f.atmt_final = final
            f.atmt_error = error
            def state_wrapper(self, *args, **kargs):
                return ATMT.NewStateRequested(f, self, *args, **kargs)

            state_wrapper.__name__ = "%s_wrapper" % f.__name__
            state_wrapper.atmt_type = ATMT.STATE
            state_wrapper.atmt_state = f.__name__
            state_wrapper.atmt_initial = initial
            state_wrapper.atmt_final = final
            state_wrapper.atmt_error = error
            state_wrapper.atmt_origfunc = f
            return state_wrapper
        return deco
    @staticmethod
    def action(cond, prio=0):
        def deco(f,cond=cond):
            if not hasattr(f,"atmt_type"):
                f.atmt_cond = {}
            f.atmt_type = ATMT.ACTION
            f.atmt_cond[cond.atmt_condname] = prio
            return f
        return deco
    @staticmethod
    def condition(state, prio=0):
        def deco(f, state=state):
            f.atmt_type = ATMT.CONDITION
            f.atmt_state = state.atmt_state
            f.atmt_condname = f.__name__
            f.atmt_prio = prio
            return f
        return deco
    @staticmethod
    def receive_condition(state, prio=0):
        def deco(f, state=state):
            f.atmt_type = ATMT.RECV
            f.atmt_state = state.atmt_state
            f.atmt_condname = f.__name__
            f.atmt_prio = prio
            return f
        return deco
    @staticmethod
    def ioevent(state, name, prio=0, as_supersocket=None):
        def deco(f, state=state):
            f.atmt_type = ATMT.IOEVENT
            f.atmt_state = state.atmt_state
            f.atmt_condname = f.__name__
            f.atmt_ioname = name
            f.atmt_prio = prio
            f.atmt_as_supersocket = as_supersocket
            return f
        return deco
    @staticmethod
    def timeout(state, timeout):
        def deco(f, state=state, timeout=timeout):
            f.atmt_type = ATMT.TIMEOUT
            f.atmt_state = state.atmt_state
            f.atmt_timeout = timeout
            f.atmt_condname = f.__name__
            return f
        return deco

class _ATMT_Command:
    RUN = "RUN"
    NEXT = "NEXT"
    FREEZE = "FREEZE"
    STOP = "STOP"
    END = "END"
    EXCEPTION = "EXCEPTION"
    SINGLESTEP = "SINGLESTEP"
    BREAKPOINT = "BREAKPOINT"
    INTERCEPT = "INTERCEPT"
    ACCEPT = "ACCEPT"
    REPLACE = "REPLACE"
    REJECT = "REJECT"

class _ATMT_supersocket(SuperSocket):
    def __init__(self, name, ioevent, automaton, proto, args, kargs):
        self.name = name
        self.ioevent = ioevent
        self.proto = proto
        self.spa,self.spb = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        kargs["external_fd"] = {ioevent:self.spb}
        self.atmt = automaton(*args, **kargs)
        self.atmt.runbg()
    def fileno(self):
        return self.spa.fileno()
    def send(self, s):
        if not isinstance(s, bytes):
            s = bytes(s)
        return self.spa.send(s)
    def recv(self, n=MTU):
        try:
            r = self.spa.recv(n)
        except recv_error:
            if not WINDOWS:
                raise
            return None
        if self.proto is not None:
            r = self.proto(r)
        return r
    def close(self):
        pass

class _ATMT_to_supersocket:
    def __init__(self, name, ioevent, automaton):
        self.name = name
        self.ioevent = ioevent
        self.automaton = automaton
    def __call__(self, proto, *args, **kargs):
        return _ATMT_supersocket(self.name, self.ioevent, self.automaton, proto, args, kargs)

class Automaton_metaclass(type):
    def __new__(cls, name, bases, dct):
        cls = super(Automaton_metaclass, cls).__new__(cls, name, bases, dct)
        cls.states={}
        cls.state = None
        cls.recv_conditions={}
        cls.conditions={}
        cls.ioevents={}
        cls.timeout={}
        cls.actions={}
        cls.initial_states=[]
        cls.ionames = []
        cls.iosupersockets = []

        members = {}
        classes = [cls]
        while classes:
            c = classes.pop(0) # order is important to avoid breaking method overloading
            classes += list(c.__bases__)
            for k,v in six.iteritems(c.__dict__):
                if k not in members:
                    members[k] = v

        decorated = [v for v in six.itervalues(members)
                     if isinstance(v, types.FunctionType) and hasattr(v, "atmt_type")]
        
        for m in decorated:
            if m.atmt_type == ATMT.STATE:
                s = m.atmt_state
                cls.states[s] = m
                cls.recv_conditions[s]=[]
                cls.ioevents[s]=[]
                cls.conditions[s]=[]
                cls.timeout[s]=[]
                if m.atmt_initial:
                    cls.initial_states.append(m)
            elif m.atmt_type in [ATMT.CONDITION, ATMT.RECV, ATMT.TIMEOUT, ATMT.IOEVENT]:
                cls.actions[m.atmt_condname] = []
    
        for m in decorated:
            if m.atmt_type == ATMT.CONDITION:
                cls.conditions[m.atmt_state].append(m)
            elif m.atmt_type == ATMT.RECV:
                cls.recv_conditions[m.atmt_state].append(m)
            elif m.atmt_type == ATMT.IOEVENT:
                cls.ioevents[m.atmt_state].append(m)
                cls.ionames.append(m.atmt_ioname)
                if m.atmt_as_supersocket is not None:
                    cls.iosupersockets.append(m)
            elif m.atmt_type == ATMT.TIMEOUT:
                cls.timeout[m.atmt_state].append((m.atmt_timeout, m))
            elif m.atmt_type == ATMT.ACTION:
                for c in m.atmt_cond:
                    cls.actions[c].append(m)
            

        for v in six.itervalues(cls.timeout):
            v.sort(key=cmp_to_key(lambda t1_f1,t2_f2: cmp(t1_f1[0],t2_f2[0])))
            v.append((None, None))
        for v in itertools.chain(six.itervalues(cls.conditions),
                                 six.itervalues(cls.recv_conditions),
                                 six.itervalues(cls.ioevents)):
            v.sort(key=cmp_to_key(lambda c1,c2: cmp(c1.atmt_prio,c2.atmt_prio)))
        for condname,actlst in six.iteritems(cls.actions):
            actlst.sort(key=cmp_to_key(lambda c1,c2: cmp(c1.atmt_cond[condname], c2.atmt_cond[condname])))

        for ioev in cls.iosupersockets:
            setattr(cls, ioev.atmt_as_supersocket, _ATMT_to_supersocket(ioev.atmt_as_supersocket, ioev.atmt_ioname, cls))

        return cls

    def graph(self, **kargs):
        s = 'digraph "%s" {\n'  % self.__class__.__name__
        
        se = "" # Keep initial nodes at the begining for better rendering
        for st in six.itervalues(self.states):
            if st.atmt_initial:
                se = ('\t"%s" [ style=filled, fillcolor=blue, shape=box, root=true];\n' % st.atmt_state)+se
            elif st.atmt_final:
                se += '\t"%s" [ style=filled, fillcolor=green, shape=octagon ];\n' % st.atmt_state
            elif st.atmt_error:
                se += '\t"%s" [ style=filled, fillcolor=red, shape=octagon ];\n' % st.atmt_state
        s += se

        for st in six.itervalues(self.states):
            for n in st.atmt_origfunc.__code__.co_names+st.atmt_origfunc.__code__.co_consts:
                if n in self.states:
                    s += '\t"%s" -> "%s" [ color=green ];\n' % (st.atmt_state,n)
            

        for c,k,v in ([("purple",k,v) for k,v in self.conditions.items()]+
                      [("red",k,v) for k,v in self.recv_conditions.items()]+
                      [("orange",k,v) for k,v in self.ioevents.items()]):
            for f in v:
                for n in f.__code__.co_names+f.__code__.co_consts:
                    if n in self.states:
                        l = f.atmt_condname
                        for x in self.actions[f.atmt_condname]:
                            l += "\\l>[%s]" % x.__name__
                        s += '\t"%s" -> "%s" [label="%s", color=%s];\n' % (k,n,l,c)
        for k,v in six.iteritems(self.timeout):
            for t,f in v:
                if f is None:
                    continue
                for n in f.__code__.co_names+f.__code__.co_consts:
                    if n in self.states:
                        l = "%s/%.1fs" % (f.atmt_condname,t)                        
                        for x in self.actions[f.atmt_condname]:
                            l += "\\l>[%s]" % x.__name__
                        s += '\t"%s" -> "%s" [label="%s",color=blue];\n' % (k,n,l)
        s += "}\n"
        return do_graph(s, **kargs)

class Automaton(six.with_metaclass(Automaton_metaclass)):
    def parse_args(self, debug=0, store=1, **kargs):
        self.debug_level=debug
        self.socket_kargs = kargs
        self.store_packets = store        

    def master_filter(self, pkt):
        return True

    def my_send(self, pkt):
        self.send_sock.send(pkt)


    ## Utility classes and exceptions
    class _IO_fdwrapper(SelectableObject):
        def __init__(self,rd,wr):
            if WINDOWS:
                # rd will be used for reading and sending
                if isinstance(rd, ObjectPipe):
                    self.rd = rd
                else:
                    raise OSError("On windows, only instances of ObjectPipe are externally available")
            else:
                if rd is not None and not isinstance(rd, int):
                    rd = rd.fileno()
                if wr is not None and not isinstance(wr, int):
                    wr = wr.fileno()
                self.rd = rd
                self.wr = wr
        def fileno(self):
            return self.rd
        def check_recv(self):
            return self.rd.check_recv()
        def read(self, n=65535):
            if WINDOWS:
                return self.rd.recv(n)
            return os.read(self.rd, n)
        def write(self, msg):
            if WINDOWS:
                self.rd.send(msg)
                return self.call_release()
            return os.write(self.wr,msg)
        def recv(self, n=65535):
            return self.read(n)        
        def send(self, msg):
            return self.write(msg)

    class _IO_mixer(SelectableObject):
        def __init__(self,rd,wr):
            self.rd = rd
            self.wr = wr
        def fileno(self):
            if isinstance(self.rd, int):
                return self.rd
            return self.rd.fileno()
        def check_recv(self):
            return self.rd.check_recv()
        def recv(self, n=None):
            return self.rd.recv(n)
        def read(self, n=None):
            return self.recv(n)
        def send(self, msg):
            self.wr.send(msg)
            return self.call_release()
        def write(self, msg):
            return self.send(msg)


    class AutomatonException(Exception):
        def __init__(self, msg, state=None, result=None):
            Exception.__init__(self, msg)
            self.state = state
            self.result = result

    class AutomatonError(AutomatonException):
        pass
    class ErrorState(AutomatonException):
        pass
    class Stuck(AutomatonException):
        pass
    class AutomatonStopped(AutomatonException):
        pass
    
    class Breakpoint(AutomatonStopped):
        pass
    class Singlestep(AutomatonStopped):
        pass
    class InterceptionPoint(AutomatonStopped):
        def __init__(self, msg, state=None, result=None, packet=None):
            Automaton.AutomatonStopped.__init__(self, msg, state=state, result=result)
            self.packet = packet

    class CommandMessage(AutomatonException):
        pass


    ## Services
    def debug(self, lvl, msg):
        if self.debug_level >= lvl:
            log_interactive.debug(msg)            

    def send(self, pkt):
        if self.state.state in self.interception_points:
            self.debug(3,"INTERCEPT: packet intercepted: %s" % pkt.summary())
            self.intercepted_packet = pkt
            cmd = Message(type = _ATMT_Command.INTERCEPT, state=self.state, pkt=pkt)
            self.cmdout.send(cmd)
            cmd = self.cmdin.recv()
            self.intercepted_packet = None
            if cmd.type == _ATMT_Command.REJECT:
                self.debug(3,"INTERCEPT: packet rejected")
                return
            elif cmd.type == _ATMT_Command.REPLACE:
                pkt = cmd.pkt
                self.debug(3,"INTERCEPT: packet replaced by: %s" % pkt.summary())
            elif cmd.type == _ATMT_Command.ACCEPT:
                self.debug(3,"INTERCEPT: packet accepted")
            else:
                raise self.AutomatonError("INTERCEPT: unkown verdict: %r" % cmd.type)
        self.my_send(pkt)
        self.debug(3,"SENT : %s" % pkt.summary())
        
        if self.store_packets:
            self.packets.append(pkt.copy())


    ## Internals
    def __init__(self, *args, **kargs):
        external_fd = kargs.pop("external_fd",{})
        self.send_sock_class = kargs.pop("ll", conf.L3socket)
        self.recv_sock_class = kargs.pop("recvsock", conf.L2listen)
        self.started = threading.Lock()
        self.threadid = None
        self.breakpointed = None
        self.breakpoints = set()
        self.interception_points = set()
        self.intercepted_packet = None
        self.debug_level=0
        self.init_args=args
        self.init_kargs=kargs
        self.io = type.__new__(type, "IOnamespace",(),{})
        self.oi = type.__new__(type, "IOnamespace",(),{})
        self.cmdin = ObjectPipe()
        self.cmdout = ObjectPipe()
        self.ioin = {}
        self.ioout = {}
        for n in self.ionames:
            extfd = external_fd.get(n)
            if not isinstance(extfd, tuple):
                extfd = (extfd,extfd)
            elif WINDOWS:
                raise OSError("Tuples are not allowed as external_fd on windows")
            ioin,ioout = extfd                
            if ioin is None:
                ioin = ObjectPipe()
            elif not isinstance(ioin, SelectableObject):
                ioin = self._IO_fdwrapper(ioin,None)
            if ioout is None:
                ioout = ioin if WINDOWS else ObjectPipe()
            elif not isinstance(ioout, SelectableObject):
                ioout = self._IO_fdwrapper(None,ioout)

            self.ioin[n] = ioin
            self.ioout[n] = ioout 
            ioin.ioname = n
            ioout.ioname = n
            setattr(self.io, n, self._IO_mixer(ioout,ioin))
            setattr(self.oi, n, self._IO_mixer(ioin,ioout))

        for stname in self.states:
            setattr(self, stname, 
                    _instance_state(getattr(self, stname)))

        self.start()

    def __iter__(self):
        return self        

    def __del__(self):
        self.stop()

    def _run_condition(self, cond, *args, **kargs):
        try:
            self.debug(5, "Trying %s [%s]" % (cond.atmt_type, cond.atmt_condname))
            cond(self,*args, **kargs)
        except ATMT.NewStateRequested as state_req:
            self.debug(2, "%s [%s] taken to state [%s]" % (cond.atmt_type, cond.atmt_condname, state_req.state))
            if cond.atmt_type == ATMT.RECV:
                if self.store_packets:
                    self.packets.append(args[0])
            for action in self.actions[cond.atmt_condname]:
                self.debug(2, "   + Running action [%s]" % action.__name__)
                action(self, *state_req.action_args, **state_req.action_kargs)
            raise
        except Exception as e:
            self.debug(2, "%s [%s] raised exception [%s]" % (cond.atmt_type, cond.atmt_condname, e))
            raise
        else:
            self.debug(2, "%s [%s] not taken" % (cond.atmt_type, cond.atmt_condname))

    def _do_start(self, *args, **kargs):
        ready = threading.Event()
        _t = threading.Thread(target=self._do_control, args=(ready,) + (args), kwargs=kargs)
        _t.setDaemon(True)
        _t.start()
        ready.wait()

    def _do_control(self, ready, *args, **kargs):
        with self.started:
            self.threadid = threading.currentThread().ident

            # Update default parameters
            a = args+self.init_args[len(args):]
            k = self.init_kargs.copy()
            k.update(kargs)
            self.parse_args(*a,**k)
    
            # Start the automaton
            self.state=self.initial_states[0](self)
            self.send_sock = self.send_sock_class(**self.socket_kargs)
            self.listen_sock = self.recv_sock_class(**self.socket_kargs)
            self.packets = PacketList(name="session[%s]"%self.__class__.__name__)

            singlestep = True
            iterator = self._do_iter()
            self.debug(3, "Starting control thread [tid=%i]" % self.threadid)
            # Sync threads
            ready.set()
            try:
                while True:
                    c = self.cmdin.recv()
                    self.debug(5, "Received command %s" % c.type)
                    if c.type == _ATMT_Command.RUN:
                        singlestep = False
                    elif c.type == _ATMT_Command.NEXT:
                        singlestep = True
                    elif c.type == _ATMT_Command.FREEZE:
                        continue
                    elif c.type == _ATMT_Command.STOP:
                        break
                    while True:
                        state = next(iterator)
                        if isinstance(state, self.CommandMessage):
                            break
                        elif isinstance(state, self.Breakpoint):
                            c = Message(type=_ATMT_Command.BREAKPOINT,state=state)
                            self.cmdout.send(c)
                            break
                        if singlestep:
                            c = Message(type=_ATMT_Command.SINGLESTEP,state=state)
                            self.cmdout.send(c)
                            break
            except StopIteration as e:
                c = Message(type=_ATMT_Command.END, result=e.args[0])
                self.cmdout.send(c)
            except Exception as e:
                exc_info = sys.exc_info()
                self.debug(3, "Transfering exception from tid=%i:\n%s"% (self.threadid, traceback.format_exception(*exc_info)))
                m = Message(type=_ATMT_Command.EXCEPTION, exception=e, exc_info=exc_info)
                self.cmdout.send(m)        
            self.debug(3, "Stopping control thread (tid=%i)"%self.threadid)
            self.threadid = None
    
    def _do_iter(self):
        while True:
            try:
                self.debug(1, "## state=[%s]" % self.state.state)
    
                # Entering a new state. First, call new state function
                if self.state.state in self.breakpoints and self.state.state != self.breakpointed: 
                    self.breakpointed = self.state.state
                    yield self.Breakpoint("breakpoint triggered on state %s" % self.state.state,
                                          state = self.state.state)
                self.breakpointed = None
                state_output = self.state.run()
                if self.state.error:
                    raise self.ErrorState("Reached %s: [%r]" % (self.state.state, state_output), 
                                          result=state_output, state=self.state.state)
                if self.state.final:
                    raise StopIteration(state_output)
    
                if state_output is None:
                    state_output = ()
                elif not isinstance(state_output, list):
                    state_output = state_output,
                
                # Then check immediate conditions
                for cond in self.conditions[self.state.state]:
                    self._run_condition(cond, *state_output)
    
                # If still there and no conditions left, we are stuck!
                if ( len(self.recv_conditions[self.state.state]) == 0 and
                     len(self.ioevents[self.state.state]) == 0 and
                     len(self.timeout[self.state.state]) == 1 ):
                    raise self.Stuck("stuck in [%s]" % self.state.state,
                                     state=self.state.state, result=state_output)
    
                # Finally listen and pay attention to timeouts
                expirations = iter(self.timeout[self.state.state])
                next_timeout,timeout_func = next(expirations)
                t0 = time.time()
                
                fds = [self.cmdin]
                if len(self.recv_conditions[self.state.state]) > 0:
                    fds.append(self.listen_sock)
                for ioev in self.ioevents[self.state.state]:
                    fds.append(self.ioin[ioev.atmt_ioname])
                while True:
                    t = time.time()-t0
                    if next_timeout is not None:
                        if next_timeout <= t:
                            self._run_condition(timeout_func, *state_output)
                            next_timeout,timeout_func = next(expirations)
                    if next_timeout is None:
                        remain = None
                    else:
                        remain = next_timeout-t
    
                    self.debug(5, "Select on %r" % fds)
                    r = select_objects(fds, remain)
                    self.debug(5, "Selected %r" % r)
                    for fd in r:
                        self.debug(5, "Looking at %r" % fd)
                        if fd == self.cmdin:
                            yield self.CommandMessage("Received command message")
                        elif fd == self.listen_sock:
                            try:
                                pkt = self.listen_sock.recv(MTU)
                            except recv_error:
                                pass
                            else:
                                if pkt is not None:
                                    if self.master_filter(pkt):
                                        self.debug(3, "RECVD: %s" % pkt.summary())
                                        for rcvcond in self.recv_conditions[self.state.state]:
                                            self._run_condition(rcvcond, pkt, *state_output)
                                    else:
                                        self.debug(4, "FILTR: %s" % pkt.summary())
                        else:
                            self.debug(3, "IOEVENT on %s" % fd.ioname)
                            for ioevt in self.ioevents[self.state.state]:
                                if ioevt.atmt_ioname == fd.ioname:
                                    self._run_condition(ioevt, fd, *state_output)
    
            except ATMT.NewStateRequested as state_req:
                self.debug(2, "switching from [%s] to [%s]" % (self.state.state,state_req.state))
                self.state = state_req
                yield state_req

    ## Public API
    def add_interception_points(self, *ipts):
        for ipt in ipts:
            if hasattr(ipt,"atmt_state"):
                ipt = ipt.atmt_state
            self.interception_points.add(ipt)
        
    def remove_interception_points(self, *ipts):
        for ipt in ipts:
            if hasattr(ipt,"atmt_state"):
                ipt = ipt.atmt_state
            self.interception_points.discard(ipt)

    def add_breakpoints(self, *bps):
        for bp in bps:
            if hasattr(bp,"atmt_state"):
                bp = bp.atmt_state
            self.breakpoints.add(bp)

    def remove_breakpoints(self, *bps):
        for bp in bps:
            if hasattr(bp,"atmt_state"):
                bp = bp.atmt_state
            self.breakpoints.discard(bp)

    def start(self, *args, **kargs):
        if not self.started.locked():
            self._do_start(*args, **kargs)
        
    def run(self, resume=None, wait=True):
        if resume is None:
            resume = Message(type = _ATMT_Command.RUN)
        self.cmdin.send(resume)
        if wait:
            try:
                c = self.cmdout.recv()
            except KeyboardInterrupt:
                self.cmdin.send(Message(type = _ATMT_Command.FREEZE))
                return
            if c.type == _ATMT_Command.END:
                return c.result
            elif c.type == _ATMT_Command.INTERCEPT:
                raise self.InterceptionPoint("packet intercepted", state=c.state.state, packet=c.pkt)
            elif c.type == _ATMT_Command.SINGLESTEP:
                raise self.Singlestep("singlestep state=[%s]"%c.state.state, state=c.state.state)
            elif c.type == _ATMT_Command.BREAKPOINT:
                raise self.Breakpoint("breakpoint triggered on state [%s]"%c.state.state, state=c.state.state)
            elif c.type == _ATMT_Command.EXCEPTION:
                six.reraise(c.exc_info[0], c.exc_info[1], c.exc_info[2])

    def runbg(self, resume=None, wait=False):
        self.run(resume, wait)

    def next(self):
        return self.run(resume = Message(type=_ATMT_Command.NEXT))
    __next__ = next

    def stop(self):
        self.cmdin.send(Message(type=_ATMT_Command.STOP))
        with self.started:
            # Flush command pipes
            while True:
                r = select_objects([self.cmdin, self.cmdout], 0)
                if not r:
                    break
                for fd in r:
                    fd.recv()
                
    def restart(self, *args, **kargs):
        self.stop()
        self.start(*args, **kargs)

    def accept_packet(self, pkt=None, wait=False):
        rsm = Message()
        if pkt is None:
            rsm.type = _ATMT_Command.ACCEPT
        else:
            rsm.type = _ATMT_Command.REPLACE
            rsm.pkt = pkt
        return self.run(resume=rsm, wait=wait)

    def reject_packet(self, wait=False):
        rsm = Message(type = _ATMT_Command.REJECT)
        return self.run(resume=rsm, wait=wait)

    

