## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Automata with states, transitions and actions.
"""

from __future__ import with_statement
import types,itertools,time,os,sys,socket
from select import select
from collections import deque
import thread
from config import conf
from utils import do_graph
from error import log_interactive
from plist import PacketList
from data import MTU
from supersocket import SuperSocket

class ObjectPipe:
    def __init__(self):
        self.rd,self.wr = os.pipe()
        self.queue = deque()
    def fileno(self):
        return self.rd
    def send(self, obj):
        self.queue.append(obj)
        os.write(self.wr,"X")
    def recv(self, n=0):
        os.read(self.rd,1)
        return self.queue.popleft()


class Message:
    def __init__(self, **args):
        self.__dict__.update(args)
    def __repr__(self):
        return "<Message %s>" % " ".join("%s=%r"%(k,v)
                                         for (k,v) in self.__dict__.iteritems()
                                         if not k.startswith("_"))

class _instance_state:
    def __init__(self, instance):
        self.im_self = instance.im_self
        self.im_func = instance.im_func
        self.im_class = instance.im_class
    def __getattr__(self, attr):
        return getattr(self.im_func, attr)

    def __call__(self, *args, **kargs):
        return self.im_func(self.im_self, *args, **kargs)
    def breaks(self):
        return self.im_self.add_breakpoints(self.im_func)
    def intercepts(self):
        return self.im_self.add_interception_points(self.im_func)
    def unbreaks(self):
        return self.im_self.remove_breakpoints(self.im_func)
    def unintercepts(self):
        return self.im_self.remove_interception_points(self.im_func)
        

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
            f.atmt_state = f.func_name
            f.atmt_initial = initial
            f.atmt_final = final
            f.atmt_error = error
            def state_wrapper(self, *args, **kargs):
                return ATMT.NewStateRequested(f, self, *args, **kargs)

            state_wrapper.func_name = "%s_wrapper" % f.func_name
            state_wrapper.atmt_type = ATMT.STATE
            state_wrapper.atmt_state = f.func_name
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
            f.atmt_condname = f.func_name
            f.atmt_prio = prio
            return f
        return deco
    @staticmethod
    def receive_condition(state, prio=0):
        def deco(f, state=state):
            f.atmt_type = ATMT.RECV
            f.atmt_state = state.atmt_state
            f.atmt_condname = f.func_name
            f.atmt_prio = prio
            return f
        return deco
    @staticmethod
    def ioevent(state, name, prio=0, as_supersocket=None):
        def deco(f, state=state):
            f.atmt_type = ATMT.IOEVENT
            f.atmt_state = state.atmt_state
            f.atmt_condname = f.func_name
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
            f.atmt_condname = f.func_name
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
        if type(s) is not str:
            s = str(s)
        return self.spa.send(s)
    def recv(self, n=MTU):
        r = self.spa.recv(n)
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
            for k,v in c.__dict__.iteritems():
                if k not in members:
                    members[k] = v

        decorated = [v for v in members.itervalues()
                     if type(v) is types.FunctionType and hasattr(v, "atmt_type")]
        
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
            

        for v in cls.timeout.itervalues():
            v.sort(lambda (t1,f1),(t2,f2): cmp(t1,t2))
            v.append((None, None))
        for v in itertools.chain(cls.conditions.itervalues(),
                                 cls.recv_conditions.itervalues(),
                                 cls.ioevents.itervalues()):
            v.sort(lambda c1,c2: cmp(c1.atmt_prio,c2.atmt_prio))
        for condname,actlst in cls.actions.iteritems():
            actlst.sort(lambda c1,c2: cmp(c1.atmt_cond[condname], c2.atmt_cond[condname]))

        for ioev in cls.iosupersockets:
            setattr(cls, ioev.atmt_as_supersocket, _ATMT_to_supersocket(ioev.atmt_as_supersocket, ioev.atmt_ioname, cls))

        return cls

    def graph(self, **kargs):
        s = 'digraph "%s" {\n'  % self.__class__.__name__
        
        se = "" # Keep initial nodes at the begining for better rendering
        for st in self.states.itervalues():
            if st.atmt_initial:
                se = ('\t"%s" [ style=filled, fillcolor=blue, shape=box, root=true];\n' % st.atmt_state)+se
            elif st.atmt_final:
                se += '\t"%s" [ style=filled, fillcolor=green, shape=octagon ];\n' % st.atmt_state
            elif st.atmt_error:
                se += '\t"%s" [ style=filled, fillcolor=red, shape=octagon ];\n' % st.atmt_state
        s += se

        for st in self.states.values():
            for n in st.atmt_origfunc.func_code.co_names+st.atmt_origfunc.func_code.co_consts:
                if n in self.states:
                    s += '\t"%s" -> "%s" [ color=green ];\n' % (st.atmt_state,n)
            

        for c,k,v in ([("purple",k,v) for k,v in self.conditions.items()]+
                      [("red",k,v) for k,v in self.recv_conditions.items()]+
                      [("orange",k,v) for k,v in self.ioevents.items()]):
            for f in v:
                for n in f.func_code.co_names+f.func_code.co_consts:
                    if n in self.states:
                        l = f.atmt_condname
                        for x in self.actions[f.atmt_condname]:
                            l += "\\l>[%s]" % x.func_name
                        s += '\t"%s" -> "%s" [label="%s", color=%s];\n' % (k,n,l,c)
        for k,v in self.timeout.iteritems():
            for t,f in v:
                if f is None:
                    continue
                for n in f.func_code.co_names+f.func_code.co_consts:
                    if n in self.states:
                        l = "%s/%.1fs" % (f.atmt_condname,t)                        
                        for x in self.actions[f.atmt_condname]:
                            l += "\\l>[%s]" % x.func_name
                        s += '\t"%s" -> "%s" [label="%s",color=blue];\n' % (k,n,l)
        s += "}\n"
        return do_graph(s, **kargs)
        


class Automaton:
    __metaclass__ = Automaton_metaclass

    ## Methods to overload
    def parse_args(self, debug=0, store=1, **kargs):
        self.debug_level=debug
        self.socket_kargs = kargs
        self.store_packets = store        

    def master_filter(self, pkt):
        return True

    def my_send(self, pkt):
        self.send_sock.send(pkt)


    ## Utility classes and exceptions
    class _IO_fdwrapper:
        def __init__(self,rd,wr):
            if rd is not None and type(rd) is not int:
                rd = rd.fileno()
            if wr is not None and type(wr) is not int:
                wr = wr.fileno()
            self.rd = rd
            self.wr = wr
        def fileno(self):
            return self.rd
        def read(self, n=65535):
            return os.read(self.rd, n)
        def write(self, msg):
            return os.write(self.wr,msg)
        def recv(self, n=65535):
            return self.read(n)        
        def send(self, msg):
            return self.write(msg)

    class _IO_mixer:
        def __init__(self,rd,wr):
            self.rd = rd
            self.wr = wr
        def fileno(self):
            if type(self.rd) is int:
                return self.rd
            return self.rd.fileno()
        def recv(self, n=None):
            return self.rd.recv(n)
        def read(self, n=None):
            return self.rd.recv(n)        
        def send(self, msg):
            return self.wr.send(msg)
        def write(self, msg):
            return self.wr.send(msg)


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
        self.packets.append(pkt.copy())


    ## Internals
    def __init__(self, *args, **kargs):
        external_fd = kargs.pop("external_fd",{})
        self.send_sock_class = kargs.pop("ll", conf.L3socket)
        self.started = thread.allocate_lock()
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
            if type(extfd) is not tuple:
                extfd = (extfd,extfd)
            ioin,ioout = extfd                
            if ioin is None:
                ioin = ObjectPipe()
            elif type(ioin) is not types.InstanceType:
                ioin = self._IO_fdwrapper(ioin,None)
            if ioout is None:
                ioout = ObjectPipe()
            elif type(ioout) is not types.InstanceType:
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
        
        self.parse_args(*args, **kargs)

        self.start()

    def __iter__(self):
        return self        

    def __del__(self):
        self.stop()

    def _run_condition(self, cond, *args, **kargs):
        try:
            self.debug(5, "Trying %s [%s]" % (cond.atmt_type, cond.atmt_condname))
            cond(self,*args, **kargs)
        except ATMT.NewStateRequested, state_req:
            self.debug(2, "%s [%s] taken to state [%s]" % (cond.atmt_type, cond.atmt_condname, state_req.state))
            if cond.atmt_type == ATMT.RECV:
                self.packets.append(args[0])
            for action in self.actions[cond.atmt_condname]:
                self.debug(2, "   + Running action [%s]" % action.func_name)
                action(self, *state_req.action_args, **state_req.action_kargs)
            raise
        except Exception,e:
            self.debug(2, "%s [%s] raised exception [%s]" % (cond.atmt_type, cond.atmt_condname, e))
            raise
        else:
            self.debug(2, "%s [%s] not taken" % (cond.atmt_type, cond.atmt_condname))

    def _do_start(self, *args, **kargs):
        
        thread.start_new_thread(self._do_control, args, kargs)


    def _do_control(self, *args, **kargs):
        with self.started:
            self.threadid = thread.get_ident()

            # Update default parameters
            a = args+self.init_args[len(args):]
            k = self.init_kargs.copy()
            k.update(kargs)
            self.parse_args(*a,**k)
    
            # Start the automaton
            self.state=self.initial_states[0](self)
            self.send_sock = self.send_sock_class()
            self.listen_sock = conf.L2listen(**self.socket_kargs)
            self.packets = PacketList(name="session[%s]"%self.__class__.__name__)

            singlestep = True
            iterator = self._do_iter()
            self.debug(3, "Starting control thread [tid=%i]" % self.threadid)
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
                        state = iterator.next()
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
            except StopIteration,e:
                c = Message(type=_ATMT_Command.END, result=e.args[0])
                self.cmdout.send(c)
            except Exception,e:
                self.debug(3, "Transfering exception [%s] from tid=%i"% (e,self.threadid))
                m = Message(type = _ATMT_Command.EXCEPTION, exception=e, exc_info=sys.exc_info())
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
                elif type(state_output) is not list:
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
                next_timeout,timeout_func = expirations.next()
                t0 = time.time()
                
                fds = [self.cmdin]
                if len(self.recv_conditions[self.state.state]) > 0:
                    fds.append(self.listen_sock)
                for ioev in self.ioevents[self.state.state]:
                    fds.append(self.ioin[ioev.atmt_ioname])
                while 1:
                    t = time.time()-t0
                    if next_timeout is not None:
                        if next_timeout <= t:
                            self._run_condition(timeout_func, *state_output)
                            next_timeout,timeout_func = expirations.next()
                    if next_timeout is None:
                        remain = None
                    else:
                        remain = next_timeout-t
    
                    self.debug(5, "Select on %r" % fds)
                    r,_,_ = select(fds,[],[],remain)
                    self.debug(5, "Selected %r" % r)
                    for fd in r:
                        self.debug(5, "Looking at %r" % fd)
                        if fd == self.cmdin:
                            yield self.CommandMessage("Received command message")
                        elif fd == self.listen_sock:
                            pkt = self.listen_sock.recv(MTU)
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
    
            except ATMT.NewStateRequested,state_req:
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
                raise c.exc_info[0],c.exc_info[1],c.exc_info[2]

    def runbg(self, resume=None, wait=False):
        self.run(resume, wait)

    def next(self):
        return self.run(resume = Message(type=_ATMT_Command.NEXT))

    def stop(self):
        self.cmdin.send(Message(type=_ATMT_Command.STOP))
        with self.started:
            # Flush command pipes
            while True:
                r,_,_ = select([self.cmdin, self.cmdout],[],[],0)
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

    

