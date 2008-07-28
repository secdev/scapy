## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

import types,itertools,time
from select import select
from config import conf
from utils import do_graph
from error import log_interactive
from plist import PacketList
from data import MTU

##############
## Automata ##
##############

class ATMT:
    STATE = "State"
    ACTION = "Action"
    CONDITION = "Condition"
    RECV = "Receive condition"
    TIMEOUT = "Timeout condition"

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
    def timeout(state, timeout):
        def deco(f, state=state, timeout=timeout):
            f.atmt_type = ATMT.TIMEOUT
            f.atmt_state = state.atmt_state
            f.atmt_timeout = timeout
            f.atmt_condname = f.func_name
            return f
        return deco


class Automaton_metaclass(type):
    def __new__(cls, name, bases, dct):
        cls = super(Automaton_metaclass, cls).__new__(cls, name, bases, dct)
        cls.states={}
        cls.state = None
        cls.recv_conditions={}
        cls.conditions={}
        cls.timeout={}
        cls.actions={}
        cls.initial_states=[]

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
                cls.conditions[s]=[]
                cls.timeout[s]=[]
                if m.atmt_initial:
                    cls.initial_states.append(m)
            elif m.atmt_type in [ATMT.CONDITION, ATMT.RECV, ATMT.TIMEOUT]:
                cls.actions[m.atmt_condname] = []
    
        for m in decorated:
            if m.atmt_type == ATMT.CONDITION:
                cls.conditions[m.atmt_state].append(m)
            elif m.atmt_type == ATMT.RECV:
                cls.recv_conditions[m.atmt_state].append(m)
            elif m.atmt_type == ATMT.TIMEOUT:
                cls.timeout[m.atmt_state].append((m.atmt_timeout, m))
            elif m.atmt_type == ATMT.ACTION:
                for c in m.atmt_cond:
                    cls.actions[c].append(m)
            

        for v in cls.timeout.itervalues():
            v.sort(lambda (t1,f1),(t2,f2): cmp(t1,t2))
            v.append((None, None))
        for v in itertools.chain(cls.conditions.itervalues(),
                                 cls.recv_conditions.itervalues()):
            v.sort(lambda c1,c2: cmp(c1.atmt_prio,c2.atmt_prio))
        for condname,actlst in cls.actions.iteritems():
            actlst.sort(lambda c1,c2: cmp(c1.atmt_cond[condname], c2.atmt_cond[condname]))

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
            

        for c,k,v in [("purple",k,v) for k,v in self.conditions.items()]+[("red",k,v) for k,v in self.recv_conditions.items()]:
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

    def __init__(self, *args, **kargs):
        self.debug_level=0
        self.init_args=args
        self.init_kargs=kargs
        self.parse_args(*args, **kargs)

    def debug(self, lvl, msg):
        if self.debug_level >= lvl:
            log_interactive.debug(msg)
            



    class ErrorState(Exception):
        def __init__(self, msg, result=None):
            Exception.__init__(self, msg)
            self.result = result
    class Stuck(ErrorState):
        pass

    def parse_args(self, debug=0, store=1, **kargs):
        self.debug_level=debug
        self.socket_kargs = kargs
        self.store_packets = store
        

    def master_filter(self, pkt):
        return True

    def run_condition(self, cond, *args, **kargs):
        try:
            cond(self,*args, **kargs)
        except ATMT.NewStateRequested, state_req:
            self.debug(2, "%s [%s] taken to state [%s]" % (cond.atmt_type, cond.atmt_condname, state_req.state))
            if cond.atmt_type == ATMT.RECV:
                self.packets.append(args[0])
            for action in self.actions[cond.atmt_condname]:
                self.debug(2, "   + Running action [%s]" % action.func_name)
                action(self, *state_req.action_args, **state_req.action_kargs)
            raise
        else:
            self.debug(2, "%s [%s] not taken" % (cond.atmt_type, cond.atmt_condname))
            

    def run(self, *args, **kargs):
        # Update default parameters
        a = args+self.init_args[len(args):]
        k = self.init_kargs
        k.update(kargs)
        self.parse_args(*a,**k)

        # Start the automaton
        self.state=self.initial_states[0](self)
        self.send_sock = conf.L3socket()
        l = conf.L2listen(**self.socket_kargs)
        self.packets = PacketList(name="session[%s]"%self.__class__.__name__)
        while 1:
            try:
                self.debug(1, "## state=[%s]" % self.state.state)

                # Entering a new state. First, call new state function
                state_output = self.state.run()
                if self.state.error:
                    raise self.ErrorState("Reached %s: [%r]" % (self.state.state, state_output), result=state_output)
                if self.state.final:
                    return state_output

                if state_output is None:
                    state_output = ()
                elif type(state_output) is not list:
                    state_output = state_output,
                
                # Then check immediate conditions
                for cond in self.conditions[self.state.state]:
                    self.run_condition(cond, *state_output)

                # If still there and no conditions left, we are stuck!
                if ( len(self.recv_conditions[self.state.state]) == 0
                     and len(self.timeout[self.state.state]) == 1 ):
                    raise self.Stuck("stuck in [%s]" % self.state.state,result=state_output)

                # Finally listen and pay attention to timeouts
                expirations = iter(self.timeout[self.state.state])
                next_timeout,timeout_func = expirations.next()
                t0 = time.time()
                
                while 1:
                    t = time.time()-t0
                    if next_timeout is not None:
                        if next_timeout <= t:
                            self.run_condition(timeout_func, *state_output)
                            next_timeout,timeout_func = expirations.next()
                    if next_timeout is None:
                        remain = None
                    else:
                        remain = next_timeout-t
    
                    r,_,_ = select([l],[],[],remain)
                    if l in r:
                        pkt = l.recv(MTU)
                        if pkt is not None:
                            if self.master_filter(pkt):
                                self.debug(3, "RECVD: %s" % pkt.summary())
                                for rcvcond in self.recv_conditions[self.state.state]:
                                    self.run_condition(rcvcond, pkt, *state_output)
                            else:
                                self.debug(4, "FILTR: %s" % pkt.summary())

            except ATMT.NewStateRequested,state_req:
                self.debug(2, "switching from [%s] to [%s]" % (self.state.state,state_req.state))
                self.state = state_req
            except KeyboardInterrupt:
                self.debug(1,"Interrupted by user")
                break

    def my_send(self, pkt):
        self.send_sock.send(pkt)

    def send(self, pkt):
        self.my_send(pkt)
        self.debug(3,"SENT : %s" % pkt.summary())
        self.packets.append(pkt.copy())


        
