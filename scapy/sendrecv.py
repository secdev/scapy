## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

import cPickle,os,sys,time,subprocess
from select import select
from data import *
import arch
from config import conf
from packet import Gen
from utils import warning,get_temp_file,PcapReader
import plist
from error import log_runtime,log_interactive
from base_classes import SetGen

#################
## Debug class ##
#################

class debug:
    recv=[]
    sent=[]
    match=[]


####################
## Send / Receive ##
####################




def sndrcv(pks, pkt, timeout = None, inter = 0, verbose=None, chainCC=0, retry=0, multi=0):
    if not isinstance(pkt, Gen):
        pkt = SetGen(pkt)
        
    if verbose is None:
        verbose = conf.verb
    debug.recv = plist.PacketList([],"Unanswered")
    debug.sent = plist.PacketList([],"Sent")
    debug.match = plist.SndRcvList([])
    nbrecv=0
    ans = []
    # do it here to fix random fields, so that parent and child have the same
    all_stimuli = tobesent = [p for p in pkt]
    notans = len(tobesent)

    hsent={}
    for i in tobesent:
        h = i.hashret()
        if h in hsent:
            hsent[h].append(i)
        else:
            hsent[h] = [i]
    if retry < 0:
        retry = -retry
        autostop=retry
    else:
        autostop=0


    while retry >= 0:
        found=0
    
        if timeout < 0:
            timeout = None
            
        rdpipe,wrpipe = os.pipe()
        rdpipe=os.fdopen(rdpipe)
        wrpipe=os.fdopen(wrpipe,"w")

        pid=1
        try:
            pid = os.fork()
            if pid == 0:
                try:
                    sys.stdin.close()
                    rdpipe.close()
                    try:
                        i = 0
                        if verbose:
                            print "Begin emission:"
                        for p in tobesent:
                            pks.send(p)
                            i += 1
                            time.sleep(inter)
                        if verbose:
                            print "Finished to send %i packets." % i
                    except SystemExit:
                        pass
                    except KeyboardInterrupt:
                        pass
                    except:
                        log_runtime.exception("--- Error in child %i" % os.getpid())
                        log_runtime.info("--- Error in child %i" % os.getpid())
                finally:
                    try:
                        os.setpgrp() # Chance process group to avoid ctrl-C
                        sent_times = [p.sent_time for p in all_stimuli if p.sent_time]
                        cPickle.dump( (conf.netcache,sent_times), wrpipe )
                        wrpipe.close()
                    except:
                        pass
            elif pid < 0:
                log_runtime.error("fork error")
            else:
                wrpipe.close()
                stoptime = 0
                remaintime = None
                inmask = [rdpipe,pks]
                try:
                    try:
                        while 1:
                            if stoptime:
                                remaintime = stoptime-time.time()
                                if remaintime <= 0:
                                    break
                            r = None
                            if arch.FREEBSD or arch.DARWIN:
                                inp, out, err = select(inmask,[],[], 0.05)
                                if len(inp) == 0 or pks in inp:
                                    r = pks.nonblock_recv()
                            else:
                                inp, out, err = select(inmask,[],[], remaintime)
                                if len(inp) == 0:
                                    break
                                if pks in inp:
                                    r = pks.recv(MTU)
                            if rdpipe in inp:
                                if timeout:
                                    stoptime = time.time()+timeout
                                del(inmask[inmask.index(rdpipe)])
                            if r is None:
                                continue
                            ok = 0
                            h = r.hashret()
                            if h in hsent:
                                hlst = hsent[h]
                                for i in range(len(hlst)):
                                    if r.answers(hlst[i]):
                                        ans.append((hlst[i],r))
                                        if verbose > 1:
                                            os.write(1, "*")
                                        ok = 1                                
                                        if not multi:
                                            del(hlst[i])
                                            notans -= 1;
                                        else:
                                            if not hasattr(hlst[i], '_answered'):
                                                notans -= 1;
                                            hlst[i]._answered = 1;
                                        break
                            if notans == 0 and not multi:
                                break
                            if not ok:
                                if verbose > 1:
                                    os.write(1, ".")
                                nbrecv += 1
                                if conf.debug_match:
                                    debug.recv.append(r)
                    except KeyboardInterrupt:
                        if chainCC:
                            raise
                finally:
                    try:
                        nc,sent_times = cPickle.load(rdpipe)
                    except EOFError:
                        warning("Child died unexpectedly. Packets may have not been sent %i"%os.getpid())
                    else:
                        conf.netcache.update(nc)
                        for p,t in zip(all_stimuli, sent_times):
                            p.sent_time = t
                    os.waitpid(pid,0)
        finally:
            if pid == 0:
                os._exit(0)

        remain = reduce(list.__add__, hsent.values(), [])
        if multi:
            remain = filter(lambda p: not hasattr(p, '_answered'), remain);
            
        if autostop and len(remain) > 0 and len(remain) != len(tobesent):
            retry = autostop
            
        tobesent = remain
        if len(tobesent) == 0:
            break
        retry -= 1
        
    if conf.debug_match:
        debug.sent=plist.PacketList(remain[:],"Sent")
        debug.match=plist.SndRcvList(ans[:])

    #clean the ans list to delete the field _answered
    if (multi):
        for s,r in ans:
            if hasattr(s, '_answered'):
                del(s._answered)
    
    if verbose:
        print "\nReceived %i packets, got %i answers, remaining %i packets" % (nbrecv+len(ans), len(ans), notans)
    return plist.SndRcvList(ans),plist.PacketList(remain,"Unanswered")


def __gen_send(s, x, inter=0, loop=0, count=None, verbose=None, realtime=None, *args, **kargs):
    if type(x) is str:
        x = Raw(load=x)
    if not isinstance(x, Gen):
        x = SetGen(x)
    if verbose is None:
        verbose = conf.verb
    n = 0
    if count is not None:
        loop = -count
    elif not loop:
        loop=-1
    dt0 = None
    try:
        while loop:
            for p in x:
                if realtime:
                    ct = time.time()
                    if dt0:
                        st = dt0+p.time-ct
                        if st > 0:
                            time.sleep(st)
                    else:
                        dt0 = ct-p.time 
                s.send(p)
                n += 1
                if verbose:
                    os.write(1,".")
                time.sleep(inter)
            if loop < 0:
                loop += 1
    except KeyboardInterrupt:
        pass
    s.close()
    if verbose:
        print "\nSent %i packets." % n
        
@conf.commands.register
def send(x, inter=0, loop=0, count=None, verbose=None, realtime=None, *args, **kargs):
    """Send packets at layer 3
send(packets, [inter=0], [loop=0], [verbose=conf.verb]) -> None"""
    __gen_send(conf.L3socket(*args, **kargs), x, inter=inter, loop=loop, count=count,verbose=verbose, realtime=realtime)

@conf.commands.register
def sendp(x, inter=0, loop=0, iface=None, iface_hint=None, count=None, verbose=None, realtime=None, *args, **kargs):
    """Send packets at layer 2
sendp(packets, [inter=0], [loop=0], [verbose=conf.verb]) -> None"""
    if iface is None and iface_hint is not None:
        iface = conf.route.route(iface_hint)[0]
    __gen_send(conf.L2socket(iface=iface, *args, **kargs), x, inter=inter, loop=loop, count=count, verbose=verbose, realtime=realtime)

@conf.commands.register
def sendpfast(x, pps=None, mbps=None, realtime=None, loop=0, iface=None):
    """Send packets at layer 2 using tcpreplay for performance
    pps:  packets per second
    mpbs: MBits per second
    realtime: use packet's timestamp, bending time with realtime value
    loop: number of times to process the packet list
    iface: output interface """
    if iface is None:
        iface = conf.iface
    argv = [conf.prog.tcpreplay, "--intf1=%s" % iface ]
    if pps is not None:
        argv.append("--pps=%i" % pps)
    elif mbps is not None:
        argv.append("--mbps=%i" % mbps)
    elif realtime is not None:
        argv.append("--multiplier=%i" % realtime)
    else:
        argv.append("--topspeed")

    if loop:
        argv.append("--loop=%i" % loop)

    f = get_temp_file()
    argv.append(f)
    wrpcap(f, x)
    try:
        subprocess.check_call(argv)
    except KeyboardInterrupt:
        log_interactive.info("Interrupted by user")
    except Exception,e:
        log_interactive.error("while trying to exec [%s]: %s" % (argv[0],e))
    finally:
        os.unlink(f)

        

        
    
@conf.commands.register
def sr(x,filter=None, iface=None, nofilter=0, *args,**kargs):
    """Send and receive packets at layer 3
nofilter: put 1 to avoid use of bpf filters
retry:    if positive, how many times to resend unanswered packets
          if negative, how many times to retry when no more packets are answered
timeout:  how much time to wait after the last packet has been sent
verbose:  set verbosity level
multi:    whether to accept multiple answers for the same stimulus
filter:   provide a BPF filter
iface:    listen answers only on the given interface"""
    if not kargs.has_key("timeout"):
        kargs["timeout"] = -1
    s = conf.L3socket(filter=filter, iface=iface, nofilter=nofilter)
    a,b=sndrcv(s,x,*args,**kargs)
    s.close()
    return a,b

@conf.commands.register
def sr1(x,filter=None,iface=None, nofilter=0, *args,**kargs):
    """Send packets at layer 3 and return only the first answer
nofilter: put 1 to avoid use of bpf filters
retry:    if positive, how many times to resend unanswered packets
          if negative, how many times to retry when no more packets are answered
timeout:  how much time to wait after the last packet has been sent
verbose:  set verbosity level
multi:    whether to accept multiple answers for the same stimulus
filter:   provide a BPF filter
iface:    listen answers only on the given interface"""
    if not kargs.has_key("timeout"):
        kargs["timeout"] = -1
    s=conf.L3socket(filter=filter, nofilter=nofilter, iface=iface)
    a,b=sndrcv(s,x,*args,**kargs)
    s.close()
    if len(a) > 0:
        return a[0][1]
    else:
        return None

@conf.commands.register
def srp(x,iface=None, iface_hint=None, filter=None, nofilter=0, type=ETH_P_ALL, *args,**kargs):
    """Send and receive packets at layer 2
nofilter: put 1 to avoid use of bpf filters
retry:    if positive, how many times to resend unanswered packets
          if negative, how many times to retry when no more packets are answered
timeout:  how much time to wait after the last packet has been sent
verbose:  set verbosity level
multi:    whether to accept multiple answers for the same stimulus
filter:   provide a BPF filter
iface:    work only on the given interface"""
    if not kargs.has_key("timeout"):
        kargs["timeout"] = -1
    if iface is None and iface_hint is not None:
        iface = conf.route.route(iface_hint)[0]
    s = conf.L2socket(iface=iface, filter=filter, nofilter=nofilter, type=type)
    a,b=sndrcv(s ,x,*args,**kargs)
    s.close()
    return a,b

@conf.commands.register
def srp1(*args,**kargs):
    """Send and receive packets at layer 2 and return only the first answer
nofilter: put 1 to avoid use of bpf filters
retry:    if positive, how many times to resend unanswered packets
          if negative, how many times to retry when no more packets are answered
timeout:  how much time to wait after the last packet has been sent
verbose:  set verbosity level
multi:    whether to accept multiple answers for the same stimulus
filter:   provide a BPF filter
iface:    work only on the given interface"""
    if not kargs.has_key("timeout"):
        kargs["timeout"] = -1
    a,b=srp(*args,**kargs)
    if len(a) > 0:
        return a[0][1]
    else:
        return None

def __sr_loop(srfunc, pkts, prn=lambda x:x[1].summary(), prnfail=lambda x:x.summary(), inter=1, timeout=None, count=None, verbose=None, store=1, *args, **kargs):
    n = 0
    r = 0
    ct = conf.color_theme
    if verbose is None:
        verbose = conf.verb
    parity = 0
    ans=[]
    unans=[]
    if timeout is None:
        timeout = min(2*inter, 5)
    try:
        while 1:
            parity ^= 1
            col = [ct.even,ct.odd][parity]
            if count is not None:
                if count == 0:
                    break
                count -= 1
            start = time.time()
            print "\rsend...\r",
            res = srfunc(pkts, timeout=timeout, verbose=0, chainCC=1, *args, **kargs)
            n += len(res[0])+len(res[1])
            r += len(res[0])
            if verbose > 1 and prn and len(res[0]) > 0:
                msg = "RECV %i:" % len(res[0])
                print  "\r"+ct.success(msg),
                for p in res[0]:
                    print col(prn(p))
                    print " "*len(msg),
            if verbose > 1 and prnfail and len(res[1]) > 0:
                msg = "fail %i:" % len(res[1])
                print "\r"+ct.fail(msg),
                for p in res[1]:
                    print col(prnfail(p))
                    print " "*len(msg),
            if verbose > 1 and not (prn or prnfail):
                print "recv:%i  fail:%i" % tuple(map(len, res[:2]))
            if store:
                ans += res[0]
                unans += res[1]
            end=time.time()
            if end-start < inter:
                time.sleep(inter+start-end)
    except KeyboardInterrupt:
        pass
 
    if verbose and n>0:
        print ct.normal("\nSent %i packets, received %i packets. %3.1f%% hits." % (n,r,100.0*r/n))
    return plist.SndRcvList(ans),plist.PacketList(unans)

@conf.commands.register
def srloop(pkts, *args, **kargs):
    """Send a packet at layer 3 in loop and print the answer each time
srloop(pkts, [prn], [inter], [count], ...) --> None"""
    return __sr_loop(sr, pkts, *args, **kargs)

@conf.commands.register
def srploop(pkts, *args, **kargs):
    """Send a packet at layer 2 in loop and print the answer each time
srloop(pkts, [prn], [inter], [count], ...) --> None"""
    return __sr_loop(srp, pkts, *args, **kargs)


def sndrcvflood(pks, pkt, prn=lambda (s,r):r.summary(), chainCC=0, store=1, unique=0):
    if not isinstance(pkt, Gen):
        pkt = SetGen(pkt)
    tobesent = [p for p in pkt]
    received = plist.SndRcvList()
    seen = {}

    hsent={}
    for i in tobesent:
        h = i.hashret()
        if h in hsent:
            hsent[h].append(i)
        else:
            hsent[h] = [i]

    def send_in_loop(tobesent):
        while 1:
            for p in tobesent:
                yield p

    packets_to_send = send_in_loop(tobesent)

    ssock = rsock = pks.fileno()

    try:
        while 1:
            readyr,readys,_ = select([rsock],[ssock],[])
            if ssock in readys:
                pks.send(packets_to_send.next())
                
            if rsock in readyr:
                p = pks.recv(MTU)
                if p is None:
                    continue
                h = p.hashret()
                if h in hsent:
                    hlst = hsent[h]
                    for i in hlst:
                        if p.answers(i):
                            res = prn((i,p))
                            if unique:
                                if res in seen:
                                    continue
                                seen[res] = None
                            if res is not None:
                                print res
                            if store:
                                received.append((i,p))
    except KeyboardInterrupt:
        if chainCC:
            raise
    return received

@conf.commands.register
def srflood(x,filter=None, iface=None, nofilter=None, *args,**kargs):
    """Flood and receive packets at layer 3
prn:      function applied to packets received. Ret val is printed if not None
store:    if 1 (default), store answers and return them
unique:   only consider packets whose print 
nofilter: put 1 to avoid use of bpf filters
filter:   provide a BPF filter
iface:    listen answers only on the given interface"""
    s = conf.L3socket(filter=filter, iface=iface, nofilter=nofilter)
    r=sndrcvflood(s,x,*args,**kargs)
    s.close()
    return r

@conf.commands.register
def srpflood(x,filter=None, iface=None, iface_hint=None, nofilter=None, *args,**kargs):
    """Flood and receive packets at layer 2
prn:      function applied to packets received. Ret val is printed if not None
store:    if 1 (default), store answers and return them
unique:   only consider packets whose print 
nofilter: put 1 to avoid use of bpf filters
filter:   provide a BPF filter
iface:    listen answers only on the given interface"""
    if iface is None and iface_hint is not None:
        iface = conf.route.route(iface_hint)[0]    
    s = conf.L2socket(filter=filter, iface=iface, nofilter=nofilter)
    r=sndrcvflood(s,x,*args,**kargs)
    s.close()
    return r

           


@conf.commands.register
def sniff(count=0, store=1, offline=None, prn = None, lfilter=None, L2socket=None, timeout=None, opened_socket=None, *arg, **karg):
    """Sniff packets
sniff([count=0,] [prn=None,] [store=1,] [offline=None,] [lfilter=None,] + L2ListenSocket args) -> list of packets

  count: number of packets to capture. 0 means infinity
  store: wether to store sniffed packets or discard them
    prn: function to apply to each packet. If something is returned,
         it is displayed. Ex:
         ex: prn = lambda x: x.summary()
lfilter: python function applied to each packet to determine
         if further action may be done
         ex: lfilter = lambda x: x.haslayer(Padding)
offline: pcap file to read packets from, instead of sniffing them
timeout: stop sniffing after a given time (default: None)
L2socket: use the provided L2socket
opened_socket: provide an object ready to use .recv() on
    """
    c = 0
    
    if opened_socket is not None:
        s = opened_socket
    else:
        if offline is None:
            if L2socket is None:
                L2socket = conf.L2listen
            s = L2socket(type=ETH_P_ALL, *arg, **karg)
        else:
            s = PcapReader(offline)

    lst = []
    if timeout is not None:
        stoptime = time.time()+timeout
    remain = None
    while 1:
        try:
            if timeout is not None:
                remain = stoptime-time.time()
                if remain <= 0:
                    break
            sel = select([s],[],[],remain)
            if s in sel[0]:
                p = s.recv(MTU)
                if p is None:
                    break
                if lfilter and not lfilter(p):
                    continue
                if store:
                    lst.append(p)
                c += 1
                if prn:
                    r = prn(p)
                    if r is not None:
                        print r
                if count > 0 and c >= count:
                    break
        except KeyboardInterrupt:
            break
    if opened_socket is None:
        s.close()
    return plist.PacketList(lst,"Sniffed")

@conf.commands.register
def tshark(*args,**kargs):
    """Sniff packets and print them calling pkt.show(), a bit like text wireshark"""
    sniff(prn=lambda x: x.display(),*args,**kargs)

