## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Functions to send and receive packets.
"""

from __future__ import absolute_import, print_function
import errno
import itertools
import threading
import os
from select import select, error as select_error
import subprocess
import sys
import time

from scapy.consts import DARWIN, FREEBSD, OPENBSD, WINDOWS
from scapy.data import ETH_P_ALL, MTU
from scapy.config import conf, CacheInstance
from scapy.packet import Gen
from scapy.utils import get_temp_file, PcapReader, tcpdump, wrpcap
from scapy import plist
from scapy.error import log_runtime, log_interactive, warning
from scapy.base_classes import SetGen
from scapy.supersocket import StreamSocket
import scapy.modules.six as six
from scapy.modules.six.moves import map, zip
if conf.route is None:
    # unused import, only to initialize conf.route
    import scapy.route

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


def _sndrcv_snd(pks, timeout, inter, verbose, tobesent, all_stimuli, stopevent):
    try:
        i = 0
        if verbose:
            print("Begin emission:")
        for p in tobesent:
            pks.send(p)
            i += 1
            time.sleep(inter)
        if verbose:
            print("Finished to send %i packets." % i)
    except SystemExit:
        pass
    except KeyboardInterrupt:
        pass
    except:
        log_runtime.exception("--- Error sending packets")
        log_runtime.info("--- Error sending packets")
    if timeout is not None:
        stopevent.wait(timeout)
        pks.close()


def sndrcv(pks, pkt, timeout=None, inter=0, verbose=None, chainCC=False,
           retry=0, multi=False):
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
        hsent.setdefault(i.hashret(), []).append(i)

    if retry < 0:
        retry = -retry
        autostop = retry
    else:
        autostop = 0

    while retry >= 0:
        if timeout < 0:
            timeout = None
        stopevent = threading.Event()

        thread = threading.Thread(
            target=_sndrcv_snd,
            args=(pks, timeout, inter, verbose, tobesent, all_stimuli,
                  stopevent),
        )
        thread.start()
        stoptime = 0
        remaintime = None
        try:
            try:
                while True:
                    if stoptime:
                        remaintime = stoptime-time.time()
                        if remaintime <= 0:
                            break
                    r = None
                    if WINDOWS:
                        r = pks.recv(MTU)
                    elif conf.use_bpf:
                        from scapy.arch.bpf.supersocket import bpf_select
                        inp = bpf_select([pks])
                        if pks in inp:
                            r = pks.recv()
                    elif conf.use_pcap:
                        r = pks.nonblock_recv()
                    elif not isinstance(pks, StreamSocket) and (
                            FREEBSD or DARWIN or OPENBSD
                    ):
                        inp, _, _ = select([pks], [], [], 0.05)
                        if len(inp) == 0 or pks in inp:
                            r = pks.nonblock_recv()
                    else:
                        inp = []
                        try:
                            inp, _, _ = select([pks], [], [], remaintime)
                        except (IOError, select_error) as exc:
                            # select.error has no .errno attribute
                            if exc.args[0] != errno.EINTR:
                                raise
                        if len(inp) == 0:
                            break
                        if pks in inp:
                            r = pks.recv(MTU)
                    if r is None:
                        if pks.closed:
                            break
                        continue
                    ok = 0
                    h = r.hashret()
                    if h in hsent:
                        hlst = hsent[h]
                        for i, sentpkt in enumerate(hlst):
                            if r.answers(sentpkt):
                                ans.append((sentpkt, r))
                                if verbose > 1:
                                    os.write(1, "*")
                                ok = 1
                                if not multi:
                                    del hlst[i]
                                    notans -= 1
                                else:
                                    if not hasattr(sentpkt, '_answered'):
                                        notans -= 1
                                    sentpkt._answered = 1
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
            stopevent.set()
            thread.join()

        remain = list(itertools.chain(*six.itervalues(hsent)))
        if multi:
            remain = [p for p in remain if not hasattr(p, '_answered')]

        if autostop and len(remain) > 0 and len(remain) != len(tobesent):
            retry = autostop
            
        tobesent = remain
        if len(tobesent) == 0:
            break
        retry -= 1

    if conf.debug_match:
        debug.sent=plist.PacketList(remain[:],"Sent")
        debug.match=plist.SndRcvList(ans[:])

    # Clean the ans list to delete the field _answered
    if multi:
        for snd, _ in ans:
            if hasattr(snd, '_answered'):
                del snd._answered

    if verbose:
        print("\nReceived %i packets, got %i answers, remaining %i packets" % (nbrecv+len(ans), len(ans), notans))
    return plist.SndRcvList(ans), plist.PacketList(remain, "Unanswered")


def __gen_send(s, x, inter=0, loop=0, count=None, verbose=None, realtime=None, return_packets=False, *args, **kargs):
    if isinstance(x, str):
        x = conf.raw_layer(load=x)
    if not isinstance(x, Gen):
        x = SetGen(x)
    if verbose is None:
        verbose = conf.verb
    n = 0
    if count is not None:
        loop = -count
    elif not loop:
        loop = -1
    if return_packets:
        sent_packets = plist.PacketList()
    try:
        while loop:
            dt0 = None
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
                if return_packets:
                    sent_packets.append(p)
                n += 1
                if verbose:
                    os.write(1,b".")
                time.sleep(inter)
            if loop < 0:
                loop += 1
    except KeyboardInterrupt:
        pass
    s.close()
    if verbose:
        print("\nSent %i packets." % n)
    if return_packets:
        return sent_packets
        
@conf.commands.register
def send(x, inter=0, loop=0, count=None, verbose=None, realtime=None, return_packets=False, socket=None,
         *args, **kargs):
    """Send packets at layer 3
send(packets, [inter=0], [loop=0], [count=None], [verbose=conf.verb], [realtime=None], [return_packets=False],
     [socket=None]) -> None"""
    if socket is None:
        socket = conf.L3socket(*args, **kargs)
    return __gen_send(socket, x, inter=inter, loop=loop, count=count,verbose=verbose,
                      realtime=realtime, return_packets=return_packets)

@conf.commands.register
def sendp(x, inter=0, loop=0, iface=None, iface_hint=None, count=None, verbose=None, realtime=None,
          return_packets=False, socket=None, *args, **kargs):
    """Send packets at layer 2
sendp(packets, [inter=0], [loop=0], [iface=None], [iface_hint=None], [count=None], [verbose=conf.verb],
      [realtime=None], [return_packets=False], [socket=None]) -> None"""
    if iface is None and iface_hint is not None and socket is None:
        iface = conf.route.route(iface_hint)[0]
    if socket is None:
        socket = conf.L2socket(iface=iface, *args, **kargs)
    return __gen_send(socket, x, inter=inter, loop=loop, count=count,
                      verbose=verbose, realtime=realtime, return_packets=return_packets)

@conf.commands.register
def sendpfast(x, pps=None, mbps=None, realtime=None, loop=0, file_cache=False, iface=None):
    """Send packets at layer 2 using tcpreplay for performance
    pps:  packets per second
    mpbs: MBits per second
    realtime: use packet's timestamp, bending time with real-time value
    loop: number of times to process the packet list
    file_cache: cache packets in RAM instead of reading from disk at each iteration
    iface: output interface """
    if iface is None:
        iface = conf.iface
    argv = [conf.prog.tcpreplay, "--intf1=%s" % iface ]
    if pps is not None:
        argv.append("--pps=%i" % pps)
    elif mbps is not None:
        argv.append("--mbps=%f" % mbps)
    elif realtime is not None:
        argv.append("--multiplier=%f" % realtime)
    else:
        argv.append("--topspeed")

    if loop:
        argv.append("--loop=%i" % loop)
        if file_cache:
            argv.append("--preload-pcap")

    f = get_temp_file()
    argv.append(f)
    wrpcap(f, x)
    try:
        subprocess.check_call(argv)
    except KeyboardInterrupt:
        log_interactive.info("Interrupted by user")
    except Exception as e:
        log_interactive.error("while trying to exec [%s]: %s" % (argv[0],e))
    finally:
        os.unlink(f)

        

        
    
@conf.commands.register
def sr(x, promisc=None, filter=None, iface=None, nofilter=0, *args,**kargs):
    """Send and receive packets at layer 3
nofilter: put 1 to avoid use of BPF filters
retry:    if positive, how many times to resend unanswered packets
          if negative, how many times to retry when no more packets are answered
timeout:  how much time to wait after the last packet has been sent
verbose:  set verbosity level
multi:    whether to accept multiple answers for the same stimulus
filter:   provide a BPF filter
iface:    listen answers only on the given interface"""
    if "timeout" not in kargs:
        kargs["timeout"] = -1
    s = conf.L3socket(promisc=promisc, filter=filter, iface=iface, nofilter=nofilter)
    result = sndrcv(s, x, *args, **kargs)
    s.close()
    return result

@conf.commands.register
def sr1(x, promisc=None, filter=None, iface=None, nofilter=0, *args,**kargs):
    """Send packets at layer 3 and return only the first answer
nofilter: put 1 to avoid use of BPF filters
retry:    if positive, how many times to resend unanswered packets
          if negative, how many times to retry when no more packets are answered
timeout:  how much time to wait after the last packet has been sent
verbose:  set verbosity level
multi:    whether to accept multiple answers for the same stimulus
filter:   provide a BPF filter
iface:    listen answers only on the given interface"""
    if "timeout" not in kargs:
        kargs["timeout"] = -1
    s=conf.L3socket(promisc=promisc, filter=filter, nofilter=nofilter, iface=iface)
    ans, _ = sndrcv(s, x, *args, **kargs)
    s.close()
    if len(ans) > 0:
        return ans[0][1]
    else:
        return None

@conf.commands.register
def srp(x, promisc=None, iface=None, iface_hint=None, filter=None, nofilter=0, type=ETH_P_ALL, *args,**kargs):
    """Send and receive packets at layer 2
nofilter: put 1 to avoid use of BPF filters
retry:    if positive, how many times to resend unanswered packets
          if negative, how many times to retry when no more packets are answered
timeout:  how much time to wait after the last packet has been sent
verbose:  set verbosity level
multi:    whether to accept multiple answers for the same stimulus
filter:   provide a BPF filter
iface:    work only on the given interface"""
    if "timeout" not in kargs:
        kargs["timeout"] = -1
    if iface is None and iface_hint is not None:
        iface = conf.route.route(iface_hint)[0]
    s = conf.L2socket(promisc=promisc, iface=iface, filter=filter, nofilter=nofilter, type=type)
    result = sndrcv(s, x, *args, **kargs)
    s.close()
    return result

@conf.commands.register
def srp1(*args,**kargs):
    """Send and receive packets at layer 2 and return only the first answer
nofilter: put 1 to avoid use of BPF filters
retry:    if positive, how many times to resend unanswered packets
          if negative, how many times to retry when no more packets are answered
timeout:  how much time to wait after the last packet has been sent
verbose:  set verbosity level
multi:    whether to accept multiple answers for the same stimulus
filter:   provide a BPF filter
iface:    work only on the given interface"""
    if "timeout" not in kargs:
        kargs["timeout"] = -1
    ans, _ = srp(*args, **kargs)
    if len(ans) > 0:
        return ans[0][1]
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
        while True:
            parity ^= 1
            col = [ct.even,ct.odd][parity]
            if count is not None:
                if count == 0:
                    break
                count -= 1
            start = time.time()
            if verbose > 1:
                print("\rsend...\r", end=' ')
            res = srfunc(pkts, timeout=timeout, verbose=0, chainCC=True, *args, **kargs)
            n += len(res[0])+len(res[1])
            r += len(res[0])
            if verbose > 1 and prn and len(res[0]) > 0:
                msg = "RECV %i:" % len(res[0])
                print("\r"+ct.success(msg), end=' ')
                for p in res[0]:
                    print(col(prn(p)))
                    print(" "*len(msg), end=' ')
            if verbose > 1 and prnfail and len(res[1]) > 0:
                msg = "fail %i:" % len(res[1])
                print("\r"+ct.fail(msg), end=' ')
                for p in res[1]:
                    print(col(prnfail(p)))
                    print(" "*len(msg), end=' ')
            if verbose > 1 and not (prn or prnfail):
                print("recv:%i  fail:%i" % tuple(map(len, res[:2])))
            if store:
                ans += res[0]
                unans += res[1]
            end=time.time()
            if end-start < inter:
                time.sleep(inter+start-end)
    except KeyboardInterrupt:
        pass
 
    if verbose and n>0:
        print(ct.normal("\nSent %i packets, received %i packets. %3.1f%% hits." % (n,r,100.0*r/n)))
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


def sndrcvflood(pks, pkt, prn=lambda s_r:s_r[1].summary(), chainCC=0, store=1, unique=0):
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
        while True:
            for p in tobesent:
                yield p

    packets_to_send = send_in_loop(tobesent)

    ssock = rsock = pks.fileno()

    try:
        while True:
            if conf.use_bpf:
                from scapy.arch.bpf.supersocket import bpf_select
                readyr = bpf_select([rsock])
                _, readys, _ = select([], [ssock], [])
            else:
                readyr, readys, _ = select([rsock], [ssock], [])

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
                                print(res)
                            if store:
                                received.append((i,p))
    except KeyboardInterrupt:
        if chainCC:
            raise
    return received

@conf.commands.register
def srflood(x, promisc=None, filter=None, iface=None, nofilter=None, *args,**kargs):
    """Flood and receive packets at layer 3
prn:      function applied to packets received. Ret val is printed if not None
store:    if 1 (default), store answers and return them
unique:   only consider packets whose print 
nofilter: put 1 to avoid use of BPF filters
filter:   provide a BPF filter
iface:    listen answers only on the given interface"""
    s = conf.L3socket(promisc=promisc, filter=filter, iface=iface, nofilter=nofilter)
    r=sndrcvflood(s,x,*args,**kargs)
    s.close()
    return r

@conf.commands.register
def srpflood(x, promisc=None, filter=None, iface=None, iface_hint=None, nofilter=None, *args,**kargs):
    """Flood and receive packets at layer 2
prn:      function applied to packets received. Ret val is printed if not None
store:    if 1 (default), store answers and return them
unique:   only consider packets whose print 
nofilter: put 1 to avoid use of BPF filters
filter:   provide a BPF filter
iface:    listen answers only on the given interface"""
    if iface is None and iface_hint is not None:
        iface = conf.route.route(iface_hint)[0]    
    s = conf.L2socket(promisc=promisc, filter=filter, iface=iface, nofilter=nofilter)
    r=sndrcvflood(s,x,*args,**kargs)
    s.close()
    return r

           


@conf.commands.register
def sniff(count=0, store=1, offline=None, prn=None, lfilter=None,
          L2socket=None, timeout=None, opened_socket=None,
          stop_filter=None, iface=None, *arg, **karg):
    """Sniff packets
sniff([count=0,] [prn=None,] [store=1,] [offline=None,]
[lfilter=None,] + L2ListenSocket args) -> list of packets

  count: number of packets to capture. 0 means infinity
  store: whether to store sniffed packets or discard them
    prn: function to apply to each packet. If something is returned,
         it is displayed. Ex:
         ex: prn = lambda x: x.summary()
 filter: provide a BPF filter
lfilter: python function applied to each packet to determine
         if further action may be done
         ex: lfilter = lambda x: x.haslayer(Padding)
offline: pcap file to read packets from, instead of sniffing them
timeout: stop sniffing after a given time (default: None)
L2socket: use the provided L2socket
opened_socket: provide an object ready to use .recv() on
stop_filter: python function applied to each packet to determine
             if we have to stop the capture after this packet
             ex: stop_filter = lambda x: x.haslayer(TCP)
iface: interface or list of interfaces (default: None for sniffing on all
interfaces)
    """
    c = 0
    label = {}
    sniff_sockets = []
    if opened_socket is not None:
        sniff_sockets = [opened_socket]
    else:
        if offline is None:
            if L2socket is None:
                L2socket = conf.L2listen
            if isinstance(iface, list):
                for i in iface:
                    s = L2socket(type=ETH_P_ALL, iface=i, *arg, **karg)
                    label[s] = i
                    sniff_sockets.append(s)
            else:
                sniff_sockets = [L2socket(type=ETH_P_ALL, iface=iface, *arg,
                                           **karg)]
        else:
            flt = karg.get('filter')
            sniff_sockets = [PcapReader(
                offline if flt is None else
                tcpdump(offline, args=["-w", "-", flt], getfd=True)
            )]
    lst = []
    if timeout is not None:
        stoptime = time.time()+timeout
    remain = None
    try:
        stop_event = False
        while not stop_event:
            if timeout is not None:
                remain = stoptime-time.time()
                if remain <= 0:
                    break
            if conf.use_bpf:
                from scapy.arch.bpf.supersocket import bpf_select
                ins = bpf_select(sniff_sockets, remain)
            else:
                ins, _, _ = select(sniff_sockets, [], [], remain)
            for s in ins:
                p = s.recv()
                if p is None and offline is not None:
                    stop_event = True
                    break
                elif p is not None:
                    if lfilter and not lfilter(p):
                        continue
                    if s in label:
                        p.sniffed_on = label[s]
                    if store:
                        lst.append(p)
                    c += 1
                    if prn:
                        r = prn(p)
                        if r is not None:
                            print(r)
                    if stop_filter and stop_filter(p):
                        stop_event = True
                        break
                    if 0 < count <= c:
                        stop_event = True
                        break
    except KeyboardInterrupt:
        pass
    if opened_socket is None:
        for s in sniff_sockets:
            s.close()
    return plist.PacketList(lst,"Sniffed")


@conf.commands.register
def bridge_and_sniff(if1, if2, count=0, store=1, offline=None, prn=None, 
                     lfilter=None, L2socket=None, timeout=None,
                     stop_filter=None, *args, **kargs):
    """Forward traffic between two interfaces and sniff packets exchanged
bridge_and_sniff([count=0,] [prn=None,] [store=1,] [offline=None,] 
[lfilter=None,] + L2Socket args) -> list of packets

  count: number of packets to capture. 0 means infinity
  store: whether to store sniffed packets or discard them
    prn: function to apply to each packet. If something is returned,
         it is displayed. Ex:
         ex: prn = lambda x: x.summary()
lfilter: python function applied to each packet to determine
         if further action may be done
         ex: lfilter = lambda x: x.haslayer(Padding)
timeout: stop sniffing after a given time (default: None)
L2socket: use the provided L2socket
stop_filter: python function applied to each packet to determine
             if we have to stop the capture after this packet
             ex: stop_filter = lambda x: x.haslayer(TCP)
    """
    c = 0
    if L2socket is None:
        L2socket = conf.L2socket
    s1 = L2socket(iface=if1)
    s2 = L2socket(iface=if2)
    peerof={s1:s2,s2:s1}
    label={s1:if1, s2:if2}
    
    lst = []
    if timeout is not None:
        stoptime = time.time()+timeout
    remain = None
    try:
        stop_event = False
        while not stop_event:
            if timeout is not None:
                remain = stoptime-time.time()
                if remain <= 0:
                    break
            if conf.use_bpf:
                from scapy.arch.bpf.supersocket import bpf_select
                ins = bpf_select([s1, s2], remain)
            else:
                ins, _, _ = select([s1, s2], [], [], remain)

            for s in ins:
                p = s.recv()
                if p is not None:
                    peerof[s].send(p.original)
                    if lfilter and not lfilter(p):
                        continue
                    if store:
                        p.sniffed_on = label[s]
                        lst.append(p)
                    c += 1
                    if prn:
                        r = prn(p)
                        if r is not None:
                            print(r)
                    if stop_filter and stop_filter(p):
                        stop_event = True
                        break
                    if 0 < count <= c:
                        stop_event = True
                        break
    except KeyboardInterrupt:
        pass
    finally:
        return plist.PacketList(lst,"Sniffed")


@conf.commands.register
def tshark(*args,**kargs):
    """Sniff packets and print them calling pkt.show(), a bit like text wireshark"""
    sniff(prn=lambda x: x.display(),*args,**kargs)


