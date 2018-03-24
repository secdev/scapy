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
import time

from scapy.consts import DARWIN, FREEBSD, OPENBSD, WINDOWS
from scapy.data import ETH_P_ALL, MTU
from scapy.config import conf
from scapy.packet import Gen
from scapy.utils import get_temp_file, PcapReader, tcpdump, wrpcap
from scapy import plist
from scapy.error import log_runtime, log_interactive
from scapy.base_classes import SetGen
from scapy.supersocket import StreamSocket, L3RawSocket, L2ListenTcpdump
from scapy.modules import six
from scapy.modules.six.moves import map
if conf.route is None:
    # unused import, only to initialize conf.route
    import scapy.route
from scapy.supersocket import SuperSocket

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


def _sndrcv_snd(pks, timeout, inter, verbose, tobesent, stopevent):
    """Function used in the sending thread of sndrcv()"""
    try:
        i = 0
        if verbose:
            print("Begin emission:")
        for p in tobesent:
            pks.send(p)
            i += 1
            time.sleep(inter)
        if verbose:
            print("Finished sending %i packets." % i)
    except SystemExit:
        pass
    except KeyboardInterrupt:
        pass
    except:
        log_runtime.info("--- Error sending packets", exc_info=True)
    if timeout is not None:
        stopevent.wait(timeout)
        stopevent.set()

class _BreakException(Exception):
    """A dummy exception used in _get_pkt() to get out of the infinite
loop

    """
    pass

def _sndrcv_rcv(pks, tobesent, stopevent, nbrecv, notans, verbose, chainCC,
                multi):
    """Function used to recieve packets and check their hashret"""
    ans = []
    hsent = {}
    for i in tobesent:
        h = i.hashret()
        hsent.setdefault(i.hashret(), []).append(i)

    if WINDOWS:
        def _get_pkt():
            return pks.recv(MTU)
    elif conf.use_bpf:
        from scapy.arch.bpf.supersocket import bpf_select
        def _get_pkt():
            if bpf_select([pks]):
                return pks.recv()
    elif (conf.use_pcap and not isinstance(pks, (StreamSocket, L3RawSocket, L2ListenTcpdump))) or \
         (not isinstance(pks, (StreamSocket, L2ListenTcpdump)) and (DARWIN or FREEBSD or OPENBSD)):
        def _get_pkt():
            res = pks.nonblock_recv()
            if res is None:
                time.sleep(0.05)
            return res
    else:
        def _get_pkt():
            try:
                inp, _, _ = select([pks], [], [], 0.05)
            except (IOError, select_error) as exc:
                # select.error has no .errno attribute
                if exc.args[0] != errno.EINTR:
                    raise
            else:
                if inp:
                    return pks.recv(MTU)
            if stopevent.is_set():
                raise _BreakException()

    try:
        try:
            while True:
                r = _get_pkt()
                if stopevent.is_set():
                    break
                if r is None:
                    continue
                ok = False
                h = r.hashret()
                if h in hsent:
                    hlst = hsent[h]
                    for i, sentpkt in enumerate(hlst):
                        if r.answers(sentpkt):
                            ans.append((sentpkt, r))
                            if verbose > 1:
                                os.write(1, b"*")
                            ok = True
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
                        os.write(1, b".")
                    nbrecv += 1
                    if conf.debug_match:
                        debug.recv.append(r)
        except KeyboardInterrupt:
            if chainCC:
                raise
        except _BreakException:
            pass
    finally:
        stopevent.set()
    return (hsent, ans, nbrecv, notans)

def sndrcv(pks, pkt, timeout=None, inter=0, verbose=None, chainCC=False,
           retry=0, multi=False, rcv_pks=None):
    """Scapy raw function to send a packet and recieve its answer.
    WARNING: This is an internal function. Using sr/srp/sr1/srp is
    more appropriate in many cases.

    pks: SuperSocket instance to send/recieve packets
    pkt: the packet to send
    rcv_pks: if set, will be used instead of pks to recieve packets. packets will still
             be sent through pks
    nofilter: put 1 to avoid use of BPF filters
    retry:    if positive, how many times to resend unanswered packets
              if negative, how many times to retry when no more packets are answered
    timeout:  how much time to wait after the last packet has been sent
    verbose:  set verbosity level
    multi:    whether to accept multiple answers for the same stimulus"""
    is_single = isinstance(pkt, Gen)
    pkts = [pkt] if is_single else pkt
    if verbose is None:
        verbose = conf.verb
    debug.recv = plist.PacketList([],"Unanswered")
    debug.sent = plist.PacketList([],"Sent")
    debug.match = plist.SndRcvList([])
    nbrecv = 0
    ans = []
    # do it here to fix random fields, so that parent and child have the same
    tobesent = [p for p in (pkt if is_single else SetGen(pkt))]
    notans = len(tobesent)

    if retry < 0:
        autostop = retry = -retry
    else:
        autostop = 0

    for pkt in pkts:
        pkt.sent_time = None
    while retry >= 0:
        if timeout is not None and timeout < 0:
            timeout = None
        stopevent = threading.Event()

        thread = threading.Thread(
            target=_sndrcv_snd,
            args=(pks, timeout, inter, verbose, tobesent, stopevent),
        )
        thread.start()

        hsent, newans, nbrecv, notans = _sndrcv_rcv(
            (rcv_pks or pks), tobesent, stopevent, nbrecv, notans, verbose, chainCC, multi,
        )
        thread.join()

        ans.extend(newans)
        to_set_time = [pkt for pkt in pkts if pkt.sent_time is None]
        if to_set_time:
            try:
                sent_time = min(p.sent_time for p in tobesent if getattr(p, "sent_time", None))
            except ValueError:
                pass
            else:
                for pkt in to_set_time:
                    pkt.sent_time = sent_time

        remain = itertools.chain(*six.itervalues(hsent))
        remain = [p for p in remain if not hasattr(p, '_answered')] if multi else list(remain)

        if not remain:
            break

        if autostop and len(remain) != len(tobesent):
            retry = autostop
            
        tobesent = remain
        retry -= 1

    if conf.debug_match:
        debug.sent=plist.PacketList(remain[:], "Sent")
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
    except Exception:
        if conf.interactive:
            log_interactive.error("Cannot execute [%s]", argv[0], exc_info=True)
        else:
            raise
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

# SEND/RECV LOOP METHODS

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

# SEND/RECV FLOOD METHODS

def sndrcvflood(pks, pkt, inter=0, verbose=None, chainCC=False, prn=lambda x: x):
    if not verbose:
        verbose = conf.verb
    is_single = isinstance(pkt, Gen)
    pkts = [pkt] if is_single else pkt
    tobesent = [p for p in (pkt if is_single else SetGen(pkt))]

    stopevent = threading.Event()
    count_packets = six.moves.queue.Queue()

    def send_in_loop(tobesent, stopevent, count_packets=count_packets):
        """Infinite generator that produces the same packet until stopevent is triggered."""
        while True:
            for p in tobesent:
                if stopevent.is_set():
                    raise StopIteration()
                count_packets.put(0)
                yield p

    infinite_gen = send_in_loop(tobesent, stopevent)

    for pkt in pkts:
        pkt.sent_time = None
    # We don't use _sndrcv_snd verbose (it messes the logs up as in a thread that ends after recieving)
    thread = threading.Thread(
        target=_sndrcv_snd,
        args=(pks, None, inter, False, infinite_gen, stopevent),
    )
    thread.start()

    hsent, ans, nbrecv, notans = _sndrcv_rcv(pks, tobesent, stopevent, 0, len(tobesent), verbose, chainCC, False)
    thread.join()

    ans = [(x, prn(y)) for (x, y) in ans]  # Apply prn
    to_set_time = [pkt for pkt in pkts if pkt.sent_time is None]
    if to_set_time:
        try:
            sent_time = min(p.sent_time for p in tobesent if getattr(p, "sent_time", None))
        except ValueError:
            pass
        else:
            for pkt in to_set_time:
                pkt.sent_time = sent_time

    remain = list(itertools.chain(*six.itervalues(hsent)))

    if verbose:
        print("\nReceived %i packets, got %i answers, remaining %i packets. Sent a total of %i packets." % (nbrecv+len(ans), len(ans), notans, count_packets.qsize()))
    count_packets.empty()
    del count_packets

    return plist.SndRcvList(ans), plist.PacketList(remain, "Unanswered")

@conf.commands.register
def srflood(x, promisc=None, filter=None, iface=None, nofilter=None, *args,**kargs):
    """Flood and receive packets at layer 3
prn:      function applied to packets received
unique:   only consider packets whose print 
nofilter: put 1 to avoid use of BPF filters
filter:   provide a BPF filter
iface:    listen answers only on the given interface"""
    s = conf.L3socket(promisc=promisc, filter=filter, iface=iface, nofilter=nofilter)
    r=sndrcvflood(s,x,*args,**kargs)
    s.close()
    return r

@conf.commands.register
def sr1flood(x, promisc=None, filter=None, iface=None, nofilter=0, *args,**kargs):
    """Flood and receive packets at layer 3 and return only the first answer
prn:      function applied to packets received
verbose:  set verbosity level
nofilter: put 1 to avoid use of BPF filters
filter:   provide a BPF filter
iface:    listen answers only on the given interface"""
    s=conf.L3socket(promisc=promisc, filter=filter, nofilter=nofilter, iface=iface)
    ans, _ = sndrcvflood(s, x, *args, **kargs)
    s.close()
    if len(ans) > 0:
        return ans[0][1]
    else:
        return None

@conf.commands.register
def srpflood(x, promisc=None, filter=None, iface=None, iface_hint=None, nofilter=None, *args,**kargs):
    """Flood and receive packets at layer 2
prn:      function applied to packets received
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
def srp1flood(x, promisc=None, filter=None, iface=None, nofilter=0, *args,**kargs):
    """Flood and receive packets at layer 2 and return only the first answer
prn:      function applied to packets received
verbose:  set verbosity level
nofilter: put 1 to avoid use of BPF filters
filter:   provide a BPF filter
iface:    listen answers only on the given interface"""
    s=conf.L2socket(promisc=promisc, filter=filter, nofilter=nofilter, iface=iface)
    ans, _ = sndrcvflood(s, x, *args, **kargs)
    s.close()
    if len(ans) > 0:
        return ans[0][1]
    else:
        return None

# SNIFF METHODS

@conf.commands.register
def sniff(count=0, store=True, offline=None, prn=None, lfilter=None,
          L2socket=None, timeout=None, opened_socket=None,
          stop_filter=None, iface=None, *arg, **karg):
    """

Sniff packets and return a list of packets.

Arguments:

  count: number of packets to capture. 0 means infinity.

  store: whether to store sniffed packets or discard them

  prn: function to apply to each packet. If something is returned, it
      is displayed.

      Ex: prn = lambda x: x.summary()

  filter: BPF filter to apply.

  lfilter: Python function applied to each packet to determine if
      further action may be done.

      Ex: lfilter = lambda x: x.haslayer(Padding)

  offline: PCAP file (or list of PCAP files) to read packets from,
      instead of sniffing them

  timeout: stop sniffing after a given time (default: None).

  L2socket: use the provided L2socket (default: use conf.L2listen).

  opened_socket: provide an object (or a list of objects) ready to use
      .recv() on.

  stop_filter: Python function applied to each packet to determine if
      we have to stop the capture after this packet.

      Ex: stop_filter = lambda x: x.haslayer(TCP)

  iface: interface or list of interfaces (default: None for sniffing
      on all interfaces).

The iface, offline and opened_socket parameters can be either an
element, a list of elements, or a dict object mapping an element to a
label (see examples below).

Examples:

  >>> sniff(filter="arp")

  >>> sniff(lfilter=lambda pkt: ARP in pkt)

  >>> sniff(iface="eth0", prn=Packet.summary)

  >>> sniff(iface=["eth0", "mon0"],
  ...       prn=lambda pkt: "%s: %s" % (pkt.sniffed_on,
  ...                                   pkt.summary()))

  >>> sniff(iface={"eth0": "Ethernet", "mon0": "Wifi"},
  ...       prn=lambda pkt: "%s: %s" % (pkt.sniffed_on,
  ...                                   pkt.summary()))

    """
    c = 0
    sniff_sockets = {}  # socket: label dict
    if opened_socket is not None:
        if isinstance(opened_socket, list):
            sniff_sockets.update((s, "socket%d" % i)
                                 for i, s in enumerate(opened_socket))
        elif isinstance(opened_socket, dict):
            sniff_sockets.update((s, label)
                                 for s, label in six.iteritems(opened_socket))
        else:
            sniff_sockets[opened_socket] = "socket0"
    if offline is not None:
        flt = karg.get('filter')
        if isinstance(offline, list):
            sniff_sockets.update((PcapReader(
                fname if flt is None else
                tcpdump(fname, args=["-w", "-", flt], getfd=True)
            ), fname) for fname in offline)
        elif isinstance(offline, dict):
            sniff_sockets.update((PcapReader(
                fname if flt is None else
                tcpdump(fname, args=["-w", "-", flt], getfd=True)
            ), label) for fname, label in six.iteritems(offline))
        else:
            sniff_sockets[PcapReader(
                offline if flt is None else
                tcpdump(offline, args=["-w", "-", flt], getfd=True)
            )] = offline
    if not sniff_sockets or iface is not None:
        if L2socket is None:
            L2socket = conf.L2listen
        if isinstance(iface, list):
            sniff_sockets.update(
                (L2socket(type=ETH_P_ALL, iface=ifname, *arg, **karg), ifname)
                for ifname in iface
            )
        elif isinstance(iface, dict):
            sniff_sockets.update(
                (L2socket(type=ETH_P_ALL, iface=ifname, *arg, **karg), iflabel)
                for ifname, iflabel in six.iteritems(iface)
            )
        else:
            sniff_sockets[L2socket(type=ETH_P_ALL, iface=iface,
                                   *arg, **karg)] = iface
    lst = []
    if timeout is not None:
        stoptime = time.time()+timeout
    remain = None
    read_allowed_exceptions = ()
    if conf.use_bpf:
        from scapy.arch.bpf.supersocket import bpf_select
        def _select(sockets):
            return bpf_select(sockets, remain)
    elif WINDOWS:
        from scapy.arch.pcapdnet import PcapTimeoutElapsed
        read_allowed_exceptions = (PcapTimeoutElapsed,)
        def _select(sockets):
            try:
                return sockets
            except PcapTimeoutElapsed:
                return []
    else:
        def _select(sockets):
            try:
                return select(sockets, [], [], remain)[0]
            except select_error as exc:
                # Catch 'Interrupted system call' errors
                if exc[0] == errno.EINTR:
                    return []
                raise
    try:
        while sniff_sockets:
            if timeout is not None:
                remain = stoptime-time.time()
                if remain <= 0:
                    break
            ins = _select(sniff_sockets)
            for s in ins:
                try:
                    p = s.recv()
                except read_allowed_exceptions:
                    continue
                if p is None:
                    del sniff_sockets[s]
                    break
                if lfilter and not lfilter(p):
                    continue
                p.sniffed_on = sniff_sockets[s]
                if store:
                    lst.append(p)
                c += 1
                if prn:
                    r = prn(p)
                    if r is not None:
                        print(r)
                if stop_filter and stop_filter(p):
                    sniff_sockets = []
                    break
                if 0 < count <= c:
                    sniff_sockets = []
                    break
    except KeyboardInterrupt:
        pass
    if opened_socket is None:
        for s in sniff_sockets:
            s.close()
    return plist.PacketList(lst,"Sniffed")


@conf.commands.register
def bridge_and_sniff(if1, if2, xfrm12=None, xfrm21=None, prn=None, L2socket=None,
                     *args, **kargs):
    """Forward traffic between interfaces if1 and if2, sniff and return
the exchanged packets.

Arguments:

  if1, if2: the interfaces to use (interface names or opened sockets).

  xfrm12: a function to call when forwarding a packet from if1 to
      if2. If it returns True, the packet is forwarded as it. If it
      returns False or None, the packet is discarded. If it returns a
      packet, this packet is forwarded instead of the original packet
      one.

  xfrm21: same as xfrm12 for packets forwarded from if2 to if1.

  The other arguments are the same than for the function sniff(),
      except for offline, opened_socket and iface that are ignored.
      See help(sniff) for more.

    """
    for arg in ['opened_socket', 'offline', 'iface']:
        if arg in kargs:
            log_runtime.warning("Argument %s cannot be used in "
                                "bridge_and_sniff() -- ignoring it.", arg)
            del kargs[arg]
    def _init_socket(iface, count):
        if isinstance(iface, SuperSocket):
            return iface, "iface%d" % count
        else:
            return (L2socket or conf.L2socket)(iface=iface), iface
    sckt1, if1 = _init_socket(if1, 1)
    sckt2, if2 = _init_socket(if2, 2)
    peers = {if1: sckt2, if2: sckt1}
    xfrms = {}
    if xfrm12 is not None:
        xfrms[if1] = xfrm12
    if xfrm21 is not None:
        xfrms[if2] = xfrm21
    def prn_send(pkt):
        try:
            sendsock = peers[pkt.sniffed_on]
        except KeyError:
            return
        if pkt.sniffed_on in xfrms:
            try:
                newpkt = xfrms[pkt.sniffed_on](pkt)
            except:
                log_runtime.warning(
                    'Exception in transformation function for packet [%s] '
                    'received on %s -- dropping',
                    pkt.summary(), pkt.sniffed_on, exc_info=True
                )
                return
            else:
                if newpkt is True:
                    newpkt = pkt.original
                elif not newpkt:
                    return
        else:
            newpkt = pkt.original
        try:
            sendsock.send(newpkt)
        except:
            log_runtime.warning('Cannot forward packet [%s] received on %s',
                                pkt.summary(), pkt.sniffed_on, exc_info=True)
    if prn is None:
        prn = prn_send
    else:
        prn_orig = prn
        def prn(pkt):
            prn_send(pkt)
            return prn_orig(pkt)

    return sniff(opened_socket={sckt1: if1, sckt2: if2}, prn=prn,
                 *args, **kargs)


@conf.commands.register
def tshark(*args,**kargs):
    """Sniff packets and print them calling pkt.summary(), a bit like text wireshark"""
    print("Capturing on '" + str(kargs.get('iface') if 'iface' in kargs else conf.iface) + "'")
    i = [0]  # This should be a nonlocal variable, using a mutable object for Python 2 compatibility
    def _cb(pkt):
        print("%5d\t%s" % (i[0], pkt.summary()))
        i[0] += 1
    sniff(prn=_cb, store=False, *args, **kargs)
    print("\n%d packet%s captured" % (i[0], 's' if i[0] > 1 else ''))
