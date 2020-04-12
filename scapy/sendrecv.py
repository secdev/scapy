# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Functions to send and receive packets.
"""

from __future__ import absolute_import, print_function
import itertools
from threading import Thread, Event
import os
import re
import subprocess
import time
import types

from scapy.compat import plain_str
from scapy.data import ETH_P_ALL
from scapy.config import conf
from scapy.error import warning
from scapy.packet import Gen, Packet
from scapy.utils import get_temp_file, tcpdump, wrpcap, \
    ContextManagerSubprocess, PcapReader
from scapy.plist import PacketList, SndRcvList
from scapy.error import log_runtime, log_interactive, Scapy_Exception
from scapy.base_classes import SetGen
from scapy.modules import six
from scapy.modules.six.moves import map
from scapy.sessions import DefaultSession
from scapy.supersocket import SuperSocket
if conf.route is None:
    # unused import, only to initialize conf.route
    import scapy.route  # noqa: F401

#################
#  Debug class  #
#################


class debug:
    recv = []
    sent = []
    match = []
    crashed_on = None


####################
#  Send / Receive  #
####################

_DOC_SNDRCV_PARAMS = """
    :param pks: SuperSocket instance to send/receive packets
    :param pkt: the packet to send
    :param rcv_pks: if set, will be used instead of pks to receive packets.
        packets will still be sent through pks
    :param nofilter: put 1 to avoid use of BPF filters
    :param retry: if positive, how many times to resend unanswered packets
        if negative, how many times to retry when no more packets
        are answered
    :param timeout: how much time to wait after the last packet has been sent
    :param verbose: set verbosity level
    :param multi: whether to accept multiple answers for the same stimulus
    :param store_unanswered: whether to store not-answered packets or not.
        setting it to False will increase speed, and will return
        None as the unans list.
    :param process: if specified, only result from process(pkt) will be stored.
        the function should follow the following format:
        ``lambda sent, received: (func(sent), func2(received))``
        if the packet is unanswered, `received` will be None.
        if `store_unanswered` is False, the function won't be called on
        un-answered packets.
    :param prebuild: pre-build the packets before starting to send them.
        Automatically enabled when a generator is passed as the packet
    """


class SndRcvHandler(object):
    """
    Util to send/receive packets, used by sr*().
    Do not use directly.

    This matches the requests and answers.

    Notes::
      - threaded mode: enabling threaded mode will likely
        break packet timestamps, but might result in a speedup
        when sending a big amount of packets. Disabled by default
      - DEVS: store the outgoing timestamp right BEFORE sending the packet
        to avoid races that could result in negative latency. We aren't Stadia
    """
    def __init__(self, pks, pkt,
                 timeout=None, inter=0, verbose=None,
                 chainCC=False,
                 retry=0, multi=False, rcv_pks=None,
                 prebuild=False, _flood=None,
                 threaded=False,
                 session=None):
        # Instantiate all arguments
        if verbose is None:
            verbose = conf.verb
        if conf.debug_match:
            debug.recv = PacketList([], "Received")
            debug.sent = PacketList([], "Sent")
            debug.match = SndRcvList([], "Matched")
        self.nbrecv = 0
        self.ans = []
        self.pks = pks
        self.rcv_pks = rcv_pks or pks
        self.inter = inter
        self.verbose = verbose
        self.chainCC = chainCC
        self.multi = multi
        self.timeout = timeout
        self.session = session
        # Instantiate packet holders
        if _flood:
            self.tobesent = pkt
            self.notans = _flood[0]
        else:
            if isinstance(pkt, types.GeneratorType) or prebuild:
                self.tobesent = [p for p in pkt]
                self.notans = len(self.tobesent)
            else:
                self.tobesent = (
                    SetGen(pkt) if not isinstance(pkt, Gen) else pkt
                )
                self.notans = self.tobesent.__iterlen__()

        if retry < 0:
            autostop = retry = -retry
        else:
            autostop = 0

        if timeout is not None and timeout < 0:
            self.timeout = None

        while retry >= 0:
            self.hsent = {}

            if threaded or _flood:
                # Send packets in thread.
                # https://github.com/secdev/scapy/issues/1791
                snd_thread = Thread(
                    target=self._sndrcv_snd
                )
                snd_thread.setDaemon(True)

                # Start routine with callback
                self._sndrcv_rcv(snd_thread.start)

                # Ended. Let's close gracefully
                if _flood:
                    # Flood: stop send thread
                    _flood[1]()
                snd_thread.join()
            else:
                self._sndrcv_rcv(self._sndrcv_snd)

            if multi:
                remain = [
                    p for p in itertools.chain(*six.itervalues(self.hsent))
                    if not hasattr(p, '_answered')
                ]
            else:
                remain = list(itertools.chain(*six.itervalues(self.hsent)))

            if autostop and len(remain) > 0 and \
               len(remain) != len(self.tobesent):
                retry = autostop

            self.tobesent = remain
            if len(self.tobesent) == 0:
                break
            retry -= 1

        if conf.debug_match:
            debug.sent = PacketList(remain[:], "Sent")
            debug.match = SndRcvList(self.ans[:])

        # Clean the ans list to delete the field _answered
        if multi:
            for snd, _ in self.ans:
                if hasattr(snd, '_answered'):
                    del snd._answered

        if verbose:
            print(
                "\nReceived %i packets, got %i answers, "
                "remaining %i packets" % (
                    self.nbrecv + len(self.ans), len(self.ans), self.notans
                )
            )

        self.ans_result = SndRcvList(self.ans)
        self.unans_result = PacketList(remain, "Unanswered")

    def results(self):
        return self.ans_result, self.unans_result

    def _sndrcv_snd(self):
        """Function used in the sending thread of sndrcv()"""
        try:
            if self.verbose:
                print("Begin emission:")
            i = 0
            for p in self.tobesent:
                # Populate the dictionary of _sndrcv_rcv
                # _sndrcv_rcv won't miss the answer of a packet that
                # has not been sent
                self.hsent.setdefault(p.hashret(), []).append(p)
                # Send packet
                self.pks.send(p)
                time.sleep(self.inter)
                i += 1
            if self.verbose:
                print("Finished sending %i packets." % i)
        except SystemExit:
            pass
        except Exception:
            log_runtime.exception("--- Error sending packets")

    def _process_packet(self, r):
        """Internal function used to process each packet."""
        if r is None:
            return
        ok = False
        h = r.hashret()
        if h in self.hsent:
            hlst = self.hsent[h]
            for i, sentpkt in enumerate(hlst):
                if r.answers(sentpkt):
                    self.ans.append((sentpkt, r))
                    if self.verbose > 1:
                        os.write(1, b"*")
                    ok = True
                    if not self.multi:
                        del hlst[i]
                        self.notans -= 1
                    else:
                        if not hasattr(sentpkt, '_answered'):
                            self.notans -= 1
                        sentpkt._answered = 1
                    break
        if self.notans <= 0 and not self.multi:
            self.sniffer.stop(join=False)
        if not ok:
            if self.verbose > 1:
                os.write(1, b".")
            self.nbrecv += 1
            if conf.debug_match:
                debug.recv.append(r)

    def _sndrcv_rcv(self, callback):
        """Function used to receive packets and check their hashret"""
        self.sniffer = None
        try:
            self.sniffer = AsyncSniffer()
            self.sniffer._run(
                prn=self._process_packet,
                timeout=self.timeout,
                store=False,
                opened_socket=self.pks,
                session=self.session,
                started_callback=callback
            )
        except KeyboardInterrupt:
            if self.chainCC:
                raise


def sndrcv(*args, **kwargs):
    """Scapy raw function to send a packet and receive its answer.
    WARNING: This is an internal function. Using sr/srp/sr1/srp is
    more appropriate in many cases.
    """
    sndrcver = SndRcvHandler(*args, **kwargs)
    return sndrcver.results()


def __gen_send(s, x, inter=0, loop=0, count=None, verbose=None, realtime=None, return_packets=False, *args, **kargs):  # noqa: E501
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
        sent_packets = PacketList()
    try:
        while loop:
            dt0 = None
            for p in x:
                if realtime:
                    ct = time.time()
                    if dt0:
                        st = dt0 + float(p.time) - ct
                        if st > 0:
                            time.sleep(st)
                    else:
                        dt0 = ct - float(p.time)
                s.send(p)
                if return_packets:
                    sent_packets.append(p)
                n += 1
                if verbose:
                    os.write(1, b".")
                time.sleep(inter)
            if loop < 0:
                loop += 1
    except KeyboardInterrupt:
        pass
    if verbose:
        print("\nSent %i packets." % n)
    if return_packets:
        return sent_packets


@conf.commands.register
def send(x, inter=0, loop=0, count=None,
         verbose=None, realtime=None,
         return_packets=False, socket=None, *args, **kargs):
    """
    Send packets at layer 3

    :param x: the packets
    :param inter: time (in s) between two packets (default 0)
    :param loop: send packet indefinetly (default 0)
    :param count: number of packets to send (default None=1)
    :param verbose: verbose mode (default None=conf.verbose)
    :param realtime: check that a packet was sent before sending the next one
    :param return_packets: return the sent packets
    :param socket: the socket to use (default is conf.L3socket(kargs))
    :param iface: the interface to send the packets on
    :param monitor: (not on linux) send in monitor mode
    :returns: None
    """
    need_closing = socket is None
    socket = socket or conf.L3socket(*args, **kargs)
    results = __gen_send(socket, x, inter=inter, loop=loop,
                         count=count, verbose=verbose,
                         realtime=realtime, return_packets=return_packets)
    if need_closing:
        socket.close()
    return results


@conf.commands.register
def sendp(x, inter=0, loop=0, iface=None, iface_hint=None, count=None,
          verbose=None, realtime=None,
          return_packets=False, socket=None, *args, **kargs):
    """
    Send packets at layer 2

    :param x: the packets
    :param inter: time (in s) between two packets (default 0)
    :param loop: send packet indefinetly (default 0)
    :param count: number of packets to send (default None=1)
    :param verbose: verbose mode (default None=conf.verbose)
    :param realtime: check that a packet was sent before sending the next one
    :param return_packets: return the sent packets
    :param socket: the socket to use (default is conf.L3socket(kargs))
    :param iface: the interface to send the packets on
    :param monitor: (not on linux) send in monitor mode
    :returns: None
    """
    if iface is None and iface_hint is not None and socket is None:
        iface = conf.route.route(iface_hint)[0]
    need_closing = socket is None
    socket = socket or conf.L2socket(iface=iface, *args, **kargs)
    results = __gen_send(socket, x, inter=inter, loop=loop,
                         count=count, verbose=verbose,
                         realtime=realtime, return_packets=return_packets)
    if need_closing:
        socket.close()
    return results


@conf.commands.register
def sendpfast(x, pps=None, mbps=None, realtime=None, loop=0, file_cache=False, iface=None, replay_args=None,  # noqa: E501
              parse_results=False):
    """Send packets at layer 2 using tcpreplay for performance

    :param pps:  packets per second
    :param mpbs: MBits per second
    :param realtime: use packet's timestamp, bending time with real-time value
    :param loop: number of times to process the packet list
    :param file_cache: cache packets in RAM instead of reading from
        disk at each iteration
    :param iface: output interface
    :param replay_args: List of additional tcpreplay args (List[str])
    :param parse_results: Return a dictionary of information
        outputted by tcpreplay (default=False)
    :returns: stdout, stderr, command used
    """
    if iface is None:
        iface = conf.iface
    argv = [conf.prog.tcpreplay, "--intf1=%s" % iface]
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

    # Check for any additional args we didn't cover.
    if replay_args is not None:
        argv.extend(replay_args)

    f = get_temp_file()
    argv.append(f)
    wrpcap(f, x)
    results = None
    with ContextManagerSubprocess(conf.prog.tcpreplay):
        try:
            cmd = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        except KeyboardInterrupt:
            log_interactive.info("Interrupted by user")
        except Exception:
            os.unlink(f)
            raise
        else:
            stdout, stderr = cmd.communicate()
            if stderr:
                log_runtime.warning(stderr.decode())
            if parse_results:
                results = _parse_tcpreplay_result(stdout, stderr, argv)
            elif conf.verb > 2:
                log_runtime.info(stdout.decode())
    os.unlink(f)
    return results


def _parse_tcpreplay_result(stdout, stderr, argv):
    """
    Parse the output of tcpreplay and modify the results_dict to populate output information.  # noqa: E501
    Tested with tcpreplay v3.4.4
    Tested with tcpreplay v4.1.2
    :param stdout: stdout of tcpreplay subprocess call
    :param stderr: stderr of tcpreplay subprocess call
    :param argv: the command used in the subprocess call
    :return: dictionary containing the results
    """
    try:
        results = {}
        stdout = plain_str(stdout).lower()
        stderr = plain_str(stderr).strip().split("\n")
        elements = {
            "actual": (int, int, float),
            "rated": (float, float, float),
            "flows": (int, float, int, int),
            "attempted": (int,),
            "successful": (int,),
            "failed": (int,),
            "truncated": (int,),
            "retried packets (eno": (int,),
            "retried packets (eag": (int,),
        }
        multi = {
            "actual": ("packets", "bytes", "time"),
            "rated": ("bps", "mbps", "pps"),
            "flows": ("flows", "fps", "flow_packets", "non_flow"),
            "retried packets (eno": ("retried_enobufs",),
            "retried packets (eag": ("retried_eagain",),
        }
        float_reg = r"([0-9]*\.[0-9]+|[0-9]+)"
        int_reg = r"([0-9]+)"
        any_reg = r"[^0-9]*"
        r_types = {int: int_reg, float: float_reg}
        for line in stdout.split("\n"):
            line = line.strip()
            for elt, _types in elements.items():
                if line.startswith(elt):
                    regex = any_reg.join([r_types[x] for x in _types])
                    matches = re.search(regex, line)
                    for i, typ in enumerate(_types):
                        name = multi.get(elt, [elt])[i]
                        results[name] = typ(matches.group(i + 1))
        results["command"] = " ".join(argv)
        results["warnings"] = stderr[:-1]
        return results
    except Exception as parse_exception:
        if not conf.interactive:
            raise
        log_runtime.error("Error parsing output: " + str(parse_exception))
        return {}


@conf.commands.register
def sr(x, promisc=None, filter=None, iface=None, nofilter=0, *args, **kargs):
    """
    Send and receive packets at layer 3
    """
    s = conf.L3socket(promisc=promisc, filter=filter,
                      iface=iface, nofilter=nofilter)
    result = sndrcv(s, x, *args, **kargs)
    s.close()
    return result


def _interface_selection(iface, packet):
    """
    Select the network interface according to the layer 3 destination
    """

    if iface is None:
        try:
            iff = packet.route()[0]
        except AttributeError:
            iff = None
        return iff or conf.iface

    return iface


@conf.commands.register
def sr1(x, promisc=None, filter=None, iface=None, nofilter=0, *args, **kargs):
    """
    Send packets at layer 3 and return only the first answer
    """
    iface = _interface_selection(iface, x)
    s = conf.L3socket(promisc=promisc, filter=filter,
                      nofilter=nofilter, iface=iface)
    ans, _ = sndrcv(s, x, *args, **kargs)
    s.close()
    if len(ans) > 0:
        return ans[0][1]
    else:
        return None


@conf.commands.register
def srp(x, promisc=None, iface=None, iface_hint=None, filter=None,
        nofilter=0, type=ETH_P_ALL, *args, **kargs):
    """
    Send and receive packets at layer 2
    """
    if iface is None and iface_hint is not None:
        iface = conf.route.route(iface_hint)[0]
    s = conf.L2socket(promisc=promisc, iface=iface,
                      filter=filter, nofilter=nofilter, type=type)
    result = sndrcv(s, x, *args, **kargs)
    s.close()
    return result


@conf.commands.register
def srp1(*args, **kargs):
    """
    Send and receive packets at layer 2 and return only the first answer
    """
    ans, _ = srp(*args, **kargs)
    if len(ans) > 0:
        return ans[0][1]
    else:
        return None


# Append doc
for sr_func in [srp, srp1, sr, sr1]:
    if sr_func.__doc__ is not None:
        sr_func.__doc__ += _DOC_SNDRCV_PARAMS


# SEND/RECV LOOP METHODS


def __sr_loop(srfunc, pkts, prn=lambda x: x[1].summary(),
              prnfail=lambda x: x.summary(),
              inter=1, timeout=None, count=None, verbose=None, store=1,
              *args, **kargs):
    n = 0
    r = 0
    ct = conf.color_theme
    if verbose is None:
        verbose = conf.verb
    parity = 0
    ans = []
    unans = []
    if timeout is None:
        timeout = min(2 * inter, 5)
    try:
        while True:
            parity ^= 1
            col = [ct.even, ct.odd][parity]
            if count is not None:
                if count == 0:
                    break
                count -= 1
            start = time.time()
            if verbose > 1:
                print("\rsend...\r", end=' ')
            res = srfunc(pkts, timeout=timeout, verbose=0, chainCC=True, *args, **kargs)  # noqa: E501
            n += len(res[0]) + len(res[1])
            r += len(res[0])
            if verbose > 1 and prn and len(res[0]) > 0:
                msg = "RECV %i:" % len(res[0])
                print("\r" + ct.success(msg), end=' ')
                for p in res[0]:
                    print(col(prn(p)))
                    print(" " * len(msg), end=' ')
            if verbose > 1 and prnfail and len(res[1]) > 0:
                msg = "fail %i:" % len(res[1])
                print("\r" + ct.fail(msg), end=' ')
                for p in res[1]:
                    print(col(prnfail(p)))
                    print(" " * len(msg), end=' ')
            if verbose > 1 and not (prn or prnfail):
                print("recv:%i  fail:%i" % tuple(map(len, res[:2])))
            if store:
                ans += res[0]
                unans += res[1]
            end = time.time()
            if end - start < inter:
                time.sleep(inter + start - end)
    except KeyboardInterrupt:
        pass

    if verbose and n > 0:
        print(ct.normal("\nSent %i packets, received %i packets. %3.1f%% hits." % (n, r, 100.0 * r / n)))  # noqa: E501
    return SndRcvList(ans), PacketList(unans)


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


def sndrcvflood(pks, pkt, inter=0, verbose=None, chainCC=False, timeout=None):
    """sndrcv equivalent for flooding."""
    stopevent = Event()

    def send_in_loop(tobesent, stopevent):
        """Infinite generator that produces the same
        packet until stopevent is triggered."""
        while True:
            for p in tobesent:
                if stopevent.is_set():
                    return
                yield p

    infinite_gen = send_in_loop(pkt, stopevent)
    _flood_len = pkt.__iterlen__() if isinstance(pkt, Gen) else len(pkt)
    _flood = [_flood_len, stopevent.set]
    return sndrcv(
        pks, infinite_gen,
        inter=inter, verbose=verbose,
        chainCC=chainCC, timeout=None,
        _flood=_flood
    )


@conf.commands.register
def srflood(x, promisc=None, filter=None, iface=None, nofilter=None, *args, **kargs):  # noqa: E501
    """Flood and receive packets at layer 3

    :param prn:      function applied to packets received
    :param unique:   only consider packets whose print
    :param nofilter: put 1 to avoid use of BPF filters
    :param filter:   provide a BPF filter
    :param iface:    listen answers only on the given interface
    """
    s = conf.L3socket(promisc=promisc, filter=filter, iface=iface, nofilter=nofilter)  # noqa: E501
    r = sndrcvflood(s, x, *args, **kargs)
    s.close()
    return r


@conf.commands.register
def sr1flood(x, promisc=None, filter=None, iface=None, nofilter=0, *args, **kargs):  # noqa: E501
    """Flood and receive packets at layer 3 and return only the first answer

    :param prn:      function applied to packets received
    :param verbose:  set verbosity level
    :param nofilter: put 1 to avoid use of BPF filters
    :param filter:   provide a BPF filter
    :param iface:    listen answers only on the given interface
    """
    s = conf.L3socket(promisc=promisc, filter=filter, nofilter=nofilter, iface=iface)  # noqa: E501
    ans, _ = sndrcvflood(s, x, *args, **kargs)
    s.close()
    if len(ans) > 0:
        return ans[0][1]
    else:
        return None


@conf.commands.register
def srpflood(x, promisc=None, filter=None, iface=None, iface_hint=None, nofilter=None, *args, **kargs):  # noqa: E501
    """Flood and receive packets at layer 2

    :param prn:      function applied to packets received
    :param unique:   only consider packets whose print
    :param nofilter: put 1 to avoid use of BPF filters
    :param filter:   provide a BPF filter
    :param iface:    listen answers only on the given interface
    """
    if iface is None and iface_hint is not None:
        iface = conf.route.route(iface_hint)[0]
    s = conf.L2socket(promisc=promisc, filter=filter, iface=iface, nofilter=nofilter)  # noqa: E501
    r = sndrcvflood(s, x, *args, **kargs)
    s.close()
    return r


@conf.commands.register
def srp1flood(x, promisc=None, filter=None, iface=None, nofilter=0, *args, **kargs):  # noqa: E501
    """Flood and receive packets at layer 2 and return only the first answer

    :param prn:      function applied to packets received
    :param verbose:  set verbosity level
    :param nofilter: put 1 to avoid use of BPF filters
    :param filter:   provide a BPF filter
    :param iface:    listen answers only on the given interface
    """
    s = conf.L2socket(promisc=promisc, filter=filter, nofilter=nofilter, iface=iface)  # noqa: E501
    ans, _ = sndrcvflood(s, x, *args, **kargs)
    s.close()
    if len(ans) > 0:
        return ans[0][1]
    else:
        return None

# SNIFF METHODS


class AsyncSniffer(object):
    """
    Sniff packets and return a list of packets.

    Args:
        count: number of packets to capture. 0 means infinity.
        store: whether to store sniffed packets or discard them
        prn: function to apply to each packet. If something is returned, it
             is displayed.
             --Ex: prn = lambda x: x.summary()
        session: a session = a flow decoder used to handle stream of packets.
                 e.g: IPSession (to defragment on-the-flow) or NetflowSession
        filter: BPF filter to apply.
        lfilter: Python function applied to each packet to determine if
                 further action may be done.
                 --Ex: lfilter = lambda x: x.haslayer(Padding)
        offline: PCAP file (or list of PCAP files) to read packets from,
                 instead of sniffing them
        timeout: stop sniffing after a given time (default: None).
        L2socket: use the provided L2socket (default: use conf.L2listen).
        opened_socket: provide an object (or a list of objects) ready to use
                      .recv() on.
        stop_filter: Python function applied to each packet to determine if
                     we have to stop the capture after this packet.
                     --Ex: stop_filter = lambda x: x.haslayer(TCP)
        iface: interface or list of interfaces (default: None for sniffing
               on all interfaces).
        monitor: use monitor mode. May not be available on all OS
        started_callback: called as soon as the sniffer starts sniffing
                          (default: None).

    The iface, offline and opened_socket parameters can be either an
    element, a list of elements, or a dict object mapping an element to a
    label (see examples below).

    Examples: synchronous
      >>> sniff(filter="arp")
      >>> sniff(filter="tcp",
      ...       session=IPSession,  # defragment on-the-flow
      ...       prn=lambda x: x.summary())
      >>> sniff(lfilter=lambda pkt: ARP in pkt)
      >>> sniff(iface="eth0", prn=Packet.summary)
      >>> sniff(iface=["eth0", "mon0"],
      ...       prn=lambda pkt: "%s: %s" % (pkt.sniffed_on,
      ...                                   pkt.summary()))
      >>> sniff(iface={"eth0": "Ethernet", "mon0": "Wifi"},
      ...       prn=lambda pkt: "%s: %s" % (pkt.sniffed_on,
      ...                                   pkt.summary()))

    Examples: asynchronous
      >>> t = AsyncSniffer(iface="enp0s3")
      >>> t.start()
      >>> time.sleep(1)
      >>> print("nice weather today")
      >>> t.stop()
    """
    def __init__(self, *args, **kwargs):
        # Store keyword arguments
        self.args = args
        self.kwargs = kwargs
        self.running = False
        self.thread = None
        self.results = None

    def _setup_thread(self):
        # Prepare sniffing thread
        self.thread = Thread(
            target=self._run,
            args=self.args,
            kwargs=self.kwargs
        )
        self.thread.setDaemon(True)

    def _run(self,
             count=0, store=True, offline=None,
             prn=None, lfilter=None,
             L2socket=None, timeout=None, opened_socket=None,
             stop_filter=None, iface=None, started_callback=None,
             session=None, session_args=[], session_kwargs={},
             *arg, **karg):
        self.running = True
        # Start main thread
        # instantiate session
        if not isinstance(session, DefaultSession):
            session = session or DefaultSession
            session = session(prn, store, *session_args, **session_kwargs)
        else:
            session.prn = prn
            session.store = store
        # sniff_sockets follows: {socket: label}
        sniff_sockets = {}
        if opened_socket is not None:
            if isinstance(opened_socket, list):
                sniff_sockets.update(
                    (s, "socket%d" % i)
                    for i, s in enumerate(opened_socket)
                )
            elif isinstance(opened_socket, dict):
                sniff_sockets.update(
                    (s, label)
                    for s, label in six.iteritems(opened_socket)
                )
            else:
                sniff_sockets[opened_socket] = "socket0"
        if offline is not None:
            flt = karg.get('filter')

            if isinstance(offline, list) and \
                    all(isinstance(elt, str) for elt in offline):
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
                # Write Scapy Packet objects to a pcap file
                def _write_to_pcap(packets_list):
                    filename = get_temp_file(autoext=".pcap")
                    wrpcap(filename, offline)
                    return filename, filename

                if isinstance(offline, Packet):
                    tempfile_written, offline = _write_to_pcap([offline])
                elif isinstance(offline, list) and \
                        all(isinstance(elt, Packet) for elt in offline):
                    tempfile_written, offline = _write_to_pcap(offline)

                sniff_sockets[PcapReader(
                    offline if flt is None else
                    tcpdump(offline, args=["-w", "-", flt], getfd=True)
                )] = offline
        if not sniff_sockets or iface is not None:
            if L2socket is None:
                L2socket = conf.L2listen
            if isinstance(iface, list):
                sniff_sockets.update(
                    (L2socket(type=ETH_P_ALL, iface=ifname, *arg, **karg),
                     ifname)
                    for ifname in iface
                )
            elif isinstance(iface, dict):
                sniff_sockets.update(
                    (L2socket(type=ETH_P_ALL, iface=ifname, *arg, **karg),
                     iflabel)
                    for ifname, iflabel in six.iteritems(iface)
                )
            else:
                sniff_sockets[L2socket(type=ETH_P_ALL, iface=iface,
                                       *arg, **karg)] = iface

        # Get select information from the sockets
        _main_socket = next(iter(sniff_sockets))
        read_allowed_exceptions = _main_socket.read_allowed_exceptions
        select_func = _main_socket.select
        _backup_read_func = _main_socket.__class__.recv
        nonblocking_socket = _main_socket.nonblocking_socket
        # We check that all sockets use the same select(), or raise a warning
        if not all(select_func == sock.select for sock in sniff_sockets):
            warning("Warning: inconsistent socket types ! "
                    "The used select function "
                    "will be the one of the first socket")

        # Fill if empty
        if not read_allowed_exceptions:
            read_allowed_exceptions = (IOError,)

        if nonblocking_socket:
            # select is non blocking
            def stop_cb():
                self.continue_sniff = False
            self.stop_cb = stop_cb
            close_pipe = None
        else:
            # select is blocking: Add special control socket
            from scapy.automaton import ObjectPipe
            close_pipe = ObjectPipe()
            sniff_sockets[close_pipe] = "control_socket"

            def stop_cb():
                if self.running:
                    close_pipe.send(None)
                self.continue_sniff = False
            self.stop_cb = stop_cb

        try:
            if started_callback:
                started_callback()
            self.continue_sniff = True

            # Start timeout
            if timeout is not None:
                stoptime = time.time() + timeout
            remain = None

            while sniff_sockets and self.continue_sniff:
                if timeout is not None:
                    remain = stoptime - time.time()
                    if remain <= 0:
                        break
                sockets, read_func = select_func(sniff_sockets, remain)
                read_func = read_func or _backup_read_func
                dead_sockets = []
                for s in sockets:
                    if s is close_pipe:
                        break
                    try:
                        p = read_func(s)
                    except EOFError:
                        # End of stream
                        try:
                            s.close()
                        except Exception:
                            pass
                        dead_sockets.append(s)
                        continue
                    except read_allowed_exceptions:
                        continue
                    except Exception as ex:
                        msg = " It was closed."
                        try:
                            # Make sure it's closed
                            s.close()
                        except Exception as ex:
                            msg = " close() failed with '%s'" % ex
                        warning(
                            "Socket %s failed with '%s'." % (s, ex) + msg
                        )
                        dead_sockets.append(s)
                        if conf.debug_dissector >= 2:
                            raise
                        continue
                    if p is None:
                        continue
                    if lfilter and not lfilter(p):
                        continue
                    p.sniffed_on = sniff_sockets[s]
                    # on_packet_received handles the prn/storage
                    session.on_packet_received(p)
                    # check
                    if (stop_filter and stop_filter(p)) or \
                            (0 < count <= session.count):
                        self.continue_sniff = False
                        break
                # Removed dead sockets
                for s in dead_sockets:
                    del sniff_sockets[s]
        except KeyboardInterrupt:
            pass
        self.running = False
        if opened_socket is None:
            for s in sniff_sockets:
                s.close()
        elif close_pipe:
            close_pipe.close()
        self.results = session.toPacketList()

    def start(self):
        """Starts AsyncSniffer in async mode"""
        self._setup_thread()
        self.thread.start()

    def stop(self, join=True):
        """Stops AsyncSniffer if not in async mode"""
        if self.running:
            try:
                self.stop_cb()
            except AttributeError:
                raise Scapy_Exception(
                    "Unsupported (offline or unsupported socket)"
                )
            if join:
                self.join()
                return self.results
        else:
            raise Scapy_Exception("Not started !")

    def join(self, *args, **kwargs):
        if self.thread:
            self.thread.join(*args, **kwargs)


@conf.commands.register
def sniff(*args, **kwargs):
    sniffer = AsyncSniffer()
    sniffer._run(*args, **kwargs)
    return sniffer.results


sniff.__doc__ = AsyncSniffer.__doc__


@conf.commands.register
def bridge_and_sniff(if1, if2, xfrm12=None, xfrm21=None, prn=None, L2socket=None,  # noqa: E501
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
            except Exception:
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
        except Exception:
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
def tshark(*args, **kargs):
    """Sniff packets and print them calling pkt.summary().
    This tries to replicate what text-wireshark (tshark) would look like"""

    if 'iface' in kargs:
        iface = kargs.get('iface')
    elif 'opened_socket' in kargs:
        iface = kargs.get('opened_socket').iface
    else:
        iface = conf.iface
    print("Capturing on '%s'" % iface)

    # This should be a nonlocal variable, using a mutable object
    # for Python 2 compatibility
    i = [0]

    def _cb(pkt):
        print("%5d\t%s" % (i[0], pkt.summary()))
        i[0] += 1

    sniff(prn=_cb, store=False, *args, **kargs)
    print("\n%d packet%s captured" % (i[0], 's' if i[0] > 1 else ''))
