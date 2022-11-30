# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

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

from scapy.compat import plain_str
from scapy.data import ETH_P_ALL
from scapy.config import conf
from scapy.error import warning
from scapy.interfaces import (
    network_name,
    resolve_iface,
    NetworkInterface,
)
from scapy.packet import Packet
from scapy.utils import get_temp_file, tcpdump, wrpcap, \
    ContextManagerSubprocess, PcapReader, EDecimal
from scapy.plist import (
    PacketList,
    QueryAnswer,
    SndRcvList,
)
from scapy.error import log_runtime, log_interactive, Scapy_Exception
from scapy.base_classes import Gen, SetGen
from scapy.libs import six
from scapy.sessions import DefaultSession
from scapy.supersocket import SuperSocket, IterSocket

# Typing imports
from scapy.compat import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Tuple,
    Type,
    Union,
    cast
)
from scapy.interfaces import _GlobInterfaceType
from scapy.plist import _PacketIterable

if conf.route is None:
    # unused import, only to initialize conf.route and conf.iface*
    import scapy.route  # noqa: F401

#################
#  Debug class  #
#################


class debug:
    recv = PacketList([], "Received")
    sent = PacketList([], "Sent")
    match = SndRcvList([], "Matched")
    crashed_on = None  # type: Optional[Tuple[Type[Packet], bytes]]


####################
#  Send / Receive  #
####################

_DOC_SNDRCV_PARAMS = """
    :param pks: SuperSocket instance to send/receive packets
    :param pkt: the packet to send
    :param timeout: how much time to wait after the last packet has been sent
    :param inter: delay between two packets during sending
    :param verbose: set verbosity level
    :param chainCC: if True, KeyboardInterrupts will be forwarded
    :param retry: if positive, how many times to resend unanswered packets
        if negative, how many times to retry when no more packets
        are answered
    :param multi: whether to accept multiple answers for the same stimulus
    :param rcv_pks: if set, will be used instead of pks to receive packets.
        packets will still be sent through pks
    :param prebuild: pre-build the packets before starting to send them.
        Automatically enabled when a generator is passed as the packet
    :param _flood:
    :param threaded: if True, packets will be sent in an individual thread
    :param session: a flow decoder used to handle stream of packets
    :param chainEX: if True, exceptions during send will be forwarded
    """


_GlobSessionType = Union[Type[DefaultSession], DefaultSession]


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
    def __init__(self,
                 pks,  # type: SuperSocket
                 pkt,  # type: _PacketIterable
                 timeout=None,  # type: Optional[int]
                 inter=0,  # type: int
                 verbose=None,  # type: Optional[int]
                 chainCC=False,  # type: bool
                 retry=0,  # type: int
                 multi=False,  # type: bool
                 rcv_pks=None,  # type: Optional[SuperSocket]
                 prebuild=False,  # type: bool
                 _flood=None,  # type: Optional[_FloodGenerator]
                 threaded=False,  # type: bool
                 session=None,  # type: Optional[_GlobSessionType]
                 chainEX=False  # type: bool
                 ):
        # type: (...) -> None
        # Instantiate all arguments
        if verbose is None:
            verbose = conf.verb
        if conf.debug_match:
            debug.recv = PacketList([], "Received")
            debug.sent = PacketList([], "Sent")
            debug.match = SndRcvList([], "Matched")
        self.nbrecv = 0
        self.ans = []  # type: List[QueryAnswer]
        self.pks = pks
        self.rcv_pks = rcv_pks or pks
        self.inter = inter
        self.verbose = verbose
        self.chainCC = chainCC
        self.multi = multi
        self.timeout = timeout
        self.session = session
        self.chainEX = chainEX
        self._send_done = False
        self.notans = 0
        self.noans = 0
        self._flood = _flood
        # Instantiate packet holders
        if prebuild and not self._flood:
            self.tobesent = list(pkt)  # type: _PacketIterable
        else:
            self.tobesent = pkt

        if retry < 0:
            autostop = retry = -retry
        else:
            autostop = 0

        if timeout is not None and timeout < 0:
            self.timeout = None

        while retry >= 0:
            self.hsent = {}  # type: Dict[bytes, List[Packet]]

            if threaded or self._flood:
                # Send packets in thread.
                # https://github.com/secdev/scapy/issues/1791
                snd_thread = Thread(
                    target=self._sndrcv_snd
                )
                snd_thread.daemon = True

                # Start routine with callback
                self._sndrcv_rcv(snd_thread.start)

                # Ended. Let's close gracefully
                if self._flood:
                    # Flood: stop send thread
                    self._flood.stop()
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
                    self.nbrecv + len(self.ans), len(self.ans),
                    max(0, self.notans - self.noans)
                )
            )

        self.ans_result = SndRcvList(self.ans)
        self.unans_result = PacketList(remain, "Unanswered")

    def results(self):
        # type: () -> Tuple[SndRcvList, PacketList]
        return self.ans_result, self.unans_result

    def _sndrcv_snd(self):
        # type: () -> None
        """Function used in the sending thread of sndrcv()"""
        i = 0
        p = None
        try:
            if self.verbose:
                print("Begin emission:")
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
            if self.chainEX:
                raise
            else:
                log_runtime.exception("--- Error sending packets")
        finally:
            try:
                cast(Packet, self.tobesent).sent_time = \
                    cast(Packet, p).sent_time
            except AttributeError:
                pass
            if self._flood:
                self.notans = self._flood.iterlen
            elif not self._send_done:
                self.notans = i
            self._send_done = True

    def _process_packet(self, r):
        # type: (Packet) -> None
        """Internal function used to process each packet."""
        if r is None:
            return
        ok = False
        h = r.hashret()
        if h in self.hsent:
            hlst = self.hsent[h]
            for i, sentpkt in enumerate(hlst):
                if r.answers(sentpkt):
                    self.ans.append(QueryAnswer(sentpkt, r))
                    if self.verbose > 1:
                        os.write(1, b"*")
                    ok = True
                    if not self.multi:
                        del hlst[i]
                        self.noans += 1
                    else:
                        if not hasattr(sentpkt, '_answered'):
                            self.noans += 1
                        sentpkt._answered = 1
                    break
        if self._send_done and self.noans >= self.notans and not self.multi:
            if self.sniffer:
                self.sniffer.stop(join=False)
        if not ok:
            if self.verbose > 1:
                os.write(1, b".")
            self.nbrecv += 1
            if conf.debug_match:
                debug.recv.append(r)

    def _sndrcv_rcv(self, callback):
        # type: (Callable[[], None]) -> None
        """Function used to receive packets and check their hashret"""
        self.sniffer = None  # type: Optional[AsyncSniffer]
        try:
            self.sniffer = AsyncSniffer()
            self.sniffer._run(
                prn=self._process_packet,
                timeout=self.timeout,
                store=False,
                opened_socket=self.rcv_pks,
                session=self.session,
                started_callback=callback
            )
        except KeyboardInterrupt:
            if self.chainCC:
                raise


def sndrcv(*args, **kwargs):
    # type: (*Any, **Any) -> Tuple[SndRcvList, PacketList]
    """Scapy raw function to send a packet and receive its answer.
    WARNING: This is an internal function. Using sr/srp/sr1/srp is
    more appropriate in many cases.
    """
    sndrcver = SndRcvHandler(*args, **kwargs)
    return sndrcver.results()


def __gen_send(s,  # type: SuperSocket
               x,  # type: _PacketIterable
               inter=0,  # type: int
               loop=0,  # type: int
               count=None,  # type: Optional[int]
               verbose=None,  # type: Optional[int]
               realtime=False,  # type: bool
               return_packets=False,  # type: bool
               *args,  # type: Any
               **kargs  # type: Any
               ):
    # type: (...) -> Optional[PacketList]
    """
    An internal function used by send/sendp to actually send the packets,
    implement the send logic...

    It will take care of iterating through the different packets
    """
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
    sent_packets = PacketList() if return_packets else None
    p = None
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
                if sent_packets is not None:
                    sent_packets.append(p)
                n += 1
                if verbose:
                    os.write(1, b".")
                time.sleep(inter)
            if loop < 0:
                loop += 1
    except KeyboardInterrupt:
        pass
    finally:
        try:
            cast(Packet, x).sent_time = cast(Packet, p).sent_time
        except AttributeError:
            pass
    if verbose:
        print("\nSent %i packets." % n)
    return sent_packets


def _send(x,  # type: _PacketIterable
          _func,  # type: Callable[[NetworkInterface], Type[SuperSocket]]
          inter=0,  # type: int
          loop=0,  # type: int
          iface=None,  # type: Optional[_GlobInterfaceType]
          count=None,  # type: Optional[int]
          verbose=None,  # type: Optional[int]
          realtime=False,  # type: bool
          return_packets=False,  # type: bool
          socket=None,  # type: Optional[SuperSocket]
          **kargs  # type: Any
          ):
    # type: (...) -> Optional[PacketList]
    """Internal function used by send and sendp"""
    need_closing = socket is None
    iface = resolve_iface(iface or conf.iface)
    socket = socket or _func(iface)(iface=iface, **kargs)
    results = __gen_send(socket, x, inter=inter, loop=loop,
                         count=count, verbose=verbose,
                         realtime=realtime, return_packets=return_packets)
    if need_closing:
        socket.close()
    return results


@conf.commands.register
def send(x,  # type: _PacketIterable
         iface=None,  # type: Optional[_GlobInterfaceType]
         **kargs  # type: Any
         ):
    # type: (...) -> Optional[PacketList]
    """
    Send packets at layer 3

    :param x: the packets
    :param inter: time (in s) between two packets (default 0)
    :param loop: send packet indefinitely (default 0)
    :param count: number of packets to send (default None=1)
    :param verbose: verbose mode (default None=conf.verb)
    :param realtime: check that a packet was sent before sending the next one
    :param return_packets: return the sent packets
    :param socket: the socket to use (default is conf.L3socket(kargs))
    :param iface: the interface to send the packets on
    :param monitor: (not on linux) send in monitor mode
    :returns: None
    """
    iface = _interface_selection(iface, x)
    return _send(
        x,
        lambda iface: iface.l3socket(),
        iface=iface,
        **kargs
    )


@conf.commands.register
def sendp(x,  # type: _PacketIterable
          iface=None,  # type: Optional[_GlobInterfaceType]
          iface_hint=None,  # type: Optional[str]
          socket=None,  # type: Optional[SuperSocket]
          **kargs  # type: Any
          ):
    # type: (...) -> Optional[PacketList]
    """
    Send packets at layer 2

    :param x: the packets
    :param inter: time (in s) between two packets (default 0)
    :param loop: send packet indefinitely (default 0)
    :param count: number of packets to send (default None=1)
    :param verbose: verbose mode (default None=conf.verb)
    :param realtime: check that a packet was sent before sending the next one
    :param return_packets: return the sent packets
    :param socket: the socket to use (default is conf.L3socket(kargs))
    :param iface: the interface to send the packets on
    :param monitor: (not on linux) send in monitor mode
    :returns: None
    """
    if iface is None and iface_hint is not None and socket is None:
        iface = conf.route.route(iface_hint)[0]
    return _send(
        x,
        lambda iface: iface.l2socket(),
        iface=iface,
        socket=socket,
        **kargs
    )


@conf.commands.register
def sendpfast(x,  # type: _PacketIterable
              pps=None,  # type: Optional[float]
              mbps=None,  # type: Optional[float]
              realtime=False,  # type: bool
              loop=None,  # type: Optional[int]
              file_cache=False,  # type: bool
              iface=None,  # type: Optional[_GlobInterfaceType]
              replay_args=None,  # type: Optional[List[str]]
              parse_results=False,  # type: bool
              ):
    # type: (...) -> Optional[Dict[str, Any]]
    """Send packets at layer 2 using tcpreplay for performance

    :param pps:  packets per second
    :param mbps: MBits per second
    :param realtime: use packet's timestamp, bending time with real-time value
    :param loop: number of times to process the packet list. 0 implies
        infinite loop
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
    argv = [conf.prog.tcpreplay, "--intf1=%s" % network_name(iface)]
    if pps is not None:
        argv.append("--pps=%i" % pps)
    elif mbps is not None:
        argv.append("--mbps=%f" % mbps)
    elif realtime is not None:
        argv.append("--multiplier=%f" % realtime)
    else:
        argv.append("--topspeed")

    if loop is not None:
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
    if os.path.exists(f):
        os.unlink(f)
    return results


def _parse_tcpreplay_result(stdout_b, stderr_b, argv):
    # type: (bytes, bytes, List[str]) -> Dict[str, Any]
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
        stdout = plain_str(stdout_b).lower()
        stderr = plain_str(stderr_b).strip().split("\n")
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
                        if matches:
                            results[name] = typ(matches.group(i + 1))
        results["command"] = " ".join(argv)
        results["warnings"] = stderr[:-1]
        return results
    except Exception as parse_exception:
        if not conf.interactive:
            raise
        log_runtime.error("Error parsing output: %s", parse_exception)
        return {}


def _interface_selection(iface,  # type: Optional[_GlobInterfaceType]
                         packet  # type: _PacketIterable
                         ):
    # type: (...) -> _GlobInterfaceType
    """
    Select the network interface according to the layer 3 destination
    """

    if iface is None:
        try:
            iff = next(packet.__iter__()).route()[0]
        except AttributeError:
            iff = None
        return iff or conf.iface

    return iface


@conf.commands.register
def sr(x,  # type: _PacketIterable
       promisc=None,  # type: Optional[bool]
       filter=None,  # type: Optional[str]
       iface=None,  # type: Optional[_GlobInterfaceType]
       nofilter=0,  # type: int
       *args,  # type: Any
       **kargs  # type: Any
       ):
    # type: (...) -> Tuple[SndRcvList, PacketList]
    """
    Send and receive packets at layer 3
    """
    iface = _interface_selection(iface, x)
    s = conf.L3socket(promisc=promisc, filter=filter,
                      iface=iface, nofilter=nofilter)
    result = sndrcv(s, x, *args, **kargs)
    s.close()
    return result


@conf.commands.register
def sr1(*args, **kargs):
    # type: (*Packet, **Any) -> Optional[Packet]
    """
    Send packets at layer 3 and return only the first answer
    """
    ans, _ = sr(*args, **kargs)
    if ans:
        return cast(Packet, ans[0][1])
    return None


@conf.commands.register
def srp(x,  # type: Packet
        promisc=None,  # type: Optional[bool]
        iface=None,  # type: Optional[_GlobInterfaceType]
        iface_hint=None,  # type: Optional[str]
        filter=None,  # type: Optional[str]
        nofilter=0,  # type: int
        type=ETH_P_ALL,  # type: int
        *args,  # type: Any
        **kargs  # type: Any
        ):
    # type: (...) -> Tuple[SndRcvList, PacketList]
    """
    Send and receive packets at layer 2
    """
    if iface is None and iface_hint is not None:
        iface = conf.route.route(iface_hint)[0]
    iface = resolve_iface(iface or conf.iface)
    s = iface.l2socket()(promisc=promisc, iface=iface,
                         filter=filter, nofilter=nofilter, type=type)
    result = sndrcv(s, x, *args, **kargs)
    s.close()
    return result


@conf.commands.register
def srp1(*args, **kargs):
    # type: (*Packet, **Any) -> Optional[Packet]
    """
    Send and receive packets at layer 2 and return only the first answer
    """
    ans, _ = srp(*args, **kargs)
    if len(ans) > 0:
        return cast(Packet, ans[0][1])
    return None


# Append doc
for sr_func in [srp, srp1, sr, sr1]:
    if sr_func.__doc__ is not None:
        sr_func.__doc__ += _DOC_SNDRCV_PARAMS


# SEND/RECV LOOP METHODS


def __sr_loop(srfunc,  # type: Callable[..., Tuple[SndRcvList, PacketList]]
              pkts,  # type: _PacketIterable
              prn=lambda x: x[1].summary(),  # type: Callable[[QueryAnswer], Any]  # noqa: E501
              prnfail=lambda x: x.summary(),  # type: Callable[[Packet], Any]
              inter=1,  # type: int
              timeout=None,  # type: Optional[int]
              count=None,  # type: Optional[int]
              verbose=None,  # type: Optional[int]
              store=1,  # type: int
              *args,  # type: Any
              **kargs  # type: Any
              ):
    # type: (...) -> Tuple[SndRcvList, PacketList]
    n = 0
    r = 0
    ct = conf.color_theme
    if verbose is None:
        verbose = conf.verb
    parity = 0
    ans = []  # type: List[QueryAnswer]
    unans = []  # type: List[Packet]
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
            if verbose == 1:
                if res[0]:
                    os.write(1, b"*")
                if res[1]:
                    os.write(1, b".")
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
def srloop(pkts,  # type: _PacketIterable
           *args,  # type: Any
           **kargs  # type: Any
           ):
    # type: (...) -> Tuple[SndRcvList, PacketList]
    """
    Send a packet at layer 3 in loop and print the answer each time
    srloop(pkts, [prn], [inter], [count], ...) --> None
    """
    return __sr_loop(sr, pkts, *args, **kargs)


@conf.commands.register
def srploop(pkts,  # type: _PacketIterable
            *args,  # type: Any
            **kargs  # type: Any
            ):
    # type: (...) -> Tuple[SndRcvList, PacketList]
    """
    Send a packet at layer 2 in loop and print the answer each time
    srloop(pkts, [prn], [inter], [count], ...) --> None
    """
    return __sr_loop(srp, pkts, *args, **kargs)

# SEND/RECV FLOOD METHODS


class _FloodGenerator(object):
    def __init__(self, tobesent, maxretries):
        # type: (_PacketIterable, Optional[int]) -> None
        self.tobesent = tobesent
        self.maxretries = maxretries
        self.stopevent = Event()
        self.iterlen = 0

    def __iter__(self):
        # type: () -> Iterator[Packet]
        i = 0
        while True:
            i += 1
            j = 0
            if self.maxretries and i >= self.maxretries:
                return
            for p in self.tobesent:
                if self.stopevent.is_set():
                    return
                j += 1
                yield p
            if self.iterlen == 0:
                self.iterlen = j

    @property
    def sent_time(self):
        # type: () -> Union[EDecimal, float, None]
        return cast(Packet, self.tobesent).sent_time

    @sent_time.setter
    def sent_time(self, val):
        # type: (Union[EDecimal, float, None]) -> None
        cast(Packet, self.tobesent).sent_time = val

    def stop(self):
        # type: () -> None
        self.stopevent.set()


def sndrcvflood(pks,  # type: SuperSocket
                pkt,  # type: _PacketIterable
                inter=0,  # type: int
                maxretries=None,  # type: Optional[int]
                verbose=None,  # type: Optional[int]
                chainCC=False,  # type: bool
                timeout=None  # type: Optional[int]
                ):
    # type: (...) -> Tuple[SndRcvList, PacketList]
    """sndrcv equivalent for flooding."""

    flood_gen = _FloodGenerator(pkt, maxretries)
    return sndrcv(
        pks, flood_gen,
        inter=inter, verbose=verbose,
        chainCC=chainCC, timeout=timeout,
        _flood=flood_gen
    )


@conf.commands.register
def srflood(x,  # type: _PacketIterable
            promisc=None,  # type: Optional[bool]
            filter=None,  # type: Optional[str]
            iface=None,  # type: Optional[_GlobInterfaceType]
            nofilter=None,  # type: Optional[bool]
            *args,  # type: Any
            **kargs  # type: Any
            ):
    # type: (...) -> Tuple[SndRcvList, PacketList]
    """Flood and receive packets at layer 3

    :param prn:      function applied to packets received
    :param unique:   only consider packets whose print
    :param nofilter: put 1 to avoid use of BPF filters
    :param filter:   provide a BPF filter
    :param iface:    listen answers only on the given interface
    """
    iface = resolve_iface(iface or conf.iface)
    s = iface.l3socket()(promisc=promisc, filter=filter, iface=iface, nofilter=nofilter)  # noqa: E501
    r = sndrcvflood(s, x, *args, **kargs)
    s.close()
    return r


@conf.commands.register
def sr1flood(x,  # type: _PacketIterable
             promisc=None,  # type: Optional[bool]
             filter=None,  # type: Optional[str]
             iface=None,  # type: Optional[_GlobInterfaceType]
             nofilter=0,  # type: int
             *args,  # type: Any
             **kargs  # type: Any
             ):
    # type: (...) -> Optional[Packet]
    """Flood and receive packets at layer 3 and return only the first answer

    :param prn:      function applied to packets received
    :param verbose:  set verbosity level
    :param nofilter: put 1 to avoid use of BPF filters
    :param filter:   provide a BPF filter
    :param iface:    listen answers only on the given interface
    """
    iface = resolve_iface(iface or conf.iface)
    s = iface.l3socket()(promisc=promisc, filter=filter, nofilter=nofilter, iface=iface)  # noqa: E501
    ans, _ = sndrcvflood(s, x, *args, **kargs)
    s.close()
    if len(ans) > 0:
        return cast(Packet, ans[0][1])
    return None


@conf.commands.register
def srpflood(x,  # type: _PacketIterable
             promisc=None,  # type: Optional[bool]
             filter=None,  # type: Optional[str]
             iface=None,  # type: Optional[_GlobInterfaceType]
             iface_hint=None,  # type: Optional[str]
             nofilter=None,  # type: Optional[bool]
             *args,  # type: Any
             **kargs  # type: Any
             ):
    # type: (...) -> Tuple[SndRcvList, PacketList]
    """Flood and receive packets at layer 2

    :param prn:      function applied to packets received
    :param unique:   only consider packets whose print
    :param nofilter: put 1 to avoid use of BPF filters
    :param filter:   provide a BPF filter
    :param iface:    listen answers only on the given interface
    """
    if iface is None and iface_hint is not None:
        iface = conf.route.route(iface_hint)[0]
    iface = resolve_iface(iface or conf.iface)
    s = iface.l2socket()(promisc=promisc, filter=filter, iface=iface, nofilter=nofilter)  # noqa: E501
    r = sndrcvflood(s, x, *args, **kargs)
    s.close()
    return r


@conf.commands.register
def srp1flood(x,  # type: _PacketIterable
              promisc=None,  # type: Optional[bool]
              filter=None,  # type: Optional[str]
              iface=None,  # type: Optional[_GlobInterfaceType]
              nofilter=0,  # type: int
              *args,  # type: Any
              **kargs  # type: Any
              ):
    # type: (...) -> Optional[Packet]
    """Flood and receive packets at layer 2 and return only the first answer

    :param prn:      function applied to packets received
    :param verbose:  set verbosity level
    :param nofilter: put 1 to avoid use of BPF filters
    :param filter:   provide a BPF filter
    :param iface:    listen answers only on the given interface
    """
    iface = resolve_iface(iface or conf.iface)
    s = iface.l2socket()(promisc=promisc, filter=filter, nofilter=nofilter, iface=iface)  # noqa: E501
    ans, _ = sndrcvflood(s, x, *args, **kargs)
    s.close()
    if len(ans) > 0:
        return cast(Packet, ans[0][1])
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
                 --Ex: session=TCPSession
                 See below for more details.
        filter: BPF filter to apply.
        lfilter: Python function applied to each packet to determine if
                 further action may be done.
                 --Ex: lfilter = lambda x: x.haslayer(Padding)
        offline: PCAP file (or list of PCAP files) to read packets from,
                 instead of sniffing them
        quiet:   when set to True, the process stderr is discarded
                 (default: False).
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

    For more information about the session argument, see
    https://scapy.rtfd.io/en/latest/usage.html#advanced-sniffing-sniffing-sessions

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
        # type: (*Any, **Any) -> None
        # Store keyword arguments
        self.args = args
        self.kwargs = kwargs
        self.running = False
        self.thread = None  # type: Optional[Thread]
        self.results = None  # type: Optional[PacketList]

    def _setup_thread(self):
        # type: () -> None
        # Prepare sniffing thread
        self.thread = Thread(
            target=self._run,
            args=self.args,
            kwargs=self.kwargs,
            name="AsyncSniffer"
        )
        self.thread.daemon = True

    def _run(self,
             count=0,  # type: int
             store=True,  # type: bool
             offline=None,  # type: Any
             quiet=False,  # type: bool
             prn=None,  # type: Optional[Callable[[Packet], Any]]
             lfilter=None,  # type: Optional[Callable[[Packet], bool]]
             L2socket=None,  # type: Optional[Type[SuperSocket]]
             timeout=None,  # type: Optional[int]
             opened_socket=None,  # type: Optional[SuperSocket]
             stop_filter=None,  # type: Optional[Callable[[Packet], bool]]
             iface=None,  # type: Optional[_GlobInterfaceType]
             started_callback=None,  # type: Optional[Callable[[], Any]]
             session=None,  # type: Optional[_GlobSessionType]
             session_kwargs={},  # type: Dict[str, Any]
             **karg  # type: Any
             ):
        # type: (...) -> None
        self.running = True
        # Start main thread
        # instantiate session
        if not isinstance(session, DefaultSession):
            session = session or DefaultSession
            session = session(prn=prn, store=store,
                              **session_kwargs)
        else:
            session.prn = prn
            session.store = store
        # sniff_sockets follows: {socket: label}
        sniff_sockets = {}  # type: Dict[SuperSocket, _GlobInterfaceType]
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

            if isinstance(offline, str):
                # Single file
                offline = [offline]
            if isinstance(offline, list) and \
                    all(isinstance(elt, str) for elt in offline):
                # List of files
                sniff_sockets.update((PcapReader(
                    fname if flt is None else
                    tcpdump(fname,
                            args=["-w", "-"],
                            flt=flt,
                            getfd=True,
                            quiet=quiet)
                ), fname) for fname in offline)
            elif isinstance(offline, dict):
                # Dict of files
                sniff_sockets.update((PcapReader(
                    fname if flt is None else
                    tcpdump(fname,
                            args=["-w", "-"],
                            flt=flt,
                            getfd=True,
                            quiet=quiet)
                ), label) for fname, label in six.iteritems(offline))
            elif isinstance(offline, (Packet, PacketList, list)):
                # Iterables (list of packets, PacketList..)
                offline = IterSocket(offline)
                sniff_sockets[offline if flt is None else PcapReader(
                    tcpdump(offline,
                            args=["-w", "-"],
                            flt=flt,
                            getfd=True,
                            quiet=quiet)
                )] = offline
            else:
                # Other (file descriptors...)
                sniff_sockets[PcapReader(
                    offline if flt is None else
                    tcpdump(offline,
                            args=["-w", "-"],
                            flt=flt,
                            getfd=True,
                            quiet=quiet)
                )] = offline
        if not sniff_sockets or iface is not None:
            # The _RL2 function resolves the L2socket of an iface
            _RL2 = lambda i: L2socket or resolve_iface(i).l2listen()  # type: Callable[[_GlobInterfaceType], Callable[..., SuperSocket]]  # noqa: E501
            if isinstance(iface, list):
                sniff_sockets.update(
                    (_RL2(ifname)(type=ETH_P_ALL, iface=ifname, **karg),
                     ifname)
                    for ifname in iface
                )
            elif isinstance(iface, dict):
                sniff_sockets.update(
                    (_RL2(ifname)(type=ETH_P_ALL, iface=ifname, **karg),
                     iflabel)
                    for ifname, iflabel in six.iteritems(iface)
                )
            else:
                iface = iface or conf.iface
                sniff_sockets[_RL2(iface)(type=ETH_P_ALL, iface=iface,
                                          **karg)] = iface

        # Get select information from the sockets
        _main_socket = next(iter(sniff_sockets))
        select_func = _main_socket.select
        nonblocking_socket = getattr(_main_socket, "nonblocking_socket", False)
        # We check that all sockets use the same select(), or raise a warning
        if not all(select_func == sock.select for sock in sniff_sockets):
            warning("Warning: inconsistent socket types ! "
                    "The used select function "
                    "will be the one of the first socket")

        close_pipe = None  # type: Optional[ObjectPipe[None]]
        if not nonblocking_socket:
            # select is blocking: Add special control socket
            from scapy.automaton import ObjectPipe
            close_pipe = ObjectPipe[None]()
            sniff_sockets[close_pipe] = "control_socket"  # type: ignore

            def stop_cb():
                # type: () -> None
                if self.running and close_pipe:
                    close_pipe.send(None)
                self.continue_sniff = False
            self.stop_cb = stop_cb
        else:
            # select is non blocking
            def stop_cb():
                # type: () -> None
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
                sockets = select_func(list(sniff_sockets.keys()), remain)
                dead_sockets = []
                for s in sockets:
                    if s is close_pipe:  # type: ignore
                        break
                    try:
                        p = s.recv()
                    except EOFError:
                        # End of stream
                        try:
                            s.close()
                        except Exception:
                            pass
                        dead_sockets.append(s)
                        continue
                    except Exception as ex:
                        msg = " It was closed."
                        try:
                            # Make sure it's closed
                            s.close()
                        except Exception as ex2:
                            msg = " close() failed with '%s'" % ex2
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
                    if len(sniff_sockets) == 1 and \
                            close_pipe in sniff_sockets:  # type: ignore
                        # Only the close_pipe left
                        del sniff_sockets[close_pipe]  # type: ignore
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
        # type: () -> None
        """Starts AsyncSniffer in async mode"""
        self._setup_thread()
        if self.thread:
            self.thread.start()

    def stop(self, join=True):
        # type: (bool) -> Optional[PacketList]
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
            return None
        else:
            raise Scapy_Exception("Not running ! (check .running attr)")

    def join(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        if self.thread:
            self.thread.join(*args, **kwargs)


@conf.commands.register
def sniff(*args, **kwargs):
    # type: (*Any, **Any) -> PacketList
    sniffer = AsyncSniffer()
    sniffer._run(*args, **kwargs)
    return cast(PacketList, sniffer.results)


sniff.__doc__ = AsyncSniffer.__doc__


@conf.commands.register
def bridge_and_sniff(if1,  # type: _GlobInterfaceType
                     if2,  # type: _GlobInterfaceType
                     xfrm12=None,  # type: Optional[Callable[[Packet], Union[Packet, bool]]]  # noqa: E501
                     xfrm21=None,  # type: Optional[Callable[[Packet], Union[Packet, bool]]]  # noqa: E501
                     prn=None,  # type: Optional[Callable[[Packet], Any]]
                     L2socket=None,  # type: Optional[Type[SuperSocket]]
                     *args,  # type: Any
                     **kargs  # type: Any
                     ):
    # type: (...) -> PacketList
    """Forward traffic between interfaces if1 and if2, sniff and return
    the exchanged packets.

    :param if1: the interfaces to use (interface names or opened sockets).
    :param if2:
    :param xfrm12: a function to call when forwarding a packet from if1 to
        if2. If it returns True, the packet is forwarded as it. If it
        returns False or None, the packet is discarded. If it returns a
        packet, this packet is forwarded instead of the original packet
        one.
    :param xfrm21: same as xfrm12 for packets forwarded from if2 to if1.

    The other arguments are the same than for the function sniff(),
    except for offline, opened_socket and iface that are ignored.
    See help(sniff) for more.
    """
    for arg in ['opened_socket', 'offline', 'iface']:
        if arg in kargs:
            log_runtime.warning("Argument %s cannot be used in "
                                "bridge_and_sniff() -- ignoring it.", arg)
            del kargs[arg]

    def _init_socket(iface,  # type: _GlobInterfaceType
                     count,  # type: int
                     L2socket=L2socket  # type: Optional[Type[SuperSocket]]
                     ):
        # type: (...) -> Tuple[SuperSocket, _GlobInterfaceType]
        if isinstance(iface, SuperSocket):
            return iface, "iface%d" % count
        else:
            if not L2socket:
                iface = resolve_iface(iface or conf.iface)
                L2socket = iface.l2socket()
            return L2socket(iface=iface), iface
    sckt1, if1 = _init_socket(if1, 1)
    sckt2, if2 = _init_socket(if2, 2)
    peers = {if1: sckt2, if2: sckt1}
    xfrms = {}
    if xfrm12 is not None:
        xfrms[if1] = xfrm12
    if xfrm21 is not None:
        xfrms[if2] = xfrm21

    def prn_send(pkt):
        # type: (Packet) -> None
        try:
            sendsock = peers[pkt.sniffed_on or ""]
        except KeyError:
            return
        if pkt.sniffed_on in xfrms:
            try:
                _newpkt = xfrms[pkt.sniffed_on](pkt)
            except Exception:
                log_runtime.warning(
                    'Exception in transformation function for packet [%s] '
                    'received on %s -- dropping',
                    pkt.summary(), pkt.sniffed_on, exc_info=True
                )
                return
            else:
                if isinstance(_newpkt, bool):
                    if not _newpkt:
                        return
                    newpkt = pkt
                else:
                    newpkt = _newpkt
        else:
            newpkt = pkt
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
            # type: (Packet) -> Any
            prn_send(pkt)
            return prn_orig(pkt)

    return sniff(opened_socket={sckt1: if1, sckt2: if2}, prn=prn,
                 *args, **kargs)


@conf.commands.register
def tshark(*args, **kargs):
    # type: (Any, Any) -> None
    """Sniff packets and print them calling pkt.summary().
    This tries to replicate what text-wireshark (tshark) would look like"""

    if 'iface' in kargs:
        iface = kargs.get('iface')
    elif 'opened_socket' in kargs:
        iface = cast(SuperSocket, kargs.get('opened_socket')).iface
    else:
        iface = conf.iface
    print("Capturing on '%s'" % iface)

    # This should be a nonlocal variable, using a mutable object
    # for Python 2 compatibility
    i = [0]

    def _cb(pkt):
        # type: (Packet) -> None
        print("%5d\t%s" % (i[0], pkt.summary()))
        i[0] += 1

    sniff(prn=_cb, store=False, *args, **kargs)
    print("\n%d packet%s captured" % (i[0], 's' if i[0] > 1 else ''))
