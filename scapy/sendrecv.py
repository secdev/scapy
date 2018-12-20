# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Functions to send and receive packets.
"""

from __future__ import absolute_import, print_function
import itertools
import threading
import os
import socket
import subprocess
import time
import types

from scapy.compat import plain_str
from scapy.data import ETH_P_ALL
from scapy.config import conf
from scapy.error import warning
from scapy.packet import Packet, Gen
from scapy.utils import get_temp_file, PcapReader, tcpdump, wrpcap
from scapy import plist
from scapy.error import log_runtime, log_interactive
from scapy.base_classes import SetGen
from scapy.modules import six
from scapy.modules.six.moves import map
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


####################
#  Send / Receive  #
####################


def _sndrcv_snd(pks, timeout, inter, verbose, tobesent, hsent, timessent, stopevent):  # noqa: E501
    """Function used in the sending thread of sndrcv()"""
    try:
        i = 0
        rec_time = timessent is not None
        if verbose:
            print("Begin emission:")
        for p in tobesent:
            # Populate the dictionary of _sndrcv_rcv
            # _sndrcv_rcv won't miss the answer of a packet that has not been sent  # noqa: E501
            hsent.setdefault(p.hashret(), []).append(p)
            if stopevent.is_set():
                break
            # Send packet
            pks.send(p)
            if rec_time:
                timessent[i] = p.sent_time
            i += 1
            time.sleep(inter)
        if verbose:
            print("Finished sending %i packets." % i)
    except SystemExit:
        pass
    except KeyboardInterrupt:
        pass
    except Exception:
        log_runtime.exception("--- Error sending packets")
    if timeout is not None:
        stopevent.wait(timeout)
        stopevent.set()


def _sndrcv_rcv(pks, hsent, stopevent, nbrecv, notans, verbose, chainCC,
                multi, _storage_policy=None):
    """Function used to receive packets and check their hashret"""
    if not _storage_policy:
        _storage_policy = lambda x, y: (x, y)
    ans = []

    def _get_pkt():
        # SuperSocket.select() returns, according to each socket type,
        # the selected sockets + the function to recv() the packets (or None)
        # (when sockets aren't selectable, should be nonblock_recv)
        selected, read_func = pks.select([pks])
        read_func = read_func or pks.__class__.recv
        if selected:
            return read_func(selected[0])

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
                        ans.append(_storage_policy(sentpkt, r))
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
            del r
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
    finally:
        stopevent.set()
    return (hsent, ans, nbrecv, notans)


def sndrcv(pks, pkt, timeout=None, inter=0, verbose=None, chainCC=False,
           retry=0, multi=False, rcv_pks=None, store_unanswered=True,
           process=None, prebuild=False):
    """Scapy raw function to send a packet and receive its answer.
    WARNING: This is an internal function. Using sr/srp/sr1/srp is
    more appropriate in many cases.

    pks: SuperSocket instance to send/receive packets
    pkt: the packet to send
    rcv_pks: if set, will be used instead of pks to receive packets. packets will still  # noqa: E501
             be sent through pks
    nofilter: put 1 to avoid use of BPF filters
    retry:    if positive, how many times to resend unanswered packets
              if negative, how many times to retry when no more packets are answered  # noqa: E501
    timeout:  how much time to wait after the last packet has been sent
    verbose:  set verbosity level
    multi:    whether to accept multiple answers for the same stimulus
    store_unanswered: whether to store not-answered packets or not. Default True.  # noqa: E501
                      setting it to False will increase speed, and will return None  # noqa: E501
                      as the unans list.
    process:  if specified, only result from process(pkt) will be stored.
              the function should follow the following format:
                lambda sent, received: (func(sent), func2(received))
              if the packet is unanswered, `received` will be None.
              if `store_unanswered` is False, the function won't be called on un-answered packets.  # noqa: E501
    prebuild: pre-build the packets before starting to send them. Default to False. Automatically used  # noqa: E501
              when a generator is passed as the packet
    """
    if verbose is None:
        verbose = conf.verb
    use_prn_mode = False
    _storage_policy = None
    if process is not None:
        use_prn_mode = True
        _storage_policy = lambda x, y: process(x, y)
    debug.recv = plist.PacketList([], "Unanswered")
    debug.sent = plist.PacketList([], "Sent")
    debug.match = plist.SndRcvList([])
    nbrecv = 0
    ans = []
    listable = (isinstance(pkt, Packet) and pkt.__iterlen__() == 1) or isinstance(pkt, list)  # noqa: E501
    # do it here to fix random fields, so that parent and child have the same
    if isinstance(pkt, types.GeneratorType) or prebuild:
        tobesent = [p for p in pkt]
        notans = len(tobesent)
    else:
        tobesent = SetGen(pkt) if not isinstance(pkt, Gen) else pkt
        notans = tobesent.__iterlen__()

    if retry < 0:
        autostop = retry = -retry
    else:
        autostop = 0

    while retry >= 0:
        if timeout is not None and timeout < 0:
            timeout = None
        stopevent = threading.Event()

        hsent = {}
        timessent = {} if listable else None

        thread = threading.Thread(
            target=_sndrcv_snd,
            args=(pks, timeout, inter, verbose, tobesent, hsent, timessent, stopevent),  # noqa: E501
        )
        thread.setDaemon(True)
        thread.start()

        hsent, newans, nbrecv, notans = _sndrcv_rcv(
            (rcv_pks or pks), hsent, stopevent, nbrecv, notans, verbose, chainCC, multi,  # noqa: E501
            _storage_policy=_storage_policy,
        )
        thread.join()

        ans.extend(newans)

        # Restore time_sent to original packets
        if listable:
            i = 0
            for p in (pkt if isinstance(pkt, list) else [pkt]):
                p.sent_time = timessent[i]
                i += 1

        if store_unanswered:
            remain = list(itertools.chain(*six.itervalues(hsent)))
            if multi:
                remain = [p for p in remain if not hasattr(p, '_answered')]

            if autostop and len(remain) > 0 and len(remain) != len(tobesent):
                retry = autostop

            tobesent = remain
            if len(tobesent) == 0:
                break
        else:
            remain = []
        retry -= 1

    if conf.debug_match:
        debug.sent = plist.PacketList(remain[:], "Sent")
        debug.match = plist.SndRcvList(ans[:])

    # Clean the ans list to delete the field _answered
    if multi:
        for snd, _ in ans:
            if hasattr(snd, '_answered'):
                del snd._answered

    if verbose:
        print("\nReceived %i packets, got %i answers, remaining %i packets" % (nbrecv + len(ans), len(ans), notans))  # noqa: E501

    if store_unanswered and use_prn_mode:
        remain = [process(x, None) for x in remain]

    ans_result = ans if use_prn_mode else plist.SndRcvList(ans)
    unans_result = remain if use_prn_mode else (None if not store_unanswered else plist.PacketList(remain, "Unanswered"))  # noqa: E501
    return ans_result, unans_result


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
        sent_packets = plist.PacketList()
    try:
        while loop:
            dt0 = None
            for p in x:
                if realtime:
                    ct = time.time()
                    if dt0:
                        st = dt0 + p.time - ct
                        if st > 0:
                            time.sleep(st)
                    else:
                        dt0 = ct - p.time
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
    s.close()
    if verbose:
        print("\nSent %i packets." % n)
    if return_packets:
        return sent_packets


@conf.commands.register
def send(x, inter=0, loop=0, count=None, verbose=None, realtime=None, return_packets=False, socket=None,  # noqa: E501
         *args, **kargs):
    """Send packets at layer 3
send(packets, [inter=0], [loop=0], [count=None], [verbose=conf.verb], [realtime=None], [return_packets=False],  # noqa: E501
     [socket=None]) -> None"""
    if socket is None:
        socket = conf.L3socket(*args, **kargs)
    return __gen_send(socket, x, inter=inter, loop=loop, count=count, verbose=verbose,  # noqa: E501
                      realtime=realtime, return_packets=return_packets)


@conf.commands.register
def sendp(x, inter=0, loop=0, iface=None, iface_hint=None, count=None, verbose=None, realtime=None,  # noqa: E501
          return_packets=False, socket=None, *args, **kargs):
    """Send packets at layer 2
sendp(packets, [inter=0], [loop=0], [iface=None], [iface_hint=None], [count=None], [verbose=conf.verb],  # noqa: E501
      [realtime=None], [return_packets=False], [socket=None]) -> None"""
    if iface is None and iface_hint is not None and socket is None:
        iface = conf.route.route(iface_hint)[0]
    if socket is None:
        socket = conf.L2socket(iface=iface, *args, **kargs)
    return __gen_send(socket, x, inter=inter, loop=loop, count=count,
                      verbose=verbose, realtime=realtime, return_packets=return_packets)  # noqa: E501


@conf.commands.register
def sendpfast(x, pps=None, mbps=None, realtime=None, loop=0, file_cache=False, iface=None, replay_args=None,  # noqa: E501
              parse_results=False):
    """Send packets at layer 2 using tcpreplay for performance
    pps:  packets per second
    mpbs: MBits per second
    realtime: use packet's timestamp, bending time with real-time value
    loop: number of times to process the packet list
    file_cache: cache packets in RAM instead of reading from disk at each iteration  # noqa: E501
    iface: output interface
    replay_args: List of additional tcpreplay args (List[str])
    parse_results: Return a dictionary of information outputted by tcpreplay (default=False)  # noqa: E501
    :returns stdout, stderr, command used"""
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
    try:
        log_runtime.info(argv)
        with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as cmd:  # noqa: E501
            stdout, stderr = cmd.communicate()
            log_runtime.info(stdout)
            log_runtime.warning(stderr)
            if parse_results:
                results = _parse_tcpreplay_result(stdout, stderr, argv)

    except KeyboardInterrupt:
        log_interactive.info("Interrupted by user")
    except Exception:
        if conf.interactive:
            log_interactive.error("Cannot execute [%s]", argv[0], exc_info=True)  # noqa: E501
        else:
            raise
    finally:
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
        results_dict = {}
        stdout = plain_str(stdout).replace("\nRated: ", "\t\tRated: ").replace("\t", "").split("\n")  # noqa: E501
        stderr = plain_str(stderr).replace("\t", "").split("\n")
        actual = [x for x in stdout[0].split(" ") if x]

        results_dict["packets"] = int(actual[1])
        results_dict["bytes"] = int(actual[3][1:])
        results_dict["time"] = float(actual[7])
        results_dict["bps"] = float(actual[10])
        results_dict["mbps"] = float(actual[12])
        results_dict["pps"] = float(actual[14])
        results_dict["attempted"] = int(stdout[2].split(" ")[-1:][0])
        results_dict["successful"] = int(stdout[3].split(" ")[-1:][0])
        results_dict["failed"] = int(stdout[4].split(" ")[-1:][0])
        results_dict["retried_enobufs"] = int(stdout[5].split(" ")[-1:][0])
        results_dict["retried_eagain"] = int(stdout[6].split(" ")[-1][0])
        results_dict["command"] = str(argv)
        results_dict["warnings"] = stderr[:len(stderr) - 1]
        return results_dict
    except Exception as parse_exception:
        log_runtime.error("Error parsing output: " + str(parse_exception))
        return {}


@conf.commands.register
def sr(x, promisc=None, filter=None, iface=None, nofilter=0, *args, **kargs):
    """Send and receive packets at layer 3
nofilter: put 1 to avoid use of BPF filters
retry:    if positive, how many times to resend unanswered packets
          if negative, how many times to retry when no more packets are answered  # noqa: E501
timeout:  how much time to wait after the last packet has been sent
verbose:  set verbosity level
multi:    whether to accept multiple answers for the same stimulus
filter:   provide a BPF filter
iface:    listen answers only on the given interface
store_unanswered: whether to store not-answered packets or not. Default True.
                  setting it to False will increase speed, and will return None
                  as the unans list.
process:  if specified, only result from process(pkt) will be stored.
          the function should follow the following format:
            lambda sent, received: (func(sent), func2(received))
          if the packet is unanswered, `received` will be None.
          if `store_unanswered` is False, the function won't be called on un-answered packets."""  # noqa: E501
    s = conf.L3socket(promisc=promisc, filter=filter, iface=iface, nofilter=nofilter)  # noqa: E501
    result = sndrcv(s, x, *args, **kargs)
    s.close()
    return result


@conf.commands.register
def sr1(x, promisc=None, filter=None, iface=None, nofilter=0, *args, **kargs):
    """Send packets at layer 3 and return only the first answer
nofilter: put 1 to avoid use of BPF filters
retry:    if positive, how many times to resend unanswered packets
          if negative, how many times to retry when no more packets are answered  # noqa: E501
timeout:  how much time to wait after the last packet has been sent
verbose:  set verbosity level
multi:    whether to accept multiple answers for the same stimulus
filter:   provide a BPF filter
iface:    listen answers only on the given interface
store_unanswered: whether to store not-answered packets or not. Default True.
                  setting it to False will increase speed, and will return None
                  as the unans list.
process:  if specified, only result from process(pkt) will be stored.
          the function should follow the following format:
            lambda sent, received: (func(sent), func2(received))
          if the packet is unanswered, `received` will be None.
          if `store_unanswered` is False, the function won't be called on un-answered packets."""  # noqa: E501
    s = conf.L3socket(promisc=promisc, filter=filter, nofilter=nofilter, iface=iface)  # noqa: E501
    ans, _ = sndrcv(s, x, *args, **kargs)
    s.close()
    if len(ans) > 0:
        return ans[0][1]
    else:
        return None


@conf.commands.register
def srp(x, promisc=None, iface=None, iface_hint=None, filter=None, nofilter=0, type=ETH_P_ALL, *args, **kargs):  # noqa: E501
    """Send and receive packets at layer 2
nofilter: put 1 to avoid use of BPF filters
retry:    if positive, how many times to resend unanswered packets
          if negative, how many times to retry when no more packets are answered  # noqa: E501
timeout:  how much time to wait after the last packet has been sent
verbose:  set verbosity level
multi:    whether to accept multiple answers for the same stimulus
filter:   provide a BPF filter
iface:    work only on the given interface
store_unanswered: whether to store not-answered packets or not. Default True.
                  setting it to False will increase speed, and will return None
                  as the unans list.
process:  if specified, only result from process(pkt) will be stored.
          the function should follow the following format:
            lambda sent, received: (func(sent), func2(received))
          if the packet is unanswered, `received` will be None.
          if `store_unanswered` is False, the function won't be called on un-answered packets."""  # noqa: E501
    if iface is None and iface_hint is not None:
        iface = conf.route.route(iface_hint)[0]
    s = conf.L2socket(promisc=promisc, iface=iface, filter=filter, nofilter=nofilter, type=type)  # noqa: E501
    result = sndrcv(s, x, *args, **kargs)
    s.close()
    return result


@conf.commands.register
def srp1(*args, **kargs):
    """Send and receive packets at layer 2 and return only the first answer
nofilter: put 1 to avoid use of BPF filters
retry:    if positive, how many times to resend unanswered packets
          if negative, how many times to retry when no more packets are answered  # noqa: E501
timeout:  how much time to wait after the last packet has been sent
verbose:  set verbosity level
multi:    whether to accept multiple answers for the same stimulus
filter:   provide a BPF filter
iface:    work only on the given interface
store_unanswered: whether to store not-answered packets or not. Default True.
                  setting it to False will increase speed, and will return None
                  as the unans list.
process:  if specified, only result from process(pkt) will be stored.
          the function should follow the following format:
            lambda sent, received: (func(sent), func2(received))
          if the packet is unanswered, `received` will be None.
          if `store_unanswered` is False, the function won't be called on un-answered packets."""  # noqa: E501
    ans, _ = srp(*args, **kargs)
    if len(ans) > 0:
        return ans[0][1]
    else:
        return None

# SEND/RECV LOOP METHODS


def __sr_loop(srfunc, pkts, prn=lambda x: x[1].summary(), prnfail=lambda x: x.summary(), inter=1, timeout=None, count=None, verbose=None, store=1, *args, **kargs):  # noqa: E501
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
    return plist.SndRcvList(ans), plist.PacketList(unans)


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


def sndrcvflood(pks, pkt, inter=0, verbose=None, chainCC=False, store_unanswered=True, process=None, timeout=None):  # noqa: E501
    if not verbose:
        verbose = conf.verb
    listable = (isinstance(pkt, Packet) and pkt.__iterlen__() == 1) or isinstance(pkt, list)  # noqa: E501
    tobesent = pkt

    use_prn_mode = False
    _storage_policy = None
    if process is not None:
        use_prn_mode = True
        _storage_policy = lambda x, y: process(x, y)

    stopevent = threading.Event()
    count_packets = six.moves.queue.Queue()
    hsent = {}
    timessent = {} if listable else None

    def send_in_loop(tobesent, stopevent, count_packets=count_packets):
        """Infinite generator that produces the same packet until stopevent is triggered."""  # noqa: E501
        while True:
            for p in tobesent:
                if stopevent.is_set():
                    return
                count_packets.put(0)
                yield p

    infinite_gen = send_in_loop(tobesent, stopevent)

    def _timeout(timeout):
        stopevent.wait(timeout)
        stopevent.set()

    timeout_thread = threading.Thread(
        target=_timeout,
        args=(timeout,)
    )
    timeout_thread.setDaemon(True)
    timeout_thread.start()

    # We don't use _sndrcv_snd verbose (it messes the logs up as in a thread that ends after receiving)  # noqa: E501
    thread = threading.Thread(
        target=_sndrcv_snd,
        args=(pks, None, inter, False, infinite_gen, hsent, timessent, stopevent),  # noqa: E501
    )
    thread.setDaemon(True)
    thread.start()

    hsent, ans, nbrecv, notans = _sndrcv_rcv(
        pks, hsent, stopevent, 0, len(tobesent), verbose, chainCC, False,
        _storage_policy=_storage_policy
    )
    thread.join()

    # Restore time_sent to original packets
    if listable:
        i = 0
        for p in (pkt if isinstance(pkt, list) else [pkt]):
            p.sent_time = timessent[i]
            i += 1

    if process is not None:
        ans = [(x, process(y)) for (x, y) in ans]  # Apply process

    if store_unanswered:
        if use_prn_mode:
            remain = [process(x, None) for x in itertools.chain(*six.itervalues(hsent))]  # noqa: E501
        else:
            remain = list(itertools.chain(*six.itervalues(hsent)))

    if verbose:
        print("\nReceived %i packets, got %i answers, remaining %i packets. Sent a total of %i packets." % (nbrecv + len(ans), len(ans), notans, count_packets.qsize()))  # noqa: E501
    count_packets.empty()
    del count_packets

    ans_result = ans if use_prn_mode else plist.SndRcvList(ans)
    unans_result = remain if use_prn_mode else (None if not store_unanswered else plist.PacketList(remain, "Unanswered"))  # noqa: E501
    return ans_result, unans_result


@conf.commands.register
def srflood(x, promisc=None, filter=None, iface=None, nofilter=None, *args, **kargs):  # noqa: E501
    """Flood and receive packets at layer 3
prn:      function applied to packets received
unique:   only consider packets whose print
nofilter: put 1 to avoid use of BPF filters
filter:   provide a BPF filter
iface:    listen answers only on the given interface"""
    s = conf.L3socket(promisc=promisc, filter=filter, iface=iface, nofilter=nofilter)  # noqa: E501
    r = sndrcvflood(s, x, *args, **kargs)
    s.close()
    return r


@conf.commands.register
def sr1flood(x, promisc=None, filter=None, iface=None, nofilter=0, *args, **kargs):  # noqa: E501
    """Flood and receive packets at layer 3 and return only the first answer
prn:      function applied to packets received
verbose:  set verbosity level
nofilter: put 1 to avoid use of BPF filters
filter:   provide a BPF filter
iface:    listen answers only on the given interface"""
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
prn:      function applied to packets received
unique:   only consider packets whose print
nofilter: put 1 to avoid use of BPF filters
filter:   provide a BPF filter
iface:    listen answers only on the given interface"""
    if iface is None and iface_hint is not None:
        iface = conf.route.route(iface_hint)[0]
    s = conf.L2socket(promisc=promisc, filter=filter, iface=iface, nofilter=nofilter)  # noqa: E501
    r = sndrcvflood(s, x, *args, **kargs)
    s.close()
    return r


@conf.commands.register
def srp1flood(x, promisc=None, filter=None, iface=None, nofilter=0, *args, **kargs):  # noqa: E501
    """Flood and receive packets at layer 2 and return only the first answer
prn:      function applied to packets received
verbose:  set verbosity level
nofilter: put 1 to avoid use of BPF filters
filter:   provide a BPF filter
iface:    listen answers only on the given interface"""
    s = conf.L2socket(promisc=promisc, filter=filter, nofilter=nofilter, iface=iface)  # noqa: E501
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
          stop_filter=None, iface=None, started_callback=None, *arg, **karg):
    """Sniff packets and return a list of packets.

    Args:
        count: number of packets to capture. 0 means infinity.
        store: whether to store sniffed packets or discard them
        prn: function to apply to each packet. If something is returned, it
             is displayed.
             --Ex: prn = lambda x: x.summary()
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
        stoptime = time.time() + timeout
    remain = None

    # Get select information from the sockets
    _main_socket = next(iter(sniff_sockets))
    read_allowed_exceptions = _main_socket.read_allowed_exceptions
    select_func = _main_socket.select
    # We check that all sockets use the same select(), or raise a warning
    if not all(select_func == sock.select for sock in sniff_sockets):
        warning("Warning: inconsistent socket types ! The used select function"
                "will be the one of the first socket")
    # Now let's build the select function, used later on
    _select = lambda sockets, remain: select_func(sockets, remain)[0]

    try:
        if started_callback:
            started_callback()
        while sniff_sockets:
            if timeout is not None:
                remain = stoptime - time.time()
                if remain <= 0:
                    break
            for s in _select(sniff_sockets, remain):
                try:
                    p = s.recv()
                except socket.error as ex:
                    log_runtime.warning("Socket %s failed with '%s' and thus"
                                        " will be ignored" % (s, ex))
                    del sniff_sockets[s]
                    continue
                except read_allowed_exceptions:
                    continue
                if p is None:
                    try:
                        if s.promisc:
                            continue
                    except AttributeError:
                        pass
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
    return plist.PacketList(lst, "Sniffed")


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
    """Sniff packets and print them calling pkt.summary(), a bit like text wireshark"""  # noqa: E501
    print("Capturing on '" + str(kargs.get('iface') if 'iface' in kargs else conf.iface) + "'")  # noqa: E501
    i = [0]  # This should be a nonlocal variable, using a mutable object for Python 2 compatibility  # noqa: E501

    def _cb(pkt):
        print("%5d\t%s" % (i[0], pkt.summary()))
        i[0] += 1
    sniff(prn=_cb, store=False, *args, **kargs)
    print("\n%d packet%s captured" % (i[0], 's' if i[0] > 1 else ''))
