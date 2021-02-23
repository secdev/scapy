# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license


# """ Default imports required for setup of CAN interfaces  """

import os
import subprocess
import sys

from platform import python_implementation

from scapy.all import load_layer, load_contrib, conf, log_runtime
import scapy.modules.six as six
from scapy.consts import LINUX

load_layer("can", globals_dict=globals())
conf.contribs['CAN']['swap-bytes'] = False

# ############################################################################
# """ Define interface names for automotive tests  """
# ############################################################################
iface0 = "vcan0"
iface1 = "vcan1"

try:
    _root = os.geteuid() == 0
except AttributeError:
    _root = False

_not_pypy = "pypy" not in python_implementation().lower()
_socket_can_support = False


def test_and_setup_socket_can(iface_name):
    if 0 != subprocess.call(("cansend %s 000#" % iface_name).split()):
        # iface_name is not enabled
        if 0 != subprocess.call("modprobe vcan".split()):
            raise Exception("modprobe vcan failed")
        if 0 != subprocess.call(
                ("ip link add name %s type vcan" % iface_name).split()):
            log_runtime.debug(
                "add %s failed: Maybe it was already up?" % iface_name)
        if 0 != subprocess.call(
                ("ip link set dev %s up" % iface_name).split()):
            raise Exception("could not bring up %s" % iface_name)

    if 0 != subprocess.call(("cansend %s 000#12" % iface_name).split()):
        raise Exception("cansend doesn't work")

    sys.__stderr__.write("SocketCAN setup done!\n")


if LINUX and _root and _not_pypy:
    test_and_setup_socket_can(iface0)
    test_and_setup_socket_can(iface1)
    log_runtime.debug("CAN should work now")
    _socket_can_support = True


sys.__stderr__.write("SocketCAN support: %s\n" % _socket_can_support)


# ############################################################################
# """ Define helper functions for CANSocket creation on all platforms """
# ############################################################################
if _socket_can_support:
    if six.PY3:
        from scapy.contrib.cansocket_native import *
        new_can_socket = NativeCANSocket
        new_can_socket0 = lambda: NativeCANSocket(iface0)
        new_can_socket1 = lambda: NativeCANSocket(iface1)
        can_socket_string_list = ["-c", iface0]
        sys.__stderr__.write("Using NativeCANSocket\n")

    else:
        from scapy.contrib.cansocket_python_can import *
        new_can_socket = lambda iface: PythonCANSocket(bustype='socketcan', channel=iface, timeout=0.01)
        new_can_socket0 = lambda: PythonCANSocket(bustype='socketcan', channel=iface0, timeout=0.01)
        new_can_socket1 = lambda: PythonCANSocket(bustype='socketcan', channel=iface1, timeout=0.01)
        can_socket_string_list = ["-i", "socketcan", "-c", iface0]
        sys.__stderr__.write("Using PythonCANSocket socketcan\n")

else:
    from scapy.contrib.cansocket_python_can import *
    new_can_socket = lambda iface: PythonCANSocket(bustype='virtual', channel=iface)
    new_can_socket0 = lambda: PythonCANSocket(bustype='virtual', channel=iface0, timeout=0.01)
    new_can_socket1 = lambda: PythonCANSocket(bustype='virtual', channel=iface1, timeout=0.01)
    sys.__stderr__.write("Using PythonCANSocket virtual\n")


# ############################################################################
# """ Test if socket creation functions work """
# ############################################################################
s = new_can_socket(iface0)
s.close()
del s

s = new_can_socket(iface1)
s.close()
del s


def cleanup_interfaces():
    """
    Helper function to remove virtual CAN interfaces after test

    :return: True on success
    """
    import threading
    from scapy.contrib.isotp import CANReceiverThread
    for t in threading.enumerate():
        if isinstance(t, CANReceiverThread):
            t.join(10)

    if LINUX and _not_pypy and _root:
        if 0 != subprocess.call(["ip", "link", "delete", iface0]):
            raise Exception("%s could not be deleted" % iface0)
        if 0 != subprocess.call(["ip", "link", "delete", iface1]):
            raise Exception("%s could not be deleted" % iface1)
    return True


def drain_bus(iface=iface0, assert_empty=True):
    """
    Utility function for draining a can interface,
    asserting that no packets are there

    :param iface: Interface name to drain
    :param assert_empty: If true, raise exception in case packets were received
    """
    with new_can_socket(iface) as s:
        pkts = s.sniff(timeout=0.1)
        if assert_empty and not len(pkts) == 0:
            raise Scapy_Exception(
                "Error in drain_bus. Packets found but no packets expected!")


drain_bus(iface0)
drain_bus(iface1)

log_runtime.debug("CAN sockets should work now")

# ############################################################################
# """ Setup and definitions for ISOTP related stuff """
# ############################################################################

# ############################################################################
# function to exit when the can-isotp kernel module is not available
# ############################################################################
ISOTP_KERNEL_MODULE_AVAILABLE = False


def exit_if_no_isotp_module():
    """
    Helper function to exit a test case if ISOTP kernel module is not available
    """
    if not ISOTP_KERNEL_MODULE_AVAILABLE:
        err = "TEST SKIPPED: can-isotp not available\n"
        sys.__stderr__.write(err)
        warning("Can't test ISOTPNativeSocket because "
                "kernel module isn't loaded")
        sys.exit(0)


# ############################################################################
# """ Evaluate if ISOTP kernel module is installed and available """
# ############################################################################
if LINUX and _root and six.PY3:
    p1 = subprocess.Popen(['lsmod'], stdout=subprocess.PIPE)
    p2 = subprocess.Popen(['grep', '^can_isotp'],
                          stdout=subprocess.PIPE, stdin=p1.stdout)
    p1.stdout.close()
    if p1.wait() == 0 and p2.wait() == 0 and b"can_isotp" in p2.stdout.read():
        p = subprocess.Popen(["isotpsend", "-s1", "-d0", iface0],
                             stdin=subprocess.PIPE)
        p.communicate(b"01")
        if p.returncode == 0:
            ISOTP_KERNEL_MODULE_AVAILABLE = True

# ############################################################################
# """ Save configuration """
# ############################################################################
conf.contribs['ISOTP'] = \
    {'use-can-isotp-kernel-module': ISOTP_KERNEL_MODULE_AVAILABLE}

# ############################################################################
# """ reload ISOTP kernel module in case configuration changed """
# ############################################################################
if six.PY3:
    import importlib
    if "scapy.contrib.isotp" in sys.modules:
        importlib.reload(scapy.contrib.isotp)

load_contrib("isotp", globals_dict=globals())

if six.PY3 and ISOTP_KERNEL_MODULE_AVAILABLE:
    if not ISOTPSocket == ISOTPNativeSocket:
        raise Scapy_Exception("Error in ISOTPSocket import!")
else:
    if not ISOTPSocket == ISOTPSoftSocket:
        raise Scapy_Exception("Error in ISOTPSocket import!")

# ############################################################################
# """ Prepare send_delay on Ecu Answering Machine to stabilize unit tests """
# ############################################################################
from scapy.contrib.automotive.ecu import *
log_runtime.debug("Set send delay to lower utilization on CI machines")
conf.contribs['EcuAnsweringMachine']['send_delay'] = 0.004
