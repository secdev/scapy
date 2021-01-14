import os
import subprocess
import sys

from platform import python_implementation

from scapy.all import *
import scapy.modules.six as six
from scapy.consts import LINUX

load_layer("can", globals_dict=globals())
conf.contribs['CAN']['swap-bytes'] = False

iface0 = "vcan0"
iface1 = "vcan1"

from scapy.contrib.automotive.ecu import *

print("Set delay to lower utilization")
conf.contribs['ECU_am']['send_delay'] = 0.004

# function to exit when the can-isotp kernel module is not available
ISOTP_KERNEL_MODULE_AVAILABLE = False


def exit_if_no_isotp_module():
    if not ISOTP_KERNEL_MODULE_AVAILABLE:
        err = "TEST SKIPPED: can-isotp not available\n"
        sys.__stderr__.write(err)
        warning("Can't test ISOTP native socket because kernel module is not loaded")
        exit(0)


if LINUX and os.geteuid() == 0:
    try:
        if 0 != subprocess.call(["cansend", iface0,  "000#"]):
            # vcan0 is not enabled
            if 0 != subprocess.call(["sudo", "modprobe", "vcan"]):
                raise Exception("modprobe vcan failed")
            if 0 != subprocess.call(["sudo", "ip", "link", "add", "name", iface0, "type", "vcan"]):
                print("add %s failed: Maybe it was already up?" % iface0)
            if 0 != subprocess.call(["sudo", "ip", "link", "set", "dev", iface0, "up"]):
                raise Exception("could not bring up %s" % iface0)

        if 0 != subprocess.call(["cansend", iface0,  "000#"]):
            raise Exception("cansend doesn't work")

        if 0 != subprocess.call(["cansend", iface1,  "000#"]):
            # vcan1 is not enabled
            if 0 != subprocess.call(["sudo", "modprobe", "vcan"]):
                raise Exception("modprobe vcan failed")
            if 0 != subprocess.call(["sudo", "ip", "link", "add", "name", iface1, "type", "vcan"]):
                print("add %s failed: Maybe it was already up?" % iface1)
            if 0 != subprocess.call(["sudo", "ip", "link", "set", "dev", iface1, "up"]):
                raise Exception("could not bring up %s" % iface1)

        if 0 != subprocess.call(["cansend", iface1,  "000#"]):
            raise Exception("cansend doesn't work")

        print("CAN should work now")
    except Exception:
        print("socket_can doesn't work")


if six.PY3 and LINUX and "pypy" not in python_implementation().lower() and os.geteuid() == 0:
    from scapy.contrib.cansocket_native import *
    new_can_socket = NativeCANSocket
    new_can_socket0 = lambda: NativeCANSocket(iface0)
    new_can_socket1 = lambda: NativeCANSocket(iface1)
    can_socket_string_list = ["-c", iface0]

elif six.PY2 and LINUX and os.geteuid() == 0:
    from scapy.contrib.cansocket_python_can import *
    new_can_socket = lambda iface: PythonCANSocket(bustype='socketcan', channel=iface, timeout=0.01)
    new_can_socket0 = lambda: PythonCANSocket(bustype='socketcan', channel=iface0, timeout=0.01)
    new_can_socket1 = lambda: PythonCANSocket(bustype='socketcan', channel=iface1, timeout=0.01)
    can_socket_string_list = ["-i", "socketcan", "-c", iface0]

else:
    from scapy.contrib.cansocket_python_can import *
    new_can_socket = lambda iface: PythonCANSocket(bustype='virtual', channel=iface)
    new_can_socket0 = lambda: PythonCANSocket(bustype='virtual', channel=iface0, timeout=0.01)
    new_can_socket1 = lambda: PythonCANSocket(bustype='virtual', channel=iface1, timeout=0.01)


s = new_can_socket(iface0)
s.close()
s = new_can_socket(iface1)
s.close()


# utility function for draining a can interface, asserting that no packets are there
def drain_bus(iface=iface0, assert_empty=True):
    with new_can_socket(iface) as s:
        pkts = s.sniff(timeout=0.1)
        if assert_empty and not len(pkts) == 0:
            raise Scapy_Exception("Error in drain_bus. "
                                  "Packets found but no packets expected!")


print("CAN sockets should work now")

if LINUX and os.geteuid() == 0 and six.PY3:
    p1 = subprocess.Popen(['lsmod'], stdout = subprocess.PIPE)
    p2 = subprocess.Popen(['grep', '^can_isotp'], stdout = subprocess.PIPE, stdin=p1.stdout)
    p1.stdout.close()
    if p1.wait() == 0 and p2.wait() == 0 and b"can_isotp" in p2.stdout.read():
        p = subprocess.Popen(["isotpsend", "-s1", "-d0", iface0], stdin = subprocess.PIPE)
        p.communicate(b"01")
        if p.returncode == 0:
            ISOTP_KERNEL_MODULE_AVAILABLE = True


conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': ISOTP_KERNEL_MODULE_AVAILABLE}

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


def cleanup_interfaces():
    if LINUX and "pypy" not in python_implementation().lower() and os.geteuid() == 0:
        if 0 != subprocess.call(["sudo", "ip", "link", "delete", iface0]):
            raise Exception("%s could not be deleted" % iface0)

        if 0 != subprocess.call(["sudo", "ip", "link", "delete", iface1]):
            raise Exception("%s could not be deleted" % iface1)

    return True
