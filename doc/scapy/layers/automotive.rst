**********
Automotive
**********

Overview
========

.. note::
    All automotive related features work best on Linux systems. CANSockets and ISOTPSockets in Scapy are based on Linux kernel modules.
    The python-can project is used to support CAN and CANSockets on other systems, besides Linux.
    This guide explains the hardware setup on a BeagleBone Black. The BeagleBone Black was chosen because of its two CAN interfaces on the main processor.
    The presence of two CAN interfaces in one device gives the possibility of CAN MITM attacks and session hijacking.
    The Cannelloni framework turns a single board computer into a CAN-to-UDP interface, which gives you the freedom to run Scapy
    on a more powerful machine.

Protocols
---------

The following table should give a brief overview about all automotive capabilities
of Scapy. Most application layer protocols have many specialized ``Packet`` classes.
These special purpose classes are not part of this overview. Use the ``explore()``
function to get all information about one specific protocol.

+---------------------+----------------------+--------------------------------------------------------+
| OSI Layer           | Protocol             | Scapy Implementations                                  |
+=====================+======================+========================================================+
| Application Layer   | UDS (ISO 14229)      | UDS, UDS_*, UDS_TesterPresentSender                    |
|                     +----------------------+--------------------------------------------------------+
|                     | GMLAN                | GMLAN, GMLAN_*, GMLAN_TesterPresentSender              |
|                     +----------------------+--------------------------------------------------------+
|                     | SOME/IP              | SOMEIP, SD                                             |
|                     +----------------------+--------------------------------------------------------+
|                     | BMW HSFZ             | HSFZ, HSFZSocket                                       |
|                     +----------------------+--------------------------------------------------------+
|                     | OBD                  | OBD, OBD_S0X                                           |
|                     +----------------------+--------------------------------------------------------+
|                     | CCP                  | CCP, DTO, CRO                                          |
|                     +----------------------+--------------------------------------------------------+
|                     | XCP                  | XCPOnCAN, XCPOnUDP, XCPOnTCP, CTORequest, CTOResponse, |
|                     |                      | DTO                                                    |
+---------------------+----------------------+--------------------------------------------------------+
| Transportation Layer| ISO-TP (ISO 15765-2) | ISOTPSocket, ISOTPNativeSocket, ISOTPSoftSocket        |
|                     |                      |                                                        |
|                     |                      | ISOTPSniffer, ISOTPMessageBuilder, ISOTPSession        |
|                     |                      |                                                        |
|                     |                      | ISOTPHeader, ISOTPHeaderEA, ISOTPScan                  |
|                     |                      |                                                        |
|                     |                      | ISOTP, ISOTP_SF, ISOTP_FF, ISOTP_CF, ISOTP_FC          |
+---------------------+----------------------+--------------------------------------------------------+
| Data Link Layer     | CAN (ISO 11898)      | CAN, CANSocket, rdcandump, CandumpReader               |
+---------------------+----------------------+--------------------------------------------------------+


CAN Layer
=========

How-To
--------

Send and receive a message over Linux SocketCAN::

   load_layer("can")
   load_contrib('cansocket')

   socket = CANSocket(channel='can0')
   packet = CAN(identifier=0x123, data=b'01020304')

   socket.send(packet)
   rx_packet = socket.recv()

   socket.sr1(packet, timeout=1)

Send a message over a Vector CAN-Interface::

   import can
   load_layer("can")
   conf.contribs['CANSocket'] = {'use-python-can' : True}
   load_contrib('cansocket')
   from can.interfaces.vector import VectorBus

   socket = CANSocket(channel=VectorBus(0, bitrate=1000000))
   packet = CAN(identifier=0x123, data=b'01020304')

   socket.send(packet)
   rx_packet = socket.recv()

   socket.sr1(packet)



Tutorials
---------

Linux SocketCAN
^^^^^^^^^^^^^^^

This subsection summarizes some basics about Linux SocketCAN. An excellent overview
from Oliver Hartkopp can be found here: https://wiki.automotivelinux.org/_media/agl-distro/agl2017-socketcan-print.pdf

Virtual CAN Setup
^^^^^^^^^^^^^^^^^

Linux SocketCAN supports virtual CAN interfaces. These interfaces are an easy way
to do some first steps on a CAN-Bus without the requirement of special hardware.
Besides that, virtual CAN interfaces are heavily used in Scapy unit test for automotive
related contributions.

Virtual CAN sockets require a special Linux kernel module. The following shell command loads the required module::

    sudo modprobe vcan

In order to use a virtual CAN interface some additional commands for setup are required.
This snippet chooses the name ``vcan0`` for the virtual CAN interface. Any name can be chosen here::

    sudo ip link add name vcan0 type vcan
    sudo ip link set dev vcan0 up

The same commands can be executed from Scapy like this::

   from scapy.layers.can import *
   import os

   bashCommand = "/bin/bash -c 'sudo modprobe vcan; sudo ip link add name vcan0 type vcan; sudo ip link set dev vcan0 up'"
   os.system(bashCommand)

If it's required, a CAN interface can be set into a ``listen-only`` or ``loopback`` mode with ``ip link set`` commands::

   ip link set vcan0 type can help  # shows additional information


Linux can-utils
^^^^^^^^^^^^^^^

As part of Linux SocketCAN, some very useful commandline tools are provided from Oliver Hartkopp: https://github.com/linux-can/can-utils

The following example shows basic functions of Linux can-utils. These utilities are very handy for
quick checks, dumping, sending or logging of CAN messages from the command line.

.. image:: ../graphics/animations/animation-cansend.svg

CAN Frame
^^^^^^^^^

Basic information about CAN can be found here: https://en.wikipedia.org/wiki/CAN_bus

The following examples assume that CAN layer in your Scapy session is loaded. If it isn't,
the CAN layer can be loaded with this command in your Scapy session::

    >>> load_layer("can")

Creation of a standard CAN frame::

    >>> frame = CAN(identifier=0x200, length=8, data=b'\x01\x02\x03\x04\x05\x06\x07\x08')

Creation of an extended CAN frame::

   frame = CAN(flags='extended', identifier=0x10010000, length=8, data=b'\x01\x02\x03\x04\x05\x06\x07\x08')
   >>> frame.show()
   ###[ CAN ]###
     flags= extended
     identifier= 0x10010000
     length= 8
     reserved= 0
     data= '\x01\x02\x03\x04\x05\x06\x07\x08'


.. image:: ../graphics/animations/animation-scapy-canframe.svg

CAN Frame in- and export
^^^^^^^^^^^^^^^^^^^^^^^^

CAN Frames can be written to and read from ``pcap`` files::

   x = CAN(identifier=0x7ff,length=8,data=b'\x01\x02\x03\x04\x05\x06\x07\x08')
   wrpcap('/tmp/scapyPcapTest.pcap', x, append=False)
   y = rdpcap('/tmp/scapyPcapTest.pcap', 1)

.. image:: ../graphics/animations/animation-scapy-rdpcap.svg

Additionally CAN Frames can be imported from ``candump`` output and log files.
The ``CandumpReader`` class can be used in the same way as a ``socket`` object.
This allows you to use ``sniff`` and other functions from Scapy::

    with CandumpReader("candump.log") as sock:
        can_msgs = sniff(count=50, opened_socket=sock)

.. image:: ../graphics/animations/animation-scapy-rdcandump.svg

Scapy CANSocket
^^^^^^^^^^^^^^^

In Scapy, two kind of CANSockets are implemented. One implementation is called **Native CANSocket**,
the other implementation is called **Python-can CANSocket**.

Since Python 3 supports ``PF_CAN`` sockets, **Native CANSockets** can be used on a
Linux based system with Python 3 or higher. These sockets have a performance advantage
because ``select`` is callable on them. This has a big effect in MITM scenarios.

For compatibility reasons, **Python-can CANSockets** were added to Scapy.
On Windows or OSX and on all systems without Python 3, CAN buses can be accessed
through ``python-can``. ``python-can`` needs to be installed on the system: https://github.com/hardbyte/python-can/
**Python-can CANSockets** are a wrapper of python-can interface objects for Scapy.
Both CANSockets provide the same API which makes them exchangeable under most conditions.
Nevertheless some unique behaviours of each CANSocket type has to be respected.
Some CAN-interfaces, like Vector hardware is only supported on Windows.
These interfaces can be used through **Python-can CANSockets**.

Native CANSocket
^^^^^^^^^^^^^^^^

Creating a simple native CANSocket::

   conf.contribs['CANSocket'] = {'use-python-can': False} #(default)
   load_contrib('cansocket')

   # Simple Socket
   socket = CANSocket(channel="vcan0")

Creating a native CANSocket only listen for messages with Id == 0x200::

   socket = CANSocket(channel="vcan0", can_filters=[{'can_id': 0x200, 'can_mask': 0x7FF}])

Creating a native CANSocket only listen for messages with Id >= 0x200 and Id <= 0x2ff::

   socket = CANSocket(channel="vcan0", can_filters=[{'can_id': 0x200, 'can_mask': 0x700}])

Creating a native CANSocket only listen for messages with Id != 0x200::

   socket = CANSocket(channel="vcan0", can_filters=[{'can_id': 0x200 | CAN_INV_FILTER, 'can_mask': 0x7FF}])

Creating a native CANSocket with multiple can_filters::

   socket = CANSocket(channel='vcan0', can_filters=[{'can_id': 0x200, 'can_mask': 0x7ff},
                                                  {'can_id': 0x400, 'can_mask': 0x7ff},
                                                  {'can_id': 0x600, 'can_mask': 0x7ff},
                                                  {'can_id': 0x7ff, 'can_mask': 0x7ff}])

Creating a native CANSocket which also receives its own messages::

   socket = CANSocket(channel="vcan0", receive_own_messages=True)

.. image:: ../graphics/animations/animation-scapy-native-cansocket.svg

Sniff on a CANSocket:

.. image:: ../graphics/animations/animation-scapy-cansockets-sniff.svg


CANSocket python-can
^^^^^^^^^^^^^^^^^^^^

python-can is required to use various CAN-interfaces on Windows, OSX or Linux.
The python-can library is used through a CANSocket object. To create a python-can
CANSocket object, all parameters of a python-can ``interface.Bus`` object has to 
be used for the initialization of the CANSocket.

Ways of creating a python-can CANSocket::

   conf.contribs['CANSocket'] = {'use-python-can': True}
   load_contrib('cansocket')

Creating a simple python-can CANSocket::

   socket = CANSocket(bustype='socketcan', channel='vcan0', bitrate=250000)

Creating a python-can CANSocket with multiple filters::

   socket = CANSocket(bustype='socketcan', channel='vcan0', bitrate=250000,
                   can_filters=[{'can_id': 0x200, 'can_mask': 0x7ff},
                               {'can_id': 0x400, 'can_mask': 0x7ff},
                               {'can_id': 0x600, 'can_mask': 0x7ff},
                               {'can_id': 0x7ff, 'can_mask': 0x7ff}])

For further details on python-can check: https://python-can.readthedocs.io/

CANSocket MITM attack with bridge and sniff
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
This example shows how to use bridge and sniff on virtual CAN interfaces.
For real world applications, use real CAN interfaces.
Set up two vcans on Linux terminal::

   sudo modprobe vcan
   sudo ip link add name vcan0 type vcan
   sudo ip link add name vcan1 type vcan
   sudo ip link set dev vcan0 up
   sudo ip link set dev vcan1 up

Import modules::

   import threading
   load_contrib('cansocket')
   load_layer("can")

Create can sockets for attack::

   socket0 = CANSocket(channel='vcan0')
   socket1 = CANSocket(channel='vcan1')

Create a function to send packet with threading::

   def sendPacket():
       sleep(0.2)
       socket0.send(CAN(flags='extended', identifier=0x10010000, length=8, data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))

Create a function for forwarding or change packets::

   def forwarding(pkt):
       return pkt

Create a function to bridge and sniff between two sockets::

   def bridge():
       bSocket0 = CANSocket(channel='vcan0')
       bSocket1 = CANSocket(channel='vcan1')
       bridge_and_sniff(if1=bSocket0, if2=bSocket1, xfrm12=forwarding, xfrm21=forwarding, timeout=1)
       bSocket0.close()
       bSocket1.close()

Create threads for sending packet and to bridge and sniff::

   threadBridge = threading.Thread(target=bridge)
   threadSender = threading.Thread(target=sendMessage)

Start the threads::

   threadBridge.start()
   threadSender.start()

Sniff packets::

   packets = socket1.sniff(timeout=0.3)

Close the sockets::

   socket0.close()
   socket1.close()

.. image:: ../graphics/animations/animation-scapy-cansockets-mitm.svg
.. image:: ../graphics/animations/animation-scapy-cansockets-mitm2.svg

DBC File Format and CAN Signals
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In order to support the DBC file format, ``SignalFields`` and the ``SignalPacket``
classes were added to Scapy. ``SignalFields`` should only be used inside a ``SignalPacket``.
Multiplexer fields (MUX) can be created through ``ConditionalFields``. The following
example demonstrates the usage::

    DBC Example:

    BO_ 4 muxTestFrame: 7 TEST_ECU
     SG_ myMuxer M : 53|3@1+ (1,0) [0|0] ""  CCL_TEST
     SG_ muxSig4 m0 : 25|7@1- (1,0) [0|0] ""  CCL_TEST
     SG_ muxSig3 m0 : 16|9@1+ (1,0) [0|0] ""  CCL_TEST
     SG_ muxSig2 m0 : 15|8@0- (1,0) [0|0] ""  CCL_TEST
     SG_ muxSig1 m0 : 0|8@1- (1,0) [0|0] ""  CCL_TEST
     SG_ muxSig5 m1 : 22|7@1- (0.01,0) [0|0] ""  CCL_TEST
     SG_ muxSig6 m1 : 32|9@1+ (2,10) [0|0] "mV"  CCL_TEST
     SG_ muxSig7 m1 : 2|8@0- (0.5,0) [0|0] ""  CCL_TEST
     SG_ muxSig8 m1 : 0|6@1- (10,0) [0|0] ""  CCL_TEST
     SG_ muxSig9 : 40|8@1- (100,-5) [0|0] "V"  CCL_TEST

    BO_ 3 testFrameFloat: 8 TEST_ECU
     SG_ floatSignal2 : 32|32@1- (1,0) [0|0] ""  CCL_TEST
     SG_ floatSignal1 : 7|32@0- (1,0) [0|0] ""  CCL_TEST

Scapy implementation of this DBC description::

    class muxTestFrame(SignalPacket):
        fields_desc = [
            LEUnsignedSignalField("myMuxer", default=0, start=53, size=3),
            ConditionalField(LESignedSignalField("muxSig4", default=0, start=25, size=7), lambda p: p.myMuxer == 0),
            ConditionalField(LEUnsignedSignalField("muxSig3", default=0, start=16, size=9), lambda p: p.myMuxer == 0),
            ConditionalField(BESignedSignalField("muxSig2", default=0, start=15, size=8), lambda p: p.myMuxer == 0),
            ConditionalField(LESignedSignalField("muxSig1", default=0, start=0, size=8), lambda p: p.myMuxer == 0),
            ConditionalField(LESignedSignalField("muxSig5", default=0, start=22, size=7, scaling=0.01), lambda p: p.myMuxer == 1),
            ConditionalField(LEUnsignedSignalField("muxSig6", default=0, start=32, size=9, scaling=2, offset=10, unit="mV"), lambda p: p.myMuxer == 1),
            ConditionalField(BESignedSignalField("muxSig7", default=0, start=2, size=8, scaling=0.5), lambda p: p.myMuxer == 1),
            ConditionalField(LESignedSignalField("muxSig8", default=0, start=3, size=3, scaling=10), lambda p: p.myMuxer == 1),
            LESignedSignalField("muxSig9", default=0, start=41, size=7, scaling=100, offset=-5, unit="V"),
        ]

    class testFrameFloat(SignalPacket):
        fields_desc = [
            LEFloatSignalField("floatSignal2", default=0, start=32),
            BEFloatSignalField("floatSignal1", default=0, start=7)
        ]

    bind_layers(SignalHeader, muxTestFrame, identifier=0x123)
    bind_layers(SignalHeader, testFrameFloat, identifier=0x321)

    dbc_sock = CANSocket("can0", basecls=SignalHeader)

    pkt = SignalHeader()/testFrameFloat(floatSignal2=3.4)

    dbc_sock.send(pkt)

This example uses the class ``SignalHeader`` as header. The payload is specified by individual ``SignalPackets``.
``bind_layers`` combines the header with the payload dependent on the CAN identifier.
If you want to directly receive ``SignalPackets`` from your ``CANSocket``, provide the parameter ``basecls`` to
the ``init`` function of your ``CANSocket``.

Canmatrix supports the creation of Scapy files from DBC or AUTOSAR XML files https://github.com/ebroecker/canmatrix


CAN Calibration Protocol (CCP)
==============================

CCP is derived from CAN. The CAN-header is part of a CCP frame. CCP has two types
of message objects. One is called Command Receive Object (CRO), the other is called
Data Transmission Object (DTO). Usually CROs are sent to an Ecu, and DTOs are received
from an Ecu. The information, if one DTO answers a CRO is implemented through a counter
field (ctr). If both objects have the same counter value, the payload of a DTO object
can be interpreted from the command of the associated CRO object.

Creating a CRO message::

    load_contrib('automotive.ccp')
    CCP(identifier=0x700)/CRO(ctr=1)/CONNECT(station_address=0x02)
    CCP(identifier=0x711)/CRO(ctr=2)/GET_SEED(resource=2)
    CCP(identifier=0x711)/CRO(ctr=3)/UNLOCK(key=b"123456")

If we aren't interested in the DTO of an Ecu, we can just send a CRO message like this:
Sending a CRO message::

    pkt = CCP(identifier=0x700)/CRO(ctr=1)/CONNECT(station_address=0x02)
    sock = CANSocket(bustype='socketcan', channel='vcan0')
    sock.send(pkt)

If we are interested in the DTO of an Ecu, we need to set the basecls parameter of the
CANSocket to CCP and we need to use sr1:
Sending a CRO message::

    cro = CCP(identifier=0x700)/CRO(ctr=0x53)/PROGRAM_6(data=b"\x10\x11\x12\x10\x11\x12")
    sock = CANSocket(bustype='socketcan', channel='vcan0', basecls=CCP)
    dto = sock.sr1(cro)
    dto.show()
    ###[ CAN Calibration Protocol ]###
      flags=
      identifier= 0x700
      length= 8
      reserved= 0
    ###[ DTO ]###
         packet_id= 0xff
         return_code= acknowledge / no error
         ctr= 83
    ###[ PROGRAM_6_DTO ]###
            MTA0_extension= 2
            MTA0_address= 0x34002006

Since sr1 calls the answers function, our payload of the DTO objects gets interpreted with the
command of our CRO object.


Universal calibration and measurement protocol (XCP)
====================================================

XCP is the successor of CCP. It is usable with several protocols. Scapy includes CAN, UDP and TCP.
XCP has two types of message types: Command Transfer Object (CTO) and Data Transmission Object (DTO).
CTOs send to an Ecu are requests (commands) and the Ecu has to reply with a positive response or an error.
Additionally, the Ecu can send a CTO to inform the master about an asynchronous event (EV) or request a service execution (SERV).
DTOs sent by the Ecu are called DAQ (Data AcQuisition) and include measured values.
DTOs received by the Ecu are used for a periodic stimulation and are called STIM (Stimulation).


Creating a CTO message::

    CTORequest() / Connect()
    CTORequest() / GetDaqResolutionInfo()
    CTORequest() / GetSeed(mode=0x01, resource=0x00)

To send the message over CAN a header has to be added

    pkt = XCPOnCAN(identifier=0x700) / CTORequest() / Connect()
    sock = CANSocket(iface=can.interface.Bus(bustype='socketcan', channel='vcan0'))
    sock.send(pkt)

If we are interested in the response of an Ecu, we need to set the basecls parameter of the
CANSocket to XCPonCAN and we need to use sr1:
Sending a CTO message::

    sock = CANSocket(bustype='socketcan', channel='vcan0', basecls=XCPonCAN)
    dto = sock.sr1(pkt)

Since sr1 calls the answers function, our payload of the XCP-response objects gets interpreted with the
command of our CTO object. Otherwise it could not be interpreted.
The first message should always be the "CONNECT" message, the response of the Ecu determines how the messages are read. E.g.: byte order.
Otherwise, one must set the address granularity, and max size of the DTOs and CTOs per hand in the contrib config::

    conf.contribs['XCP']['Address_Granularity_Byte'] = 1  # Can be 1, 2 or 4
    conf.contribs['XCP']['MAX_CTO'] = 8
    conf.contribs['XCP']['MAX_DTO'] = 8

If you do not want this to be set after receiving the message you can also disable that feature::

    conf.contribs['XCP']['allow_byte_order_change'] = False
    conf.contribs['XCP']['allow_ag_change'] = False
    conf.contribs['XCP']['allow_cto_and_dto_change'] = False

To send a pkt over TCP or UDP another header must be used.
TCP::

    prt1, prt2 = 12345, 54321
    XCPOnTCP(sport=prt1, dport=prt2) / CTORequest() / Connect()

UDP::

    XCPOnUDP(sport=prt1, dport=prt2) / CTORequest() / Connect()



ISOTP
=====

System compatibilities
----------------------

Dependent on your setup, different implementations have to be used.

+---------------------+----------------------+-------------------------------------+----------------------------------------------------------+
| Python \ OS         | Linux with can_isotp | Linux wo can_isotp                  | Windows / OSX                                            |
+=====================+======================+=====================================+==========================================================+
| Python 3            | ISOTPNativeSocket    | ISOTPSoftSocket                     | ISOTPSoftSocket                                          |
|                     +----------------------+-------------------------------------+                                                          |
|                     | ``conf.contribs['CANSocket'] = {'use-python-can': False}`` | ``conf.contribs['CANSocket'] = {'use-python-can': True}``|
+---------------------+------------------------------------------------------------+----------------------------------------------------------+
| Python 2            | ISOTPSoftSocket                                                                                                       |
|                     |                                                                                                                       |
|                     | ``conf.contribs['CANSocket'] = {'use-python-can': True}``                                                             |
+---------------------+------------------------------------------------------------+----------------------------------------------------------+

The class ``ISOTPSocket`` can be set to a ``ISOTPNativeSocket`` or a ``ISOTPSoftSocket``.
The decision is made dependent on the configuration ``conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}`` (to select ``ISOTPNativeSocket``) or
``conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': False}`` (to select ``ISOTPSoftSocket``).
This will allow you to write platform independent code. Apply this configuration before loading the ISOTP layer
with ``load_contrib('isotp')``.

Another remark in respect to ISOTPSocket compatibility. Always use with for socket creation. Example::

    with ISOTPSocket("vcan0", did=0x241, sid=0x641) as sock:
        sock.send(...)



ISOTP message
-------------

Creating an ISOTP message::

   load_contrib('isotp')
   ISOTP(src=0x241, dst=0x641, data=b"\x3eabc")

Creating an ISOTP message with extended addressing::

   ISOTP(src=0x241, dst=0x641, exdst=0x41, data=b"\x3eabc")

Creating an ISOTP message with extended addressing::

   ISOTP(src=0x241, dst=0x641, exdst=0x41, exsrc=0x41, data=b"\x3eabc")

Create CAN-frames from an ISOTP message::

   ISOTP(src=0x241, dst=0x641, exdst=0x41, exsrc=0x55, data=b"\x3eabc" * 10).fragment()

Send ISOTP message over ISOTP socket::

   isoTpSocket = ISOTPSocket('vcan0', sid=0x241, did=0x641)
   isoTpMessage = ISOTP('Message')
   isoTpSocket.send(isoTpMessage)

Sniff ISOTP message::

   isoTpSocket = ISOTPSocket('vcan0', sid=0x641, did=0x241)
   packets = isoTpSocket.sniff(timeout=0.5)

ISOTP MITM attack with bridge and sniff
---------------------------------------

Set up two vcans on Linux terminal::

   sudo modprobe vcan
   sudo ip link add name vcan0 type vcan
   sudo ip link add name vcan1 type vcan
   sudo ip link set dev vcan0 up
   sudo ip link set dev vcan1 up

Set up ISOTP:

First make sure you installed an iso-tp kernel module.

When the vcan core module is loaded with "sudo modprobe vcan" the iso-tp module can be loaded to the kernel.

Therefore navigate to isotp directory, and load module with "sudo insmod ./net/can/can-isotp.ko". (Tested on Kernel 4.9.135-1-MANJARO)

Detailed instructions you find in https://github.com/hartkopp/can-isotp.

Import modules::

   import threading
   load_contrib('cansocket')
   conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
   load_contrib('isotp')

Create to ISOTP sockets for attack::

   isoTpSocketVCan0 = ISOTPSocket('vcan0', sid=0x241, did=0x641)
   isoTpSocketVCan1 = ISOTPSocket('vcan1', sid=0x641, did=0x241)

Create function to send packet on vcan0 with threading::

   def sendPacketWithISOTPSocket():
       sleep(0.2)
       packet = ISOTP('Request')
       isoTpSocketVCan0.send(packet)

Create function to forward packet::

   def forwarding(pkt):
       return pkt

Create function to bridge and sniff between two buses::

   def bridge():
       bSocket0 = ISOTPSocket('vcan0', sid=0x641, did=0x241)
       bSocket1 = ISOTPSocket('vcan1', sid=0x241, did=0x641)
       bridge_and_sniff(if1=bSocket0, if2=bSocket1, xfrm12=forwarding, xfrm21=forwarding, timeout=1)
       bSocket0.close()
       bSocket1.close()

Create threads for sending packet and to bridge and sniff::

   threadBridge = threading.Thread(target=bridge)
   threadSender = threading.Thread(target=sendPacketWithISOTPSocket)

Start threads are based on Linux kernel modules. The python-can project is used to support CAN and CANSockets on other systems, besides Linux. This guide explains the hardware setup on a BeagleBone Black. The BeagleBone Black was chosen because of its two CAN interfaces on the main processor. The presence of two CAN interfaces in one device gives the possibility of CAN MITM attacks and session hijacking. The Cannelloni framework turns a BeagleBone Black into a CAN-to-UDP interface, which gives you the freedom to run Scapy on a more powerful machine.::

   threadBridge.start()
   threadSender.start()

Sniff on vcan1::

   receive = isoTpSocketVCan1.sniff(timeout=1)

Close sockets::

   isoTpSocketVCan0.close()
   isoTpSocketVCan1.close()

An ISOTPSocket will not respect ``src, dst, exdst, exsrc`` of an ISOTP message object.

ISOTP Sockets
=============

Scapy provides two kinds of ISOTP Sockets. One implementation, the ISOTPNativeSocket
is using the Linux kernel module from Hartkopp. The other implementation, the ISOTPSoftSocket
is completely implemented in Python. This implementation can be used on Linux,
Windows, and OSX.

ISOTPNativeSocket
-----------------

**Requires:**

* Python3
* Linux
* Hartkopp's Linux kernel module: ``https://github.com/hartkopp/can-isotp.git``

During pentests, the ISOTPNativeSockets has a better performance and
reliability, usually. If you are working on Linux, consider this implementation::

   conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
   load_contrib('isotp')
   sock = ISOTPSocket("can0", sid=0x641, did=0x241)

Since this implementation is using a standard Linux socket, all Scapy functions
like ``sniff, sr, sr1, bridge_and_sniff`` work out of the box.

ISOTPSoftSocket
---------------

ISOTPSoftSockets can use any CANSocket. This gives the flexibility to use all
python-can interfaces. Additionally, these sockets work on Python2 and Python3.
Usage on Linux with native CANSockets::

   conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': False}
   load_contrib('isotp')
   with ISOTPSocket("can0", sid=0x641, did=0x241) as sock:
       sock.send(...)

Usage with python-can CANSockets::

   conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': False}
   conf.contribs['CANSocket'] = {'use-python-can': True}
   load_contrib('isotp')
   with ISOTPSocket(CANSocket(bustype='socketcan', channel="can0"), sid=0x641, did=0x241) as sock:
       sock.send(...)

This second example allows the usage of any ``python_can.interface`` object.

**Attention:** The internal implementation of ISOTPSoftSockets requires a background
thread. In order to be able to close this thread properly, we suggest the use of
Pythons ``with`` statement.


ISOTPScan and ISOTPScanner
--------------------------

ISOTPScan is a utility function to find ISOTP-Endpoints on a CAN-Bus.
ISOTPScanner is a commandline-utility for the identical function.

.. image:: ../graphics/animations/animation-scapy-isotpscan.svg

Commandline usage example::

    python -m scapy.tools.automotive.isotpscanner -h
    usage:	isotpscanner [-i interface] [-c channel] [-b bitrate]
                    [-n NOISE_LISTEN_TIME] [-t SNIFF_TIME] [-x|--extended]
                    [-C|--piso] [-v|--verbose] [-h|--help] [-s start] [-e end]

        Scan for open ISOTP-Sockets.

        required arguments:
        -c, --channel         python-can channel or Linux SocketCAN interface name
        -s, --start           Start scan at this identifier (hex)
        -e, --end             End scan at this identifier (hex)

        additional required arguments for WINDOWS or Python 2:
        -i, --interface       python-can interface for the scan.
                              Depends on used interpreter and system,
                              see examples below. Any python-can interface can
                              be provided. Please see:
                              https://python-can.readthedocs.io for
                              further interface examples.
        -b, --bitrate         python-can bitrate.

        optional arguments:
        -h, --help            show this help message and exit
        -n NOISE_LISTEN_TIME, --noise_listen_time NOISE_LISTEN_TIME
                              Seconds listening for noise before scan.
        -t SNIFF_TIME, --sniff_time SNIFF_TIME
                              Duration in milliseconds a sniff is waiting for a
                              flow-control response.
        -x, --extended        Scan with ISOTP extended addressing.
        -C, --piso            Print 'Copy&Paste'-ready ISOTPSockets.
        -v, --verbose         Display information during scan.

        Example of use:

        Python2 or Windows:
        python2 -m scapy.tools.automotive.isotpscanner --interface=pcan --channel=PCAN_USBBUS1 --bitrate=250000 --start 0 --end 100
        python2 -m scapy.tools.automotive.isotpscanner --interface vector --channel 0 --bitrate 250000 --start 0 --end 100
        python2 -m scapy.tools.automotive.isotpscanner --interface socketcan --channel=can0 --bitrate=250000 --start 0 --end 100

        Python3 on Linux:
        python3 -m scapy.tools.automotive.isotpscanner --channel can0 --start 0 --end 100


Interactive shell usage example::

    >>> conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
    >>> conf.contribs['CANSocket'] = {'use-python-can': False}
    >>> load_contrib('cansocket')
    >>> load_contrib('isotp')
    >>> socks = ISOTPScan(CANSocket("vcan0"), range(0x700, 0x800), can_interface="vcan0")
    >>> socks
    [<<ISOTPNativeSocket: read/write packets at a given CAN interface using CAN_ISOTP socket > at 0x7f98e27c8210>,
     <<ISOTPNativeSocket: read/write packets at a given CAN interface using CAN_ISOTP socket > at 0x7f98f9079cd0>,
     <<ISOTPNativeSocket: read/write packets at a given CAN interface using CAN_ISOTP socket > at 0x7f98f90cd490>,
     <<ISOTPNativeSocket: read/write packets at a given CAN interface using CAN_ISOTP socket > at 0x7f98f912ec50>,
     <<ISOTPNativeSocket: read/write packets at a given CAN interface using CAN_ISOTP socket > at 0x7f98f912e950>,
     <<ISOTPNativeSocket: read/write packets at a given CAN interface using CAN_ISOTP socket > at 0x7f98f906c0d0>]

XCPScanner
---------------

The XCPScanner is a utility to find the CAN identifiers of ECUs that support XCP.

Commandline usage example::

    python -m scapy.tools.automotive.xcpscanner -h
    Finds XCP slaves using the "GetSlaveId"-message(Broadcast) or the "Connect"-message.

    positional arguments:
      channel               Linux SocketCAN interface name, e.g.: vcan0

    optional arguments:
      -h, --help            show this help message and exit
      --start START, -s START
                            Start identifier CAN (in hex).
                            The scan will test ids between --start and --end (inclusive)
                            Default: 0x00
      --end END, -e END     End identifier CAN (in hex).
                            The scan will test ids between --start and --end (inclusive)
                            Default: 0x7ff
      --sniff_time', '-t'   Duration in milliseconds a sniff is waiting for a response.
                            Default: 100
      --broadcast, -b       Use Broadcast-message GetSlaveId instead of default "Connect"
                            (GetSlaveId is an optional Message that is not always implemented)
      --verbose VERBOSE, -v
                            Display information during scan

        Examples:
            python3.6 -m scapy.tools.automotive.xcpscanner can0
            python3.6 -m scapy.tools.automotive.xcpscanner can0 -b 500
            python3.6 -m scapy.tools.automotive.xcpscanner can0 -s 50 -e 100
            python3.6 -m scapy.tools.automotive.xcpscanner can0 -b 500 -v


Interactive shell usage example::
    >>> conf.contribs['CANSocket'] = {'use-python-can': False}
    >>> load_layer("can")
    >>> load_contrib("automotive.xcp.xcp")
    >>> sock = CANSocket("vcan0")
    >>> sock.basecls = XCPOnCAN
    >>> scanner = XCPOnCANScanner(sock)
    >>> result = scanner.start_scan()

The result includes the slave_id (the identifier of the Ecu that receives XCP messages),
and the response_id (the identifier that the Ecu will send XCP messages to).



UDS
===

The main usage of UDS is flashing and diagnostic of an Ecu. UDS is an
application layer protocol and can be used as a DoIP or HSFZ payload or a UDS packet
can directly be sent over an ISOTPSocket. Every OEM has its own customization of UDS.
This increases the difficulty of generic applications and OEM specific knowledge is
required for penetration tests. RoutineControl jobs and ReadDataByIdentifier/WriteDataByIdentifier
services are heavily customized.

Use the argument ``basecls=UDS`` on the ``init`` function of an ISOTPSocket.

Here are two usage examples:

.. image:: ../graphics/animations/animation-scapy-uds.svg
.. image:: ../graphics/animations/animation-scapy-uds2.svg


Customization of UDS_RDBI, UDS_WDBI
-----------------------------------

In real-world use-cases, the UDS layer is heavily customized. OEMs define their own substructure of packets.
Especially the packets ReadDataByIdentifier or WriteDataByIdentifier have a very OEM or even Ecu specific
substructure. Therefore a ``StrField`` ``dataRecord`` is not added to the ``field_desc``.
The intended usage is to create Ecu or OEM specific description files, which extend the general UDS layer of
Scapy with further protocol implementations.

Customization example::

    cat scapy/contrib/automotive/OEM-XYZ/car-model-xyz.py
    #! /usr/bin/env python

    # Protocol customization for car model xyz of OEM XYZ
    # This file contains further OEM car model specific UDS additions.

    from scapy.packet import Packet
    from scapy.contrib.automotive.uds import *

    # Define a new packet substructure

    class DBI_IP(Packet):
    name = 'DataByIdentifier_IP_Packet'
    fields_desc = [
        ByteField('ADDRESS_FORMAT_ID', 0),
        IPField('IP', ''),
        IPField('SUBNETMASK', ''),
        IPField('DEFAULT_GATEWAY', '')
    ]

    # Bind the new substructure onto the existing UDS packets

    bind_layers(UDS_RDBIPR, DBI_IP, dataIdentifier=0x172b)
    bind_layers(UDS_WDBI, DBI_IP, dataIdentifier=0x172b)

    # Give add a nice name to dataIdentifiers enum

    UDS_RDBI.dataIdentifiers[0x172b] = 'GatewayIP'

If one wants to work with this custom additions, these can be loaded at runtime to the Scapy interpreter::

    >>> load_contrib('automotive.uds')
    >>> load_contrib('automotive.OEM-XYZ.car-model-xyz')

    >>> pkt = UDS()/UDS_WDBI()/DBI_IP(IP='192.168.2.1', SUBNETMASK='255.255.255.0', DEFAULT_GATEWAY='192.168.2.1')

    >>> pkt.show()
    ###[ UDS ]###
      service= WriteDataByIdentifier
    ###[ WriteDataByIdentifier ]###
         dataIdentifier= GatewayIP
         dataRecord= 0
    ###[ DataByIdentifier_IP_Packet ]###
            ADDRESS_FORMAT_ID= 0
            IP= 192.168.2.1
            SUBNETMASK= 255.255.255.0
            DEFAULT_GATEWAY= 192.168.2.1

    >>> hexdump(pkt)
    0000  2E 17 2B 00 C0 A8 02 01 FF FF FF 00 C0 A8 02 01  ..+.............

.. image:: ../graphics/animations/animation-scapy-uds3.svg

GMLAN
=====
GMLAN is very similar to UDS. It's GMs application layer protocol for
flashing, calibration and diagnostic of their cars.
Use the argument ``basecls=GMLAN`` on the ``init`` function of an ISOTPSocket.

Usage example:

.. image:: ../graphics/animations/animation-scapy-gmlan.svg


Ecu Utility examples
====================

The Ecu utility can be used to analyze the internal states of an Ecu under investigation.
This utility depends heavily on the support of the used protocol. ``UDS`` is supported.

Log all commands applied to an Ecu
----------------------------------

This example shows the logging mechanism of an Ecu object. The log of an Ecu is a dictionary of applied UDS commands. The key for this dictionary is the UDS service name. The value consists of a list of tuples, containing a timestamp and a log value

Usage example::

    ecu = Ecu(verbose=False, store_supported_responses=False)
    ecu.update(PacketList(msgs))
    print(ecu.log)
    timestamp, value = ecu.log["DiagnosticSessionControl"][0]



Trace all commands applied to an Ecu
------------------------------------

This example shows the trace mechanism of an Ecu object. Traces of the current state of the Ecu object and the received message are printed on stdout. Some messages, depending on the protocol, will change the internal state of the Ecu.

Usage example::

    ecu = Ecu(verbose=True, logging=False, store_supported_responses=False)
    ecu.update(PacketList(msgs))
    print(ecu.current_session)



Generate supported responses of an Ecu
--------------------------------------

This example shows a mechanism to clone a real world Ecu by analyzing a list of Packets.

Usage example::

    ecu = Ecu(verbose=False, logging=False, store_supported_responses=True)
    ecu.update(PacketList(msgs))
    supported_responses = ecu.supported_responses
    unanswered_packets = ecu.unanswered_packets
    print(supported_responses)
    print(unanswered_packets)



Analyze multiple UDS messages
-----------------------------

This example shows how to load ``UDS`` messages from a ``.pcap`` file containing ``CAN`` messages. A ``PcapReader`` object is used as socket and an ``ISOTPSession`` parses ``CAN`` frames to ``ISOTP`` frames which are then casted to ``UDS`` objects through the ``basecls`` parameter

Usage example::

    with PcapReader("test/contrib/automotive/ecu_trace.pcap") as sock:
        udsmsgs = sniff(session=ISOTPSession, session_kwargs={"use_ext_addr":False, "basecls":UDS}, count=50, opened_socket=sock)


    ecu = Ecu()
    ecu.update(udsmsgs)
    print(ecu.log)
    print(ecu.supported_responses)
    assert len(ecu.log["TransferData"]) == 2



Analyze on the fly with EcuSession
----------------------------------

This example shows the usage of an EcuSession in sniff. An ISOTPSocket or any socket like object which returns entire messages of the right protocol can be used. An ``EcuSession`` is used as supersession in an ``ISOTPSession``. To obtain the ``Ecu`` object from an ``EcuSession``, the ``EcuSession`` has to be created outside of sniff.

Usage example::

    session = EcuSession()

    with PcapReader("test/contrib/automotive/ecu_trace.pcap") as sock:
        udsmsgs = sniff(session=ISOTPSession, session_kwargs={"supersession": session, "use_ext_addr":False, "basecls":UDS}, count=50, opened_socket=sock)

    ecu = session.ecu
    print(ecu.log)
    print(ecu.supported_responses)



SOME/IP and SOME/IP SD messages
===============================

Creating a SOME/IP message
--------------------------

This example shows a SOME/IP message which requests a service 0x1234 with the method 0x421. Different types of SOME/IP messages follow the same procedure and their specifications can be seen here ``http://www.some-ip.com/papers/cache/AUTOSAR_TR_SomeIpExample_4.2.1.pdf``.


Load the contribution::

   load_contrib('automotive.someip')

Create UDP package::

   u = UDP(sport=30509, dport=30509)

Create IP package::

   i = IP(src="192.168.0.13", dst="192.168.0.10")

Create SOME/IP package::

   sip = SOMEIP()
   sip.iface_ver = 0
   sip.proto_ver = 1
   sip.msg_type = "REQUEST"
   sip.retcode = "E_OK"
   sip.srv_id = 0x1234
   sip.method_id = 0x421

Add the payload::

   sip.add_payload(Raw ("Hello"))

Stack it and send it::

   p = i/u/sip
   send(p)


Creating a SOME/IP SD message
-----------------------------

In this example a SOME/IP SD offer service message is shown with an IPv4 endpoint. Different entries and options basically follow the same procedure as shown here and can be seen at ``https://www.autosar.org/fileadmin/user_upload/standards/classic/4-3/AUTOSAR_SWS_ServiceDiscovery.pdf``.

Load the contribution::

   load_contrib('automotive.someip')

Create UDP package::

   u = UDP(sport=30490, dport=30490)

The UDP port must be the one which was chosen for the SOME/IP SD transmission.

Create IP package::

   i = IP(src="192.168.0.13", dst="224.224.224.245")

The IP source must be from the service and the destination address needs to be the chosen multicast address.

Create the entry array input::

   ea = SDEntry_Service()

   ea.type = 0x01
   ea.srv_id = 0x1234
   ea.inst_id = 0x5678
   ea.major_ver = 0x00
   ea.ttl = 3

Create the options array input::

   oa = SDOption_IP4_EndPoint()
   oa.addr = "192.168.0.13"
   oa.l4_proto = 0x11
   oa.port = 30509

l4_proto defines the protocol for the communication with the endpoint, UDP in this case.

Create the SD package and put in the inputs::

   sd = SD()
   sd.set_entryArray(ea)
   sd.set_optionArray(oa)

Stack it and send it::

   p = i/u/sd
   send(p)


OBD
===

OBD message
-----------

OBD is implemented on top of ISOTP. Use an ISOTPSocket for the communication with an Ecu.
You should set the parameters ``basecls=OBD`` and ``padding=True`` in your ISOTPSocket init call.

OBD is split into different service groups. Here are some example requests:

Request supported PIDs of service 0x01::

   req = OBD()/OBD_S01(pid=[0x00])

The response will contain a PacketListField, called `data_records`. This field contains the actual response::

   resp = OBD()/OBD_S01_PR(data_records=[OBD_S01_PR_Record()/OBD_PID00(supported_pids=3196041235)])
   resp.show()
   ###[ On-board diagnostics ]###
     service= CurrentPowertrainDiagnosticDataResponse
   ###[ Parameter IDs ]###
        \data_records\
         |###[ OBD_S01_PR_Record ]###
         |  pid= 0x0
         |###[ PID_00_PIDsSupported ]###
         |     supported_pids= PID20+PID1F+PID1C+PID15+PID14+PID13+PID11+PID10+PID0F+PID0E+PID0D+PID0C+PID0B+PID0A+PID07+PID06+PID05+PID04+PID03+PID01

Let's assume our Ecu under test supports the pid 0x15::
   
   req = OBD()/OBD_S01(pid=[0x15])
   resp = sock.sr1(req)
   resp.show()
   ###[ On-board diagnostics ]### 
     service= CurrentPowertrainDiagnosticDataResponse
   ###[ Parameter IDs ]### 
        \data_records\
         |###[ OBD_S01_PR_Record ]###
         |  pid= 0x15
         |###[ PID_15_OxygenSensor2 ]### 
         |     outputVoltage= 1.275 V
         |     trim= 0 %


The different services in OBD support different kinds of data. 
Service 01 and Service 02 support Parameter Identifiers (pid).
Service 03, 07 and 0A support Diagnostic Trouble codes (dtc).
Service 04 doesn't require a payload.
Service 05 is not implemented on OBD over CAN.
Service 06 supports Monitoring Identifiers (mid).
Service 08 supports Test Identifiers (tid).
Service 09 supports Information Identifiers (iid).

Examples:
^^^^^^^^^

Request supported Information Identifiers::

   req = OBD()/OBD_S09(iid=[0x00])

Request the Vehicle Identification Number (VIN)::

   req = OBD()/OBD_S09(iid=0x02)
   resp = sock.sr1(req)
   resp.show()
   ###[ On-board diagnostics ]### 
     service= VehicleInformationResponse
   ###[ Infotype IDs ]###
        \data_records\
         |###[ OBD_S09_PR_Record ]###
         |  iid= 0x2
         |###[ IID_02_VehicleIdentificationNumber ]###
         |     count= 1
         |     vehicle_identification_numbers= ['W0L000051T2123456']

   
.. image:: ../graphics/animations/animation-scapy-obd.svg


Test-Setup Tutorials
====================

Hardware Setup
--------------

Beagle Bone Black Operating System Setup
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. | **Download an Image**
   | The latest Debian Linux image can be found at the website
   | ``https://beagleboard.org/latest-images``. Choose the BeagleBone
     Black IoT version and download it.

   ::

       wget https://debian.beagleboard.org/images/bone-debian-8.7\
       -iot-armhf-2017-03-19-4gb.img.xz


   After the download, copy it to an SD-Card with minimum of 4 GB storage.

   ::

       xzcat bone-debian-8.7-iot-armhf-2017-03-19-4gb.img.xz | \
       sudo dd of=/dev/xvdj


#. | **Enable WiFi**
   | USB-WiFi dongles are well supported by Debian Linux. Login over SSH
     on the BBB and add the WiFi network credentials to the file
     ``/var/lib/connman/wifi.config``. If a USB-WiFi dongle is not
     available, it is also possible to share the host's internet
     connection with the Ethernet connection of the BBB emulated over
     USB. A tutorial to share the host network connection can be found
     on this page:
   | ``https://elementztechblog.wordpress.com/2014/12/22/sharing-internet -using-network-over-usb-in-beaglebone-black/``.
   | Login as root onto the BBB:

   ::

       ssh debian@192.168.7.2
       sudo su


   Provide the WiFi login credentials to connman:

   ::

       echo "[service_home]
       Type = wifi
       Name = ssid
       Security = wpa
       Passphrase = xxxxxxxxxxxxx" \
       > /var/lib/connman/wifi.config


   Restart the connman service:

   ::

       systemctl restart connman.service


Dual-CAN Setup
^^^^^^^^^^^^^^

#. | **Device tree setup**
   | You'll need to follow this section only if you want to use two CAN
    interfaces (DCAN0 and DCAN1). This will disable I2C2 from using pins
    P9.19 and P9.20, which are needed by DCAN0. You only need to perform the
    steps in this section once.

   | Warning: The configuration in this section will disable BBB capes from
    working. Each cape has a small I2C EEPROM that stores info that the BBB
    needs to know in order to communicate with the cape. Disable I2C2, and
    the BBB has no way to talk to cape EEPROMs. Of course, if you don't use
    capes then this is not a problem.

   | Acquire DTS sources that matches your kernel version. Go
    `here <https://github.com/beagleboard/linux/>`__ and switch over to the
    branch that represents your kernel version. Download the entire branch
    as a ZIP file. Extract it and do the following (version 4.1 shown as an
    example):

    ::

        # cd ~/src/linux-4.1/arch/arm/boot/dts/include/
        # rm dt-bindings
        # ln -s ../../../../../include/dt-bindings
        # cd ..
        Edit am335x-bone-common.dtsi and ensure the line with "//pinctrl-0 = <&i2c2_pins>;" is commented out.
        Remove the complete &ocp section at the end of this file
        # mv am335x-boneblack.dts am335x-boneblack.raw.dts
        # cpp -nostdinc -I include -undef -x assembler-with-cpp am335x-boneblack.raw.dts > am335x-boneblack.dts
        # dtc -W no-unit_address_vs_reg -O dtb -o am335x-boneblack.dtb -b 0 -@ am335x-boneblack.dts
        # cp /boot/dtbs/am335x-boneblack.dtb /boot/dtbs/am335x-boneblack.orig.dtb
        # cp am335x-boneblack.dtb /boot/dtbs/
        Reboot

#. **Overlay setup**
    | This section describes how to build the device overlays for the two CAN devices (DCAN0 and DCAN1). You only need to perform the steps in this section once.
    | Acquire BBB cape overlays, in one of two ways…

    ::

        # apt-get install bb-cape-overlays
        https://github.com/beagleboard/bb.org-overlays/

    | Then do the following:


    ::

        # cd ~/src/bb.org-overlays-master/src/arm
        # ln -s ../../include
        # mv BB-CAN1-00A0.dts BB-CAN1-00A0.raw.dts
        # cp BB-CAN1-00A0.raw.dts BB-CAN0-00A0.raw.dts
        Edit BB-CAN0-00A0.raw.dts and make relevant to CAN0. Example is shown below.
        # cpp -nostdinc -I include -undef -x assembler-with-cpp BB-CAN0-00A0.raw.dts > BB-CAN0-00A0.dts
        # cpp -nostdinc -I include -undef -x assembler-with-cpp BB-CAN1-00A0.raw.dts > BB-CAN1-00A0.dts
        # dtc -W no-unit_address_vs_reg -O dtb -o BB-CAN0-00A0.dtbo -b 0 -@ BB-CAN0-00A0.dts
        # dtc -W no-unit_address_vs_reg -O dtb -o BB-CAN1-00A0.dtbo -b 0 -@ BB-CAN1-00A0.dts
        # cp *.dtbo /lib/firmware


#. | **CAN0 Example Overlay**
   | Inside the DTS folder, create a file with the content of the
     following listing.

   ::

        cd ~/bb.org-overlays/src/arm
        cat <<EOF > BB-CAN0-00A0.raw.dts

        /*
         * Copyright (C) 2015 Robert Nelson <robertcnelson@gmail.com>
         *
         * Virtual cape for CAN0 on connector pins P9.19 P9.20
         *
         * This program is free software; you can redistribute it and/or modify
         * it under the terms of the GNU General Public License version 2 as
         * published by the Free Software Foundation.
         */
        /dts-v1/;
        /plugin/;

        #include <dt-bindings/board/am335x-bbw-bbb-base.h>
        #include <dt-bindings/pinctrl/am33xx.h>

        / {
            compatible = "ti,beaglebone", "ti,beaglebone-black", "ti,beaglebone-green";

            /* identification */
            part-number = "BB-CAN0";
            version = "00A0";

            /* state the resources this cape uses */
            exclusive-use =
                /* the pin header uses */
                "P9.19",	/* can0_rx */
                "P9.20",	/* can0_tx */
                /* the hardware ip uses */
                "dcan0";

            fragment@0 {
                target = <&am33xx_pinmux>;
                __overlay__ {
                    bb_dcan0_pins: pinmux_dcan0_pins {
                        pinctrl-single,pins = <
                            BONE_P9_19 (PIN_INPUT_PULLUP | MUX_MODE2) /* uart1_txd.d_can0_rx */
                            BONE_P9_20 (PIN_OUTPUT_PULLUP | MUX_MODE2) /* uart1_rxd.d_can0_tx */
                        >;
                    };
                };
            };

            fragment@1 {
                target = <&dcan0>;
                __overlay__ {
                    status = "okay";
                    pinctrl-names = "default";
                    pinctrl-0 = <&bb_dcan0_pins>;
                };
            };
        };
        EOF


#. | **Test the Dual-CAN Setup**
   | Do the following each time you need CAN, or automate these steps if you like.

   ::

        # echo BB-CAN0 > /sys/devices/platform/bone_capemgr/slots
        # echo BB-CAN1 > /sys/devices/platform/bone_capemgr/slots
        # modprobe can
        # modprobe can-dev
        # modprobe can-raw
        # ip link set can0 up type can bitrate 50000
        # ip link set can1 up type can bitrate 50000

   Check the output of the Capemanager if both CAN interfaces have been
   loaded.

   ::

       cat /sys/devices/platform/bone_capemgr/slots

       0: PF----  -1
       1: PF----  -1
       2: PF----  -1
       3: PF----  -1
       4: P-O-L-   0 Override Board Name,00A0,Override Manuf, BB-CAN0
       5: P-O-L-   1 Override Board Name,00A0,Override Manuf, BB-CAN1


   If something went wrong, ``dmesg`` provides kernel messages to analyse the root of failure.

#. | **References**

    -  `embedded-things.com: Enable CANbus on the Beaglebone
       Black <http://www.embedded-things.com/bbb/enable-canbus-on-the-beaglebone-black/>`__
    -  `electronics.stackexchange.com: Beaglebone Black CAN bus
       Setup <https://electronics.stackexchange.com/questions/195416/beaglebone-black-can-bus-setup>`__

#. | **Acknowledgment**
   | Thanks to Tom Haramori. Parts of this section are copied from his guide: https://github.com/haramori/rhme3/blob/master/Preparation/BBB_CAN_setup.md



ISO-TP Kernel Module Installation
---------------------------------

A Linux ISO-TP kernel module can be downloaded from this website:
``https://github.com/hartkopp/can-isotp.git``. The file
``README.isotp`` in this repository provides all information and
necessary steps for downloading and building this kernel module. The
ISO-TP kernel module should also be added to the ``/etc/modules`` file,
to load this module automatically at system boot of the BBB.

CAN-Interface Setup
-------------------

As the final step to prepare the BBB's CAN interfaces for usage, these
interfaces have to be set up through some terminal commands. The bitrate
can be chosen to fit the bitrate of a CAN bus under test.

::

    ip link set can0 up type can bitrate 500000
    ip link set can1 up type can bitrate 500000

Raspberry Pi SOME/IP setup
--------------------------

To build a small test environment in which you can send SOME/IP messages to and from server instances or disguise yourself as a server, one Raspberry Pi, your laptop and the vsomeip library are sufficient.

#. | **Download image**

   Download the latest raspbian image (``https://www.raspberrypi.org/downloads/raspbian/``) and install it on the Raspberry.

#. | **Vsomeip setup**

   Download the vsomeip library on the Rapsberry, apply the git patch so it can work with the newer boost libraries and then install it.

   ::

      git clone https://github.com/GENIVI/vsomeip.git
      cd vsomeip
      wget -O 0001-Support-boost-v1.66.patch.zip \
      https://github.com/GENIVI/vsomeip/files/2244890/0001-Support-boost-v1.66.patch.zip
      unzip 0001-Support-boost-v1.66.patch.zip
      git apply 0001-Support-boost-v1.66.patch
      mkdir build
      cd build
      cmake -DENABLE_SIGNAL_HANDLING=1 ..
      make
      make install

#. | **Make applications**

   Write some small applications which function as either a service or a client and use the Scapy SOME/IP implementation to communicate with the client or the server. Examples for vsomeip applications are available on the vsomeip github wiki page (``https://github.com/GENIVI/vsomeip/wiki/vsomeip-in-10-minutes``).



Software Setup
--------------

Cannelloni Framework Installation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The Cannelloni framework is a small application written in C++ to
transfer CAN data over UDP. In this way, a researcher can map the CAN
communication of a remote device to its workstation, or even combine
multiple remote CAN devices on his machine. The framework can be
downloaded from this website:
``https://github.com/mguentner/cannelloni.git``. The ``README.md`` file
explains the installation and usage in detail. Cannelloni needs virtual
CAN interfaces on the operator's machine. The next listing shows the
setup of virtual CAN interfaces.

::

    modprobe vcan

    ip link add name vcan0 type vcan
    ip link add name vcan1 type vcan

    ip link set dev vcan0 up
    ip link set dev vcan1 up

    tc qdisc add dev vcan0 root tbf rate 300kbit latency 100ms burst 1000
    tc qdisc add dev vcan1 root tbf rate 300kbit latency 100ms burst 1000

    cannelloni -I vcan0 -R <remote-IP> -r 20000 -l 20000 &
    cannelloni -I vcan1 -R <remote-IP> -r 20001 -l 20001 &

