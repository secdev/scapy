****************
Automotive usage
****************

.. note::
    All automotive related features work best on linux systems. CAN and ISOTP sockets in scapy are based on linux kernel modules.
    The python-can project is used to support CAN and CANSockets on other systems, besides Linux.
    This guide explains the hardware setup on a BeagleBone Black. The BeagleBone Black was chosen because of its two CAN interfaces on the main processor.
    The presence of two CAN interfaces in one device gives the possibility of CAN MITM attacks and session hijacking.
    The Cannelloni framework turns a BeagleBone Black into a CAN-to-UDP interface, which gives you the freedom to run scapy
    on a more powerful machine.

Examples
========

CAN Layer
---------

Setup
~~~~~

This commands enable a virtual CAN interface on your machine::

    from scapy.layers.can import *
    import os

    bashCommand = "/bin/bash -c 'sudo modprobe vcan; sudo ip link add name vcan0 type vcan; sudo ip link set dev vcan0 up'"
    os.system(bashCommand)

If it's required, the CAN interface can be set into an listen-only or loop back mode with ip link set commands::

    ip link set vcan0 type can help  # shows additional information

CAN Frame
~~~~~~~~~

Creating a standard CAN frame::

    frame = CAN(identifier=0x200, length=8, data=b'\x01\x02\x03\x04\x05\x06\x07\x08')

Creating an extended CAN frame::

    frame = CAN(flags='extended', identifier=0x10010000, length=8, data=b'\x01\x02\x03\x04\x05\x06\x07\x08')

Writing and reading to pcap files::

    x = CAN(identifier=0x7ff,length=8,data=b'\x01\x02\x03\x04\x05\x06\x07\x08')
    wrpcap('/tmp/scapyPcapTest.pcap', x, append=False)
    y = rdpcap('/tmp/scapyPcapTest.pcap', 1)

CAN Socket
~~~~~~~~~~

Ways of creating a native CANSocket::

    conf.contribs['CANSocket'] = {'use-python-can': False} #(default)
    load_contrib('cansocket')

    # Simple Socket
    socket = CANSocket(iface="vcan0")
    # Socket only listen for messages with Id == 0x200
    socket = CANSocket(iface="vcan0", canfilters=[{'can_id': 0x200, 'can_mask': 0x7FF}])
    # Socket only listen for messages with Id >= 0x200 and Id <= 0x2ff
    socket = CANSocket(iface="vcan0", canfilters=[{'can_id': 0x200, 'can_mask': 0x700}])
    # Socket only listen for messages with Id != 0x200
    socket = CANSocket(iface="vcan0", canfilters=[{'can_id': 0x200 | CAN_INV_FILTER, 'can_mask': 0x7FF}])
    # Socket with multiple canfilters
    socket = CANSocket(iface='vcan0', canfilters=[{'can_id': 0x200, 'can_mask': 0x7ff},
                                                     {'can_id': 0x400, 'can_mask': 0x7ff},
                                                     {'can_id': 0x600, 'can_mask': 0x7ff},
                                                     {'can_id': 0x7ff, 'can_mask': 0x7ff}])
    # Socket which also receives its own messages
    socket = CANSocket(iface="vcan0", receive_own_messages=True)


Ways of creating a python-can CANSocket::

    conf.contribs['CANSocket'] = {'use-python-can': True}
    load_contrib('cansocket')
    import can

    # Simple Socket
    socket = CANSocket(iface=can.interface.Bus(bustype='socketcan', channel='vcan0', bitrate=250000
    # Socket with multiple filters
    socket = CANSocket(iface=can.interface.Bus(bustype='socketcan', channel='vcan0', bitrate=250000,
                    canfilters=[{'can_id': 0x200, 'can_mask': 0x7ff},
                                {'can_id': 0x400, 'can_mask': 0x7ff},
                                {'can_id': 0x600, 'can_mask': 0x7ff},
                                {'can_id': 0x7ff, 'can_mask': 0x7ff}]))

For further details on python-can check: https://python-can.readthedocs.io/en/2.1.0/

Setup
=====

Hardware Setup
--------------

Beagle Bone Black Operating System Setup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. | **Download an Image**
   | The latest Debian Linux image can be found at the website
   | ``https://beagleboard.org/latest-images``. Choose the BeagleBone
     Black IoT version and download it.

   ::

       wget https://debian.beagleboard.org/images/bone-debian-8.7\
       -iot-armhf-2017-03-19-4gb.img.xz


   After the download, copy it to an SD-Card with minimum 4 GB storage.

   ::

       xzcat bone-debian-8.7-iot-armhf-2017-03-19-4gb.img.xz | \
       sudo dd of=/dev/xvdj


#. | **Enable WiFi**
   | USB-WiFi dongles are well supported by Debian Linux. Login over SSH
     on the BBB and add the WiFi network credentials to the file
     ``/var/lib/connman/wifi.config``. If a USB-WiFi dongle is not
     available, it is also possible to share the host’s internet
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


#. | **Install Required Packages**
   | This step is required to install all necessary software packages to
     continue with the modification of the BBB device tree overlay.

   ::

       apt-get update
       apt-get -y upgrade
       exit
       git clone https://github.com/beagleboard/bb.org-overlays
       cd ./bb.org-overlays


   Verify the installed DTC1 version to ensure that the DTC1 is suitable
   for the downloaded overlays. Version 1.4.1 or higher is required.

   ::

       dtc --version


   Update the installed DTC1 with an update script in the cloned
   repository.

   ::

       ./dtc-overlay.sh


   Compile all delivered DTS files and install the DTBO onto the current
   system. Again, a delivered script simplifies this job.

   ::

       ./install.sh


   Now, the operating system and the device tree are ready for
   modifications.

Dual-CAN Setup
~~~~~~~~~~~~~~

#. | **Create a CAN0 Overlay**
   | Inside the DTS folder, create a file with the content of the
     following listing.

   ::

       cd ~/bb.org-overlays/src/arm
       cat <<EOF > BB-CAN0-00A0.dts

       /dts-v1/;
       /plugin/;

       #include <dt-bindings/board/am335x-bbw-bbb-base.h>
       #include <dt-bindings/pinctrl/am33xx.h>

       / {
           compatible = "ti,beaglebone", \
           "ti,beaglebone-black", "ti,beaglebone-green";

           /* identification */
           part-number = "BB-CAN0";
           version = "00A0";

           /* state the resources this cape uses */
           exclusive-use =
           /* the pin header uses */
           "P9.19", /* can0_rx */
           "P9.20", /* can0_tx */
           /* the hardware ip uses */
           "dcan0";

           fragment@0 {
               target = <&am33xx_pinmux>;
               __overlay__ {
                bb_dcan0_pins: pinmux_dcan0_pins {
                   pinctrl-single,pins = <
                    0x178 0x12 /* d_can0_tx */
                    0x17C 0x32 /* d_can0_rx */
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


   Compile the generated file with the delivered Makefile from the
   repository.

   ::

       cd ../../
       make
       sudo make install


#. | **Modify the Boot Device Tree Blob**
   | Backup and decompile the current device tree blob.

   ::

       cp /boot/dtbs/4.4.54-ti-r93/am335x-boneblack.dtb ~/
       dtc -I dtb -O dts ~/am335x-boneblack.dtb > ~/am335x-boneblack.dts


   To free the CAN0 pins of the BBB, used I2C2 pins need to be disabled.
   This can be done by commenting out the appropriate lines in the DTS
   file. Search for the pinmux\_i2c2\_pins section and save the modified
   file with a new name. The BeagleBone community uses the I2C2
   peripheral module for the communication and identification of
   extension modules, so called capes. This modification disables the
   compatibility to any of these capes.

   ::

       vim am335x-boneblack.dts

       895 /* pinmux_i2c2_pins {
       896     pinctrl-single,pins = <0x178 0x33 0x17c 0x33>;
       897     linux,phandle = <0x35>;
       898     phandle = <0x35>;
       899 };*/

       : wq am335x-boneblack_new.dts


   Compile the modified DTS file and replace the original file in the
   boot partition of the BBB. Reboot the BBB after the replacement.

   ::

       dtc -O dtb -o ~/am335x-boneblack_new.dtb -b 0 ~/am335x-boneblack_new.dts

       cp ~/am335x-boneblack_new.dtb /boot/dtbs/4.4.54-ti-r93/am335x-boneblack.dtb

       reboot


#. | **Test the Dual-CAN Setup**
   | Load the CAN kernel modules and the overlays.

   ::

       sudo su
       modprobe can
       modprobe can-dev
       modprobe can-raw

       echo BB-CAN0 > /sys/devices/platform/bone_capemgr/slots
       echo BB-CAN1 > /sys/devices/platform/bone_capemgr/slots


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


   If something went wrong, ``dmesg`` provides kernel messages to
   analyze the root of failure.

#. **Optional: Enable Dual-CAN Setup at Boot**

   ::

       echo "modprobe can \
       modprobe can-dev \
       modprobe can-raw" >> /etc/modules

       echo "cape_enable=bone_capemgr.enable_partno=BB-CAN0,BB-CAN1" >> /boot/uEnv.txt

       update-initramfs -u


ISO-TP Kernel Module Installation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A Linux ISO-TP kernel module can be downloaded from this website:
``https://github.com/ hartkopp/can-isotp.git``. The file
``README.isotp`` in this repository provides all information and
necessary steps for downloading and building this kernel module. The
ISO-TP kernel module should also be added to the ``/etc/modules`` file,
to load this module automatically at system boot of the BBB.

CAN-Interface Setup
~~~~~~~~~~~~~~~~~~~

As final step to prepare the BBB’s CAN interfaces for usage, these
interfaces have to be setup through some terminal commands. The bitrate
can be chosen to fit the bitrate of a CAN bus under test.

::

    ip link set can0 up type can bitrate 500000
    ip link set can1 up type can bitrate 500000
    ifconfig can0 up
    ifconfig can1 up

Software Setup
--------------

Cannelloni Framework Installation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Cannelloni framework is a small application written in C++ to
transfer CAN data over UDP. In this way, a researcher can map the CAN
communication of a remote device to its workstation, or even combine
multiple remote CAN devices on his machine. The framework can be
downloaded from this website:
``https://github.com/mguentner/cannelloni.git``. The ``README.md`` file
explains the installation and usage in detail. Cannelloni needs virtual
CAN interfaces on the operators machine. The next listing shows the
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


