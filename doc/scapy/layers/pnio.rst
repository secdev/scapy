***************
PROFINET IO RTC
***************

PROFINET IO is an industrial protocol composed of different layers such as the Real-Time Cyclic (RTC) layer, used to exchange data. However, this RTC layer is stateful and depends on a configuration sent through another layer: the DCE/RPC endpoint of PROFINET. This configuration defines where each exchanged piece of data must be located in the RTC ``data`` buffer, as well as the length of this same buffer. Building such packet is then a bit more complicated than other protocols.

RTC data packet
---------------

The first thing to do when building the RTC ``data`` buffer is to instantiate each Scapy packet which represents a piece of data. Some of the basic packets are:

* ``ProfinetIO``: the building block for PROFINET packets. Can be layered on top of Ether() or UDP()

* ``PROFIsafe``: the PROFIsafe profile to perform functional safety

* ``PNIORealTime_IOxS``: either an IO Consumer or Provider Status byte

Instantiate the packets as follows::

    >>> load_contrib('pnio')
    >>> raw(ProfinetIO()/b'AAA')
    b'\x00\x00AAA'
    >>> raw(PROFIsafe.build_PROFIsafe_class(PROFIsafeControl, 4)(data = b'AAA', control=0x20, crc=0x424242))
    b'AAA\x00 BBB'
    >>> hexdump(PNIORealTime_IOxS())
    0000   80                                                 .


RTC packet
----------

Now that a data packet can be instantiated, a whole RTC packet may be built. ``PNIORealTimeCyclicPDU`` contains a field ``data`` which is a list of all data packets to add in the buffer, however, without the configuration, Scapy won't be
able to dissect it::

    >>> load_contrib('pnio')
    >>> p=PNIORealTimeCyclicPDU(cycleCounter=1024, data=[
    ... PNIORealTime_IOxS(),
    ... PNIORealTimeCyclicPDU.build_fixed_len_raw_type(4)(data = b'AAA') / PNIORealTime_IOxS(),
    ... PROFIsafe.build_PROFIsafe_class(PROFIsafeControl, 4)(data = b'AAA', control=0x20, crc=0x424242)/PNIORealTime_IOxS(),
    ... ])
    >>> p.show()
    ###[ PROFINET Real-Time ]###
      \data      \
       |###[ PNIO RTC IOxS ]###
       |  dataState = good
       |  instance  = subslot
       |  reserved  = 0x0
       |  extension = 0
       |###[ FixedLenRawPacketLen4 ]###
       |  data      = 'AAA'
       |###[ PNIO RTC IOxS ]###
       |     dataState = good
       |     instance  = subslot
       |     reserved  = 0x0
       |     extension = 0
       |###[ PROFISafe Control Message with F_CRC_Seed=0 ]###
       |  dat(      = 'AAA'
       |  control   = Toggle_h
       |  crc       = 0x424242
       |###[ PNIO RTC IOxS ]###
       |     dataState = good
       |     instance  = subslot
       |     reserved  = 0x0
       |     extension = 0
      padding   = ''
      cycleCounter= 1024
      dataStatus= primary+validData+run+no_problem
      transferStatus= 0


For Scapy to be able to dissect it correctly, one must also configure the layer for it to know the location of each data in the buffer. This configuration is saved in the dictionary ``conf.contribs["PNIO_RTC"]`` which can be updated with the ``conf.contribs["PNIO_RTC"].update`` method. Each item in the dictionary uses the tuple ``(Ether.src, Ether.dst, ProfinetIO.frameID)`` as key, to be able to separate the configuration of each communication. Each value is then a list of classes which describes a data packet. If we continue the previous example, here is the configuration to set::

    >>> e=Ether(src='00:01:02:03:04:05', dst='06:07:08:09:0a:0b') / ProfinetIO(frameID="RT_CLASS_1") / p
    >>> e.show2()
    ###[ Ethernet ]###
      dst       = 06:07:08:09:0a:0b
      src       = 00:01:02:03:04:05
      type      = 0x8892
    ###[ ProfinetIO ]###
         frameID   = RT_CLASS_1 (8000)
    ###[ PROFINET Real-Time ]###
            \data      \
             |###[ PROFINET IO Real Time Cyclic Default Raw Data ]###
             |  data      = '\\x80AAA\x00\\x80AAA\x00 BBB\\x80'
            padding   = ''
            cycleCounter= 1024
            dataStatus= primary+validData+run+no_problem
            transferStatus= 0
    >>> conf.contribs["PNIO_RTC"].update({('00:01:02:03:04:05', '06:07:08:09:0a:0b', 0x8000): [
    ... PNIORealTime_IOxS,
    ... PNIORealTimeCyclicPDU.build_fixed_len_raw_type(4),
    ... PNIORealTime_IOxS,
    ... PROFIsafe.build_PROFIsafe_class(PROFIsafeControl, 4),
    ... PNIORealTime_IOxS,
    ... ]})
    >>> e.show2()
    ###[ Ethernet ]###
      dst       = 06:07:08:09:0a:0b
      src       = 00:01:02:03:04:05
      type      = 0x8892
    ###[ ProfinetIO ]###
         frameID   = RT_CLASS_1 (8000)
    ###[ PROFINET Real-Time ]###
            \data      \
             |###[ PNIO RTC IOxS ]###
             |  dataState = good
             |  instance  = subslot
             |  reserved  = 0x0
             |  extension = 0
             |###[ FixedLenRawPacketLen4 ]###
             |  data      = 'AAA'
             |###[ PNIO RTC IOxS ]###
             |  dataState = good
             |  instance  = subslot
             |  reserved  = 0x0
             |  extension = 0
             |###[ PROFISafe Control Message with F_CRC_Seed=0 ]###
             |  data      = 'AAA'
             |  control   = Toggle_h
             |  crc       = 0x424242
             |###[ PNIO RTC IOxS ]###
             |  dataState = good
             |  instance  = subslot
             |  reserved  = 0x0
             |  extension = 0
            padding   = ''
            cycleCounter= 1024
            dataStatus= primary+validData+run+no_problem
            transferStatus= 0

If no data packets are configured for a given offset, it defaults to a ``PNIORealTimeCyclicDefaultRawData``.
