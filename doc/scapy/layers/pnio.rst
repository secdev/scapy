***************
PROFINET IO RTC
***************

PROFINET IO is an industrial protocol composed of different layers such as the Real-Time Cyclic (RTC) layer, used to exchange data. However, this RTC layer is stateful and depends on a configuration sent through another layer: the DCE/RPC endpoint of PROFINET. This configuration defines where each exchanged piece of data must be located in the RTC ``data`` buffer, as well as the length of this same buffer. Building such packet is then a bit more complicated than other protocols.

RTC data packet
---------------

The first thing to do when building the RTC ``data`` buffer is to instantiate each Scapy packet which represents a piece of data. Each one of them may require some specific piece of configuration, such as its length. All packets and their configuration are:

* ``PNIORealTimeRawData``: a simple raw data like ``Raw``

  * ``length``: defines the length of the data

* ``Profisafe``: the PROFIsafe profile to perform functional safety

  * ``length``: defines the length of the whole packet
  * ``CRC``: defines the length of the CRC, either ``3`` or ``4``

* ``PNIORealTimeIOxS``: either an IO Consumer or Provider Status byte

  * Doesn't require any configuration

To instantiate one of these packets with its configuration, the ``config`` argument must be given. It is a ``dict()`` which contains all the required piece of configuration::

    >>> load_contrib('pnio_rtc')
    >>> raw(PNIORealTimeRawData(load='AAA', config={'length': 4}))
    'AAA\x00'
    >>> raw(Profisafe(load='AAA', Control_Status=0x20, CRC=0x424242, config={'length': 8, 'CRC': 3}))
    'AAA\x00 BBB'
    >>> hexdump(PNIORealTimeIOxS())
    0000   80                                                 .


RTC packet
----------

Now that a data packet can be instantiated, a whole RTC packet may be built. ``PNIORealTime`` contains a field ``data`` which is a list of all data packets to add in the buffer, however, without the configuration, Scapy won't be
able to dissect it::

    >>> load_contrib("pnio_rtc")
    >>> p=PNIORealTime(cycleCounter=1024, data=[
    ... PNIORealTimeIOxS(),
    ... PNIORealTimeRawData(load='AAA', config={'length':4}) / PNIORealTimeIOxS(),
    ... Profisafe(load='AAA', Control_Status=0x20, CRC=0x424242, config={'length': 8, 'CRC': 3}) / PNIORealTimeIOxS(),
    ... ])
    >>> p.show()
    ###[ PROFINET Real-Time ]### 
      len= None
      dataLen= None
      \data\
       |###[ PNIO RTC IOxS ]### 
       |  dataState= good
       |  instance= subslot
       |  reserved= 0x0
       |  extension= 0
       |###[ PNIO RTC Raw data ]### 
       |  load= 'AAA'
       |###[ PNIO RTC IOxS ]### 
       |     dataState= good
       |     instance= subslot
       |     reserved= 0x0
       |     extension= 0
       |###[ PROFISafe ]### 
       |  load= 'AAA'
       |  Control_Status= 0x20
       |  CRC= 0x424242
       |###[ PNIO RTC IOxS ]### 
       |     dataState= good
       |     instance= subslot
       |     reserved= 0x0
       |     extension= 0
      padding= ''
      cycleCounter= 1024
      dataStatus= primary+validData+run+no_problem
      transferStatus= 0
    
    >>> p.show2()
    ###[ PROFINET Real-Time ]### 
      len= 44
      dataLen= 15
      \data\
       |###[ PNIO RTC Raw data ]### 
       |  load= '\x80AAA\x00\x80AAA\x00 BBB\x80'
      padding= ''
      cycleCounter= 1024
      dataStatus= primary+validData+run+no_problem
      transferStatus= 0

For Scapy to be able to dissect it correctly, one must also configure the layer for it to know the location of each data in the buffer. This configuration is saved in the dictionary ``conf.contribs["PNIO_RTC"]`` which can be updated with the ``pnio_update_config`` method. Each item in the dictionary uses the tuple ``(Ether.src, Ether.dst)`` as key, to be able to separate the configuration of each communication. Each value is then a list of a tuple which describes a data packet. It is composed of the negative index, from the end of the data buffer, of the packet position, the class of the packet as the second item and the ``config`` dictionary to provide to the class as last. If we continue the previous example, here is the configuration to set::

    >>> load_contrib("pnio")
    >>> e=Ether(src='00:01:02:03:04:05', dst='06:07:08:09:0a:0b') / ProfinetIO() / p
    >>> e.show2()
    ###[ Ethernet ]### 
      dst= 06:07:08:09:0a:0b
      src= 00:01:02:03:04:05
      type= 0x8892
    ###[ ProfinetIO ]### 
         frameID= RT_CLASS_1
    ###[ PROFINET Real-Time ]### 
      len= 44
      dataLen= 15
      \data\
       |###[ PNIO RTC Raw data ]### 
       |  load= '\x80AAA\x00\x80AAA\x00 BBB\x80'
      padding= ''
      cycleCounter= 1024
      dataStatus= primary+validData+run+no_problem
      transferStatus= 0
    >>> pnio_update_config({('00:01:02:03:04:05', '06:07:08:09:0a:0b'): [
    ... (-9, Profisafe, {'length': 8, 'CRC': 3}),
    ... (-9 - 5, PNIORealTimeRawData, {'length':4}),
    ... ]})
    >>> e.show2()
    ###[ Ethernet ]### 
      dst= 06:07:08:09:0a:0b
      src= 00:01:02:03:04:05
      type= 0x8892
    ###[ ProfinetIO ]### 
         frameID= RT_CLASS_1
    ###[ PROFINET Real-Time ]### 
            len= 44
            dataLen= 15
            \data\
             |###[ PNIO RTC IOxS ]### 
             |  dataState= good
             |  instance= subslot
             |  reserved= 0x0L
             |  extension= 0L
             |###[ PNIO RTC Raw data ]### 
             |  load= 'AAA'
             |###[ PNIO RTC IOxS ]### 
             |     dataState= good
             |     instance= subslot
             |     reserved= 0x0L
             |     extension= 0L
             |###[ PROFISafe ]### 
             |  load= 'AAA'
             |  Control_Status= 0x20
             |  CRC= 0x424242L
             |###[ PNIO RTC IOxS ]### 
             |     dataState= good
             |     instance= subslot
             |     reserved= 0x0L
             |     extension= 0L
            padding= ''
            cycleCounter= 1024
            dataStatus= primary+validData+run+no_problem
            transferStatus= 0

If no data packets are configured for a given offset, it defaults to a ``PNIORealTimeIOxS``. However, this method is not very convenient for the user to configure the layer and it only affects the dissection of packets. In such cases, one may have access to several RTC packets, sniffed or retrieved from a PCAP file. Thus, ``PNIORealTime`` provides some methods to analyse a list of ``PNIORealTime`` packets and locate all data in it, based on simple heuristics. All of them take as first argument an iterable which contains the list of packets to analyse.

* ``PNIORealTime.find_data()`` analyses the data buffer and separate real data from IOxS. It returns a dict which can be provided to ``pnio_update_config``.
* ``PNIORealTime.find_profisafe()`` analyses the data buffer and find the PROFIsafe profiles among the real data. It returns a dict which can be provided to ``pnio_update_config``.
* ``PNIORealTime.analyse_data()`` executes both previous methods and update the configuration. **This is usually the method to call.**
* ``PNIORealTime.draw_entropy()`` will draw the entropy of each byte in the data buffer. It can be used to easily visualize PROFIsafe locations as entropy is the base of the decision algorithm of ``find_profisafe``.

::

    >>> load_contrib('pnio_rtc')
    >>> t=rdpcap('/path/to/trace.pcap', 1024)
    >>> PNIORealTime.analyse_data(t)
    {('00:01:02:03:04:05', '06:07:08:09:0a:0b'): [(-19, <class 'scapy.contrib.pnio_rtc.PNIORealTimeRawData'>, {'length': 1}), (-15, <class 'scapy.contrib.pnio_rtc.Profisafe'>, {'CRC': 3, 'length': 6}), (-7, <class 'scapy.contrib.pnio_rtc.Profisafe'>, {'CRC': 3, 'length': 5})]}
    >>> t[100].show()
    ###[ Ethernet ]###
      dst= 06:07:08:09:0a:0b
      src= 00:01:02:03:04:05
      type= n_802_1Q
    ###[ 802.1Q ]###
         prio= 6L
         id= 0L
         vlan= 0L
         type= 0x8892
    ###[ ProfinetIO ]###
            frameID= RT_CLASS_1
    ###[ PROFINET Real-Time ]###
               len= 44
               dataLen= 22
               \data\
                |###[ PNIO RTC Raw data ]###
                |  load= '\x80\x80\x80\x80\x80\x80\x00\x80\x80\x80\x12:\x0e\x12\x80\x80\x00\x12\x8b\x97\xe3\x80'
               padding= ''
               cycleCounter= 6208
               dataStatus= primary+validData+run+no_problem
               transferStatus= 0
    
    >>> t[100].show2()
    ###[ Ethernet ]###
      dst= 06:07:08:09:0a:0b
      src= 00:01:02:03:04:05
      type= n_802_1Q
    ###[ 802.1Q ]###
         prio= 6L
         id= 0L
         vlan= 0L
         type= 0x8892
    ###[ ProfinetIO ]###
            frameID= RT_CLASS_1
    ###[ PROFINET Real-Time ]###
               len= 44
               dataLen= 22
               \data\
                |###[ PNIO RTC IOxS ]###
                |  dataState= good
                |  instance= subslot
                |  reserved= 0x0L
                |  extension= 0L
                [...]
                |###[ PNIO RTC IOxS ]###
                |  dataState= good
                |  instance= subslot
                |  reserved= 0x0L
                |  extension= 0L
                |###[ PNIO RTC Raw data ]###
                |  load= ''
                |###[ PNIO RTC IOxS ]###
                |     dataState= good
                |     instance= subslot
                |     reserved= 0x0L
                |     extension= 0L
                [...]
                |###[ PNIO RTC IOxS ]###
                |  dataState= good
                |  instance= subslot
                |  reserved= 0x0L
                |  extension= 0L
                |###[ PROFISafe ]###
                |  load= ''
                |  Control_Status= 0x12
                |  CRC= 0x3a0e12L
                |###[ PNIO RTC IOxS ]###
                |     dataState= good
                |     instance= subslot
                |     reserved= 0x0L
                |     extension= 0L
                |###[ PNIO RTC IOxS ]###
                |  dataState= good
                |  instance= subslot
                |  reserved= 0x0L
                |  extension= 0L
                |###[ PROFISafe ]###
                |  load= ''
                |  Control_Status= 0x12
                |  CRC= 0x8b97e3L
                |###[ PNIO RTC IOxS ]###
                |     dataState= good
                |     instance= subslot
                |     reserved= 0x0L
                |     extension= 0L
               padding= ''
               cycleCounter= 6208
               dataStatus= primary+validData+run+no_problem
               transferStatus= 0
    
In addition, one can see, when displaying a ``PNIORealTime`` packet, the field ``len``. This is a computed field which is not added in the final packet build. It is mainly useful for dissection and reconstruction, but it can also be used to modify the behaviour of the packet. In fact, RTC packet must always be long enough for an Ethernet frame and to do so, a padding must be added right after the ``data`` buffer. The default behaviour is to add ``padding`` whose size is computed during the ``build`` process::

    >>> raw(PNIORealTime(cycleCounter=0x4242, data=[PNIORealTimeIOxS()]))
    '\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00BB5\x00'

However, one can set ``len`` to modify this behaviour. ``len`` controls the length of the whole ``PNIORealTime`` packet. Then, to shorten the length of the padding, ``len`` can be set to a lower value::

    >>> raw(PNIORealTime(cycleCounter=0x4242, data=[PNIORealTimeIOxS()], len=50))
    '\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00BB5\x00'
    >>> raw(PNIORealTime(cycleCounter=0x4242, data=[PNIORealTimeIOxS()]))
    '\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00BB5\x00'
    >>> raw(PNIORealTime(cycleCounter=0x4242, data=[PNIORealTimeIOxS()], len=30))
    '\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00BB5\x00'
