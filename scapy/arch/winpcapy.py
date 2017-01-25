#-------------------------------------------------------------------------------
# Name:        winpcapy.py
#
# Author:      Massimo Ciani
#
# Created:     01/09/2009
# Copyright:   (c) Massimo Ciani 2009
#
#-------------------------------------------------------------------------------


from ctypes import *
from ctypes.util import find_library
import sys

WIN32=False
HAVE_REMOTE=False


if sys.platform.startswith('win'):
    WIN32=True
    HAVE_REMOTE=True

if WIN32:
    SOCKET = c_uint
    _lib=CDLL('wpcap.dll')
else:
    SOCKET = c_int
    _lib_name = find_library('pcap')
    if not _lib_name:
      raise OSError("Cannot fine libpcap.so library")
    _lib=CDLL(_lib_name)



##
## misc
##
u_short = c_ushort
bpf_int32 = c_int
u_int = c_int
bpf_u_int32 = u_int
pcap = c_void_p
pcap_dumper = c_void_p
u_char = c_ubyte
FILE = c_void_p
STRING = c_char_p

class bpf_insn(Structure):
    _fields_=[("code",c_ushort),
              ("jt",c_ubyte),
              ("jf",c_ubyte),
              ("k",bpf_u_int32)]
    
class bpf_program(Structure):
    pass
bpf_program._fields_ = [('bf_len', u_int),
                        ('bf_insns', POINTER(bpf_insn))]

class bpf_version(Structure):
    _fields_=[("bv_major",c_ushort),
              ("bv_minor",c_ushort)]


class timeval(Structure):
    pass
timeval._fields_ = [('tv_sec', c_long),
                    ('tv_usec', c_long)]

## sockaddr is used by pcap_addr.
## For exapmle if sa_family==socket.AF_INET then we need cast
## with sockaddr_in 
if WIN32:
    class sockaddr(Structure):
        _fields_ = [("sa_family", c_ushort),
                    ("sa_data",c_ubyte * 14)]

    class sockaddr_in(Structure):
        _fields_ = [("sin_family", c_ushort),
                    ("sin_port", c_uint16),
                    ("sin_addr", 4 * c_ubyte)]

    class sockaddr_in6(Structure):
        _fields_ = [("sin6_family", c_ushort),
                    ("sin6_port", c_uint16),
                    ("sin6_flowinfo", c_uint32),
                    ("sin6_addr", 16 * c_ubyte),
                    ("sin6_scope", c_uint32)]
else:
    class sockaddr(Structure):
        _fields_ = [("sa_len", c_ubyte),
                    ("sa_family",c_ubyte),
                    ("sa_data",c_ubyte * 14)]

    class sockaddr_in(Structure):
        _fields_ = [("sin_len", c_ubyte),
                    ("sin_family", c_ubyte),
                    ("sin_port", c_uint16),
                    ("sin_addr", 4 * c_ubyte),
                    ("sin_zero", 8 * c_char)]

    class sockaddr_in6(Structure):
        _fields_ = [("sin6_len", c_ubyte),
                    ("sin6_family", c_ubyte),
                    ("sin6_port", c_uint16),
                    ("sin6_flowinfo", c_uint32),
                    ("sin6_addr", 16 * c_ubyte),
                    ("sin6_scope", c_uint32)]

    class sockaddr_dl(Structure):
        _fields_ = [("sdl_len", c_ubyte),
                    ("sdl_family", c_ubyte),
                    ("sdl_index", c_ushort),
                    ("sdl_type", c_ubyte),
                    ("sdl_nlen", c_ubyte),
                    ("sdl_alen", c_ubyte),
                    ("sdl_slen", c_ubyte),
                    ("sdl_data", 46 * c_ubyte)]
##
## END misc
##

##
## Data Structures
##

## struct   pcap_file_header
##  Header of a libpcap dump file.
class pcap_file_header(Structure):
    _fields_ = [('magic', bpf_u_int32),
                ('version_major', u_short),
                ('version_minor', u_short),
                ('thiszone', bpf_int32),
                ('sigfigs', bpf_u_int32),
                ('snaplen', bpf_u_int32),
                ('linktype', bpf_u_int32)]

## struct   pcap_pkthdr
##  Header of a packet in the dump file.
class pcap_pkthdr(Structure):
    _fields_ = [('ts', timeval),
                ('caplen', bpf_u_int32),
                ('len', bpf_u_int32)]

## struct   pcap_stat
##  Structure that keeps statistical values on an interface.
class pcap_stat(Structure):
    pass
### _fields_ list in Structure is final.
### We need a temp list
_tmpList = [("ps_recv", c_uint), ("ps_drop", c_uint), ("ps_ifdrop", c_uint)]
if HAVE_REMOTE:
    _tmpList.append(("ps_capt",c_uint))
    _tmpList.append(("ps_sent",c_uint))
    _tmpList.append(("ps_netdrop",c_uint))
pcap_stat._fields_=_tmpList

## struct   pcap_addr
##  Representation of an interface address, used by pcap_findalldevs().
class pcap_addr(Structure):
    pass
pcap_addr._fields_ = [('next', POINTER(pcap_addr)),
                      ('addr', POINTER(sockaddr)),
                      ('netmask', POINTER(sockaddr)),
                      ('broadaddr', POINTER(sockaddr)),
                      ('dstaddr', POINTER(sockaddr))]

## struct   pcap_if
##  Item in a list of interfaces, used by pcap_findalldevs().
class pcap_if(Structure):
    pass
pcap_if._fields_ = [('next', POINTER(pcap_if)),
                    ('name', STRING),
                    ('description', STRING),
                    ('addresses', POINTER(pcap_addr)),
                    ('flags', bpf_u_int32)]

##
## END Data Structures
##

##
## Defines
##

##define  PCAP_VERSION_MAJOR   2
#   Major libpcap dump file version.
PCAP_VERSION_MAJOR = 2 
##define  PCAP_VERSION_MINOR   4
#   Minor libpcap dump file version.
PCAP_VERSION_MINOR = 4 
##define  PCAP_ERRBUF_SIZE   256
#   Size to use when allocating the buffer that contains the libpcap errors.
PCAP_ERRBUF_SIZE = 256 
##define  PCAP_IF_LOOPBACK   0x00000001
#   interface is loopback
PCAP_IF_LOOPBACK = 1 
##define  MODE_CAPT   0
#   Capture mode, to be used when calling pcap_setmode().
MODE_CAPT = 0
##define  MODE_STAT   1
#   Statistical mode, to be used when calling pcap_setmode().
MODE_STAT = 1

##
## END Defines
##

##
## Typedefs
##

#typedef int  bpf_int32 (already defined)
#   32-bit integer
#typedef u_int  bpf_u_int32 (already defined)
#   32-bit unsigned integer
#typedef struct pcap  pcap_t
#   Descriptor of an open capture instance. This structure is opaque to the user, that handles its content through the functions provided by wpcap.dll.
pcap_t = pcap
#typedef struct pcap_dumper   pcap_dumper_t
#   libpcap savefile descriptor.
pcap_dumper_t = pcap_dumper
#typedef struct pcap_if   pcap_if_t
#   Item in a list of interfaces, see pcap_if.
pcap_if_t = pcap_if
#typedef struct pcap_addr   pcap_addr_t
#   Representation of an interface address, see pcap_addr.
pcap_addr_t = pcap_addr

##
## END Typedefs
##





# values for enumeration 'pcap_direction_t'
#pcap_direction_t = c_int # enum

##
## Unix-compatible Functions
## These functions are part of the libpcap library, and therefore work both on Windows and on Linux. 
##

#typedef void(* pcap_handler )(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
#   Prototype of the callback function that receives the packets.
## This one is defined from programmer
pcap_handler=CFUNCTYPE(None,POINTER(c_ubyte),POINTER(pcap_pkthdr),POINTER(c_ubyte))

#pcap_t *   pcap_open_live (const char *device, int snaplen, int promisc, int to_ms, char *ebuf)
#   Open a live capture from the network.
pcap_open_live = _lib.pcap_open_live
pcap_open_live.restype = POINTER(pcap_t)
pcap_open_live.argtypes = [STRING, c_int, c_int, c_int, STRING]

#pcap_t *   pcap_open_dead (int linktype, int snaplen)
#   Create a pcap_t structure without starting a capture.
pcap_open_dead = _lib.pcap_open_dead
pcap_open_dead.restype = POINTER(pcap_t)
pcap_open_dead.argtypes = [c_int, c_int]

#pcap_t *   pcap_open_offline (const char *fname, char *errbuf)
#   Open a savefile in the tcpdump/libpcap format to read packets.
pcap_open_offline = _lib.pcap_open_offline
pcap_open_offline.restype = POINTER(pcap_t)
pcap_open_offline.argtypes = [STRING, STRING]

#pcap_dumper_t *   pcap_dump_open (pcap_t *p, const char *fname)
#   Open a file to write packets.
pcap_dump_open = _lib.pcap_dump_open
pcap_dump_open.restype = POINTER(pcap_dumper_t)
pcap_dump_open.argtypes = [POINTER(pcap_t), STRING]

#int pcap_setnonblock (pcap_t *p, int nonblock, char *errbuf)
#   Switch between blocking and nonblocking mode.
pcap_setnonblock = _lib.pcap_setnonblock
pcap_setnonblock.restype = c_int
pcap_setnonblock.argtypes = [POINTER(pcap_t), c_int, STRING]

#int pcap_getnonblock (pcap_t *p, char *errbuf)
#   Get the "non-blocking" state of an interface.
pcap_getnonblock = _lib.pcap_getnonblock
pcap_getnonblock.restype = c_int
pcap_getnonblock.argtypes = [POINTER(pcap_t), STRING]

#int pcap_findalldevs (pcap_if_t **alldevsp, char *errbuf)
#   Construct a list of network devices that can be opened with pcap_open_live().
pcap_findalldevs = _lib.pcap_findalldevs
pcap_findalldevs.restype = c_int
pcap_findalldevs.argtypes = [POINTER(POINTER(pcap_if_t)), STRING]

#void pcap_freealldevs (pcap_if_t *alldevsp)
#   Free an interface list returned by pcap_findalldevs().
pcap_freealldevs = _lib.pcap_freealldevs
pcap_freealldevs.restype = None
pcap_freealldevs.argtypes = [POINTER(pcap_if_t)]

#char *   pcap_lookupdev (char *errbuf)
#   Return the first valid device in the system.
pcap_lookupdev = _lib.pcap_lookupdev
pcap_lookupdev.restype = STRING
pcap_lookupdev.argtypes = [STRING]

#int pcap_lookupnet (const char *device, bpf_u_int32 *netp, bpf_u_int32 *maskp, char *errbuf)
#   Return the subnet and netmask of an interface.
pcap_lookupnet = _lib.pcap_lookupnet
pcap_lookupnet.restype = c_int
pcap_lookupnet.argtypes = [STRING, POINTER(bpf_u_int32), POINTER(bpf_u_int32), STRING]

#int pcap_dispatch (pcap_t *p, int cnt, pcap_handler callback, u_char *user)
#   Collect a group of packets.
pcap_dispatch = _lib.pcap_dispatch
pcap_dispatch.restype = c_int
pcap_dispatch.argtypes = [POINTER(pcap_t), c_int, pcap_handler, POINTER(u_char)]

#int pcap_loop (pcap_t *p, int cnt, pcap_handler callback, u_char *user)
#   Collect a group of packets.
pcap_loop = _lib.pcap_loop
pcap_loop.restype = c_int
pcap_loop.argtypes = [POINTER(pcap_t), c_int, pcap_handler, POINTER(u_char)]

#u_char *   pcap_next (pcap_t *p, struct pcap_pkthdr *h)
#   Return the next available packet.
pcap_next = _lib.pcap_next
pcap_next.restype = POINTER(u_char)
pcap_next.argtypes = [POINTER(pcap_t), POINTER(pcap_pkthdr)]

#int pcap_next_ex (pcap_t *p, struct pcap_pkthdr **pkt_header, const u_char **pkt_data)
#   Read a packet from an interface or from an offline capture.
pcap_next_ex = _lib.pcap_next_ex
pcap_next_ex.restype = c_int
pcap_next_ex.argtypes = [POINTER(pcap_t), POINTER(POINTER(pcap_pkthdr)), POINTER(POINTER(u_char))]

#void pcap_breakloop (pcap_t *)
#   set a flag that will force pcap_dispatch() or pcap_loop() to return rather than looping.
pcap_breakloop = _lib.pcap_breakloop
pcap_breakloop.restype = None
pcap_breakloop.argtypes = [POINTER(pcap_t)]

#int pcap_sendpacket (pcap_t *p, u_char *buf, int size)
#   Send a raw packet.
pcap_sendpacket = _lib.pcap_sendpacket
pcap_sendpacket.restype = c_int
#pcap_sendpacket.argtypes = [POINTER(pcap_t), POINTER(u_char), c_int]
pcap_sendpacket.argtypes = [POINTER(pcap_t), c_void_p, c_int]

#void pcap_dump (u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
#   Save a packet to disk.
pcap_dump = _lib.pcap_dump
pcap_dump.restype = None
pcap_dump.argtypes = [POINTER(pcap_dumper_t), POINTER(pcap_pkthdr), POINTER(u_char)]

#long pcap_dump_ftell (pcap_dumper_t *)
#   Return the file position for a "savefile".
pcap_dump_ftell = _lib.pcap_dump_ftell
pcap_dump_ftell.restype = c_long
pcap_dump_ftell.argtypes = [POINTER(pcap_dumper_t)]

#int pcap_compile (pcap_t *p, struct bpf_program *fp, char *str, int optimize, bpf_u_int32 netmask)
#   Compile a packet filter, converting an high level filtering expression (see Filtering expression syntax) in a program that can be interpreted by the kernel-level filtering engine.
pcap_compile = _lib.pcap_compile
pcap_compile.restype = c_int
pcap_compile.argtypes = [POINTER(pcap_t), POINTER(bpf_program), STRING, c_int, bpf_u_int32]

#int pcap_compile_nopcap (int snaplen_arg, int linktype_arg, struct bpf_program *program, char *buf, int optimize, bpf_u_int32 mask)
#   Compile a packet filter without the need of opening an adapter. This function converts an high level filtering expression (see Filtering expression syntax) in a program that can be interpreted by the kernel-level filtering engine.
pcap_compile_nopcap = _lib.pcap_compile_nopcap
pcap_compile_nopcap.restype = c_int
pcap_compile_nopcap.argtypes = [c_int, c_int, POINTER(bpf_program), STRING, c_int, bpf_u_int32]

#int pcap_setfilter (pcap_t *p, struct bpf_program *fp)
#   Associate a filter to a capture.
pcap_setfilter = _lib.pcap_setfilter
pcap_setfilter.restype = c_int
pcap_setfilter.argtypes = [POINTER(pcap_t), POINTER(bpf_program)]

#void pcap_freecode (struct bpf_program *fp)
#   Free a filter.
pcap_freecode = _lib.pcap_freecode
pcap_freecode.restype = None
pcap_freecode.argtypes = [POINTER(bpf_program)]

#int pcap_datalink (pcap_t *p)
#   Return the link layer of an adapter.
pcap_datalink = _lib.pcap_datalink
pcap_datalink.restype = c_int
pcap_datalink.argtypes = [POINTER(pcap_t)]

#int pcap_list_datalinks (pcap_t *p, int **dlt_buf)
#   list datalinks
pcap_list_datalinks = _lib.pcap_list_datalinks
pcap_list_datalinks.restype = c_int
#pcap_list_datalinks.argtypes = [POINTER(pcap_t), POINTER(POINTER(c_int))]

#int pcap_set_datalink (pcap_t *p, int dlt)
#   Set the current data link type of the pcap descriptor to the type specified by dlt. -1 is returned on failure.
pcap_set_datalink = _lib.pcap_set_datalink
pcap_set_datalink.restype = c_int
pcap_set_datalink.argtypes = [POINTER(pcap_t), c_int]

#int pcap_datalink_name_to_val (const char *name)
#   Translates a data link type name, which is a DLT_ name with the DLT_ removed, to the corresponding data link type value. The translation is case-insensitive. -1 is returned on failure.
pcap_datalink_name_to_val = _lib.pcap_datalink_name_to_val
pcap_datalink_name_to_val.restype = c_int
pcap_datalink_name_to_val.argtypes = [STRING]

#const char *   pcap_datalink_val_to_name (int dlt)
#   Translates a data link type value to the corresponding data link type name. NULL is returned on failure.
pcap_datalink_val_to_name = _lib.pcap_datalink_val_to_name
pcap_datalink_val_to_name.restype = STRING
pcap_datalink_val_to_name.argtypes = [c_int]

#const char *   pcap_datalink_val_to_description (int dlt)
#   Translates a data link type value to a short description of that data link type. NULL is returned on failure.
pcap_datalink_val_to_description = _lib.pcap_datalink_val_to_description
pcap_datalink_val_to_description.restype = STRING
pcap_datalink_val_to_description.argtypes = [c_int]

#int pcap_snapshot (pcap_t *p)
#   Return the dimension of the packet portion (in bytes) that is delivered to the application.
pcap_snapshot = _lib.pcap_snapshot
pcap_snapshot.restype = c_int
pcap_snapshot.argtypes = [POINTER(pcap_t)]

#int pcap_is_swapped (pcap_t *p)
#   returns true if the current savefile uses a different byte order than the current system.
pcap_is_swapped = _lib.pcap_is_swapped
pcap_is_swapped.restype = c_int
pcap_is_swapped.argtypes = [POINTER(pcap_t)]

#int pcap_major_version (pcap_t *p)
#   return the major version number of the pcap library used to write the savefile.
pcap_major_version = _lib.pcap_major_version
pcap_major_version.restype = c_int
pcap_major_version.argtypes = [POINTER(pcap_t)]

#int pcap_minor_version (pcap_t *p)
#   return the minor version number of the pcap library used to write the savefile.
pcap_minor_version = _lib.pcap_minor_version
pcap_minor_version.restype = c_int
pcap_minor_version.argtypes = [POINTER(pcap_t)]

#FILE *   pcap_file (pcap_t *p)
#   Return the standard stream of an offline capture.
pcap_file=_lib.pcap_file
pcap_file.restype = FILE
pcap_file.argtypes = [POINTER(pcap_t)]

#int pcap_stats (pcap_t *p, struct pcap_stat *ps)
#   Return statistics on current capture.
pcap_stats = _lib.pcap_stats
pcap_stats.restype = c_int
pcap_stats.argtypes = [POINTER(pcap_t), POINTER(pcap_stat)]

#void pcap_perror (pcap_t *p, char *prefix)
#   print the text of the last pcap library error on stderr, prefixed by prefix.
pcap_perror = _lib.pcap_perror
pcap_perror.restype = None
pcap_perror.argtypes = [POINTER(pcap_t), STRING]

#char *   pcap_geterr (pcap_t *p)
#   return the error text pertaining to the last pcap library error.
pcap_geterr = _lib.pcap_geterr
pcap_geterr.restype = STRING
pcap_geterr.argtypes = [POINTER(pcap_t)]

#char *   pcap_strerror (int error)
#   Provided in case strerror() isn't available.
pcap_strerror = _lib.pcap_strerror
pcap_strerror.restype = STRING
pcap_strerror.argtypes = [c_int]

#const char *   pcap_lib_version (void)
#   Returns a pointer to a string giving information about the version of the libpcap library being used; note that it contains more information than just a version number.
pcap_lib_version = _lib.pcap_lib_version
pcap_lib_version.restype = STRING
pcap_lib_version.argtypes = []

#void pcap_close (pcap_t *p)
#   close the files associated with p and deallocates resources.
pcap_close = _lib.pcap_close
pcap_close.restype = None
pcap_close.argtypes = [POINTER(pcap_t)]

#FILE *   pcap_dump_file (pcap_dumper_t *p)
#   return the standard I/O stream of the 'savefile' opened by pcap_dump_open().
pcap_dump_file=_lib.pcap_dump_file
pcap_dump_file.restype=FILE
pcap_dump_file.argtypes= [POINTER(pcap_dumper_t)]

#int pcap_dump_flush (pcap_dumper_t *p)
#   Flushes the output buffer to the ``savefile,'' so that any packets written with pcap_dump() but not yet written to the ``savefile'' will be written. -1 is returned on error, 0 on success.
pcap_dump_flush = _lib.pcap_dump_flush
pcap_dump_flush.restype = c_int
pcap_dump_flush.argtypes = [POINTER(pcap_dumper_t)]

#void pcap_dump_close (pcap_dumper_t *p)
#   Closes a savefile. 
pcap_dump_close = _lib.pcap_dump_close
pcap_dump_close.restype = None
pcap_dump_close.argtypes = [POINTER(pcap_dumper_t)]

if not WIN32:

    pcap_get_selectable_fd = _lib.pcap_get_selectable_fd
    pcap_get_selectable_fd.restype = c_int    
    pcap_get_selectable_fd.argtypes = [POINTER(pcap_t)]

###########################################
## Windows-specific Extensions
## The functions in this section extend libpcap to offer advanced functionalities
## (like remote packet capture, packet buffer size variation or high-precision packet injection).
## Howerver, at the moment they can be used only in Windows.
###########################################
if WIN32:
    HANDLE = c_void_p
    
    ##############
    ## Identifiers related to the new source syntax
    ##############
    #define   PCAP_SRC_FILE   2
    #define   PCAP_SRC_IFLOCAL   3
    #define   PCAP_SRC_IFREMOTE   4
    #Internal representation of the type of source in use (file, remote/local interface).
    PCAP_SRC_FILE = 2
    PCAP_SRC_IFLOCAL = 3
    PCAP_SRC_IFREMOTE = 4
    
    ##############
    ## Strings related to the new source syntax
    ##############
    #define   PCAP_SRC_FILE_STRING   "file://"
    #define   PCAP_SRC_IF_STRING   "rpcap://"
    #String that will be used to determine the type of source in use (file, remote/local interface).
    PCAP_SRC_FILE_STRING="file://"
    PCAP_SRC_IF_STRING="rpcap://"
    
    ##############
    ## Flags defined in the pcap_open() function
    ##############
    # define  PCAP_OPENFLAG_PROMISCUOUS   1
    #   Defines if the adapter has to go in promiscuous mode.
    PCAP_OPENFLAG_PROMISCUOUS=1
    # define  PCAP_OPENFLAG_DATATX_UDP   2
    #   Defines if the data trasfer (in case of a remote capture) has to be done with UDP protocol.
    PCAP_OPENFLAG_DATATX_UDP=2
    # define  PCAP_OPENFLAG_NOCAPTURE_RPCAP   4
    PCAP_OPENFLAG_NOCAPTURE_RPCAP=4
    #   Defines if the remote probe will capture its own generated traffic.
    # define  PCAP_OPENFLAG_NOCAPTURE_LOCAL   8
    PCAP_OPENFLAG_NOCAPTURE_LOCAL = 8
    # define  PCAP_OPENFLAG_MAX_RESPONSIVENESS   16
    #   This flag configures the adapter for maximum responsiveness.
    PCAP_OPENFLAG_MAX_RESPONSIVENESS=16
    
    ##############
    ## Sampling methods defined in the pcap_setsampling() function
    ##############
    # define  PCAP_SAMP_NOSAMP   0
    # No sampling has to be done on the current capture.
    PCAP_SAMP_NOSAMP=0
    # define  PCAP_SAMP_1_EVERY_N   1
    # It defines that only 1 out of N packets must be returned to the user.
    PCAP_SAMP_1_EVERY_N=1
    #define   PCAP_SAMP_FIRST_AFTER_N_MS   2
    # It defines that we have to return 1 packet every N milliseconds.
    PCAP_SAMP_FIRST_AFTER_N_MS=2
    
    ##############
    ## Authentication methods supported by the RPCAP protocol
    ##############
    # define  RPCAP_RMTAUTH_NULL   0
    # It defines the NULL authentication.
    RPCAP_RMTAUTH_NULL=0
    # define  RPCAP_RMTAUTH_PWD   1
    # It defines the username/password authentication.
    RPCAP_RMTAUTH_PWD=1
    

    ##############
    ## Remote struct and defines
    ##############
    # define  PCAP_BUF_SIZE   1024
    # Defines the maximum buffer size in which address, port, interface names are kept.
    PCAP_BUF_SIZE = 1024
    # define  RPCAP_HOSTLIST_SIZE   1024
    # Maximum lenght of an host name (needed for the RPCAP active mode).
    RPCAP_HOSTLIST_SIZE = 1024
    
    class pcap_send_queue(Structure):
        _fields_=[("maxlen",c_uint),
                  ("len",c_uint),
                  ("buffer",c_char_p)]
        
    ## struct   pcap_rmtauth
    ## This structure keeps the information needed to autheticate the user on a remote machine
    class pcap_rmtauth(Structure):
        _fields_=[("type",c_int),
                  ("username",c_char_p),
                  ("password",c_char_p)]
    
    ## struct   pcap_samp
    ## This structure defines the information related to sampling    
    class pcap_samp(Structure):
        _fields_=[("method",c_int),
                  ("value",c_int)]

    #PAirpcapHandle   pcap_get_airpcap_handle (pcap_t *p)
    #   Returns the AirPcap handler associated with an adapter. This handler can be used to change the wireless-related settings of the CACE Technologies AirPcap wireless capture adapters.
    
    #bool pcap_offline_filter (struct bpf_program *prog, const struct pcap_pkthdr *header, const u_char *pkt_data)
    #   Returns if a given filter applies to an offline packet.
    pcap_offline_filter = _lib.pcap_offline_filter
    pcap_offline_filter.restype = c_bool
    pcap_offline_filter.argtypes = [POINTER(bpf_program),POINTER(pcap_pkthdr),POINTER(u_char)]
    
    #int pcap_live_dump (pcap_t *p, char *filename, int maxsize, int maxpacks)
    #   Save a capture to file.
    pcap_live_dump = _lib.pcap_live_dump
    pcap_live_dump.restype = c_int
    pcap_live_dump.argtypes = [POINTER(pcap_t), POINTER(c_char), c_int,c_int]
    
    #int pcap_live_dump_ended (pcap_t *p, int sync)
    #   Return the status of the kernel dump process, i.e. tells if one of the limits defined with pcap_live_dump() has been reached.
    pcap_live_dump_ended = _lib.pcap_live_dump_ended
    pcap_live_dump_ended.restype = c_int
    pcap_live_dump_ended.argtypes = [POINTER(pcap_t), c_int]
    
    #struct pcap_stat *  pcap_stats_ex (pcap_t *p, int *pcap_stat_size)
    #   Return statistics on current capture.
    pcap_stats_ex = _lib.pcap_stats_ex
    pcap_stats_ex.restype = POINTER(pcap_stat)
    pcap_stats_ex.argtypes = [POINTER(pcap_t), POINTER(c_int)]
    
    #int pcap_setbuff (pcap_t *p, int dim)
    #   Set the size of the kernel buffer associated with an adapter.
    pcap_setbuff = _lib.pcap_setbuff
    pcap_setbuff.restype = c_int
    pcap_setbuff.argtypes = [POINTER(pcap_t), c_int]
    
    #int pcap_setmode (pcap_t *p, int mode)
    #   Set the working mode of the interface p to mode.
    pcap_setmode = _lib.pcap_setmode
    pcap_setmode.restype = c_int
    pcap_setmode.argtypes = [POINTER(pcap_t), c_int]
    
    #int pcap_setmintocopy (pcap_t *p, int size)
    #   Set the minumum amount of data received by the kernel in a single call.
    pcap_setmintocopy = _lib.pcap_setmintocopy
    pcap_setmintocopy.restype = c_int
    pcap_setmintocopy.argtype = [POINTER(pcap_t), c_int]
    
    #HANDLE pcap_getevent (pcap_t *p)
    #   Return the handle of the event associated with the interface p.
    pcap_getevent = _lib.pcap_getevent
    pcap_getevent.restype = HANDLE
    pcap_getevent.argtypes = [POINTER(pcap_t)]

    #pcap_send_queue *  pcap_sendqueue_alloc (u_int memsize)
    #   Allocate a send queue.
    pcap_sendqueue_alloc = _lib.pcap_sendqueue_alloc
    pcap_sendqueue_alloc.restype = POINTER(pcap_send_queue)
    pcap_sendqueue_alloc.argtypes = [c_uint]
    
    #void pcap_sendqueue_destroy (pcap_send_queue *queue)
    #   Destroy a send queue.
    pcap_sendqueue_destroy = _lib.pcap_sendqueue_destroy
    pcap_sendqueue_destroy.restype = None
    pcap_sendqueue_destroy.argtypes = [POINTER(pcap_send_queue)]
    
    #int pcap_sendqueue_queue (pcap_send_queue *queue, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
    #   Add a packet to a send queue.
    pcap_sendqueue_queue = _lib.pcap_sendqueue_queue
    pcap_sendqueue_queue.restype = c_int
    pcap_sendqueue_queue.argtypes = [POINTER(pcap_send_queue), POINTER(pcap_pkthdr), POINTER(u_char)]
    
    #u_int pcap_sendqueue_transmit (pcap_t *p, pcap_send_queue *queue, int sync)
    #   Send a queue of raw packets to the network.
    pcap_sendqueue_transmit = _lib.pcap_sendqueue_transmit
    pcap_sendqueue_transmit.retype = u_int
    pcap_sendqueue_transmit.argtypes = [POINTER(pcap_t), POINTER(pcap_send_queue), c_int]
    
    #int pcap_findalldevs_ex (char *source, struct pcap_rmtauth *auth, pcap_if_t **alldevs, char *errbuf)
    #   Create a list of network devices that can be opened with pcap_open().
    pcap_findalldevs_ex = _lib.pcap_findalldevs_ex
    pcap_findalldevs_ex.retype = c_int
    pcap_findalldevs_ex.argtypes = [STRING, POINTER(pcap_rmtauth), POINTER(POINTER(pcap_if_t)), STRING]
    
    #int pcap_createsrcstr (char *source, int type, const char *host, const char *port, const char *name, char *errbuf)
    #   Accept a set of strings (host name, port, ...), and it returns the complete source string according to the new format (e.g. 'rpcap://1.2.3.4/eth0').
    pcap_createsrcstr = _lib.pcap_createsrcstr
    pcap_createsrcstr.restype = c_int
    pcap_createsrcstr.argtypes = [STRING, c_int, STRING, STRING, STRING, STRING]
    
    #int pcap_parsesrcstr (const char *source, int *type, char *host, char *port, char *name, char *errbuf)
    #   Parse the source string and returns the pieces in which the source can be split.
    pcap_parsesrcstr = _lib.pcap_parsesrcstr
    pcap_parsesrcstr.retype = c_int
    pcap_parsesrcstr.argtypes = [STRING, POINTER(c_int), STRING, STRING, STRING, STRING]
    
    #pcap_t *   pcap_open (const char *source, int snaplen, int flags, int read_timeout, struct pcap_rmtauth *auth, char *errbuf)
    #   Open a generic source in order to capture / send (WinPcap only) traffic.
    pcap_open = _lib.pcap_open
    pcap_open.restype = POINTER(pcap_t)
    pcap_open.argtypes = [STRING, c_int, c_int, c_int, POINTER(pcap_rmtauth), STRING]
    
    #struct pcap_samp *  pcap_setsampling (pcap_t *p)
    #   Define a sampling method for packet capture.
    pcap_setsampling = _lib.pcap_setsampling
    pcap_setsampling.restype = POINTER(pcap_samp)
    pcap_setsampling.argtypes = [POINTER(pcap_t)]
    
    #SOCKET pcap_remoteact_accept (const char *address, const char *port, const char *hostlist, char *connectinghost, struct pcap_rmtauth *auth, char *errbuf)
    #   Block until a network connection is accepted (active mode only).
    pcap_remoteact_accept = _lib.pcap_remoteact_accept
    pcap_remoteact_accept.restype = SOCKET
    pcap_remoteact_accept.argtypes = [STRING, STRING, STRING, STRING, POINTER(pcap_rmtauth), STRING]
    
    #int pcap_remoteact_close (const char *host, char *errbuf)
    #   Drop an active connection (active mode only).
    pcap_remoteact_close = _lib.pcap_remoteact_close
    pcap_remoteact_close.restypes = c_int
    pcap_remoteact_close.argtypes = [STRING, STRING]
    
    #void pcap_remoteact_cleanup ()
    #   Clean the socket that is currently used in waiting active connections.
    pcap_remoteact_cleanup = _lib.pcap_remoteact_cleanup
    pcap_remoteact_cleanup.restypes = None
    pcap_remoteact_cleanup.argtypes = []
    
    #int pcap_remoteact_list (char *hostlist, char sep, int size, char *errbuf)
    #   Return the hostname of the host that have an active connection with us (active mode only). 
    pcap_remoteact_list = _lib.pcap_remoteact_list
    pcap_remoteact_list.restype = c_int
    pcap_remoteact_list.argtypes = [STRING, c_char, c_int, STRING]
