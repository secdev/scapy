import struct
import ipaddress

MPTCPSubtypes = {
    0x0: 'MP_CAPABLE',
    0x1: 'MP_JOIN',
    0x2: 'DSS',
    0x3: 'ADD_ADDR',
    0x4: 'REMOVE_ADDR',
    0x5: 'MP_PRIO',
    0x6: 'MP_FAIL',
    0x7: 'MP_FASTCLOSE',
    0x8: 'MP_TCPRST',
    0xf: 'MP_EXPRIMENTAL'
}

MP_TCPRSTReasons = {
    0x0: 'Unspecified error',
    0x1: 'MPTCP-specific error',
    0x2: 'Lack of resources',
    0x3: 'Administratively prohibited',
    0x4: 'Too much outstanding data',
    0x5: 'Unacceptable performance',
    0x6: 'Middlebox interference'
}


def decodeMpOption(olen, oval):
    return MpOption(olen, oval).__dict__


class MpOption:
    def __init__(self, olen, oval):
        opt = struct.unpack('!B', oval[:1])[0]
        enum = opt >> 4

        if enum in MPTCPSubtypes:
            self.subtype = MPTCPSubtypes[enum]

            oval = oval[1:]

            if enum == 0:
                self._MP_CAPABLE(olen, opt, oval)
            elif enum == 1:
                self._MP_JOIN(opt, olen, oval)
            elif enum == 2:
                self._DSS(oval)
            elif enum == 3:
                self._ADD_ADDR(opt, olen, oval)
            elif enum == 4:
                self._REMOVE_ADDR(olen, oval)
            elif enum == 5:
                self._MP_PRIO(opt)
            elif enum == 6:
                self._MP_FAIL(oval)
            elif enum == 7:
                self._MP_FASTCLOSE(oval)
            elif enum == 8:
                self._MP_TCPRST(opt, oval)
            elif enum == 15:
                self._MP_EXPRIMENTAL(oval)
        else:
            self.raw = oval

    def _MP_CAPABLE(self, olen, opt, oval):
        self.version = opt & 1  # v0 or v1
        flags = struct.unpack('!B', oval[:1])[0]
        oval = oval[1:]

        self.checksumReq = bool(flags & (1 << 7))       # A -> Checksum Req
        self.extensibility = bool(flags & (1 << 6))     # B -> Extensibility
        self.noMoreSubFlows = bool(flags & (1 << 5))    # C -> No more subflows
        self.useHMACSHA256 = bool(flags & 1)            # H -> Use HMAC-SHA256

        if olen > 4:
            self.sendKey = struct.unpack('!Q', oval[:8])[0]
            oval = oval[8:]

        if olen > 12:
            self.recvKey = struct.unpack('!Q', oval[:8])[0]
            oval = oval[8:]

        if olen > 20:
            self.dll = struct.unpack('!H', oval[:2])[0]
            oval = oval[2:]

        if self.checksumReq:
            self.checksum = struct.unpack('!H', oval)[0]

    def _MP_JOIN(self, opt, olen, oval):
        if olen == 12:
            oval = struct.unpack('!BII', oval)
            self.backup = bool(opt & 1)  # B -> Use as backup
            self.id = oval[0]
            self.recvToken = oval[1]
            self.sendRNumber = oval[2]

        elif olen == 16:
            oval = struct.unpack('!BQI', oval)
            self.backup = bool(opt & 1)  # B -> Use as backup
            self.id = oval[0]
            self.recvTHMAC = oval[1]
            self.sendRNumber = oval[2]

        elif olen == 24:
            oval = oval[1:]  # Skip reserved byte
            self.sendHmac = struct.unpack('!20s', oval)[0]

    def _DSS(self, oval):
        flags = struct.unpack('!B', oval[:1])[0]
        oval = oval[1:]

        self.fin = bool(flags & (1 << 4))   # F -> Data FIN

        if flags & 1:   # A -> ACK present
            if flags & (1 << 1):    # a -> Data ACK is 8 octects
                self.ack = struct.unpack('!Q', oval[:8])[0]
                oval = oval[8:]
            else:
                self.ack = struct.unpack('!I', oval[:4])[0]
                oval = oval[4:]

        if flags & (1 << 2):    # M -> DSN, SSN, DLL and Checksum present
            f = '!'
            if flags & (1 << 3):    # m -> DSN is 8 octects
                f += 'Q'
            else:
                f += 'I'

            f += 'IH'  # SSN and DLL

            r = struct.unpack(f, oval[:struct.calcsize(f)])

            self.dsn = r[0]
            self.ssn = r[1]
            self.dll = r[2]

            oval = oval[struct.calcsize(f):]

            if len(oval) > 0:   # Checksum is present
                self.checksum = struct.unpack('!H', oval)

    def _ADD_ADDR(self, opt, olen, oval):
        f = '!B'

        ipSize = 4
        if olen >= 20:  # IPV6
            f += '16s'
            ipSize = 16
        else:           # IPV4
            f += '4s'

        r = struct.unpack(f, oval[:ipSize + 1])
        self.id = r[0]

        if ipSize == 4:
            self.ip = str(ipaddress.IPv4Address(r[1]))
        else:
            self.ip = str(ipaddress.IPv6Address(r[1]))

        oval = oval[ipSize + 1:]

        self.echo = bool(opt & 1)   # E

        if not self.echo:  # HMAC is present
            if len(oval) > 8:  # Port is present
                self.port = struct.unpack('!H', oval[:2])[0]
                oval = oval[2:]

            self.hmac = struct.unpack('!Q', oval)[0]

    def _REMOVE_ADDR(self, olen, oval):
        f = '!'

        for _ in range(olen - 3):
            f += 'B'

        self.ids = struct.unpack(f, oval)

    def _MP_PRIO(self, opt):
        self.backup = bool(opt & 1)

    def _MP_FAIL(self, oval):
        oval = oval[1:]  # Skip reserved byte
        self.dsn = struct.unpack('!Q', oval)[0]

    def _MP_FASTCLOSE(self, oval):
        oval = oval[1:]  # Skip reserved byte
        self.recvKey = struct.unpack('!Q', oval)[0]

    def _MP_TCPRST(self, opt, oval):
        self.transient = bool(opt & 1)
        reasonCode = struct.unpack('!B', oval)

        if reasonCode in MP_TCPRSTReasons:
            self.reason = MP_TCPRSTReasons[reasonCode]
        else:
            self.reason = "Unknown Reason"

    def _MP_EXPRIMENTAL(self, oval):
        self.raw = oval
