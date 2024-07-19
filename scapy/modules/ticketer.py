# SPDX-License-Identifier: GPL-2.0-or-later OR MPL-2.0
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

# flake8: noqa

"""
Create/Edit Kerberos ticket using Scapy

See https://scapy.readthedocs.io/en/latest/layers/kerberos.html
"""

from datetime import datetime, timedelta, timezone

import collections
import platform
import struct
import random
import re

from scapy.asn1.asn1 import (
    ASN1_BIT_STRING,
    ASN1_GENERAL_STRING,
    ASN1_GENERALIZED_TIME,
    ASN1_INTEGER,
    ASN1_STRING,
)
from scapy.compat import bytes_hex, hex_bytes
from scapy.config import conf
from scapy.error import log_interactive
from scapy.fields import (
    ByteField,
    FieldLenField,
    FlagsField,
    IntEnumField,
    IntField,
    PacketField,
    PacketListField,
    ShortEnumField,
    ShortField,
    StrLenField,
    UTCTimeField,
)
from scapy.packet import Packet
from scapy.utils import pretty_list

from scapy.layers.dcerpc import NDRUnion
from scapy.layers.kerberos import (
    AuthorizationData,
    AuthorizationDataItem,
    EncTicketPart,
    EncryptedData,
    EncryptionKey,
    KRB_Ticket,
    KerberosClient,
    KerberosSSP,
    PrincipalName,
    TransitedEncoding,
    kpasswd,
    krb_as_req,
    krb_tgs_req,
    _AD_TYPES,
    _ADDR_TYPES,
    _KRB_E_TYPES,
    _KRB_S_TYPES,
    _PRINCIPAL_NAME_TYPES,
    _TICKET_FLAGS,
)
from scapy.layers.msrpce.mspac import (
    CLAIM_ENTRY,
    CLAIMS_ARRAY,
    CLAIMS_SET,
    CLAIMS_SET_METADATA,
    CYPHER_BLOCK,
    FILETIME,
    GROUP_MEMBERSHIP,
    KERB_SID_AND_ATTRIBUTES,
    KERB_VALIDATION_INFO,
    PAC_ATTRIBUTES_INFO,
    PAC_CLIENT_CLAIMS_INFO,
    PAC_CLIENT_INFO,
    PAC_INFO_BUFFER,
    PAC_INFO_BUFFER,
    PAC_REQUESTOR,
    PAC_SIGNATURE_DATA,
    PACTYPE,
    RPC_SID_IDENTIFIER_AUTHORITY,
    RPC_UNICODE_STRING,
    SID,
    UPN_DNS_INFO,
    USER_SESSION_KEY,
    CLAIM_ENTRY_sub2,
)
from scapy.layers.smb2 import (
    WINNT_SID,
    WINNT_SID_IDENTIFIER_AUTHORITY,
)

from scapy.libs.rfc3961 import EncryptionType, Key, _checksums

try:
    import tkinter as tk
    import tkinter.simpledialog as tksd
    from tkinter import ttk
except ImportError:
    tk = None

# CCache
# https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html (official doc but garbage)
# https://josefsson.org/shishi/ccache.txt (much better)


class CCCountedOctetString(Packet):
    fields_desc = [
        FieldLenField("length", None, length_of="data", fmt="I"),
        StrLenField("data", b"", length_from=lambda pkt: pkt.length),
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer


class CCPrincipal(Packet):
    fields_desc = [
        IntEnumField("name_type", 0, _PRINCIPAL_NAME_TYPES),
        FieldLenField("num_components", None, count_of="components", fmt="I"),
        PacketField("realm", CCCountedOctetString(), CCCountedOctetString),
        PacketListField(
            "components",
            [],
            CCCountedOctetString,
            count_from=lambda pkt: pkt.num_components,
        ),
    ]

    def toPN(self):
        return "%s@%s" % (
            "/".join(x.data.decode() for x in self.components),
            self.realm.data.decode(),
        )

    def guess_payload_class(self, payload):
        return conf.padding_layer


class CCDeltaTime(Packet):
    fields_desc = [
        IntField("time_offset", 0),
        IntField("usec_offset", 0),
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer


class CCHeader(Packet):
    fields_desc = [
        ShortEnumField("tag", 1, {1: "DeltaTime"}),
        ShortField("taglen", 8),
        PacketField("tagdata", CCDeltaTime(), CCDeltaTime),
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer


class CCKeyBlock(Packet):
    fields_desc = [
        ShortEnumField("keytype", 0, _KRB_E_TYPES),
        ShortField("etype", 0),
        FieldLenField("keylen", None, length_of="keyvalue"),
        StrLenField("keyvalue", b"", length_from=lambda pkt: pkt.keylen),
    ]

    def toKey(self):
        return Key(self.keytype, key=self.keyvalue)

    def guess_payload_class(self, payload):
        return conf.padding_layer


class CCAddress(Packet):
    fields_desc = [
        ShortEnumField("addrtype", 0, _ADDR_TYPES),
        PacketField("address", CCCountedOctetString(), CCCountedOctetString),
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer


class CCAuthData(Packet):
    fields_desc = [
        ShortEnumField("authtype", 0, _AD_TYPES),
        PacketField("authdata", CCCountedOctetString(), CCCountedOctetString),
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer


class CCCredential(Packet):
    fields_desc = [
        PacketField("client", CCPrincipal(), CCPrincipal),
        PacketField("server", CCPrincipal(), CCPrincipal),
        PacketField("keyblock", CCKeyBlock(), CCKeyBlock),
        UTCTimeField("authtime", None),
        UTCTimeField("starttime", None),
        UTCTimeField("endtime", None),
        UTCTimeField("renew_till", None),
        ByteField("is_skey", 0),
        FlagsField(
            "ticket_flags",
            0,
            32,
            # stored in reversed byte order (wtf)
            (_TICKET_FLAGS + [""] * (32 - len(_TICKET_FLAGS)))[::-1],
        ),
        FieldLenField("num_address", None, count_of="addrs", fmt="I"),
        PacketListField("addrs", [], CCAddress, count_from=lambda pkt: pkt.num_address),
        FieldLenField("num_authdata", None, count_of="authdata", fmt="I"),
        PacketListField(
            "authdata", [], CCAuthData, count_from=lambda pkt: pkt.num_authdata
        ),
        PacketField("ticket", CCCountedOctetString(), CCCountedOctetString),
        PacketField("second_ticket", CCCountedOctetString(), CCCountedOctetString),
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer

    def set_from_krb(self, tkt, clientpart, sessionkey, kdcrep):
        self.ticket.data = bytes(tkt)

        # Set sname
        self.server.name_type = tkt.sname.nameType.val
        self.server.realm = CCCountedOctetString(data=tkt.realm.val)
        self.server.components = [
            CCCountedOctetString(data=x.val) for x in tkt.sname.nameString
        ]

        # Set cname
        self.client.name_type = clientpart.cname.nameType.val
        self.client.realm = CCCountedOctetString(data=clientpart.crealm.val)
        self.client.components = [
            CCCountedOctetString(data=x.val) for x in clientpart.cname.nameString
        ]

        # Set the sessionkey
        self.keyblock = CCKeyBlock(
            keytype=sessionkey.etype,
            keyvalue=sessionkey.key,
        )

        # Set timestamps
        self.authtime = kdcrep.authtime.datetime.timestamp()
        if kdcrep.starttime is not None:
            self.starttime = kdcrep.starttime.datetime.timestamp()
        self.endtime = kdcrep.endtime.datetime.timestamp()
        if kdcrep.flags.val[8] == "1":  # renewable
            self.renew_till = kdcrep.renewTill.datetime.timestamp()

        # Set flags
        self.ticket_flags = int(kdcrep.flags.val, 2)


class CCache(Packet):
    fields_desc = [
        ShortField("file_format_version", 0x0504),
        ShortField("headerlen", 0),
        PacketListField("headers", [], CCHeader, length_from=lambda pkt: pkt.headerlen),
        PacketField("primary_principal", CCPrincipal(), CCPrincipal),
        PacketListField("credentials", [], CCCredential),
    ]


# TK scrollFrame (MPL-2.0)
# Credits to @mp035
# https://gist.github.com/mp035/9f2027c3ef9172264532fcd6262f3b01

if tk is not None:

    class ScrollFrame(tk.Frame):
        def __init__(self, parent):
            super().__init__(parent)

            self.canvas = tk.Canvas(self, borderwidth=0)
            self.viewPort = ttk.Frame(self.canvas)
            self.vsb = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
            self.canvas.configure(yscrollcommand=self.vsb.set)

            self.vsb.pack(side="right", fill="y")
            self.canvas.pack(side="left", fill="both", expand=True)
            self.canvas_window = self.canvas.create_window(
                (4, 4), window=self.viewPort, anchor="nw", tags="self.viewPort"
            )

            self.viewPort.bind("<Configure>", self.onFrameConfigure)
            self.canvas.bind("<Configure>", self.onCanvasConfigure)

            self.viewPort.bind("<Enter>", self.onEnter)
            self.viewPort.bind("<Leave>", self.onLeave)

            self.onFrameConfigure(None)

        def onFrameConfigure(self, event):
            """Reset the scroll region to encompass the inner frame"""
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))

        def onCanvasConfigure(self, event):
            """Reset the canvas window to encompass inner frame when required"""
            canvas_width = event.width
            self.canvas.itemconfig(self.canvas_window, width=canvas_width)

        def onMouseWheel(self, event):
            if platform.system() == "Windows":
                self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            elif platform.system() == "Darwin":
                self.canvas.yview_scroll(int(-1 * event.delta), "units")
            else:
                if event.num == 4:
                    self.canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    self.canvas.yview_scroll(1, "units")

        def onEnter(self, event):
            if platform.system() == "Linux":
                self.canvas.bind_all("<Button-4>", self.onMouseWheel)
                self.canvas.bind_all("<Button-5>", self.onMouseWheel)
            else:
                self.canvas.bind_all("<MouseWheel>", self.onMouseWheel)

        def onLeave(self, event):
            if platform.system() == "Linux":
                self.canvas.unbind_all("<Button-4>")
                self.canvas.unbind_all("<Button-5>")
            else:
                self.canvas.unbind_all("<MouseWheel>")


# Build ticketer


class Ticketer:
    def __init__(self):
        self._data = collections.defaultdict(dict)
        self.fname = None
        self.ccache = CCache()
        self.hashes_cache = collections.defaultdict(dict)

    def open_file(self, fname):
        """
        Load CCache from file
        """
        self.fname = fname
        self.hashes_cache = collections.defaultdict(dict)
        with open(self.fname, "rb") as fd:
            self.ccache = CCache(fd.read())

    def save(self, fname=None):
        """
        Save opened CCache file
        """
        if fname:
            self.fname = fname
        if not self.fname:
            raise ValueError("No file opened. Specify the 'fname' argument !")
        with open(self.fname, "wb") as fd:
            return fd.write(bytes(self.ccache))

    def show(self, utc=False):
        """
        Show the content of a CCache
        """
        if not self.ccache.credentials:
            print("No tickets in CCache !")
            return
        else:
            print("Tickets:")

        def _to_str(x):
            if x is None:
                return "None"
            else:
                x = datetime.fromtimestamp(x, tz=timezone.utc if utc else None)
            return x.strftime("%d/%m/%y %H:%M:%S")

        for i, cred in enumerate(self.ccache.credentials):
            if cred.keyblock.keytype == 0:
                continue
            print(
                "%s. %s -> %s"
                % (
                    i,
                    cred.client.toPN(),
                    cred.server.toPN(),
                )
            )
            print(cred.sprintf("   %ticket_flags%"))
            print(
                pretty_list(
                    [
                        (
                            _to_str(cred.starttime),
                            _to_str(cred.endtime),
                            _to_str(cred.renew_till),
                            _to_str(cred.authtime),
                        )
                    ],
                    [("Start time", "End time", "Renew until", "Auth time")],
                )
            )
            print()

    def _prompt(self, msg):
        try:
            from prompt_toolkit import prompt

            return prompt(msg)
        except ImportError:
            return input(msg)

    def _prompt_hash(self, spn, etype=None, cksumtype=None, hash=None):
        if etype:
            hashtype = _KRB_E_TYPES[etype]
        elif cksumtype:
            hashtype = _KRB_S_TYPES[cksumtype]
        else:
            raise ValueError("No cksumtype nor etype specified")
        if not hash:
            if spn in self.hashes_cache and hashtype in self.hashes_cache[spn]:
                hash = self.hashes_cache[spn][hashtype]
            else:
                msg = "Enter the %s hash for %s (as hex): " % (hashtype, spn)
                hash = hex_bytes(self._prompt(msg))
                if (
                    hash
                    == b"\xaa\xd3\xb45\xb5\x14\x04\xee\xaa\xd3\xb45\xb5\x14\x04\xee"
                ):
                    log_interactive.warning(
                        "This hash is the LM 'no password' hash. Is that what you intended?"
                    )
        key = Key(etype=etype, cksumtype=cksumtype, key=hash)
        self.hashes_cache[spn][hashtype] = hash
        if key and etype and key.cksumtype:
            self.hashes_cache[spn][_KRB_S_TYPES[key.cksumtype]] = hash
        return key

    def dec_ticket(self, i, key=None, hash=None):
        """
        Get the decrypted ticket by credentials ID
        """
        cred = self.ccache.credentials[i]
        tkt = KRB_Ticket(cred.ticket.data)
        if key is None:
            key = self._prompt_hash(
                tkt.getSPN(),
                etype=tkt.encPart.etype.val,
                hash=hash,
            )
        try:
            return tkt.encPart.decrypt(key)
        except Exception:
            try:
                del self.hashes_cache[tkt.getSPN()]
            except IndexError:
                pass
            raise

    def update_ticket(self, i, decTkt, resign=False, hash=None, kdc_hash=None):
        """
        Update a decrypted ticket by credentials ID
        """
        # Get CCCredential
        cred = self.ccache.credentials[i]
        tkt = KRB_Ticket(cred.ticket.data)

        # Optional: resign the new ticket
        if resign:
            # resign the ticket
            decTkt = self._resign_ticket(
                decTkt,
                tkt.getSPN(),
                hash=hash,
                kdc_hash=kdc_hash,
            )

        # Encrypt the new ticket
        key = self._prompt_hash(
            tkt.getSPN(),
            etype=tkt.encPart.etype.val,
            hash=hash,
        )
        tkt.encPart.encrypt(key, bytes(decTkt))

        # Update the CCCredential with the new ticket
        cred.set_from_krb(
            tkt,
            decTkt,
            decTkt.key.toKey(),
            decTkt,
        )

    def import_krb(self, res, key=None, hash=None, _inplace=None):
        """
        Import the result of krb_[tgs/as]_req or a Ticket into the CCache.

        :param obj: a KRB_Ticket object or a AS_REP/TGS_REP object
        :param sessionkey: the session key that comes along the ticket
        """
        # Instantiate CCCredential
        if _inplace is not None:
            cred = self.ccache.credentials[_inplace]
        else:
            cred = CCCredential()

        # Update the cred
        if isinstance(res, KRB_Ticket):
            if key is None:
                key = self._prompt_hash(
                    res.getSPN(),
                    etype=res.encPart.etype.val,
                    hash=hash,
                )
            decTkt = res.encPart.decrypt(key)
            cred.set_from_krb(
                res,
                decTkt,
                decTkt.key.toKey(),
                decTkt,
            )
        else:
            if isinstance(res, KerberosClient.RES_AS_MODE):
                rep = res.asrep
            elif isinstance(res, KerberosClient.RES_TGS_MODE):
                rep = res.tgsrep
            else:
                raise ValueError("Unknown type of obj !")
            cred.set_from_krb(
                rep.ticket,
                rep,
                res.sessionkey,
                res.kdcrep,
            )

        # Append to ccache
        if _inplace is None:
            self.ccache.credentials.append(cred)

    def export_krb(self, i):
        """
        Export a full ticket, session key, UPN and SPN.
        """
        cred = self.ccache.credentials[i]
        return (
            KRB_Ticket(cred.ticket.data),
            cred.keyblock.toKey(),
            cred.client.toPN(),
            cred.server.toPN(),
        )

    def ssp(self, i):
        """
        Create a KerberosSSP from a ticket
        """
        ticket, sessionkey, upn, spn = self.export_krb(i)
        return KerberosSSP(
            ST=ticket,
            KEY=sessionkey,
            UPN=upn,
            SPN=spn,
        )

    def _add_cred(self, decTkt, hash=None, kdc_hash=None):
        """
        Add a decoded ticket to the CCache
        """
        cred = CCCredential()
        etype = (
            self._prompt(
                "What key should we use (AES128-CTS-HMAC-SHA1-96/AES256-CTS-HMAC-SHA1-96/RC4-HMAC) ? [AES256-CTS-HMAC-SHA1-96]: "
            )
            or "AES256-CTS-HMAC-SHA1-96"
        )
        if etype not in _KRB_E_TYPES.values():
            print("Unknown keytype")
            return
        etype = next(k for k, v in _KRB_E_TYPES.items() if v == etype)
        cred.ticket.data = bytes(
            KRB_Ticket(
                realm=decTkt.crealm,
                sname=PrincipalName(
                    nameString=[
                        ASN1_GENERAL_STRING(b"krbtgt"),
                        decTkt.crealm,
                    ],
                    nameType=ASN1_INTEGER(2),  # NT-SRV-INST
                ),
                encPart=EncryptedData(
                    etype=etype,
                ),
            )
        )
        self.ccache.credentials.append(cred)
        self.update_ticket(
            len(self.ccache.credentials) - 1,
            decTkt,
            resign=True,
            hash=hash,
            kdc_hash=kdc_hash,
        )

    def create_ticket(self, **kwargs):
        """
        Create a Kerberos ticket
        """
        user = kwargs.get("user", self._prompt("User [User]: ") or "User")
        domain = kwargs.get(
            "domain", (self._prompt("Domain [DOM.LOCAL]: ") or "DOM.LOCAL").upper()
        )
        domain_sid = kwargs.get(
            "domain_sid",
            self._prompt("Domain SID [S-1-5-21-1-2-3]: ") or "S-1-5-21-1-2-3",
        )
        group_ids = kwargs.get(
            "group_ids",
            [
                int(x.strip())
                for x in (
                    self._prompt("Group IDs [513, 512, 520, 518, 519]: ")
                    or "513, 512, 520, 518, 519"
                ).split(",")
            ],
        )
        user_id = kwargs.get("user_id", int(self._prompt("User ID [500]: ") or "500"))
        primary_group_id = kwargs.get(
            "primary_group_id", int(self._prompt("Primary Group ID [513]: ") or "513")
        )
        extra_sids = kwargs.get("extra_sids", None)
        if extra_sids is None:
            extra_sids = self._prompt("Extra SIDs [] :") or []
            if extra_sids:
                extra_sids = [x.strip() for x in extra_sids.split(",")]
        duration = kwargs.get(
            "duration", int(self._prompt("Expires in (h) [10]: ") or "10")
        )
        now_time = datetime.now(timezone.utc).replace(microsecond=0)
        rand = random.SystemRandom()
        key = Key.random_to_key(
            EncryptionType.AES256_CTS_HMAC_SHA1_96, rand.randbytes(32)
        )
        store = {
            # KRB
            "flags": ASN1_BIT_STRING("01000000111000010000000000000000"),
            "key": {
                "keytype": ASN1_INTEGER(key.etype),
                "keyvalue": ASN1_STRING(key.key),
            },
            "crealm": ASN1_GENERAL_STRING(domain),
            "cname": {
                "nameString": [ASN1_GENERAL_STRING(user)],
                "nameType": ASN1_INTEGER(1),
            },
            "authtime": ASN1_GENERALIZED_TIME(now_time),
            "starttime": ASN1_GENERALIZED_TIME(now_time + timedelta(hours=duration)),
            "endtime": ASN1_GENERALIZED_TIME(now_time + timedelta(hours=duration)),
            "renewTill": ASN1_GENERALIZED_TIME(now_time + timedelta(hours=duration)),
            # PAC
            # Validation info
            "VI.LogonTime": self._time_to_filetime(now_time.timestamp()),
            "VI.LogoffTime": self._time_to_filetime("NEVER"),
            "VI.KickOffTime": self._time_to_filetime("NEVER"),
            "VI.PasswordLastSet": self._time_to_filetime(
                (now_time - timedelta(hours=10)).timestamp()
            ),
            "VI.PasswordCanChange": self._time_to_filetime(0),
            "VI.PasswordMustChange": self._time_to_filetime("NEVER"),
            "VI.EffectiveName": user,
            "VI.FullName": "",
            "VI.LogonScript": "",
            "VI.ProfilePath": "",
            "VI.HomeDirectory": "",
            "VI.HomeDirectoryDrive": "",
            "VI.UserSessionKey": b"\x00" * 16,
            "VI.LogonServer": "",
            "VI.LogonDomainName": domain.rsplit(".", 1)[0],
            "VI.LogonCount": 70,
            "VI.BadPasswordCount": 0,
            "VI.UserId": user_id,
            "VI.PrimaryGroupId": primary_group_id,
            "VI.GroupIds": [
                {
                    "RelativeId": x,
                    "Attributes": 7,
                }
                for x in group_ids
            ],
            "VI.UserFlags": 32,
            "VI.LogonDomainId": domain_sid,
            "VI.UserAccountControl": 128,
            "VI.ExtraSids": [{"Sid": x, "Attributes": 7} for x in extra_sids],
            "VI.ResourceGroupDomainSid": None,
            "VI.ResourceGroupIds": [],
            # Pac Client infos
            "CI.ClientId": self._utc_to_mstime(now_time.timestamp()),
            "CI.Name": user,
            # UPN DNS Info
            "UPNDNS.Flags": 3,
            "UPNDNS.Upn": "%s@%s" % (user, domain.lower()),
            "UPNDNS.DnsDomainName": domain.upper(),
            "UPNDNS.SamName": user,
            "UPNDNS.Sid": "%s-%s" % (domain_sid, user_id),
            # Client Claims
            "CC.ClaimsArrays": [
                {
                    "ClaimsSourceType": 1,
                    "ClaimEntries": [
                        {
                            "Id": "ad://ext/AuthenticationSilo",
                            "Type": 3,
                            "StringValues": "T0-silo",
                        }
                    ],
                }
            ],
            # Attributes Info
            "AI.Flags": "PAC_WAS_REQUESTED",
            # Requestor
            "REQ.Sid": "%s-%s" % (domain_sid, user_id),
            # Server Checksum
            "SC.SignatureType": 16,
            "SC.Signature": b"\x00" * 12,
            "SC.RODCIdentifier": b"",
            # KDC Checksum
            "KC.SignatureType": 16,
            "KC.Signature": b"\x00" * 12,
            "KC.RODCIdentifier": b"",
            # Ticket Checksum
            "TKT.SignatureType": -1,
            "TKT.Signature": b"\x00" * 12,
            "TKT.RODCIdentifier": b"",
            # Extended KDC Checksum
            "EXKC.SignatureType": -1,
            "EXKC.Signature": b"\x00" * 12,
            "EXKC.RODCIdentifier": b"",
        }
        # Build & store ticket
        tkt = self._build_ticket(store)
        self._add_cred(tkt)

    def _build_sid(self, sidstr, msdn=False):
        if not sidstr:
            return None
        m = re.match(r"S-(\d+)-(\d+)-?((?:\d+-?)*)", sidstr.strip())
        if not m:
            raise ValueError("Invalid SID format: %s" % sidstr)
        subauthors = []
        if m.group(3):
            subauthors = [int(x) for x in m.group(3).split("-")]
        if msdn:
            return WINNT_SID(
                Revision=int(m.group(1)),
                IdentifierAuthority=WINNT_SID_IDENTIFIER_AUTHORITY(
                    Value=struct.pack(">Q", int(m.group(2)))[2:],
                ),
                SubAuthority=subauthors,
            )
        else:
            return SID(
                Revision=int(m.group(1)),
                IdentifierAuthority=RPC_SID_IDENTIFIER_AUTHORITY(
                    Value=struct.pack(">Q", int(m.group(2)))[2:]
                ),
                SubAuthority=subauthors,
            )

    def _build_ticket(self, store):
        if store["CC.ClaimsArrays"]:
            claimSet = CLAIMS_SET(
                ndr64=False,
                ClaimsArrays=[
                    CLAIMS_ARRAY(
                        usClaimsSourceType=ca["ClaimsSourceType"],
                        ClaimEntries=[
                            CLAIM_ENTRY(
                                Id=ce["Id"],
                                Type=ce["Type"],
                                Values=NDRUnion(
                                    tag=ce["Type"],
                                    value=CLAIM_ENTRY_sub2(
                                        ValueCount=ce["StringValues"].count(";") + 1,
                                        StringValues=ce["StringValues"].split(";"),
                                    ),
                                ),
                            )
                            for ce in ca["ClaimEntries"]
                        ],
                    )
                    for ca in store["CC.ClaimsArrays"]
                ],
                usReservedType=0,
                ulReservedFieldSize=0,
                ReservedField=None,
            )
        else:
            claimSet = None
        _signature_set = lambda x: store[x + ".SignatureType"] != -1
        return EncTicketPart(
            transited=TransitedEncoding(
                trType=ASN1_INTEGER(0), contents=ASN1_STRING(b"")
            ),
            addresses=None,
            flags=store["flags"],
            key=EncryptionKey(
                keytype=store["key"]["keytype"],
                keyvalue=store["key"]["keyvalue"],
            ),
            crealm=store["crealm"],
            cname=PrincipalName(
                nameString=store["cname"]["nameString"],
                nameType=store["cname"]["nameType"],
            ),
            authtime=store["authtime"],
            starttime=store["starttime"],
            endtime=store["endtime"],
            renewTill=store["renewTill"],
            authorizationData=AuthorizationData(
                seq=[
                    AuthorizationDataItem(
                        adType=ASN1_INTEGER(1),
                        adData=AuthorizationData(
                            seq=[
                                AuthorizationDataItem(
                                    adType="AD-WIN2K-PAC",
                                    adData=PACTYPE(
                                        Buffers=[
                                            PAC_INFO_BUFFER(
                                                ulType="Logon information",
                                            ),
                                        ]
                                        + (
                                            [
                                                PAC_INFO_BUFFER(
                                                    ulType="Server Signature",
                                                ),
                                            ]
                                            if _signature_set("SC")
                                            else []
                                        )
                                        + (
                                            [
                                                PAC_INFO_BUFFER(
                                                    ulType="KDC Signature",
                                                ),
                                            ]
                                            if _signature_set("KC")
                                            else []
                                        )
                                        + [
                                            PAC_INFO_BUFFER(
                                                ulType="Client name and ticket information",
                                            ),
                                            PAC_INFO_BUFFER(
                                                ulType="UPN and DNS information",
                                            ),
                                        ]
                                        + (
                                            [
                                                PAC_INFO_BUFFER(
                                                    ulType="Client claims information",
                                                ),
                                            ]
                                            if claimSet
                                            else []
                                        )
                                        + (
                                            [
                                                PAC_INFO_BUFFER(
                                                    ulType="PAC Attributes",
                                                ),
                                            ]
                                            if store["AI.Flags"]
                                            else []
                                        )
                                        + (
                                            [
                                                PAC_INFO_BUFFER(
                                                    ulType="PAC Requestor",
                                                ),
                                            ]
                                            if store["REQ.Sid"]
                                            else []
                                        )
                                        + (
                                            [
                                                PAC_INFO_BUFFER(
                                                    ulType="Ticket Signature",
                                                ),
                                            ]
                                            if _signature_set("TKT")
                                            else []
                                        )
                                        + (
                                            [
                                                PAC_INFO_BUFFER(
                                                    ulType="Extended KDC Signature",
                                                ),
                                            ]
                                            if _signature_set("EXKC")
                                            else []
                                        ),
                                        Payloads=[
                                            KERB_VALIDATION_INFO(
                                                ndr64=False,
                                                ndrendian="little",
                                                LogonTime=store["VI.LogonTime"],
                                                LogoffTime=store["VI.LogoffTime"],
                                                KickOffTime=store["VI.KickOffTime"],
                                                PasswordLastSet=store[
                                                    "VI.PasswordLastSet"
                                                ],
                                                PasswordCanChange=store[
                                                    "VI.PasswordCanChange"
                                                ],
                                                PasswordMustChange=store[
                                                    "VI.PasswordMustChange"
                                                ],
                                                EffectiveName=RPC_UNICODE_STRING(
                                                    Buffer=store["VI.EffectiveName"],
                                                ),
                                                FullName=RPC_UNICODE_STRING(
                                                    Buffer=store["VI.FullName"],
                                                ),
                                                LogonScript=RPC_UNICODE_STRING(
                                                    Buffer=store["VI.LogonScript"],
                                                ),
                                                ProfilePath=RPC_UNICODE_STRING(
                                                    Buffer=store["VI.ProfilePath"],
                                                ),
                                                HomeDirectory=RPC_UNICODE_STRING(
                                                    Buffer=store["VI.HomeDirectory"],
                                                ),
                                                HomeDirectoryDrive=RPC_UNICODE_STRING(
                                                    Buffer=store[
                                                        "VI.HomeDirectoryDrive"
                                                    ],
                                                ),
                                                UserSessionKey=USER_SESSION_KEY(
                                                    data=[
                                                        CYPHER_BLOCK(
                                                            data=store[
                                                                "VI.UserSessionKey"
                                                            ][:8]
                                                        ),
                                                        CYPHER_BLOCK(
                                                            data=store[
                                                                "VI.UserSessionKey"
                                                            ][8:]
                                                        ),
                                                    ]
                                                ),
                                                LogonServer=RPC_UNICODE_STRING(
                                                    Buffer=store["VI.LogonServer"],
                                                ),
                                                LogonDomainName=RPC_UNICODE_STRING(
                                                    Buffer=store["VI.LogonDomainName"],
                                                ),
                                                LogonCount=store["VI.LogonCount"],
                                                BadPasswordCount=store[
                                                    "VI.BadPasswordCount"
                                                ],
                                                UserId=store["VI.UserId"],
                                                PrimaryGroupId=store[
                                                    "VI.PrimaryGroupId"
                                                ],
                                                GroupIds=[
                                                    GROUP_MEMBERSHIP(
                                                        RelativeId=x["RelativeId"],
                                                        Attributes=x["Attributes"],
                                                    )
                                                    for x in store["VI.GroupIds"]
                                                ],
                                                UserFlags=store["VI.UserFlags"],
                                                LogonDomainId=self._build_sid(
                                                    store["VI.LogonDomainId"]
                                                ),
                                                Reserved1=[0, 0],
                                                UserAccountControl=store[
                                                    "VI.UserAccountControl"
                                                ],
                                                Reserved3=[0, 0, 0, 0, 0, 0, 0],
                                                ExtraSids=[
                                                    KERB_SID_AND_ATTRIBUTES(
                                                        Sid=self._build_sid(x["Sid"]),
                                                        Attributes=x["Attributes"],
                                                    )
                                                    for x in store["VI.ExtraSids"]
                                                ]
                                                if store["VI.ExtraSids"]
                                                else None,
                                                ResourceGroupDomainSid=self._build_sid(
                                                    store["VI.ResourceGroupDomainSid"]
                                                ),
                                                ResourceGroupIds=[
                                                    GROUP_MEMBERSHIP(
                                                        RelativeId=x["RelativeId"],
                                                        Attributes=x["Attributes"],
                                                    )
                                                    for x in store[
                                                        "VI.ResourceGroupIds"
                                                    ]
                                                ]
                                                if store["VI.ResourceGroupIds"]
                                                else None,
                                            ),
                                        ]
                                        + (
                                            [
                                                PAC_SIGNATURE_DATA(
                                                    SignatureType=store[
                                                        "SC.SignatureType"
                                                    ],
                                                    Signature=store["SC.Signature"],
                                                    RODCIdentifier=store[
                                                        "SC.RODCIdentifier"
                                                    ],
                                                ),
                                            ]
                                            if _signature_set("SC")
                                            else []
                                        )
                                        + (
                                            [
                                                PAC_SIGNATURE_DATA(
                                                    SignatureType=store[
                                                        "KC.SignatureType"
                                                    ],
                                                    Signature=store["KC.Signature"],
                                                    RODCIdentifier=store[
                                                        "KC.RODCIdentifier"
                                                    ],
                                                ),
                                            ]
                                            if _signature_set("KC")
                                            else []
                                        )
                                        + [
                                            PAC_CLIENT_INFO(
                                                ClientId=store["CI.ClientId"],
                                                Name=store["CI.Name"],
                                            ),
                                            UPN_DNS_INFO(
                                                Flags=store["UPNDNS.Flags"],
                                                Payload=[
                                                    (
                                                        "Upn",
                                                        store["UPNDNS.Upn"],
                                                    ),
                                                    (
                                                        "DnsDomainName",
                                                        store["UPNDNS.DnsDomainName"],
                                                    ),
                                                    (
                                                        "SamName",
                                                        store["UPNDNS.SamName"],
                                                    ),
                                                    (
                                                        "Sid",
                                                        self._build_sid(
                                                            store["UPNDNS.Sid"],
                                                            msdn=True,
                                                        ),
                                                    ),
                                                ],
                                            ),
                                        ]
                                        + (
                                            [
                                                PAC_CLIENT_CLAIMS_INFO(
                                                    ndr64=False,
                                                    Claims=CLAIMS_SET_METADATA(
                                                        ClaimsSet=[
                                                            claimSet,
                                                        ],
                                                        usCompressionFormat=0,
                                                        usReservedType=0,
                                                        ulReservedFieldSize=0,
                                                        ReservedField=None,
                                                    ),
                                                ),
                                            ]
                                            if claimSet
                                            else []
                                        )
                                        + (
                                            [
                                                PAC_ATTRIBUTES_INFO(
                                                    Flags=[store["AI.Flags"]],
                                                    FlagsLength=2,
                                                )
                                            ]
                                            if store["AI.Flags"]
                                            else []
                                        )
                                        + (
                                            [
                                                PAC_REQUESTOR(
                                                    Sid=self._build_sid(
                                                        store["REQ.Sid"], msdn=True
                                                    ),
                                                ),
                                            ]
                                            if store["REQ.Sid"]
                                            else []
                                        )
                                        + (
                                            [
                                                PAC_SIGNATURE_DATA(
                                                    SignatureType=store[
                                                        "TKT.SignatureType"
                                                    ],
                                                    Signature=store["TKT.Signature"],
                                                    RODCIdentifier=store[
                                                        "TKT.RODCIdentifier"
                                                    ],
                                                ),
                                            ]
                                            if _signature_set("TKT")
                                            else []
                                        )
                                        + (
                                            [
                                                PAC_SIGNATURE_DATA(
                                                    SignatureType=store[
                                                        "EXKC.SignatureType"
                                                    ],
                                                    Signature=store["EXKC.Signature"],
                                                    RODCIdentifier=store[
                                                        "EXKC.RODCIdentifier"
                                                    ],
                                                )
                                            ]
                                            if _signature_set("EXKC")
                                            else []
                                        ),
                                    ),
                                )
                            ]
                        ),
                    )
                ]
            ),
        )

    def _getPayloadIfExist(self, pac, ulType):
        for i, buf in enumerate(pac.Buffers):
            if buf.ulType == ulType:
                return pac.Payloads[i]
        return None

    def _make_fields(self, element, fields, datastore=None):
        frm = ttk.Frame(element)
        frm.pack(fill="x")
        for i, fld in enumerate(fields):
            (self._data if datastore is None else datastore)[fld[0]] = v = tk.StringVar(
                frm, value=fld[1]
            )
            ttk.Label(frm, text=fld[0]).grid(row=i, column=0, sticky="w")
            ttk.Entry(frm, textvariable=v).grid(row=i, column=1, sticky="e")
        frm.grid_columnconfigure(1, weight=1)

    def _make_checkbox(self, element, keys, flags, datastore):
        for flg in keys:
            datastore[flg] = v = tk.BooleanVar(value=flg in flags)
            tk.Checkbutton(element, text=flg, variable=v, anchor=tk.W).pack(
                fill="x", padx=5, pady=1
            )

    def _make_table(self, element, name, headers, lst, datastore=None):
        wrap = ttk.LabelFrame(element, text=name)
        tree = ttk.Treeview(wrap, column=headers, show="headings", height=4)
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        vsb.pack(side="right", fill="y")
        tree.configure(yscrollcommand=vsb.set)
        for h in headers:
            tree.column(h, anchor=tk.CENTER)
            tree.heading(h, text=h)
        for i, row in enumerate(lst):
            tree.insert(parent="", index="end", iid=i, values=row)
        tree.pack(fill="x", padx=10, pady=10)

        def _update_datastore():
            children = [tree.item(x, "values") for x in tree.get_children()]
            (self._data if datastore is None else datastore)[name] = children

        _update_datastore()

        class EditDialog(tksd.Dialog):
            def __init__(self, *args, **kwargs):
                self.data = {}
                self.initial_values = kwargs.pop("values", {})
                self.success = False
                super(EditDialog, self).__init__(*args, **kwargs)

            def body(diag, frame):
                self._make_fields(
                    frame,
                    [(x, diag.initial_values.get(x, "")) for x in headers],
                    datastore=diag.data,
                )
                return frame

            def ok(self, *args, **kwargs):
                self.success = True
                super(EditDialog, self).ok(*args, **kwargs)

            def values(self):
                return tuple(x.get() for x in self.data.values())

        def add():
            dialog = EditDialog(title="Add", parent=tree)
            if dialog.success:
                i = len(tree.get_children())
                tree.insert(parent="", index="end", iid=i, values=dialog.values())
            _update_datastore()

        def edit():
            selected = tree.focus()
            if not selected:
                return
            values = dict(zip(headers, tree.item(selected, "values")))
            dialog = EditDialog(title="Edit", parent=tree, values=values)
            if dialog.success:
                tree.item(selected, values=dialog.values())
            _update_datastore()

        def remove():
            selected = tree.focus()
            if selected:
                tree.delete(selected)
            _update_datastore()

        btns = ttk.Frame(wrap)
        ttk.Button(btns, text="Add", command=add).grid(row=0, column=0, padx=10)
        ttk.Button(btns, text="Edit", command=edit).grid(row=0, column=1, padx=10)
        ttk.Button(btns, text="Remove", command=remove).grid(row=0, column=2, padx=10)
        btns.pack()
        wrap.pack(fill="x")

    def _make_list(self, element, func, key, fields_list, new_values):
        tbl = ttk.Frame(element)
        tbl.pack()

        self._data[key] = data = collections.defaultdict(dict)

        def append(val):
            i = tbl.grid_size()[1]
            elt = ttk.Frame(tbl, style="BorderFrame.TFrame")
            elt.grid(padx=10, pady=10, row=i, column=0)
            func(elt, val, data[i])

        for val in fields_list:
            append(val)

        def add():
            append(new_values.copy())

        def delete():
            slavescount = len(tbl.grid_slaves())
            i = tksd.askinteger(
                "Delete",
                "Input the index of the Claim to delete [0-%s]" % (slavescount - 1),
                parent=tbl,
            )
            if i is None or i > slavescount - 1:
                return
            tbl.grid_slaves(row=i, column=0)[0].destroy()
            del data[i]

        btns = ttk.Frame(element)
        ttk.Button(btns, text="Add", command=add).grid(row=0, column=0, padx=10)
        ttk.Button(btns, text="Delete", command=delete).grid(row=0, column=1, padx=10)
        btns.pack()

    _TIME_FIELD = UTCTimeField(
        "",
        None,
        fmt="<Q",
        epoch=[1601, 1, 1, 0, 0, 0],
        custom_scaling=1e7,
        strf="%Y-%m-%d %H:%M:%S",
    )

    def _pretty_time(self, x):
        return self._TIME_FIELD.i2repr(None, x).rsplit(" ", 1)[0]

    def _utc_to_mstime(self, x):
        return int((x - self._TIME_FIELD.delta) * 1e7)

    def _time_to_int(self, x):
        return self._utc_to_mstime(
            datetime.strptime(x, self._TIME_FIELD.strf).timestamp()
        )

    def _time_to_asn1(self, x):
        return ASN1_GENERALIZED_TIME(datetime.strptime(x, self._TIME_FIELD.strf))

    def _time_to_filetime(self, x):
        if isinstance(x, str) and x.strip() == "NEVER":
            return FILETIME(dwHighDateTime=0x7FFFFFFF, dwLowDateTime=0xFFFFFFFF)
        if isinstance(x, str):
            x = self._time_to_int(x)
        else:
            x = self._utc_to_mstime(x)
        return FILETIME(
            dwHighDateTime=(x >> 32) & 0xFFFFFFFF,
            dwLowDateTime=x & 0xFFFFFFFF,
        )

    def _filetime_totime(self, x):
        if x.dwHighDateTime == 0x7FFFFFFF and x.dwLowDateTime == 0xFFFFFFFF:
            return "NEVER"
        return self._pretty_time((x.dwHighDateTime << 32) + x.dwLowDateTime)

    def _pretty_sid(self, sid):
        if not sid or not sid.IdentifierAuthority.Value:
            return ""
        return sid.summary()

    def _getLogonInformation(self, pac, element):
        logonInfo = self._getPayloadIfExist(pac, 0x00000001)
        if not logonInfo:
            pac.Buffers.append(PAC_INFO_BUFFER(ulType=0x00000001))
            logonInfo = KERB_VALIDATION_INFO()
        else:
            logonInfo = logonInfo.value
        self._make_fields(
            element,
            [
                ("LogonTime", self._filetime_totime(logonInfo.LogonTime)),
                ("LogoffTime", self._filetime_totime(logonInfo.LogoffTime)),
                ("KickOffTime", self._filetime_totime(logonInfo.KickOffTime)),
                (
                    "PasswordLastSet",
                    self._filetime_totime(logonInfo.PasswordLastSet),
                ),
                (
                    "PasswordCanChange",
                    self._filetime_totime(logonInfo.PasswordCanChange),
                ),
                (
                    "PasswordMustChange",
                    self._filetime_totime(logonInfo.PasswordMustChange),
                ),
                (
                    "EffectiveName",
                    logonInfo.EffectiveName.Buffer.value.value[0].value.decode(),
                ),
                (
                    "FullName",
                    logonInfo.FullName.Buffer.value.value[0].value.decode(),
                ),
                (
                    "LogonScript",
                    logonInfo.LogonScript.Buffer.value.value[0].value.decode(),
                ),
                (
                    "ProfilePath",
                    logonInfo.ProfilePath.Buffer.value.value[0].value.decode(),
                ),
                (
                    "HomeDirectory",
                    logonInfo.HomeDirectory.Buffer.value.value[0].value.decode(),
                ),
                (
                    "HomeDirectoryDrive",
                    logonInfo.HomeDirectoryDrive.Buffer.value.value[0].value.decode(),
                ),
                ("LogonCount", str(logonInfo.LogonCount)),
                ("BadPasswordCount", str(logonInfo.BadPasswordCount)),
                ("UserId", str(logonInfo.UserId)),
                ("PrimaryGroupId", str(logonInfo.PrimaryGroupId)),
            ],
        )
        self._make_table(
            element,
            "GroupIds",
            ["RelativeId", "Attributes"],
            [
                (str(x.RelativeId), str(x.Attributes))
                for x in logonInfo.GroupIds.value.value
            ],
        )
        self._make_fields(
            element,
            [
                ("UserFlags", str(logonInfo.UserFlags)),
                (
                    "UserSessionKey",
                    bytes_hex(
                        b"".join(x.data for x in logonInfo.UserSessionKey.data)
                    ).decode(),
                ),
                (
                    "LogonServer",
                    logonInfo.LogonServer.Buffer.value.value[0].value.decode(),
                ),
                (
                    "LogonDomainName",
                    logonInfo.LogonDomainName.Buffer.value.value[0].value.decode(),
                ),
                (
                    "LogonDomainId",
                    self._pretty_sid(logonInfo.LogonDomainId.value),
                ),
                ("UserAccountControl", str(logonInfo.UserAccountControl)),
            ],
        )
        self._make_table(
            element,
            "ExtraSids",
            ["Sid", "Attributes"],
            [
                (self._pretty_sid(x.Sid.value), str(x.Attributes))
                for x in (
                    logonInfo.ExtraSids.value.value if logonInfo.ExtraSids else []
                )
            ],
        )
        self._make_fields(
            element,
            [
                (
                    "ResourceGroupDomainSid",
                    self._pretty_sid(
                        logonInfo.ResourceGroupDomainSid.value
                        if logonInfo.ResourceGroupDomainSid
                        else None
                    ),
                ),
            ],
        )
        self._make_table(
            element,
            "ResourceGroupIds",
            ["RelativeId", "Attributes"],
            [
                (str(x.RelativeId), str(x.Attributes))
                for x in (
                    logonInfo.ResourceGroupIds.value.value
                    if logonInfo.ResourceGroupIds
                    else []
                )
            ],
        )

    def _getClientInfo(self, pac, element):
        clientInfo = self._getPayloadIfExist(pac, 0x0000000A)
        if not clientInfo:
            pac.Buffers.append(PAC_INFO_BUFFER(ulType=0x0000000A))
            clientInfo = PAC_CLIENT_INFO()
        return self._make_fields(
            element,
            [
                ("ClientId", self._pretty_time(clientInfo.ClientId)),
                ("Name", clientInfo.Name),
            ],
        )

    def _getUPNDnsInfo(self, pac, element):
        upndnsinfo = self._getPayloadIfExist(pac, 0x0000000C)
        if not upndnsinfo:
            pac.Buffers.append(PAC_INFO_BUFFER(ulType=0x0000000C))
            upndnsinfo = UPN_DNS_INFO()
        return self._make_fields(
            element,
            [
                ("Upn", upndnsinfo.Upn),
                ("DnsDomainName", upndnsinfo.DnsDomainName),
                (
                    "SamName",
                    upndnsinfo.SamName
                    if upndnsinfo.Flags.S and upndnsinfo.SamNameLen
                    else "",
                ),
                (
                    "UpnDnsSid",
                    self._pretty_sid(upndnsinfo.Sid)
                    if upndnsinfo.Flags.S and upndnsinfo.SidLen
                    else "",
                ),
            ],
        )

    def _getClientClaims(self, pac, element):
        clientClaims = self._getPayloadIfExist(pac, 0x0000000D)
        if not clientClaims or isinstance(clientClaims, conf.padding_layer):
            pac.Buffers.append(PAC_INFO_BUFFER(ulType=0x0000000D))
            claimsArray = []
        else:
            claimsArray = (
                clientClaims.value.valueof("Claims")
                .valueof("ClaimsSet")
                .value.valueof("ClaimsArrays")
            )

        def func(elt, x, datastore):
            self._make_fields(
                elt,
                [
                    ("ClaimsSourceType", str(x.usClaimsSourceType)),
                ],
                datastore=datastore,
            )
            self._make_table(
                elt,
                "ClaimEntries",
                ["Id", "Type", "Values"],
                [
                    (
                        y.valueof("Id").decode(),
                        str(y.Type),
                        ";".join(
                            z.decode()
                            for z in y.valueof("Values").valueof("StringValues")
                        ),
                    )
                    for y in x.valueof("ClaimEntries")
                ],
                datastore=datastore,
            )

        return self._make_list(
            element,
            func=func,
            key="ClaimsArrays",
            fields_list=claimsArray,
            new_values=CLAIMS_ARRAY(ClaimEntries=[]),
        )

    def _getPACAttributes(self, pac, element):
        pacAttributes = self._getPayloadIfExist(pac, 0x00000011)
        if not pacAttributes:
            pac.Buffers.append(PAC_INFO_BUFFER(ulType=0x00000011))
            pacAttributes = PAC_ATTRIBUTES_INFO(Flags=0)
        flags = str(pacAttributes.Flags[0]).split("+")
        self._data["pacAttributes"] = {}
        self._make_checkbox(
            element,
            [
                "PAC_WAS_REQUESTED",
                "PAC_WAS_GIVEN_IMPLICITLY",
            ],
            flags,
            self._data["pacAttributes"],
        )

    def _getPACRequestor(self, pac, element):
        pacRequestor = self._getPayloadIfExist(pac, 0x00000012)
        if not pacRequestor:
            pac.Buffers.append(PAC_INFO_BUFFER(ulType=0x00000012))
            pacRequestor = PAC_REQUESTOR()
        return self._make_fields(
            element, [("ReqSid", self._pretty_sid(pacRequestor.Sid))]
        )

    def _getServerChecksum(self, pac, element):
        serverChecksum = self._getPayloadIfExist(pac, 0x00000006)
        if not serverChecksum:
            pac.Buffers.append(PAC_INFO_BUFFER(ulType=0x00000006))
            serverChecksum = PAC_SIGNATURE_DATA()
        return self._make_fields(
            element,
            [
                (
                    "SRVSignatureType",
                    str(serverChecksum.SignatureType)
                    if serverChecksum.SignatureType is not None
                    else "",
                ),
                ("SRVSignature", bytes_hex(serverChecksum.Signature).decode()),
                ("SRVRODCIdentifier", serverChecksum.RODCIdentifier.decode()),
            ],
        )

    def _getKDCChecksum(self, pac, element):
        kdcChecksum = self._getPayloadIfExist(pac, 0x00000007)
        if not kdcChecksum:
            pac.Buffers.append(PAC_INFO_BUFFER(ulType=0x00000007))
            kdcChecksum = PAC_SIGNATURE_DATA()
        return self._make_fields(
            element,
            [
                (
                    "KDCSignatureType",
                    str(kdcChecksum.SignatureType)
                    if kdcChecksum.SignatureType is not None
                    else "",
                ),
                ("KDCSignature", bytes_hex(kdcChecksum.Signature).decode()),
                ("KDCRODCIdentifier", kdcChecksum.RODCIdentifier.decode()),
            ],
        )

    def _getTicketChecksum(self, pac, element):
        ticketChecksum = self._getPayloadIfExist(pac, 0x00000010)
        if not ticketChecksum:
            pac.Buffers.append(PAC_INFO_BUFFER(ulType=0x00000010))
            ticketChecksum = PAC_SIGNATURE_DATA()
        return self._make_fields(
            element,
            [
                (
                    "TKTSignatureType",
                    str(ticketChecksum.SignatureType)
                    if ticketChecksum.SignatureType is not None
                    else "",
                ),
                ("TKTSignature", bytes_hex(ticketChecksum.Signature).decode()),
                ("TKTRODCIdentifier", ticketChecksum.RODCIdentifier.decode()),
            ],
        )

    def _getExtendedKDCChecksum(self, pac, element):
        exkdcChecksum = self._getPayloadIfExist(pac, 0x00000013)
        if not exkdcChecksum:
            pac.Buffers.append(PAC_INFO_BUFFER(ulType=0x00000013))
            exkdcChecksum = PAC_SIGNATURE_DATA()
        return self._make_fields(
            element,
            [
                (
                    "EXKDCSignatureType",
                    str(exkdcChecksum.SignatureType)
                    if exkdcChecksum.SignatureType is not None
                    else "",
                ),
                ("EXKDCSignature", bytes_hex(exkdcChecksum.Signature).decode()),
                ("EXKDCRODCIdentifier", exkdcChecksum.RODCIdentifier.decode()),
            ],
        )

    def edit_ticket(self, i, key=None, hash=None):
        """
        Edit a Kerberos ticket using the GUI
        """
        if tk is None:
            raise ImportError(
                "tkinter is not installed (`apt install python3-tk` on debian)"
            )
        tkt = self.dec_ticket(i, key=key, hash=hash)
        pac = tkt.authorizationData.seq[0].adData[0].seq[0].adData

        # WIDTH, HEIGHT = 1120, 1000

        # Note: for TK doc, use https://tkdocs.com

        # Root
        root = tk.Tk()
        root.title("Ticketer++ (@secdev/scapy)")
        # root.geometry("%sx%s" % (WIDTH, HEIGHT))
        # root.resizable(0, 1)

        scrollFrame = ScrollFrame(root)
        frm = scrollFrame.viewPort

        tk_ticket = ttk.Frame(frm, padding=5)
        tk_pac = ttk.Frame(frm, padding=5)

        ttk.Button(frm, text="Quit", command=root.destroy).grid(
            column=0, row=1, columnspan=2
        )

        # TTK style

        ttkstyle = ttk.Style()
        ttkstyle.theme_use("alt")
        ttkstyle.configure(
            "BorderFrame.TFrame",
            relief="groove",
            borderwidth=3,
        )

        # MAIN TICKET

        # Flags
        tk_flags = ttk.LabelFrame(
            tk_ticket,
            text="Flags",
            style="BorderFrame.TFrame",
        )
        tk_flags.pack(fill="x", pady=5)
        flags = tkt.get_field("flags").get_flags(tkt)
        self._data["flags"] = {}
        self._make_checkbox(tk_flags, _TICKET_FLAGS, flags, self._data["flags"])

        # Key
        tk_key = ttk.LabelFrame(
            tk_ticket,
            text="key",
            style="BorderFrame.TFrame",
        )
        tk_key.pack(fill="x", pady=5)
        self._make_fields(
            tk_key,
            [
                ("keytype", str(tkt.key.keytype.val)),
                (
                    "keyvalue",
                    bytes_hex(tkt.key.keyvalue.val).decode(),
                ),
            ],
        )

        # crealm
        self._make_fields(tk_ticket, [("crealm", tkt.crealm.val.decode())])

        # cname
        tk_cname = ttk.LabelFrame(
            tk_ticket,
            text="cname",
            style="BorderFrame.TFrame",
        )
        tk_cname.pack(fill="x", pady=5)
        self._make_fields(
            tk_cname,
            [
                (
                    "nameType",
                    str(tkt.cname.nameType.val),
                ),
            ],
        )
        self._make_table(
            tk_cname,
            "nameString",
            ["Value"],
            [(x.val.decode(),) for x in tkt.cname.nameString],
        )

        # transited
        tk_transited = ttk.LabelFrame(
            tk_ticket,
            text="transited",
            style="BorderFrame.TFrame",
        )
        tk_transited.pack(fill="x", pady=5)
        self._make_fields(
            tk_transited,
            [
                #
                (
                    "trType",
                    str(tkt.transited.trType.val),
                ),
                (
                    "contents",
                    tkt.transited.contents.val.decode(),
                ),
            ],
        )

        # times
        self._make_fields(
            tk_ticket,
            [
                ("authtime", tkt.authtime.pretty_time.rstrip(" UTC")),
                ("starttime", tkt.starttime.pretty_time.rstrip(" UTC")),
                ("endtime", tkt.endtime.pretty_time.rstrip(" UTC")),
                ("renewTill", tkt.renewTill.pretty_time.rstrip(" UTC")),
            ],
        )

        # PAC

        # Logon information
        tk_logoninfo = ttk.LabelFrame(
            tk_pac,
            text="Logon information",
            style="BorderFrame.TFrame",
        )
        tk_logoninfo.pack(fill="x", pady=5)
        self._getLogonInformation(pac, tk_logoninfo)

        # Client name and ticket information
        tk_clientinfo = ttk.LabelFrame(
            tk_pac,
            text="Client name and ticket information",
            style="BorderFrame.TFrame",
        )
        tk_clientinfo.pack(fill="x", pady=5)
        self._getClientInfo(pac, tk_clientinfo)

        # UPN and DNS information
        tk_upndnsinfo = ttk.LabelFrame(
            tk_pac,
            text="UPN and DNS information",
            style="BorderFrame.TFrame",
        )
        tk_upndnsinfo.pack(fill="x", pady=5)
        self._getUPNDnsInfo(pac, tk_upndnsinfo)

        # Client claims information
        tk_clientclaims = ttk.LabelFrame(
            tk_pac,
            text="Client claims information",
            style="BorderFrame.TFrame",
        )
        tk_clientclaims.pack(fill="x", pady=5)
        self._getClientClaims(pac, tk_clientclaims)

        # PAC Attributes
        tk_pacattributes = ttk.LabelFrame(
            tk_pac,
            text="PAC Attributes",
            style="BorderFrame.TFrame",
        )
        tk_pacattributes.pack(fill="x", pady=5)
        self._getPACAttributes(pac, tk_pacattributes)

        # PAC Requestor
        tk_pacrequestor = ttk.LabelFrame(
            tk_pac,
            text="PAC Requestor",
            style="BorderFrame.TFrame",
        )
        tk_pacrequestor.pack(fill="x", pady=5)
        self._getPACRequestor(pac, tk_pacrequestor)

        # Server checksum
        tk_serverchksum = ttk.LabelFrame(
            tk_pac,
            text="Server checksum",
            style="BorderFrame.TFrame",
        )
        tk_serverchksum.pack(fill="x", pady=5)
        self._getServerChecksum(pac, tk_serverchksum)

        # KDC checksum
        tk_serverchksum = ttk.LabelFrame(
            tk_pac,
            text="KDC checksum",
            style="BorderFrame.TFrame",
        )
        tk_serverchksum.pack(fill="x", pady=5)
        self._getKDCChecksum(pac, tk_serverchksum)

        # Ticket checksum
        tk_serverchksum = ttk.LabelFrame(
            tk_pac,
            text="Ticket checksum",
            style="BorderFrame.TFrame",
        )
        tk_serverchksum.pack(fill="x", pady=5)
        self._getTicketChecksum(pac, tk_serverchksum)

        # Extended KDC checksum
        tk_serverchksum = ttk.LabelFrame(
            tk_pac,
            text="Extended KDC checksum",
            style="BorderFrame.TFrame",
        )
        tk_serverchksum.pack(fill="x", pady=5)
        self._getExtendedKDCChecksum(pac, tk_serverchksum)

        # Run

        tk_ticket.grid(column=0, row=0, sticky=tk.N)
        tk_pac.grid(column=1, row=0, sticky=tk.N)

        scrollFrame.pack(side="top", fill="both", expand=True)
        root.mainloop()

        # Rebuild
        store = {
            # KRB
            "flags": ASN1_BIT_STRING(
                "".join(
                    "1" if self._data["flags"][x].get() else "0" for x in _TICKET_FLAGS
                )
                + "0" * (-len(_TICKET_FLAGS) % 32)
            ),
            "key": {
                "keytype": ASN1_INTEGER(int(self._data["keytype"].get())),
                "keyvalue": ASN1_STRING(hex_bytes(self._data["keyvalue"].get())),
            },
            "crealm": ASN1_GENERAL_STRING(self._data["crealm"].get()),
            "cname": {
                "nameString": [
                    ASN1_GENERAL_STRING(x[0]) for x in self._data["nameString"]
                ],
                "nameType": ASN1_INTEGER(int(self._data["nameType"].get())),
            },
            "authtime": self._time_to_asn1(self._data["authtime"].get()),
            "starttime": self._time_to_asn1(self._data["starttime"].get()),
            "endtime": self._time_to_asn1(self._data["endtime"].get()),
            "renewTill": self._time_to_asn1(self._data["renewTill"].get()),
            # PAC
            # Validation info
            "VI.LogonTime": self._time_to_filetime(self._data["LogonTime"].get()),
            "VI.LogoffTime": self._time_to_filetime(self._data["LogoffTime"].get()),
            "VI.KickOffTime": self._time_to_filetime(self._data["KickOffTime"].get()),
            "VI.PasswordLastSet": self._time_to_filetime(
                self._data["PasswordLastSet"].get()
            ),
            "VI.PasswordCanChange": self._time_to_filetime(
                self._data["PasswordCanChange"].get()
            ),
            "VI.PasswordMustChange": self._time_to_filetime(
                self._data["PasswordMustChange"].get()
            ),
            "VI.EffectiveName": self._data["EffectiveName"].get(),
            "VI.FullName": self._data["FullName"].get(),
            "VI.LogonScript": self._data["LogonScript"].get(),
            "VI.ProfilePath": self._data["ProfilePath"].get(),
            "VI.HomeDirectory": self._data["HomeDirectory"].get(),
            "VI.HomeDirectoryDrive": self._data["HomeDirectoryDrive"].get(),
            "VI.UserSessionKey": hex_bytes(self._data["UserSessionKey"].get()),
            "VI.LogonServer": self._data["LogonServer"].get(),
            "VI.LogonDomainName": self._data["LogonDomainName"].get(),
            "VI.LogonCount": int(self._data["LogonCount"].get()),
            "VI.BadPasswordCount": int(self._data["BadPasswordCount"].get()),
            "VI.UserId": int(self._data["UserId"].get()),
            "VI.PrimaryGroupId": int(self._data["PrimaryGroupId"].get()),
            "VI.GroupIds": [
                {
                    "RelativeId": int(x[0]),
                    "Attributes": int(x[1]),
                }
                for x in self._data["GroupIds"]
            ],
            "VI.UserFlags": int(self._data["UserFlags"].get()),
            "VI.LogonDomainId": self._data["LogonDomainId"].get(),
            "VI.UserAccountControl": int(self._data["UserAccountControl"].get()),
            "VI.ExtraSids": [
                {
                    "Sid": x[0],
                    "Attributes": int(x[1]),
                }
                for x in self._data["ExtraSids"]
            ],
            "VI.ResourceGroupDomainSid": self._data["ResourceGroupDomainSid"].get(),
            "VI.ResourceGroupIds": [
                {
                    "RelativeId": int(x[0]),
                    "Attributes": int(x[1]),
                }
                for x in self._data["ResourceGroupIds"]
            ],
            # Pac Client infos
            "CI.ClientId": self._time_to_int(self._data["ClientId"].get()),
            "CI.Name": self._data["Name"].get(),
            # UPN DNS Info
            "UPNDNS.Flags": 3,
            "UPNDNS.Upn": self._data["Upn"].get(),
            "UPNDNS.DnsDomainName": self._data["DnsDomainName"].get(),
            "UPNDNS.SamName": self._data["SamName"].get(),
            "UPNDNS.Sid": self._data["UpnDnsSid"].get(),
            # Client Claims
            "CC.ClaimsArrays": [
                {
                    "ClaimsSourceType": int(ca["ClaimsSourceType"].get()),
                    "ClaimEntries": [
                        {
                            "Id": ce[0],
                            "Type": int(ce[1]),
                            "StringValues": ce[2],
                        }
                        for ce in ca["ClaimEntries"]
                    ],
                }
                for ca in self._data["ClaimsArrays"].values()
            ],
            # Attributes Info
            "AI.Flags": "+".join(
                x
                for x in ["PAC_WAS_REQUESTED", "PAC_WAS_GIVEN_IMPLICITLY"]
                if self._data["pacAttributes"][x].get()
            ),
            # Requestor
            "REQ.Sid": self._data["ReqSid"].get(),
            # Server Checksum
            "SC.SignatureType": int(self._data["SRVSignatureType"].get()),
            "SC.Signature": hex_bytes(self._data["SRVSignature"].get()),
            "SC.RODCIdentifier": hex_bytes(self._data["SRVRODCIdentifier"].get()),
            # KDC Checksum
            "KC.SignatureType": int(self._data["KDCSignatureType"].get() or "-1"),
            "KC.Signature": hex_bytes(self._data["KDCSignature"].get()),
            "KC.RODCIdentifier": hex_bytes(self._data["KDCRODCIdentifier"].get()),
            # Ticket Checksum
            "TKT.SignatureType": int(self._data["TKTSignatureType"].get() or "-1"),
            "TKT.Signature": hex_bytes(self._data["TKTSignature"].get()),
            "TKT.RODCIdentifier": hex_bytes(self._data["TKTRODCIdentifier"].get()),
            # Extended KDC Checksum
            "EXKC.SignatureType": int(self._data["EXKDCSignatureType"].get() or "-1"),
            "EXKC.Signature": hex_bytes(self._data["EXKDCSignature"].get()),
            "EXKC.RODCIdentifier": hex_bytes(self._data["EXKDCRODCIdentifier"].get()),
        }
        tkt = self._build_ticket(store)
        if hash is None and key is not None:  # TODO: add key to update_ticket
            hash = key.key
        self.update_ticket(i, tkt, hash=hash)

    def _resign_ticket(self, tkt, spn, hash=None, kdc_hash=None):
        """
        Resign a ticket (priv)
        """
        # [MS-PAC] 2.8.1 - 2.8.5
        rpac = tkt.authorizationData.seq[0].adData.seq[0].adData  # real pac
        tmp_tkt = tkt.copy()  # fake ticket and pac used for computation
        pac = tmp_tkt.authorizationData.seq[0].adData.seq[0].adData
        # Variables for Signatures, indexed by ulType
        sig_i = {}
        sig_type = {}
        # Read PAC buffers to find all signatures, and set them to 0
        for k, buf in enumerate(pac.Buffers):
            if buf.ulType in [0x00000006, 0x00000007, 0x00000010, 0x00000013]:
                sig_i[buf.ulType] = k
                sig_type[buf.ulType] = pac.Payloads[k].SignatureType
                try:
                    pac.Payloads[k].Signature = (
                        b"\x00" * _checksums[pac.Payloads[k].SignatureType].macsize
                    )
                except KeyError:
                    raise ValueError("Unknown/Unsupported signatureType")
                rpac.Buffers[k].cbBufferSize = None
                rpac.Buffers[k].Offset = None

        # There must at least be Server Signature and KDC Signature
        if any(x not in sig_i for x in [0x00000006, 0x00000007]):
            raise ValueError("Cannot sign PAC: missing a compulsory signature")

        # Build the 2 necessary keys
        key_srv = self._prompt_hash(
            spn,
            cksumtype=sig_type[0x00000006],
            hash=hash,
        )
        key_kdc = self._prompt_hash(
            "krbtgt/" + "@".join(spn.split("@")[1:] * 2),
            cksumtype=sig_type[0x00000007],
            hash=kdc_hash,
        )

        # NOTE: the doc is very unclear regarding the order of the Signatures.

        # "The extended KDC signature is a keyed hash [RFC4757] of the entire PAC
        # message, with the Signature fields of all other PAC_SIGNATURE_DATA structures
        # (section 2.8) set to zero."
        # ==> This is wrong.
        # The Ticket Signature is present when computing the Extended KDC Signature.

        # sect 2.8.3 - Ticket Signature

        if 0x00000010 in sig_i:
            # "The ad-data in the PAC’s AuthorizationData element ([RFC4120]
            # section 5.2.6) is replaced with a single zero byte"
            tmp_tkt.authorizationData.seq[0].adData.seq[0].adData = b"\x00"
            rpac.Payloads[
                sig_i[0x00000010]
            ].Signature = ticket_sig = key_kdc.make_checksum(
                17, bytes(tmp_tkt)  # KERB_NON_KERB_CKSUM_SALT(17)
            )
            # included in the PAC when signing it for Extended Server Signature & Server Signature
            pac.Payloads[sig_i[0x00000010]].Signature = ticket_sig

        # sect 2.8.4 - Extended KDC Signature

        if 0x00000013 in sig_i:
            rpac.Payloads[
                sig_i[0x00000013]
            ].Signature = extended_kdc_sig = key_kdc.make_checksum(
                17, bytes(pac)  # KERB_NON_KERB_CKSUM_SALT(17)
            )
            # included in the PAC when signing it for Server Signature
            pac.Payloads[sig_i[0x00000013]].Signature = extended_kdc_sig

        # sect 2.8.1 - Server Signature

        rpac.Payloads[sig_i[0x00000006]].Signature = server_sig = key_srv.make_checksum(
            17, bytes(pac)  # KERB_NON_KERB_CKSUM_SALT(17)
        )

        # sect 2.8.2 - KDC Signature

        rpac.Payloads[sig_i[0x00000007]].Signature = key_kdc.make_checksum(
            17, server_sig  # KERB_NON_KERB_CKSUM_SALT(17)
        )
        return tkt

    def resign_ticket(self, i, hash=None, kdc_hash=None):
        """
        Resign a ticket from CCache

        :param hash: the hash to use to compute the Server Signature
        :param kdc_hash: the hash to use to compute the KDC signature
                         (if None, not recomputed unless its a TGT where is uses hash)
        """
        tkt = self.dec_ticket(i, hash=hash)
        self.update_ticket(i, tkt, resign=True, hash=hash, kdc_hash=kdc_hash)

    def request_tgt(self, upn, ip=None, key=None, password=None, realm=None, **kwargs):
        """
        Request a Kerberos TGT and add it to the local CCache

        See :func:`~scapy.layers.kerberos.krb_as_req` for the full documentation.
        """
        res = krb_as_req(upn, ip=ip, key=key, password=password, realm=realm, **kwargs)
        if not res:
            return

        self.import_krb(res)

    def request_st(
        self, i, spn, ip=None, renew=False, realm=None, additional_tickets=[], **kwargs
    ):
        """
        Request a Kerberos TS and add it to the local CCache using another ticket

        :param i: the ticket/sessionkey to use in the TGS request

        See :func:`~scapy.layers.kerberos.krb_tgs_req` for the the other parameters.
        """
        ticket, sessionkey, upn, _ = self.export_krb(i)

        res = krb_tgs_req(
            upn,
            spn,
            sessionkey=sessionkey,
            ticket=ticket,
            ip=ip,
            renew=renew,
            realm=realm,
            additional_tickets=additional_tickets,
            **kwargs,
        )
        if not res:
            return

        self.import_krb(res)

    def kpasswdset(self, i, targetupn=None):
        """
        Use kpasswd in 'Set Password' mode to set the password of an account.

        :param i: the TGT to use.
        """
        ticket, sessionkey, upn, _ = self.export_krb(i)
        kpasswd(
            upn=upn,
            targetupn=targetupn,
            setpassword=True,
            ticket=ticket,
            key=sessionkey,
        )

    def renew(self, i, ip=None, additional_tickets=[], **kwargs):
        """
        Renew a Kerberos TGT or a TS from the local CCache using a TGS-REQ

        :param i: the ticket/sessionkey to renew.
        """
        ticket, sessionkey, upn, spn = self.export_krb(i)

        res = krb_tgs_req(
            upn,
            spn,
            sessionkey=sessionkey,
            ticket=ticket,
            ip=ip,
            renew=True,
            additional_tickets=additional_tickets,
            **kwargs,
        )
        if not res:
            return

        self.import_krb(res, _inplace=i)
