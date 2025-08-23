# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""
LDAP Hero: a LDAP browser based on the Scapy LDAP client
"""

import uuid

from scapy.layers.ldap import (
    LDAP_AttributeValue,
    LDAP_BIND_MECHS,
    LDAP_Client,
    LDAP_CONTROL_ACCESS_RIGHTS,
    LDAP_Control,
    LDAP_DS_ACCESS_RIGHTS,
    LDAP_Exception,
    LDAP_ModifyRequestChange,
    LDAP_PartialAttribute,
    LDAP_PROPERTY_SET,
    LDAP_serverSDFlagsControl,
)
from scapy.layers.dcerpc import (
    DCERPC_Transport,
    NDRUnion,
    DCE_C_AUTHN_LEVEL,
    find_dcerpc_interface,
)
from scapy.layers.gssapi import SSP
from scapy.layers.msrpce.rpcclient import (
    DCERPC_Client,
)
from scapy.layers.msrpce.msdrsr import (
    DRS_EXTENSIONS_INT,
    DRS_EXTENSIONS,
    DRS_MSG_CRACKREQ_V1,
    IDL_DRSBind_Request,
    IDL_DRSCrackNames_Request,
    NTDSAPI_CLIENT_GUID,
)
from scapy.layers.ntlm import NTLMSSP
from scapy.layers.kerberos import KerberosSSP
from scapy.layers.spnego import SPNEGOSSP
from scapy.layers.smb2 import (
    SECURITY_DESCRIPTOR,
    WELL_KNOWN_SIDS,
    WINNT_ACE_FLAGS,
    WINNT_ACE_HEADER,
    WINNT_SID,
    WINNT_ACCESS_ALLOWED_ACE,
    WINNT_ACCESS_ALLOWED_OBJECT_ACE,
    WINNT_ACCESS_DENIED_OBJECT_ACE,
    WINNT_ACCESS_DENIED_ACE,
    WINNT_SYSTEM_AUDIT_OBJECT_ACE,
    WINNT_SYSTEM_AUDIT_ACE,
)
from scapy.utils import valid_ip

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
except ImportError:
    raise ImportError("tkinter is not installed (`apt install python3-tk` on debian)")


class AutoHideScrollbar(ttk.Scrollbar):
    def __init__(self, *args, **kwargs):
        self.shown = False
        super(AutoHideScrollbar, self).__init__(*args, **kwargs)

    def set(self, first, last):
        show = float(first) > 0 or float(last) < 1
        if show and not self.shown:
            self.grid(row=0, column=1, sticky="nsew")
        elif not show and self.shown:
            self.grid_forget()
        self.shown = show
        super(AutoHideScrollbar, self).set(first, last)


class BasePopup:
    """
    A tkinter wrapper used to have a popup window with basic controls
    """

    def __init__(self, parent):
        # Get dialog
        self.dlg = tk.Toplevel(parent)
        self.parent = parent
        self.cancelled = False

        # Configure some bindings
        self.dlg.bind("<Return>", self.dismiss)
        self.dlg.bind("<KP_Enter>", self.dismiss)

    def dismiss(self, *_) -> None:
        """
        Close the popup
        """
        self.dlg.grab_release()
        self.dlg.destroy()

    def cancel(self) -> None:
        """
        Cancel the popup
        """
        self.cancelled = True
        self.dismiss()

    def run(self) -> False:
        """
        Show the popup. Returns True if cancelled, False otherwise.
        """
        self.dlg.protocol("WM_DELETE_WINDOW", self.dismiss)
        self.dlg.transient(self.parent)
        self.dlg.wait_visibility()
        self.dlg.grab_set()
        self.dlg.wait_window()

        return self.cancelled


class LDAPHero:
    """
    LDAP Hero - LDAP GUI browser over Scapy's LDAP_Client

    :param ssp: the SSP object to use when binding.
    :param mech: the LDAP_BIND_MECHS to use when binding.
    :param simple_username: if provided, used for Simple binding (instead of the 'ssp')
    :param simple_password:
    :param encrypt: request encryption by default (useful when using 'ssp')
    :param host: auto-connect to a specific host
    :param port: the port to connect to (default: 389/636)
                 (This is only in use when using 'host')
    :param ssl: whether to use SSL to connect or not
                (This is only in use when using 'host')
    """

    def __init__(
        self,
        ssp: SSP = None,
        mech: LDAP_BIND_MECHS = None,
        simple_username: str = None,
        simple_password: str = None,
        encrypt: bool = False,
        host: str = None,
        port: int = None,
        ssl: bool = False,
    ):
        self.client = LDAP_Client()
        self.ssp = ssp
        self.mech = mech
        self.simple_username = simple_username
        self.simple_password = simple_password
        self.encrypt = encrypt
        # Session parameters
        self.connected = False
        self.bound = False
        self.host = host
        self.port = port
        self.ssl = ssl
        self.dns_domain_name = ""
        self.rootDSE = {}
        self.sids = dict(WELL_KNOWN_SIDS)
        self.sidscombo = {}
        self.guids = {}
        self.guidscombo = {"None": None}
        self.guidscomboobject = {"None": None}
        self.loadedSchemaIDGuids = False
        self.crop_output = None
        self.currently_editing = None
        # UI cache
        self.lastSearchString = ""
        # Launch
        self.main()

    def connect(self):
        """
        Connect command.
        """
        # If host is None, we need to ask for it via a dialog.
        if self.host is None:
            # Get dialog
            popup = BasePopup(self.root)
            dlg = popup.dlg

            # Connect UI
            serverv = tk.StringVar()
            serverv.set(self.host or "")
            ttk.Label(dlg, text="Server").grid(row=0, column=0)
            serverf = tk.Entry(dlg, textvariable=serverv)
            serverf.grid(row=0, column=1)

            portv = tk.StringVar()
            portv.set("389")
            ttk.Label(dlg, text="Port").grid(row=1, column=0)
            tk.Entry(dlg, textvariable=portv).grid(row=1, column=1)

            sslv = tk.BooleanVar()
            ttk.Label(dlg, text="SSL").grid(row=2, column=0)
            ttk.Checkbutton(dlg, variable=sslv).grid(row=2, column=1)

            ttk.Button(dlg, text="OK", command=popup.dismiss).grid(row=3, column=0)
            ttk.Button(dlg, text="Cancel", command=popup.cancel).grid(row=3, column=1)

            serverf.focus()

            # Setup
            if popup.run():
                # Cancelled
                return

            # Get values
            self.host = serverv.get()
            try:
                self.port = int(portv.get())
            except ValueError:
                return
            self.ssl = sslv.get()

        # Connect now !
        self.tprint(
            "client.connect(host='%s', port=%s, ssl=%s)"
            % (self.host, self.port, self.ssl)
        )
        try:
            self.client.connect(self.host, port=self.port, use_ssl=self.ssl)
        except Exception as ex:
            self.tprint(str(ex))
            raise
        self.tprint("Established connection to %s." % self.host)
        self.connected = True

        # Alright, change the UI.
        self.menu_connection.entryconfig("Connect", state=tk.DISABLED)
        self.menu_connection.entryconfig("Bind", state=tk.ACTIVE)
        self.menu_connection.entryconfig("Disconnect", state=tk.ACTIVE)
        self.menu_browse.entryconfig("Add child", state=tk.ACTIVE)
        self.menu_browse.entryconfig("Modify", state=tk.ACTIVE)
        self.menu_browse.entryconfig("Modify DN", state=tk.ACTIVE)
        self.menu_browse.entryconfig("Search", state=tk.ACTIVE)
        self.menu_view.entryconfig("Tree", state=tk.ACTIVE)

        # Get rootDSE
        self.tprint("Retrieving base DSA information...")
        try:
            results = self.client.search(
                baseObject="",
                scope=0,
            )
        except LDAP_Exception as ex:
            self.tprint(
                ex.diagnosticMessage or "Error: %s" % ex.resultCode,
                tags=["error"],
            )
            return

        attrs = results.get("", None)  # root
        if attrs is None:
            return

        self.rootDSE = attrs

        # Get some infos on the server
        try:
            self.dns_domain_name = self.rootDSE["ldapServiceName"][0].split(":")[0]
        except KeyError:
            pass

        # Display
        self._showsearchresult("", results)

        # If we have a SSP, auto-bind.
        if self.ssp is not None:
            self.bind()

    def disconnect(self):
        """
        Disconnect command.
        """
        if not self.connected:
            return

        self.tprint("client.close()")
        self.client.close()
        self.connected = False

        self.menu_connection.entryconfig("Connect", state=tk.ACTIVE)
        self.menu_connection.entryconfig("Bind", state=tk.DISABLED)
        self.menu_connection.entryconfig("Disconnect", state=tk.DISABLED)
        self.menu_browse.entryconfig("Add child", state=tk.DISABLED)
        self.menu_browse.entryconfig("Modify", state=tk.DISABLED)
        self.menu_browse.entryconfig("Modify DN", state=tk.DISABLED)
        self.menu_browse.entryconfig("Search", state=tk.DISABLED)
        self.menu_view.entryconfig("Tree", state=tk.DISABLED)

    def bind(self, *args):
        """
        Bind command.
        """
        if not self.connected:
            return

        if self.bound:
            # We are re-binding !
            self.ssp = None
            self.bound = False

        if self.ssp is not None or self.simple_username is not None:
            # We have an SSP. Don't prompt
            self.tprint("client.bind(%s, ssl=self.ssp)" % self.mech)
            try:
                self.client.bind(
                    self.mech,
                    ssp=self.ssp,
                    simple_username=self.simple_username,
                    simple_password=self.simple_password,
                    encrypt=self.encrypt,
                )
            except LDAP_Exception as ex:
                self.tprint(
                    ex.diagnosticMessage or "Error: %s" % ex.resultCode,
                    tags=["error"],
                )
                return
            except Exception as ex:
                self.tprint(str(ex))
                raise
            self.tprint("Authenticated.\n", tags=["bold"])
            self.bound = True
            return

        # Get dialog
        popup = BasePopup(self.root)
        dlg = popup.dlg

        # Bind UI
        userv = tk.StringVar()
        ttk.Label(dlg, text="User").grid(row=0, column=0)
        userf = tk.Entry(dlg, textvariable=userv)
        userf.grid(row=0, column=1)

        passwordv = tk.StringVar()
        ttk.Label(dlg, text="Password").grid(row=1, column=0)
        tk.Entry(dlg, textvariable=passwordv).grid(row=1, column=1)

        domainv = tk.StringVar()
        domainv.set(self.dns_domain_name)
        ttk.Label(dlg, text="Domain").grid(row=2, column=0)
        domentry = tk.Entry(dlg, textvariable=domainv)
        domentry.grid(row=2, column=1)

        bindtypefrm = ttk.LabelFrame(
            dlg,
            text="Bind type",
        )
        bindtypev = tk.StringVar()
        ttk.Radiobutton(
            bindtypefrm,
            variable=bindtypev,
            text="Sicily bind (NTLM)",
            value=LDAP_BIND_MECHS.SICILY.value,
        ).pack(anchor=tk.W)
        ttk.Radiobutton(
            bindtypefrm,
            variable=bindtypev,
            text="GSSAPI bind (Kerberos)",
            value=LDAP_BIND_MECHS.SASL_GSSAPI.value,
        ).pack(anchor=tk.W)
        ttk.Radiobutton(
            bindtypefrm,
            variable=bindtypev,
            text="SPNEGO bind (NTLM/Kerberos)",
            value=LDAP_BIND_MECHS.SASL_GSS_SPNEGO.value,
        ).pack(anchor=tk.W)
        ttk.Radiobutton(
            bindtypefrm,
            variable=bindtypev,
            text="Simple bind",
            value=LDAP_BIND_MECHS.SIMPLE.value,
        ).pack(anchor=tk.W)
        bindtypefrm.grid(row=3, column=0, columnspan=2)

        encryptv = tk.BooleanVar()
        encryptv.set(self.encrypt)
        ttk.Label(dlg, text="Encrypt traffic after bind").grid(row=4, column=0)
        encrbtn = ttk.Checkbutton(dlg, variable=encryptv)
        encrbtn.grid(row=4, column=1)

        ttk.Button(dlg, text="OK", command=popup.dismiss).grid(row=5, column=0)
        ttk.Button(dlg, text="Cancel", command=popup.cancel).grid(row=5, column=1)

        # Default state
        if self.dns_domain_name and not valid_ip(self.host):
            bindtypev.set(LDAP_BIND_MECHS.SASL_GSS_SPNEGO.value)
        else:
            domentry.configure(state=tk.DISABLED)
            bindtypev.set(LDAP_BIND_MECHS.SICILY.value)

        # Handle dynamic UI
        def bindtypechange(*args, **kwargs):
            bindtype = LDAP_BIND_MECHS(bindtypev.get())
            if bindtype == LDAP_BIND_MECHS.SIMPLE:
                domentry.config(state=tk.DISABLED)
                encrbtn.config(state=tk.DISABLED)
                encryptv.set(False)
            elif bindtype == LDAP_BIND_MECHS.SICILY:
                domentry.config(state=tk.DISABLED)
                encrbtn.config(state=tk.NORMAL)
            else:
                domentry.config(state=tk.NORMAL, textvariable=domainv)
                encrbtn.config(state=tk.NORMAL)

        bindtypev.trace("w", bindtypechange)
        userf.focus()

        # Setup
        if popup.run():
            # Cancelled
            return

        # Get values
        username = userv.get()
        password = passwordv.get()
        domain = domainv.get()
        bindtype = LDAP_BIND_MECHS(bindtypev.get())
        encrypt = encryptv.get()

        # Bind !
        self.tprint("client.bind(%s, ...)" % bindtype)
        try:
            simple_username = None
            simple_password = None
            if bindtype == LDAP_BIND_MECHS.SIMPLE:
                self.ssp = None
                simple_username = username
                simple_password = password
                encrypt = False
            elif bindtype == LDAP_BIND_MECHS.SICILY:
                self.ssp = NTLMSSP(
                    UPN=username,
                    PASSWORD=password,
                )
            elif bindtype == LDAP_BIND_MECHS.SASL_GSSAPI:
                self.ssp = KerberosSSP(
                    UPN="%s@%s" % (username, domain),
                    SPN="ldap/%s" % self.host,
                    PASSWORD=password,
                )
            elif bindtype == LDAP_BIND_MECHS.SASL_GSS_SPNEGO:
                self.ssp = SPNEGOSSP(
                    [
                        NTLMSSP(
                            UPN=username,
                            PASSWORD=password,
                        ),
                        KerberosSSP(
                            UPN="%s@%s" % (username, domain),
                            SPN="ldap/%s" % self.host,
                            PASSWORD=password,
                        ),
                    ]
                )
            self.client.bind(
                bindtype,
                ssp=self.ssp,
                simple_username=simple_username,
                simple_password=simple_password,
                encrypt=encrypt,
            )
        except LDAP_Exception as ex:
            self.tprint(
                ex.diagnosticMessage or "Error: %s" % ex.resultCode,
                tags=["error"],
            )
            # Reset SSP.
            self.ssp = None
            return
        except Exception as ex:
            self.tprint(str(ex))
            # Reset SSP.
            self.ssp = None
            raise
        self.tprint("Authenticated.\n")
        self.bound = True

    def tree(self, *args):
        """
        Tree command.
        """
        if not self.connected:
            return

        # Get namingContexts from rootDSE
        try:
            results = self.client.search(attributes=["namingContexts"])
        except LDAP_Exception as ex:
            self.tprint(
                ex.diagnosticMessage or "Error: %s" % ex.resultCode,
                tags=["error"],
            )
            return

        attrs = results.get("", None)  # root
        if attrs is None:
            return

        if "namingContexts" in attrs:
            self.tk_tree.delete(*self.tk_tree.get_children())
            for root in attrs["namingContexts"]:
                self.tk_tree.insert("", "end", root, text=root)

    def _showsearchresult(self, baseObject, results):
        """
        Display attributes search result
        """
        if baseObject in results:
            self.tprint("Dn: %s" % (baseObject or "(RootDSE)"), tags=["bold"])
            self.tprint(
                "\n".join(
                    "    %s%s: %s"
                    % (
                        k,
                        "" if len(v) == 1 else " (%s)" % len(v),
                        self._format_attribute(k, v, crop=True),
                    )
                    for k, v in sorted(results[baseObject].items(), key=lambda x: x[0])
                )
                + "\n"
            )

    def treedoubleclick(self, _):
        """
        Action done on tree double-click.
        """
        # Get clicked item
        item = self.tk_tree.selection()[0]

        # Unclickable
        if self.tk_tree.tag_has("unclickable", item):
            return

        # Does it already have children? If so delete them.
        self.tk_tree.delete(*self.tk_tree.get_children(item))

        self.tprint("-----------\nExpanding base '%s'..." % item)

        # Get children
        try:
            results = self.client.search(
                baseObject=item,
                scope=1,
                attributes=["1.1"],
            )
        except LDAP_Exception as ex:
            self.tprint(
                ex.diagnosticMessage or "Error: %s" % ex.resultCode,
                tags=["error"],
            )
            return

        # Add to tree
        if not results:
            self.tk_tree.insert(item, "end", text="No children", tags=("unclickable",))
        else:
            for child in results:
                self.tk_tree.insert(item, "end", child, text=child)

        # Get attributes
        try:
            results = self.client.search(
                baseObject=item,
                scope=0,
            )
        except LDAP_Exception as ex:
            self.tprint(
                ex.diagnosticMessage or "Error: %s" % ex.resultCode,
                tags=["error"],
            )
            return

        # Display
        self._showsearchresult(item, results)

    def load_guids(self):
        """
        Load the various guids:
        - schemaIDguid
        - propset

        This cache is used to resolve the GUIDs of objects in ACEs.
        """
        if self.loadedSchemaIDGuids:
            return True

        # Property set
        self.guids.update(
            (
                k,
                {
                    "objectClass": ["propset"],
                    "name": v,
                },
            )
            for k, v in LDAP_PROPERTY_SET.items()
        )

        # Control access
        self.guids.update(
            (
                k,
                {
                    "objectClass": ["controlset access right"],
                    "name": v,
                },
            )
            for k, v in LDAP_CONTROL_ACCESS_RIGHTS.items()
        )

        self.tprint("Resolving schemaIDguid... ", flush=True)
        try:
            results = self.client.search(
                baseObject=self.rootDSE["schemaNamingContext"][0],
                scope=1,
                attributes=["lDAPDisplayName", "schemaIDGUID", "objectClass"],
            )
        except LDAP_Exception as ex:
            self.tprint(
                ex.diagnosticMessage or "Error: %s" % ex.resultCode,
                tags=["error"],
            )
            return False

        self.guids.update(
            {
                uuid.UUID(bytes_le=v["schemaIDGUID"][0]): {
                    "objectClass": v["objectClass"],
                    "name": v["lDAPDisplayName"][0],
                }
                for v in results.values()
                if "schemaIDGUID" in v
            }
        )

        self.guidscombo.update({v["name"]: k for k, v in self.guids.items()})
        self.guidscomboobject.update(
            {
                v["name"]: k
                for k, v in self.guids.items()
                if "classSchema" in v["objectClass"]
            }
        )
        self.loadedSchemaIDGuids = True
        self.tprint("OK !")
        return True

    def _rslvtype(self, x):
        """
        Resolve Object types GUIDs
        """
        if x in self.guids:
            return self.guids[x]["name"]
        return str(x)

    def _rslvsid(self, x):
        """
        Resolve SIDs
        """
        if isinstance(x, WINNT_SID):
            x = x.summary()
        if x in self.sids:
            return self.sids[x]
        return x or ""

    def resolvesids(self, sids):
        """
        Queue a list of SIDs for resolution.
        They are then added to self.sids if successful.
        """
        unknowns = [x for x in (y.summary() for y in sids) if x not in self.sids]
        if not unknowns:
            return

        # Perform a resolution using [MS-LSAT] LsarLookupSids3
        client = DCERPC_Client(
            DCERPC_Transport.NCACN_IP_TCP,
            ndr64=False,
            auth_level=DCE_C_AUTHN_LEVEL.PKT_PRIVACY,
            ssp=self.ssp,
        )
        client.connect_and_bind(self.host, find_dcerpc_interface("drsuapi"))

        # 1. DRSBind
        bind_resp = client.sr1_req(
            IDL_DRSBind_Request(
                puuidClientDsa=NTDSAPI_CLIENT_GUID,
                pextClient=DRS_EXTENSIONS(rgb=bytes(DRS_EXTENSIONS_INT(Pid=1234))),
                ndr64=client.ndr64,
            ),
        )
        if bind_resp.status != 0:
            self.tprint("Bind Request failed.")
            bind_resp.show()
            return

        # 2. DRSCrackNames
        resp = client.sr1_req(
            IDL_DRSCrackNames_Request(
                hDrs=bind_resp.phDrs,
                dwInVersion=1,
                pmsgIn=NDRUnion(
                    tag=1,
                    value=DRS_MSG_CRACKREQ_V1(
                        CodePage=0x4E4,  #
                        LocaleId=0x409,  # US-EN
                        formatOffered=11,  # SID
                        formatDesired=0xFFFFFFF2,  # DS_USER_PRINCIPAL_NAME_FOR_LOGON
                        rpNames=unknowns,
                    ),
                ),
                ndr64=client.ndr64,
            ),
        )
        if resp.status != 0:
            self.tprint("DsCracknames Request failed.")
            resp.show()
            return

        # 3. parse results
        for i, res in enumerate(resp.valueof("pmsgOut.pResult.rItems")):
            if res.status != 0:
                # Errored
                continue
            name = res.valueof("pName")
            self.sids[unknowns[i]] = name.decode()

        # alias for combobox
        self.sidscombo = {self._rslvsid(x): x for x in self.sids.keys()}

    def viewsec(self, *args):
        """
        View security descriptor
        """
        # Get clicked item
        item = self.tk_tree.selection()[0]

        # Get SD
        try:
            results = self.client.search(
                baseObject=item,
                scope=0,
                attributes=["ntSecurityDescriptor"],
                controls=[
                    LDAP_Control(
                        controlType="1.2.840.113556.1.4.801",
                        criticality=True,
                        controlValue=LDAP_serverSDFlagsControl(
                            flags="OWNER+GROUP+DACL+SACL",
                        ),
                    )
                ],
            )
        except LDAP_Exception as ex:
            self.tprint(
                ex.diagnosticMessage or "Error: %s" % ex.resultCode,
                tags=["error"],
            )
            return

        if item not in results:
            return

        try:
            nTSecurityDescriptor = SECURITY_DESCRIPTOR(
                results[item]["nTSecurityDescriptor"][0]
            )
        except LDAP_Exception as ex:
            self.tprint(
                "Error parsing the Security Descriptor: " + str(ex),
                tags=["error"],
            )
            return

        # Resolve the guids
        if not self.load_guids():
            return

        # Pre-resolve all the SIDs.
        owner = getattr(nTSecurityDescriptor, "OwnerSid", None)
        group = getattr(nTSecurityDescriptor, "GroupSid", None)
        _to_resolve = [
            owner,
            group,
        ]
        if hasattr(nTSecurityDescriptor, "DACL"):
            _to_resolve.extend(x.Sid for x in nTSecurityDescriptor.DACL.Aces)
        if hasattr(nTSecurityDescriptor, "SACL"):
            _to_resolve.extend(x.Sid for x in nTSecurityDescriptor.SACL.Aces)
        self.resolvesids(_to_resolve)

        # Get dialog
        popup = BasePopup(self.root)
        dlg = popup.dlg

        # Security Descriptor UI
        dlg.columnconfigure(0, weight=1)
        dlg.rowconfigure(tuple(range(5)), weight=1)

        sidfrm = ttk.Frame(dlg)
        sidfrm.grid(row=0, sticky="we")
        sidfrm.grid_columnconfigure(1, weight=1)

        ownerv = tk.StringVar()
        ownerv.set(self._rslvsid(owner))
        ttk.Label(sidfrm, text="Owner").grid(row=0, column=0, sticky="we")
        ttk.Combobox(
            sidfrm, textvariable=ownerv, values=list(self.sidscombo.keys())
        ).grid(row=0, column=1, sticky="we")

        groupv = tk.StringVar()
        groupv.set(self._rslvsid(group))
        ttk.Label(sidfrm, text="Group").grid(row=1, column=0, sticky="we")
        ttk.Combobox(
            sidfrm, textvariable=groupv, values=list(self.sidscombo.keys())
        ).grid(row=1, column=1, sticky="we")

        sdcontrolfrm = ttk.LabelFrame(
            dlg,
            text="SD Control",
        )
        sdflags = [
            "SELF_RELATIVE",
            "DACL_PRESENT",
            "SACL_PRESENT",
            "OWNER_DEFAULTED",
            "DACL_PROTECTED",
            "SACL_PROTECTED",
            "GROUP_DEFAULTED",
            "DACL_AUTO_INHERITED",
            "SACL_AUTO_INHERITED",
            "RM_CONTROL_VALID",
            "DACL_DEFAULTED",
            "SACL_DEFAULTED",
            "SERVER_SECURITY",
            "DACL_COMPUTED",
            "SACL_COMPUTED",
            None,
            "DACL_TRUSTED",
        ]
        sdvars = [None] * len(sdflags)
        for i, sdflag in enumerate(sdflags):
            if sdflag is None:
                continue
            sdvars[i] = tk.BooleanVar()
            sdvars[i].set(getattr(nTSecurityDescriptor.Control, sdflag))
            ttk.Checkbutton(sdcontrolfrm, variable=sdvars[i], text=sdflag).grid(
                row=(i // 3) * 4, column=(i % 3) * 4, columnspan=4, sticky="w"
            )
        sdcontrolfrm.grid(row=1, sticky="we")

        def acegui(ace, parentdlg=dlg):
            data = ace.extractData(accessMask=LDAP_DS_ACCESS_RIGHTS)

            # Sub-dialog
            subpopup = BasePopup(parentdlg)
            dlg = subpopup.dlg

            # Edit ACE UI
            dlg.columnconfigure(1, weight=1)
            dlg.rowconfigure(tuple(range(8)), weight=1)

            # Trustee
            trusteev = tk.StringVar()
            trusteev.set(self._rslvsid(data["sid-string"]))
            ttk.Label(dlg, text="Trustee").grid(row=0, column=0, sticky="we")
            ttk.Combobox(
                dlg, textvariable=trusteev, values=list(self.sidscombo.keys())
            ).grid(row=0, column=1, sticky="we")

            # ACE type
            ttk.Label(dlg, text="ACE type").grid(row=1, column=0, sticky="we")
            acetypefrm = ttk.Frame(
                dlg,
            )
            acetypev = tk.IntVar()
            acetypev.set(ace.AceType - 5 if ace.AceType >= 5 else ace.AceType)
            ttk.Radiobutton(
                acetypefrm,
                variable=acetypev,
                text="Allow",
                value=0x00,
            ).grid(row=0, column=0)
            ttk.Radiobutton(
                acetypefrm,
                variable=acetypev,
                text="Deny",
                value=0x01,
            ).grid(row=0, column=1)
            ttk.Radiobutton(
                acetypefrm,
                variable=acetypev,
                text="Audit",
                value=0x02,
            ).grid(row=0, column=2)
            ttk.Radiobutton(
                acetypefrm,
                variable=acetypev,
                text="Alarm",
                value=0x03,
                state=tk.DISABLED,
            ).grid(row=0, column=3)
            acetypefrm.grid(row=1, column=1, sticky="we")

            # Access Mask
            accessmaskfrm = ttk.LabelFrame(
                dlg,
                text="Access Mask",
            )
            sdvars = [None] * len(LDAP_DS_ACCESS_RIGHTS)
            for i, maskval in enumerate(LDAP_DS_ACCESS_RIGHTS.values()):
                sdvars[i] = tk.BooleanVar()
                sdvars[i].set(getattr(data["mask"], maskval))
                ttk.Checkbutton(accessmaskfrm, variable=sdvars[i], text=maskval).grid(
                    row=i // 4, column=i % 4, sticky="w"
                )
            accessmaskfrm.grid(row=2, column=0, columnspan=2, sticky="we")

            # ACE flags
            aceflagsfrm = ttk.LabelFrame(
                dlg,
                text="Access Mask",
            )
            aceflagsvars = [None] * len(WINNT_ACE_FLAGS)
            for i, aceval in enumerate(WINNT_ACE_FLAGS.values()):
                aceflagsvars[i] = tk.BooleanVar()
                aceflagsvars[i].set(getattr(ace.AceFlags, aceval))
                ttk.Checkbutton(
                    aceflagsfrm, variable=aceflagsvars[i], text=aceval
                ).grid(row=i // 4, column=i % 4, sticky="w")
            aceflagsfrm.grid(row=3, column=0, columnspan=2, sticky="we")

            # Object type
            objecttypev = tk.StringVar()
            objecttypev.set(self._rslvtype(data["object-guid"]) or "None")
            ttk.Label(dlg, text="Object type").grid(row=5, column=0, sticky="we")
            ttk.Combobox(
                dlg, textvariable=objecttypev, values=list(self.guidscombo.keys())
            ).grid(row=5, column=1, sticky="we")

            # Inherited object type
            inheritedobjecttypev = tk.StringVar()
            inheritedobjecttypev.set(
                self._rslvtype(data["inherited-object-guid"]) or "None"
            )
            ttk.Label(dlg, text="Inherited object type").grid(
                row=6, column=0, sticky="we"
            )
            ttk.Combobox(
                dlg,
                textvariable=inheritedobjecttypev,
                values=list(self.guidscomboobject.keys()),
            ).grid(row=6, column=1, sticky="we")

            # OK / Cancel
            btnfrm = ttk.Frame(dlg)
            ttk.Button(btnfrm, text="OK", command=subpopup.dismiss).grid(
                row=0, column=0
            )
            ttk.Button(btnfrm, text="Cancel", command=subpopup.cancel).grid(
                row=0, column=1
            )
            btnfrm.grid(row=7)

            # Setup
            if subpopup.run():
                # Cancelled
                return

            # Get values
            trustee = trusteev.get()
            acetype = acetypev.get()
            objecttype = objecttypev.get()
            inheritedobjecttype = inheritedobjecttypev.get()
            mask = 0
            for i, (sdvar, v) in enumerate(
                zip(sdvars, list(LDAP_DS_ACCESS_RIGHTS.keys()))
            ):
                if sdvar is None:
                    continue
                if sdvar.get():
                    mask |= v
            aceflags = 0
            for i, (aceflagvar, v) in enumerate(
                zip(aceflagsvars, list(WINNT_ACE_FLAGS.keys()))
            ):
                if aceflagvar is None:
                    continue
                if aceflagvar.get():
                    aceflags |= v

            # Set back into ACE
            if trustee in self.sidscombo:
                Sid = WINNT_SID.fromstr(self.sidscombo[trustee])
            else:
                Sid = WINNT_SID.fromstr(trustee)
            if objecttype in self.guidscombo:
                objecttype = self.guidscombo[objecttype]
            elif objecttype:
                objecttype = uuid.UUID(objecttype)
            if inheritedobjecttype in self.guidscomboobject:
                inheritedobjecttype = self.guidscomboobject[inheritedobjecttype]
            elif inheritedobjecttype:
                inheritedobjecttype = uuid.UUID(inheritedobjecttype)
            Flags = 0
            if objecttype:
                Flags |= 1
            if inheritedobjecttype:
                Flags |= 2
            if acetype == 0x00:
                if Flags:
                    ace.AceType = 0x05
                    ace.payload = WINNT_ACCESS_ALLOWED_OBJECT_ACE(
                        Mask=mask,
                        Sid=Sid,
                        Flags=Flags,
                        ObjectType=objecttype,
                        InheritedObjectType=inheritedobjecttype,
                    )
                else:
                    ace.AceType = 0x00
                    ace.payload = WINNT_ACCESS_ALLOWED_ACE(
                        Mask=mask,
                        Sid=Sid,
                    )
            elif acetype == 0x01:
                if Flags:
                    ace.AceType = 0x06
                    ace.payload = WINNT_ACCESS_DENIED_OBJECT_ACE(
                        Mask=mask,
                        Sid=Sid,
                        Flags=Flags,
                        ObjectType=objecttype,
                        InheritedObjectType=inheritedobjecttype,
                    )
                else:
                    ace.AceType = 0x01
                    ace.payload = WINNT_ACCESS_DENIED_ACE(
                        Mask=mask,
                        Sid=Sid,
                    )
            elif acetype == 0x02:
                if Flags:
                    ace.AceType = 0x07
                    ace.payload = WINNT_SYSTEM_AUDIT_OBJECT_ACE(
                        Mask=mask,
                        Sid=Sid,
                        Flags=Flags,
                        ObjectType=objecttype,
                        InheritedObjectType=inheritedobjecttype,
                    )
                else:
                    ace.AceType = 0x02
                    ace.payload = WINNT_SYSTEM_AUDIT_ACE(
                        Mask=mask,
                        Sid=Sid,
                    )
            else:
                raise NotImplementedError
            ace.AceFlags = aceflags

        def addace(id, table, ace, pos="end"):
            data = ace.extractData(accessMask=LDAP_DS_ACCESS_RIGHTS)
            table.insert(
                "",
                pos,
                id,
                values=(
                    ace.sprintf("%AceType%"),
                    self._rslvsid(data["sid-string"]),
                    str(data["mask"])
                    + (
                        " (%s)" % self._rslvtype(data["object-guid"])
                        if data["object-guid"]
                        else ""
                    ),
                    ace.sprintf("%AceFlags%"),
                ),
            )

        def acltable(name):
            aclfrm = ttk.LabelFrame(dlg, text=name, borderwidth=0)

            tvfr = ttk.Frame(aclfrm)
            tvfr.grid_columnconfigure(0, weight=1)
            tvfr.grid_rowconfigure(0, weight=1)

            acltree = ttk.Treeview(
                tvfr, show="headings", columns=("type", "trustee", "rights", "flags")
            )
            acltree.heading("type", text="Type")
            acltree.heading("trustee", text="Trustee")
            acltree.heading("rights", text="Rights")
            acltree.heading("flags", text="Flags")

            tree_scrollbar = AutoHideScrollbar(
                tvfr, orient="vertical", command=acltree.yview
            )
            acltree.configure(yscrollcommand=tree_scrollbar.set)
            acltree.grid(row=0, column=0, sticky="nsew")

            # Populate
            aclobj = getattr(nTSecurityDescriptor, name, None)
            if aclobj is not None:
                for i, ace in enumerate(aclobj.Aces):
                    addace(i, acltree, ace)

            def add(*_):
                ace = WINNT_ACE_HEADER() / WINNT_ACCESS_ALLOWED_ACE()
                acegui(ace)
                # Append
                aclobj.Aces.append(ace)
                addace(len(aclobj.Aces) - 1, acltree, ace)

            def delete(*_):
                try:
                    selected = int(acltree.selection()[0])
                    del aclobj.Aces[selected]
                except IndexError:
                    return
                # Full refresh as indexes change.
                acltree.delete(*acltree.get_children())
                for i, ace in enumerate(aclobj.Aces):
                    addace(i, acltree, ace)

            def edit(*_):
                try:
                    selected = int(acltree.selection()[0])
                    ace = aclobj.Aces[selected]
                except IndexError:
                    return
                acegui(ace)
                # Update
                acltree.delete(selected)
                addace(selected, acltree, ace, pos=selected)

            btnfrm = ttk.Frame(aclfrm)
            btnfrm.grid_columnconfigure(0, weight=1)
            ttk.Button(btnfrm, text="Add", command=add).grid(row=0)
            ttk.Button(btnfrm, text="Delete", command=delete).grid(row=1)
            ttk.Button(btnfrm, text="Edit", command=edit).grid(row=2)
            btnfrm.pack(side="right")

            tvfr.pack(fill="both", expand=True)
            return aclfrm

        acltable("DACL").grid(row=2, sticky="we")
        acltable("SACL").grid(row=3, sticky="we")

        btnfrm = ttk.Frame(dlg)
        ttk.Button(btnfrm, text="Update", command=popup.dismiss).grid(row=0, column=0)
        ttk.Button(btnfrm, text="Cancel", command=popup.cancel).grid(row=0, column=1)
        btnfrm.grid(row=4)

        # Setup
        if popup.run():
            # Cancelled
            return

        # From UI back into ntSecurityDescriptor

        # Owner
        owner = ownerv.get()
        if owner in self.sidscombo:
            nTSecurityDescriptor.OwnerSid = WINNT_SID.fromstr(self.sidscombo[owner])
        else:
            nTSecurityDescriptor.OwnerSid = WINNT_SID.fromstr(owner)

        # Group
        group = groupv.get()
        if group in self.sidscombo:
            nTSecurityDescriptor.GroupSid = WINNT_SID.fromstr(self.sidscombo[group])
        else:
            nTSecurityDescriptor.GroupSid = WINNT_SID.fromstr(group)

        # Control
        control = SECURITY_DESCRIPTOR(Control=0).Control
        for i, (sdvar, v) in enumerate(zip(sdvars, sdflags)):
            if sdvar is None:
                continue
            if sdvar.get():
                control |= v
        nTSecurityDescriptor.Control = control

        # Offsets need to be recalculated
        nTSecurityDescriptor.OwnerSidOffset = None
        nTSecurityDescriptor.GroupSidOffset = None
        nTSecurityDescriptor.DACLOffset = None
        nTSecurityDescriptor.SACLOffset = None

        # Pfew, we did it. That was some big UI.

        # Now update the SD.
        try:
            self.client.modify(
                object=item,
                changes=[
                    LDAP_ModifyRequestChange(
                        operation="replace",
                        modification=LDAP_PartialAttribute(
                            type="ntSecurityDescriptor",
                            values=[
                                LDAP_AttributeValue(value=bytes(nTSecurityDescriptor))
                            ],
                        ),
                    )
                ],
                controls=[
                    LDAP_Control(
                        controlType="1.2.840.113556.1.4.801",
                        criticality=True,
                        controlValue=LDAP_serverSDFlagsControl(
                            flags="OWNER+GROUP+DACL+SACL",
                        ),
                    )
                ],
            )
        except LDAP_Exception as ex:
            self.tprint(
                ex.diagnosticMessage or "Error: %s" % ex.resultCode,
                tags=["error"],
            )
            return

        self.tprint("Security descriptor updated.")

    def _members_popup(self, selection, mode="memberof"):
        """
        The base of the "Member Of" and "Members" popups

        :param mode: either "memberof" or "members"
        """
        # Get clicked item
        item = self.tk_tree.selection()[0]

        # Get the user attributes
        try:
            results = self.client.search(
                baseObject=item,
                scope=0,
                attributes=["objectClass", "memberOf"],
            )
            if item not in results:
                raise ValueError("Bad output")
            attributes = results[item]
        except ValueError as ex:
            self.tprint(str(ex))
            return
        except LDAP_Exception as ex:
            self.tprint(
                ex.diagnosticMessage or "Error: %s" % ex.resultCode,
                tags=["error"],
            )
            return

        # Check that this item is indeed, a user or a group
        if not any(x in ["user", "group"] for x in attributes.get("objectClass", [])):
            messagebox.showerror("Error", "Object is neither a user nor a group !")
            return

        # Keep track of previous members, and changed ones
        og_members = set(attributes.get("memberOf", []))
        members = list(og_members)

        # Get dialog
        popup = BasePopup(self.root)
        dlg = popup.dlg

        # "Member Of" UI
        dlg.grid_rowconfigure(0, weight=1)
        dlg.grid_columnconfigure(0, weight=1)

        memberoffrm = ttk.LabelFrame(
            dlg,
            text="Member Of",
        )
        memberoffrm.grid_rowconfigure(0, weight=1)
        memberoffrm.grid_columnconfigure(0, weight=1)

        # Members list
        entrylist = tk.Listbox(memberoffrm)
        entrylist.grid(row=0, sticky="new")

        def add(*_, parentdlg=dlg):
            # Sub-dialog
            subpopup = BasePopup(parentdlg)
            dlg = subpopup.dlg

            # New group field
            newgroupv = tk.StringVar()
            ttk.Label(dlg, text="Group CN:").grid(row=0, sticky="we")
            newgroupf = tk.Entry(dlg, textvariable=newgroupv)
            newgroupf.grid(row=1, sticky="we")

            # OK / Cancel
            btnfrm = ttk.Frame(dlg)
            ttk.Button(btnfrm, text="OK", command=subpopup.dismiss).grid(
                row=0, column=0
            )
            ttk.Button(btnfrm, text="Cancel", command=subpopup.cancel).grid(
                row=0, column=1
            )
            btnfrm.grid(row=2, ipadx=5)

            # Focus
            newgroupf.focus()

            if subpopup.run():
                return

            # Get results
            newgroup = newgroupv.get()

            if newgroup:
                # Store
                members.append(newgroup)
                # Display
                entrylist.insert("end", newgroup)

        def delete(*_):
            try:
                selected = int(entrylist.curselection()[0])
            except IndexError:
                return
            # Drop
            del members[selected]
            # Remove from list
            entrylist.delete(selected)

        # Add / Delete
        btnfrm = ttk.Frame(memberoffrm)
        ttk.Button(btnfrm, text="Add", command=add).grid(row=0, column=0)
        ttk.Button(btnfrm, text="Delete", command=delete).grid(row=0, column=1)
        btnfrm.grid(row=1, sticky="we")

        # Populate
        for group in og_members:
            entrylist.insert("end", group)
            og_members.add(group)

        memberoffrm.grid(row=0, columnspan=2, sticky="we")

        # OK / Cancel
        btnfrm = ttk.Frame(dlg)
        ttk.Button(btnfrm, text="OK", command=popup.dismiss).grid(row=0, column=0)
        ttk.Button(btnfrm, text="Cancel", command=popup.cancel).grid(row=0, column=1)
        btnfrm.grid(row=1, ipadx=5)

        # Setup
        if popup.run():
            # Cancelled
            return

        # Get results
        members = set(members)
        to_add = members - og_members
        to_rem = og_members - members
        operations = [("add", x) for x in to_add] + [("delete", x) for x in to_rem]

        for op, group in operations:
            # Run the operations: on multiple groups, add/remove ourselves from "member"
            try:
                results = self.client.modify(
                    object=group,
                    changes=[
                        LDAP_ModifyRequestChange(
                            operation=op,
                            modification=LDAP_PartialAttribute(
                                type="member",
                                values=[LDAP_AttributeValue(value=item)],
                            ),
                        )
                    ],
                )
            except ValueError as ex:
                self.tprint(str(ex))
                return
            except LDAP_Exception as ex:
                self.tprint(
                    ex.diagnosticMessage or "Error: %s" % ex.resultCode,
                    tags=["error"],
                )
                return

        self.tprint("Groups of '%s' updated !" % item)

    def editmemberof(self, *_):
        """
        Edit popup for "Member Of"
        """
        # Get clicked item
        item = self.tk_tree.selection()[0]

        self._members_popup(item, "memberof")

    def _edit_popup(self, selection, mode="edit", editattrs={}):
        """
        The base of the "Edit" and "Duplicate" popups

        :param mode: either "edit" or "new"
        :param editattrs: existing attributes to edit
        """
        # Get dialog
        popup = BasePopup(self.root)
        dlg = popup.dlg

        # Edit UI
        dlg.grid_columnconfigure(1, weight=1)

        # DN
        dnv = tk.StringVar()
        dnv.set(selection)
        if mode == "edit":
            ttk.Label(dlg, text="DN:").grid(row=0, column=0, sticky="w")
        else:
            ttk.Label(dlg, text="New DN:").grid(row=0, column=0, sticky="w")
        tk.Entry(dlg, textvariable=dnv).grid(row=0, column=1, sticky="we")

        # "Edit entry" sub-box
        editentryfrm = ttk.LabelFrame(
            dlg,
            text="Edit Entry",
        )
        attributev = tk.StringVar()
        ttk.Label(editentryfrm, text="Attribute:").grid(row=0, column=0)
        tk.Entry(editentryfrm, textvariable=attributev).grid(
            row=0, column=1, sticky="we"
        )

        valuesv = tk.StringVar()
        ttk.Label(editentryfrm, text="Values:").grid(row=1, column=0)
        tk.Entry(editentryfrm, textvariable=valuesv).grid(row=1, column=1, sticky="we")

        # "Operation" subbox: the radio + the buttons
        opsfrm = ttk.Frame(editentryfrm)
        operationfrm = ttk.LabelFrame(
            opsfrm,
            text="Operation",
        )
        scopev = tk.IntVar()
        scopev.set(0)
        ttk.Radiobutton(
            operationfrm,
            variable=scopev,
            text="Add",
            value=0,
        ).grid(row=0, column=0)
        ttk.Radiobutton(
            operationfrm,
            variable=scopev,
            text="Delete",
            value=1,
        ).grid(row=0, column=1)
        ttk.Radiobutton(
            operationfrm,
            variable=scopev,
            text="Replace",
            value=2,
        ).grid(row=0, column=2)
        operationfrm.grid(row=0, column=0, columnspan=2, sticky="we")

        if mode == "new":
            # In 'new', the only allowed operation is 'Add'
            for child in operationfrm.winfo_children():
                child.configure(state=tk.DISABLED)

        operations = []

        def enterentrylist():
            """
            This is called to add an element to the "Entry List"
            """
            op = scopev.get()
            attr = attributev.get()
            val = valuesv.get()
            ident = "[%s]%s:%s" % (
                {0: "Add", 1: "Delete", 2: "Replace"}[op],
                attr,
                val,
            )
            # Once we have an ident, actually parse the value entered by the user
            try:
                val = self._parse_attribute(attr, val)
            except ValueError:
                # Parsing failed, show a popup and return without clearing !
                return
            # Get current selection and reset it
            selected = self.currently_editing
            self.currently_editing = None
            # Do we have a selection
            if selected is not None:
                # Yes, edit
                # Set in storage
                operations[selected] = (op, attr, val)
                # Re-add to display
                entrylist.delete(selected)
                entrylist.insert(selected, ident)
                # Reset selection btw
                entrylist.itemconfigure(selected, fg="black")
                entrylist.see(selected)
            else:
                # No, create
                # Add to storage
                operations.append((op, attr, val))
                # Add to display
                entrylist.insert("end", ident)
            # Clear to really show we're done
            scopev.set(0)
            attributev.set("")
            valuesv.set("")

        def editentrylist():
            """
            This is called to load an element from the "Entry List"
            """
            try:
                selected = int(entrylist.curselection()[0])
            except IndexError:
                return
            # If there's a previously edited (unfinished), clear
            if self.currently_editing is not None:
                entrylist.itemconfigure(self.currently_editing, fg="black")
            # Set currently edited mode
            self.currently_editing = selected
            # Show selected item in blue
            entrylist.itemconfigure(selected, fg="blue")
            entrylist.selection_clear(selected)

            operation = operations[selected]
            # Set textboxes
            scopev.set(operation[0])
            attributev.set(operation[1])
            valuesv.set(self._format_attribute(operation[1], operation[2]))

        def removeentrylist():
            """
            This is called to remove an element from the "Entry List"
            """
            try:
                selected = entrylist.curselection()[0]
            except IndexError:
                return
            # Remove from storage
            del operations[selected]
            # Remove from display
            entrylist.delete(selected)

        ttk.Button(
            opsfrm,
            text="Enter",
            command=enterentrylist,
        ).grid(row=0, column=2)

        opsfrm.grid(row=2, column=0, columnspan=2)
        editentryfrm.grid(row=1, column=0, columnspan=2)

        # Entry list
        entrylistfrm = ttk.LabelFrame(
            dlg,
            text="Entry List",
        )
        entrylistfrm.grid_columnconfigure(0, weight=1)

        entrylist = tk.Listbox(entrylistfrm)
        entrylist.grid(row=0, sticky="we", padx=5)

        entrylistbtns = ttk.Frame(entrylistfrm)
        ttk.Button(
            entrylistbtns,
            text="Edit",
            command=editentrylist,
        ).pack(side="left")
        ttk.Button(
            entrylistbtns,
            text="Remove",
            command=removeentrylist,
        ).pack(side="right")
        entrylistbtns.grid(row=1, sticky="we", padx=10)

        entrylistfrm.grid(row=3, column=0, columnspan=2, sticky="we", pady=5)

        if mode == "new":
            for attr, val in editattrs.items():
                # Add to storage
                operations.append((0, attr, val))
                # Add to display
                ident = "[Add]%s:%s" % (
                    attr,
                    self._format_attribute(attr, val),
                )
                entrylist.insert("end", ident)

        # OK / Cancel
        btnfrm = ttk.Frame(dlg)
        ttk.Button(btnfrm, text="Run", command=popup.dismiss).pack(side="left")
        ttk.Button(btnfrm, text="Cancel", command=popup.cancel).pack(side="right")
        btnfrm.grid(row=4, column=0, columnspan=2, ipadx=10)

        # Setup
        if popup.run():
            # Cancelled
            return

        # Get values
        dn = dnv.get()

        return dn, operations

    def edit(self, *args):
        """
        Edit popup
        """
        # Get selected item
        try:
            selection = self.tk_tree.selection()[0]
        except IndexError:
            selection = ""

        results = self._edit_popup(selection)
        if not results:
            return
        dn, operations = results

        # Perform edit
        try:
            self.client.modify(
                object=dn,
                changes=[
                    LDAP_ModifyRequestChange(
                        operation=op,
                        modification=LDAP_PartialAttribute(
                            type=attr,
                            values=[LDAP_AttributeValue(value=x) for x in values],
                        ),
                    )
                    for (op, attr, values) in operations
                ],
            )
        except LDAP_Exception as ex:
            self.tprint(
                ex.diagnosticMessage or "Error: %s" % ex.resultCode,
                tags=["error"],
            )
            return

        self.tprint("Modify request succeeded.")

    def search(self, *args):
        """
        Search popup
        """
        # Get selected item
        try:
            selection = self.tk_tree.selection()[0]
        except IndexError:
            selection = "rootDSE"

        # Get dialog
        popup = BasePopup(self.root)
        dlg = popup.dlg

        # Search UI
        dlg.grid_columnconfigure(1, weight=1)

        basednv = tk.StringVar()
        basednv.set(selection)
        ttk.Label(dlg, text="Base DN").grid(row=0, column=0)
        basednf = tk.Entry(dlg, textvariable=basednv)
        basednf.grid(row=0, column=1, sticky="we")

        filterv = tk.StringVar()
        filterv.set(self.lastSearchString)
        ttk.Label(dlg, text="Filter").grid(row=1, column=0)
        tk.Entry(dlg, textvariable=filterv).grid(row=1, column=1, sticky="we")

        scopefrm = ttk.LabelFrame(
            dlg,
            text="Scope",
        )
        scopev = tk.IntVar()
        scopev.set(1)
        ttk.Radiobutton(
            scopefrm,
            variable=scopev,
            text="Base",
            value=0,
        ).grid(row=0, column=0)
        ttk.Radiobutton(
            scopefrm,
            variable=scopev,
            text="One Level",
            value=1,
        ).grid(row=0, column=1)
        ttk.Radiobutton(
            scopefrm,
            variable=scopev,
            text="Subtree",
            value=2,
        ).grid(row=0, column=2)
        scopefrm.grid(row=2, column=0, columnspan=2)

        ttk.Button(dlg, text="OK", command=popup.dismiss).grid(row=3, column=0)
        ttk.Button(dlg, text="Cancel", command=popup.cancel).grid(row=3, column=1)

        basednf.focus()

        # Setup
        if popup.run():
            # Cancelled
            return

        # Get values
        basedn = basednv.get()
        flt = filterv.get()
        scope = scopev.get()

        self.lastSearchString = flt

        # Perform search
        self.tprint("Searching...", flush=True)
        try:
            results = self.client.search(
                baseObject=basedn,
                scope=scope,
                filter=flt,
            )
        except ValueError as ex:
            self.tprint(str(ex))
            return
        except LDAP_Exception as ex:
            self.tprint(
                ex.diagnosticMessage or "Error: %s" % ex.resultCode,
                tags=["error"],
            )
            return

        self.tprint("Getting %s entries..." % len(results))
        for item in results:
            self._showsearchresult(item, results)

    def modifydn(self, *args):
        """
        Modify the DN of an item
        """
        # Get selected item
        try:
            selection = self.tk_tree.selection()[0]
        except IndexError:
            selection = ""

        # Get dialog
        popup = BasePopup(self.root)
        dlg = popup.dlg

        # Duplicate UI
        dlg.grid_columnconfigure(1, weight=1)

        basednv = tk.StringVar()
        basednv.set(selection)
        ttk.Label(dlg, text="DN:").grid(row=0, column=0, sticky="w")
        basednf = tk.Entry(dlg, textvariable=basednv)
        basednf.grid(row=0, column=1, sticky="we")

        newdnv = tk.StringVar()
        ttk.Label(dlg, text="New DN:").grid(row=1, column=0, sticky="w")
        newdnf = tk.Entry(dlg, textvariable=newdnv)
        newdnf.grid(row=1, column=1, sticky="we")

        ttk.Button(dlg, text="OK", command=popup.dismiss).grid(row=2, column=0)
        ttk.Button(dlg, text="Cancel", command=popup.cancel).grid(row=2, column=1)

        if selection:
            newdnf.focus()
        else:
            basednf.focus()

        # Setup
        if popup.run():
            # Cancelled
            return

        # Get values
        basedn = basednv.get()
        newdn = newdnv.get()

        self.tprint("Changing %s to %s..." % (basedn, newdn))
        try:
            self.client.modifydn(
                entry=basedn,
                newdn=newdn,
            )
        except ValueError as ex:
            self.tprint(str(ex))
            return
        except LDAP_Exception as ex:
            self.tprint(
                ex.diagnosticMessage or "Error: %s" % ex.resultCode,
                tags=["error"],
            )
            return

        self.tprint("OK !")

    def new(self, mode):
        """
        New popup. Called by both 'Add child' and 'Duplicate' popups
        """
        if mode == "duplicate":
            # Get selected item
            try:
                selection = self.tk_tree.selection()[0]
            except IndexError:
                selection = ""
        else:
            selection = ""

        existing_attributes = {}
        if selection:
            # Perform search to retrieve the attributes
            self.tprint("Getting attributes for %s..." % selection, flush=True)
            try:
                results = self.client.search(
                    baseObject=selection,
                    scope=0,
                )
                if selection not in results:
                    raise ValueError("Bad result")
                existing_attributes = results[selection]
            except ValueError as ex:
                self.tprint(str(ex))
                return
            except LDAP_Exception as ex:
                self.tprint(
                    ex.diagnosticMessage or "Error: %s" % ex.resultCode,
                    tags=["error"],
                )
                return

        # Show edit popup to be able to change an attribute
        results = self._edit_popup(selection, mode="new", editattrs=existing_attributes)
        if not results:
            return
        newdn, changes = results

        # Extract all the 'add' attributes operations from changes
        attributes = {attr: val for (_, attr, val) in changes}

        self.tprint("Adding %s..." % newdn)
        try:
            self.client.add(
                newdn,
                attributes=attributes,
            )
        except LDAP_Exception as ex:
            self.tprint(
                ex.diagnosticMessage or "Error: %s" % ex.resultCode,
                tags=["error"],
            )
            return

        self.tprint("OK !")

    def duplicate(self, *args):
        return self.new("duplicate")

    def addchild(self, *args):
        return self.new("addchild")

    def _format_attribute(self, name, value, crop=False):
        """
        Format a LDAP attribute
        """
        if isinstance(value, list):
            # It's a list.
            return ";".join(self._format_attribute(name, v, crop=crop) for v in value)
        elif name == "objectSid":
            return WINNT_SID(value).summary()
        elif isinstance(value, bytes):
            # Catch-all for bytes values
            value = value.hex()
        else:
            # Catch-all
            value = str(value)
        # If cropping is enabled and requested, crop
        if crop and self.crop_output.get() and len(value) >= 80:
            return value[:80] + "... (%so)" % len(value)
        return value

    def _parse_attribute(self, name, value):
        """
        Parse a formatted attribute
        """
        parsed = []
        # Split across ;
        for val in value.split(";"):
            if name == "objectSid":
                val = WINNT_SID.fromstr(val)
            parsed.append(val)
        return parsed

    def tprint(self, x, tags=[], flush=False):
        """
        Print to text pane
        """
        self.tk_textpane.configure(state=tk.NORMAL)
        self.tk_textpane.insert("end", x + "\n", tuple(tags))
        self.tk_textpane.configure(state=tk.DISABLED)
        self.tk_textpane.see(tk.END)
        if flush:
            self.root.update()

    def main(self):
        """
        Main loop: start the GUI.
        """
        # Note: for TK doc, use https://tkdocs.com

        # Root
        self.root = tk.Tk()
        self.root.title("LDAPhero (@secdev/scapy)")
        self.root.option_add("*tearOff", False)

        # TTK style

        ttkstyle = ttk.Style()
        ttkstyle.theme_use("alt")
        ttkstyle.configure(
            "BorderFrame.TFrame",
            relief="groove",
            borderwidth=3,
        )

        # Global configuration variables
        self.crop_output = tk.BooleanVar()
        self.crop_output.set(True)

        # Create main frames, pack them in scrollable elements
        content = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)

        tvfr = ttk.Frame(content)
        tvfr.grid_columnconfigure(0, weight=1)
        tvfr.grid_rowconfigure(0, weight=1)
        self.tk_tree = ttk.Treeview(tvfr, show="tree")
        content.add(tvfr)
        self.tk_tree.bind("<Double-1>", self.treedoubleclick)

        tree_scrollbar = AutoHideScrollbar(
            tvfr, orient="vertical", command=self.tk_tree.yview
        )
        self.tk_tree.configure(yscrollcommand=tree_scrollbar.set)
        self.tk_tree.grid(row=0, column=0, sticky="nsew")
        self.tk_tree.column("#0", width=200)

        self.tk_textpane = tk.Text(content, state=tk.DISABLED)
        self.tk_textpane.tag_configure("bold", font="TkCaptionFont")
        self.tk_textpane.tag_configure("error", foreground="red")
        content.add(self.tk_textpane)

        # Menu
        menubar = tk.Menu(self.root)
        self.menu_connection = tk.Menu(menubar)
        self.menu_browse = tk.Menu(menubar)
        self.menu_view = tk.Menu(menubar)
        menubar.add_cascade(menu=self.menu_connection, label="Connection")
        self.menu_connection.add_command(label="Connect", command=self.connect)
        self.menu_connection.add_command(
            label="Bind", command=self.bind, state=tk.DISABLED, accelerator="Ctrl+B"
        )
        self.menu_connection.add_command(
            label="Disconnect", command=self.disconnect, state=tk.DISABLED
        )
        self.menu_connection.add_command(label="Quit", command=self.root.destroy)
        menubar.add_cascade(menu=self.menu_browse, label="Browse")
        self.menu_browse.add_command(
            label="Add child",
            command=self.addchild,
            state=tk.DISABLED,
            accelerator="Ctrl+A",
        )
        self.menu_browse.add_command(
            label="Modify", command=self.edit, state=tk.DISABLED, accelerator="Ctrl+M"
        )
        self.menu_browse.add_command(
            label="Modify DN",
            command=self.modifydn,
            state=tk.DISABLED,
            accelerator="Ctrl+R",
        )
        self.menu_browse.add_command(
            label="Search", command=self.search, state=tk.DISABLED, accelerator="Ctrl+S"
        )
        menubar.add_cascade(menu=self.menu_view, label="View")
        self.menu_view.add_command(
            label="Tree", command=self.tree, state=tk.DISABLED, accelerator="Ctrl+T"
        )
        self.menu_view.add_checkbutton(
            label="Crop output", onvalue=True, offvalue=False, variable=self.crop_output
        )
        self.root["menu"] = menubar

        # Right-click menu
        self.popup = tk.Menu(self.root, tearoff=0)
        self.popup.add_command(
            label="Search", command=self.search, accelerator="Ctrl+S"
        )
        self.popup.add_command(label="Modify", command=self.edit, accelerator="Ctrl+M")
        self.popup.add_command(
            label="Modify DN", command=self.modifydn, accelerator="Ctrl+R"
        )
        self.popup.add_command(label="Duplicate", command=self.duplicate)
        popup_adv = tk.Menu(self.popup)
        self.popup.add_cascade(label="Advanced", menu=popup_adv)
        popup_adv.add_command(label="Security descriptor", command=self.viewsec)
        popup_adv.add_command(label="Member Of", command=self.editmemberof)

        def do_popup(event):
            item = self.tk_tree.identify_row(event.y)
            if item:
                if self.tk_tree.tag_has("unclickable", item):
                    # Unclickable
                    return
                self.tk_tree.selection_set(item)
                self.popup.tk_popup(event.x_root, event.y_root)

        self.tk_tree.bind("<Button-3>", do_popup)

        # Shortcuts
        self.root.bind_all("<Control-b>", self.bind)
        self.root.bind_all("<Control-t>", self.tree)

        # Initial rendering
        content.pack(fill="both", expand=True)
        self.root.update()

        # Try connecting
        if self.host is not None:
            self.root.after(0, self.connect)

        # Main loop
        self.root.mainloop()
