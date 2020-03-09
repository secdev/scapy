# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from six import PY2
from typing import List
from urwid import AttrMap, SimpleListWalker, CheckBox
from urwid.version import VERSION as URWID_VERSION

from scapy.packet import Packet
from scapy.modules.packet_viewer.extended_listbox import ExtendedListBox
from scapy.modules.packet_viewer.row_formatter import RowFormatter


class PacketListView(ExtendedListBox):
    """
    Lists all the packets which have been sniffed so far
    or were given in a list.
    """

    def __init__(self, row_formatter):
        # type: (RowFormatter) -> None
        self.row_formatter = row_formatter
        self.packets = []  # type: List[Packet]

        super(PacketListView, self).__init__(True, SimpleListWalker([]))

    def update_selected_packet(self):
        # type: () -> None
        text = self.row_formatter.format(self.focus.base_widget.tag)
        self.focus.base_widget.set_label(text)

    # noinspection PyProtectedMember
    def _create_gui_packet(self, pkt):
        # type: (Packet) -> CheckBox
        text = self.row_formatter.format(pkt)
        gui_packet = CheckBox(text)

        # Unfortunately we need to access some protected variables here,
        # to customize the underlying widgets

        wrap = "clip" if PY2 and URWID_VERSION <= (2, 1, 1) else "ellipsis"
        gui_packet._label.set_layout("left", wrap)

        # The cursor of `urwid.SelectableIcon` doesn't take a color scheme.
        # So just hide the cursor.
        # len(text) + 1 hides the cursor
        checked_state = gui_packet.states[True]
        unchecked_state = gui_packet.states[False]
        checked_state._cursor_position = len(checked_state.text) + 1
        unchecked_state._cursor_position = len(unchecked_state.text) + 1
        gui_packet.tag = pkt
        return gui_packet

    def add_packet(self, pkt):
        # type: (Packet) -> None

        """
        Creates and appends a Packet widget to the end of the list.
        The cursor in front of the packet content is colored
        in the default background color.
        This way, it is invisible and only the cursor
        in front of the packet in focus is colored.

        :param pkt: packet, which is passed on from the sniffer
        :type pkt: Packet
        :return: None
        """

        if not self.row_formatter.is_pkt_supported(pkt):
            return

        self.packets.append(pkt)
        self.body.append(
            AttrMap(self._create_gui_packet(pkt), None, "cyan"))
