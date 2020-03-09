# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

import six

from ast import literal_eval
from typing import List, Type, Any, Union, Optional
from urwid import Columns, SimpleListWalker, Text, connect_signal

from scapy.base_classes import SetGen
from scapy.config import conf
from scapy.fields import ConditionalField, Emph
from scapy.packet import Packet
from scapy.themes import BlackAndWhite
from scapy.utils import hexdump
from scapy.modules.packet_viewer.extended_listbox import ExtendedListBox
from scapy.modules.packet_viewer.details_view import DetailsView
from scapy.modules.packet_viewer.extended_edit import ExtendedEdit


class EditView(DetailsView):
    """
    Custom view which holds the output of Packet.show() as editable list and
    shows a hexdump of the current selected Packet
    """
    action_name = "Edit"

    def __init__(self):
        # type: () -> None
        """
        Initialize ShowView
        """
        self._current_packet = None  # type: Optional[Packet]
        self._show_text = ExtendedListBox(False, SimpleListWalker([]))
        self._hex_text = ExtendedListBox(False, SimpleListWalker([]))

        hexdump_str_width = 71
        col = Columns([self._show_text, (hexdump_str_width, self._hex_text)],
                      dividechars=2)
        super(EditView, self).__init__(col)

    def update_packets(self, focused_packet, all_packets):
        # type: (Packet, List[Packet]) -> None
        self._update(focused_packet)

    def _update(self, packet, force_update=False):
        # type: (Packet, Optional[bool]) -> None
        """
        Internal update function
        :param packet: Packet which get displayed by this view
        :param force_update: Forces re-rendering
        """
        if packet == self._current_packet and not force_update:
            return

        self._current_packet = packet

        show_text = self._show(packet) + [Text("")]
        hexdump_text = hexdump(packet, dump=True)

        # Keep an empty line as the last line. This gives a nice
        # visual feedback that the end of the list is reached.
        # For `show_text` this is given because it always ends with an "\n"
        # For `hexdump_text` we add it manually
        self._update_hexdump(hexdump_text.split("\n"))
        self._update_show(show_text)

    @staticmethod
    def _build_command(target_type, string):
        # type: (Type[Any], str) -> Any
        """
        This method tries to build a value from a string for any type.
        :param target_type: desired type of string
        :param string: string that should be build to a value
        :return: value
        """
        try:
            # For Python3 we need to add the "b" prefix for bytes
            # Python2 does not need this
            if target_type == bytes and six.PY3:
                value = literal_eval(
                    'b"' + string[1:-1].replace('"', '\\"') + '"')
            else:
                value = literal_eval(string)
        except (SyntaxError, ValueError):
            # Encapsulate value_str as a string and parse as simple string
            # Should always work except if the field doesn't accept a string
            value = literal_eval('"' + string.replace('"', '\\"') + '"')
        return value

    def _edit_done_callback(self, packet, field_name, _edit_widget, new_text):
        # type: (Packet, str, ExtendedEdit, str) -> None
        """
        Gets called after a field has been edited. This method sets a new
        value in the field of the current packet

        :param packet: Packet where the field has to be updated
        :param field_name: Destination field for the new value
        :param _edit_widget: Edit widget which caused the callback
        :param new_text: Text content of the Edit widget which should be set
                         as new field value
        """
        old_type = type(packet.getfieldval(field_name))
        value = self._build_command(old_type, new_text.strip())

        if not EditView._is_valid_value(packet, field_name, value):
            self._emit("notification",
                       "Invalid value.\nGiven type: %s\nExpected type: %s" %
                       (type(value).__name__, old_type.__name__))
        else:
            packet.setfieldval(field_name, value)
            # show changes also in hexdump view
            # Also "beautifies" output in show widget automatically
            if self._current_packet:
                self._update(self._current_packet, True)
            self._emit("packet_modified")

    @staticmethod
    def _is_valid_value(packet, field_name, value):
        # type: (Packet, str, Any) -> bool
        """
        Checks if the value is valid for the field of a packet
        :param packet: Packet where field should get a new value
        :param field_name: Destination field for the value
        :param value: Value to set in field
        :return: Returns True if value can be set without Exception
        """
        # noinspection PyBroadException
        try:
            clone = packet.copy()
            clone.setfieldval(field_name, value)
            clone.build()
            return True
        except Exception:
            return False

    def _update_show(self, lines):
        # type: (List[Text]) -> None
        """
        :param lines: Lines to display in show part of this view
        """
        self._update_existing_lines(self._show_text, lines)

    def _update_hexdump(self, lines):
        # type: (List[str]) -> None
        """
        :param lines: Lines to display in hexdump part of this view
        """
        self._update_existing_lines(self._hex_text,
                                    [Text(line) for line in lines])

    @staticmethod
    def _update_existing_lines(listbox, lines):
        # type: (ExtendedListBox, List[Text]) -> None
        """
        This method reuses existing lines.
        If there are too many, they are stripped.
        If there are too few, new ones are created.
        This also ensures that if a new package should becomes shown
        the view does not "scroll" back to the top but keeps the line.
        :param listbox: ListBox which holds lines to update
        :param lines: Lines to display
        """
        # strip lines which are too much
        del listbox.body[len(lines):]
        for i, item in enumerate(lines):
            if i < len(listbox.body):
                # reuse line with urwid.Text
                listbox.body[i] = item
            else:
                # Seems the former shown packet had less lines than the new one
                # Or it's the first Packet to be shown
                listbox.body.append(item)

    # noinspection PyProtectedMember,DuplicatedCode,SpellCheckingInspection
    def _show(self, pkt, lvl="", label_lvl=""):  # noqa: E501
        # type: (Packet, str, str) -> List[Union[Text, ExtendedEdit]]
        """
        Custom implementation of `Packet.show()`
        Returns a list of widgets which represent the show output.
        Lines with fields are editable.

        :param pkt: the packet for which the show should be generated
        :param str lvl: additional information about the layer lvl
        :param str label_lvl: additional information about the layer fields
        :return: return a hierarchical list of Text objects
        """

        ct = BlackAndWhite()
        s = "%s%s %s %s" % (label_lvl,
                            ct.punct("###["),
                            ct.layer_name(pkt.name),
                            ct.punct("]###"))
        lines = [Text(s)]

        for f in pkt.fields_desc:
            if isinstance(f, ConditionalField) and not f._evalcond(pkt):
                continue
            if isinstance(f, Emph) or f in conf.emph:
                ncol = ct.emph_field_name
                vcol = ct.emph_field_value
            else:
                ncol = ct.field_name
                vcol = ct.field_value
            fvalue = pkt.getfieldval(f.name)
            if isinstance(fvalue, Packet) or (f.islist and f.holds_packets and isinstance(fvalue, list)):  # noqa: E501
                s = "%s  \\%-10s\\" % (label_lvl + lvl, ncol(f.name))
                lines.append(Text(s))
                fvalue_gen = SetGen(fvalue, _iterpacket=0)
                for fvalue in fvalue_gen:
                    lines.extend(self._show(fvalue, label_lvl=label_lvl + lvl + "   |"))  # noqa: E501
            else:
                begn = "%s  %-10s%s " % (label_lvl + lvl, ncol(f.name), ct.punct("="),)  # noqa: E501
                reprval = f.i2repr(pkt, fvalue)
                if isinstance(reprval, str):
                    reprval = reprval.replace("\n", "\n" + " " * (len(label_lvl) + len(lvl) + len(f.name) + 4))    # noqa: E501
                edit = ExtendedEdit(True, begn, vcol(reprval), test="5", asf=3)
                connect_signal(edit, "apply", self._edit_done_callback,
                               weak_args=[pkt], user_args=[f.name])
                lines.append(edit)
        if pkt.payload:
            new_lines = self._show(pkt.payload, lvl=lvl + (" " * pkt.show_indent), label_lvl=label_lvl)  # noqa: E501
            lines.extend(new_lines)

        return lines
