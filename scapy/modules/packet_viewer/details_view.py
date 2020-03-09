# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from typing import List, Tuple, Any
from urwid import LineBox

from scapy.packet import Packet


class DetailsView(LineBox):
    """
    Baseclass for custom views.
    The signals packet_modified and notification should be used to communicate
    with the parent widget.

    packet_modified: This signal informs the parent widget that this view has
                     changed a packet and that a update of other views is
                     necessary

    notification: This signal can be used to open PopUps with certain
                  information, for example error handling notification to the
                  user.
    """
    signals = ["packet_modified", "notification", "msg_to_main_thread"]
    palette = []  # type: List[Tuple[str, str, str]]
    action_name = ""

    def __init__(self, *args, **kwargs):
        # type: (Any, Any) -> None
        """
        Initialize class. Forward all arguments and set the action name
        as title
        :param args: args for LineBox
        :param kwargs: kwargs for LineBox
        """
        super(DetailsView, self).__init__(
            *args, title=self.action_name, **kwargs)

    def update_packets(self, focused_packet, all_packets):
        # type: (Packet, List[Packet]) -> None
        """
        This method is used by the parent widget to notify this view about
        updates on the packets.
        :param focused_packet: The packet that currently has the focus on the
                               parent view
        :param all_packets: All packets of the parent view
        """
        raise NotImplementedError
