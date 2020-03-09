# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license


try:
    import urwid  # noqa: F401
    from scapy.modules.packet_viewer.viewer import viewer  # noqa: F401
except ImportError:
    raise ImportError("urwid is not installed! "
                      "You may install urwid in order to use the "
                      "packet_viewer, via `pip install urwid`")
