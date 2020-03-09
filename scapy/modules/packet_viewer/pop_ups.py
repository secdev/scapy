# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from typing import Callable, Any
from urwid import Text, AttrMap, Button, LineBox, Overlay, ListBox, MainLoop, \
    SimpleListWalker


def show_info_pop_up(loop, info):
    # type: (MainLoop, str) -> None
    """
    Shows a popup with a information, for example an error message.
    Popup closes on button press
    :param loop: urwid MainLoop where the popup is shown
    :param info: Information text
    """
    current_widget = loop.widget

    def delete_overlay(_sender=None):
        # type: (Any) -> None
        loop.widget = current_widget

    info = Text(("default_bold", info), "center")
    ok_btn = AttrMap(Button("OK", delete_overlay), "green")

    prompt = LineBox(ListBox(SimpleListWalker([info, ok_btn])))
    overlay = Overlay(prompt, loop.widget.base_widget, "center",
                      30, "middle", 8, 16, 8)
    loop.widget = overlay


def show_question_pop_up(loop, message, yes_callback):
    # type: (MainLoop, str, Callable[[Any], None]) -> None
    """
    Shows a popup with a information, for example an error message.
    Popup closes on button press
    :param loop: urwid MainLoop where the popup is shown
    :param message: Question text
    :param yes_callback: Callback which gets called
                         if question is answered with yes
    """
    current_widget = loop.widget

    def delete_overlay(_sender=None):
        # type: (Any) -> None
        loop.widget = current_widget

    question = Text(("default_bold", message), "center")
    no_btn = AttrMap(Button("No", delete_overlay), "red")
    yes_btn = AttrMap(Button("Yes", yes_callback), "green")
    listbox = ListBox(SimpleListWalker([question, yes_btn, no_btn]))
    listbox.focus_position = 2
    linebox = LineBox(listbox)
    overlay = Overlay(linebox, loop.widget.base_widget,
                      "center", 20, "middle", 8, 16, 8)
    loop.widget = overlay
