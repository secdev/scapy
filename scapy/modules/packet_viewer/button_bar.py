# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from collections import OrderedDict
from typing import Tuple, Callable, List
from urwid import AttrMap, Button, Columns, Text


class ButtonBar(Columns):
    def __init__(self, commands):
        # type: (OrderedDict[str, Action]) -> None
        """
        The commandline interface renders a set of buttons implemented
        through Action objects. The key for each button is defined by the
        key in the commands dict. The Action object delivers the text to
        display and the function to execute on a key press.
        :param commands: A dictionary to describe the supported keys. The key
                         of the dict maps to the key press, when the Action
                         is executed.
        """
        self._actions = commands
        self._key_button_map = OrderedDict((cmd[0], self._create_button(cmd))
                                           for cmd in commands.items())

        widgets = [(len(btn.get_label()) + 2, btn)
                   for btn in self._key_button_map.values()]
        # Fill the rest of the row with the right color
        widgets.append(AttrMap(Text(""), "cyan"))
        super(ButtonBar, self).__init__(widgets)

    def refresh(self):
        # type: () -> None
        """
        Refreshes the texts of the buttons.
        """
        for action, btn in zip(self._actions.values(),
                               self._key_button_map.values()):
            btn.set_label(("cyan", action.text))

    def keypress(self, size, key):
        # type: (int, str) -> None
        """
        Handle editing keystrokes, return None to not forward key press.
        :param size:
        :param key: Name of key pressed.
        """
        if key in self._actions:
            self._execute_and_change_state(key)

    def _execute_and_change_state(self, key):
        # type: (str) -> None
        """
        Executes action for a key and updates the according button text
        :param key: Key to execute
        """
        action = self._actions[key]
        action.execute()

        btn = self._key_button_map[key]
        btn.set_label(("cyan", action.text))

    # noinspection PyProtectedMember
    def _create_button(self, cmd):
        # type: (Tuple[str, Action]) -> Button
        """
        Helper function to create a Button object for a command
        :param cmd: Tuple of key and Action object
        :return: Button for this Action
        """
        key, action = cmd

        btn = Button(("cyan", action.text),
                     on_press=lambda _sender, k:
                     self._execute_and_change_state(k),
                     user_data=key)
        # We need to access the underlying Columns widget
        cols = btn._w
        # We don't want any dividing chars
        cols.dividechars = 0
        # Set the prefix and make it pack instead of "<" and fixed length
        cols.contents[0] = (Text(key.upper()), cols.options("pack"))
        # Remove the ">" behind the actual button text
        del cols.contents[2]
        # len(text) + 1 hides the cursor
        cols.contents[1][0]._cursor_position = len(btn.label) + 1
        # Ensure buttons won't gain focus but they are still clickable
        cols._selectable = False
        return btn


class Action(object):
    """
    Helper class to store a list of texts and functions. On every execute,
    the internal index increases. The internal index points to the current
    text and function. If the index points to the last function, the next
    execution causes a roll-over to index zero.
    """
    def __init__(self, texts, funcs, state_index=0):
        # type: (List[str], List[Callable[[], None]], int) -> None  # noqa: E501
        """
        Initialize an Action object
        :param texts: A list of texts. Has to have the same order as funcs.
        :param funcs: A list of functions. Has to have the same order as texts.
        :param state_index: initial index if necessary
        """
        self._texts = texts
        self._funcs = funcs
        self._state_index = state_index
        if len(self._texts) != len(self._funcs):
            raise AssertionError("The lists texts and funcs need to have "
                                 "the same length")
        if self._state_index > len(self._texts):
            raise AssertionError("State index can't be greater than length "
                                 "of texts or funcs")

    def execute(self):
        # type: () -> None
        """
        Executes the function selected by the current index. Afterwards the
        index is increased.
        """
        self._funcs[self._state_index]()
        self._state_index += 1
        self._state_index %= len(self._funcs)

    def reset(self):
        # type: () -> None
        """
        Resets internal index back to zero.
        """
        self._state_index = 0

    @property
    def text(self):
        # type: () -> str
        """
        Get the text selected by the current index.
        :return: text selected.
        """
        text_width = 12
        return self._texts[self._state_index].ljust(text_width)[:text_width]
