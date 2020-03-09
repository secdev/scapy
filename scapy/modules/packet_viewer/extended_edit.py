# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license
from typing import Any, Tuple

from urwid import Edit, Canvas


class ExtendedEdit(Edit):
    """
    A new signal "apply" is emitted by this Edit after Enter is pressed.
    A new signal "exit" is emitted by this Edit after Escape is pressed.
    It also takes care of resetting the text after losing focus.
    """
    signals = ["apply", "exit"] + Edit.signals

    def __init__(self, use_reset, *args, **kwargs):
        # type: (bool, Any, Any) -> None
        """
        Initialize ExtendedEdit
        :param args: args for Edit
        :param use_reset: whether a reset after losing focus is desired
        :param kwargs: kwargs for Edit
        """

        self._use_reset = use_reset

        # Holds this widgets focus state from last rendering
        self._had_focus = False
        # The text the edit field contained before gaining the focus
        self._old_value = ""
        super(ExtendedEdit, self).__init__(*args, **kwargs)

    def keypress(self, size, key):
        # type: (Tuple[int, int], str) -> Any
        """
        Custom implementation of keypress from Widget. Key-Presses to Enter
        are handled by the edit. The apply signal is emitted on enter.
        Other keys are not handled and forwarded.
        :param size:
        :param key: key which is pressed
        :return: None if key is handled otherwise let the super class return
        """
        if key == "enter":
            # Lose focus already here that
            # the old value doesn't get applied in `render`
            self._had_focus = False
            self._emit("apply", self.edit_text)
            return None

        if key == "esc":
            self._emit("exit")
            return None

        return super(ExtendedEdit, self).keypress(size, key)

    def render(self, size, focus=False):
        # type: (Tuple[int], bool) -> Canvas
        """
        Custom implementation of render to reset to old value as soon as
        the focus is lost.
        """
        if self._use_reset:
            if not self._had_focus and focus:
                # we got the focus
                # Cache original value
                self._old_value = self.get_edit_text()
            elif self._had_focus and not focus:
                # We lost the focus
                # Set edit_text to old one
                self.edit_text = self._old_value

            self._had_focus = focus
        return super(ExtendedEdit, self).render(size, focus=focus)
