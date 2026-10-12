# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2025 Thales
# Author: Alexis Royer <https://github.com/alxroyer-thales>

"""
PacketCmp class

Provides refined packet comparisons.
"""

import copy
import logging

from scapy.error import log_runtime
from scapy.fields import _FieldContainer, _PacketField, AnyField, ApproximateField
from scapy.layers.l2 import Ether
from scapy.packet import Packet

# Typing imports
from typing import (
    Any,
    ContextManager,
    List,
    Optional,
    Sequence,
    Union,
)


class PacketCmp:
    """
    Refined packet comparisons.

    Usage:

    .. code-block:: python

        # Programmatic usage:
        cmp = PacketCmp(a, expected)
        if not cmp.compare():
            for error in cmp.errors:
                print(f"{error!r}")

        # Or just use the assertion form:
        PacketCmp(a, expected).assert_equal()

        # Show all fields compared one by one:
        PacketCmp(a, expected).assert_equal(log_success_level=logging.INFO)

    Recursive class:
    a packet comparison with a root :class:`PacketCmp` instance
    recurses with child :class:`PacketCmp` instances for packet fields and payloads.
    """

    def __init__(
            self,
            compared,  # type: Packet
            expected,  # type: Packet
            *,
            field_path="",  # type: str
            rebuild_expected=True,  # type: bool
            initial_expected=None,  # type: Optional[Packet]
            debug_logging_level=None,  # type: Optional[int]
    ):  # type: (...) -> None
        """
        :param compared:
            Usually a packet freshly parsed.
            All auto fields expected to be resolved.
        :param expected:
            Usually a packet built and fed programmatically.
            Auto fields shall usually not be resolved yet, so that they can be recomputed in case of approximate fields.
        :param field_path:
            Path of field names being compared.
            Empty for root call of recursion.
            Full path of fields from the root packet for recursive calls.
        :param rebuild_expected:
            For performance concerns.
            If ``expected`` already fully built, set to ``False`` to avoid ``expected`` be rebuilt before comparison.
            ``True`` by default for root call of recursion.
            Set to ``False`` for recursive calls.
        :param initial_expected:
            Reserved for recursive calls only.
        :param debug_logging_level:
            Set to some logging level to display debugging information.
        """
        # Set `_debug_logging_level` and `_debug_indentation` at first so that we can call `_debug()` right away.
        self._debug_logging_level = debug_logging_level  # type: Optional[int]
        self._debug_indentation = ""  # type: str

        #: Packet being compared.
        self.compared = compared  # type: Packet
        self._debug(f"self.compared=\n\t%r", self.compared)

        #: Packet holding expected values for :attr:`compared`.
        self.expected = expected  # type: Packet
        if rebuild_expected:
            self.expected = type(expected)(expected.build())
        self._debug("self.expected=\n\t%r", self.expected)

        #: Path of field names being compared.
        #: Empty for root call of recursion.
        self.field_path = field_path  # type: str

        #: All :class:`PacketCmp.Diff` objects, errors and successes.
        #:
        #: May start with approximate comparisons justifying comparison restarts.
        self.diffs = []  # type: List[PacketCmp.Diff]

        #: Only error diffs from :attr:`diffs`.
        self.errors = []  # type: List[PacketCmp.Diff]

        #: Initial expected packet.
        #: Useful for fixes in case of approximate fields.
        #:
        #: Stores the same layer as :attr:`expected`.
        self._initial_expected = (
            initial_expected if (initial_expected is not None)
            # Make a clone of `expected` in order to avoid modifying input data unexpectedly.
            else expected.copy()
        )  # type: Packet
        self._debug("self._initial_expected=\n\t%r", self._initial_expected)

        #: Flag to save if current process is a recursive call.
        self._recursive = (initial_expected is not None)  # type: bool

    def assert_equal(
            self,
            *,
            log_success_level=None,  # type: Optional[int]
    ):  # type: (...) -> None
        """
        Launches the comparison (see :meth:`compare()`), and raises an assertion exception in case the comparison fails.

        :param log_success_level: Logging level used to log matching data. Use ``None`` not to log anything on success.
        """
        # Smart comparison: display differences with detailed logging.
        self.compare(
            log_success_level=log_success_level,
            log_error_level=logging.ERROR,
        )
        assert not self.errors, f"Errors: {self.errors!r}"
        # Raw packet comparison, by security, in case the smart comparison above would be buggy...
        compared_bytes = self.compared.build()  # type: bytes
        expected_bytes = self.expected.build()  # type: bytes
        assert compared_bytes == expected_bytes, f"{compared_bytes!r} != {expected_bytes!r}"

    def compare(
            self,
            *,
            log_success_level=None,  # type: Optional[int]
            log_error_level=logging.WARNING,  # type: Optional[int]
    ):  # type: (...) -> bool
        """
        Compares the two packets and returns the result.

        Recursive by packet fields and by layer.

        :param log_success_level: Logging level used to log matching data. Use ``None`` not to log anything on success.
        :param log_error_level: Logging level used to log mismatching data. Use ``None`` not to log anything on error.
        :return: ``True`` when the two packets have same data.
        """
        self._debug("PacketCmp[%s].compare()", self.expected.name)

        self.diffs.clear()
        self.errors.clear()

        # Loop until all approximate field comparisons have been processed,
        # either with exact success, with approximate success, or with error.
        while True:
            try:
                # Don't push directly in `self.diffs` until all approximate fields have been processed.
                # Save in `tmp_diffs` first.
                tmp_diffs = []  # type: List[PacketCmp.Diff]

                # Compute field info lists.
                # Consider payloads as packet fields.
                compared_fields_info = list(self._get_fields_info(self.compared, with_payload=True))  # type: List[PacketCmp._FieldInfo]
                expected_fields_info = list(self._get_fields_info(self.expected, with_payload=True))  # type: List[PacketCmp._FieldInfo]
                initial_expected_fields_info = list(self._get_fields_info(self._initial_expected, with_payload=True))  # type: List[PacketCmp._FieldInfo]

                # Compare the expected and compared lists.
                if len(compared_fields_info) != len(expected_fields_info):
                    tmp_diffs.append(PacketCmp.Diff(
                        "field-count",
                        self.compared, self._FieldInfo(name="field-count", desc=None, value=len(compared_fields_info)),
                        self.expected, self._FieldInfo(name="field-count", desc=None, value=len(expected_fields_info)),
                        f"Mismatching number of fields {[_.name for _ in compared_fields_info]!r} v/s {[_.name for _ in expected_fields_info]!r}",
                    ))
                    self._log_new_diff(tmp_diffs[-1])
                else:
                    self._check_expected_consistency(
                        "field-count", expected_fields_info, initial_expected_fields_info,
                        len(initial_expected_fields_info) == len(expected_fields_info),
                    )

                    # Check all fields for the current layer.
                    for field_index in range(len(compared_fields_info)):  # type: int
                        compared = compared_fields_info[field_index]  # type: PacketCmp._FieldInfo
                        expected = expected_fields_info[field_index]  # type: PacketCmp._FieldInfo
                        initial_expected = initial_expected_fields_info[field_index]  # type: PacketCmp._FieldInfo

                        # Check item names.
                        if compared.name != expected.name:
                            tmp_diffs.append(PacketCmp.Diff(
                                f"item#{field_index + 1}",
                                self.compared, self._FieldInfo(name=f"item#{field_index + 1}", desc=None, value=compared.name),
                                self.expected, self._FieldInfo(name=f"item#{field_index + 1}", desc=None, value=expected.name),
                                "Mismatching names",
                            ))
                            self._log_new_diff(tmp_diffs[-1])
                            # End comparison for the current layer.
                            break

                        # Check item types and values.
                        with self._debug_indentation_ctx():
                            tmp_diffs.extend(self._compare_fields(
                                item_name=expected.name,
                                compared=compared,
                                expected=expected,
                                initial_expected=initial_expected,
                            ))

                # No more approximate fields.
                # Save the diffs in `self.diffs` the get out of the `while True:` loop.
                self.diffs.extend(tmp_diffs)
                break

            except PacketCmp._RestartCompareException as restart:
                if self._recursive:
                    # Not the root `PacketCmp` in recursion.
                    # Let the exception go to the upper `PacketCmp`.
                    raise
                else:
                    # Root `PacketCmp` in recursion.

                    # Security against infinite loops:
                    # Check the given field has not already been processed as an approximate field.
                    if restart.diff.item in [diff.item for diff in self.diffs]:
                        # If already processed, fail with duplicate error messge.
                        self.diffs.append(PacketCmp.Diff(
                            restart.diff.item,
                            restart.diff.compared_pkt, restart.diff.compared_info,
                            restart.diff.expected_pkt, restart.diff.expected_info,
                            error_message=f"Duplicate approximate comparison",
                            delta=restart.diff.delta, tolerance=restart.diff.tolerance,
                        ))
                        self._log_new_diff(self.diffs[-1])
                        # Break the `while True:` loop.
                        break

                    # Save the diff instance help in the exception in `self.diffs`.
                    self.diffs.append(restart.diff)
                    self._log_new_diff(self.diffs[-1])

                    # Rebuild the expected packet from `initial_expected` (fixed to take into account approximate values).
                    self._debug("Rebuilding expected from initial expected %r", self._initial_expected)
                    b = self._initial_expected.build()  # type: bytes
                    self._debug(f"=> %r", b.hex())
                    self.expected = type(self._initial_expected)(b)
                    self._debug("self.expected=%r", self.expected)

                    # Then let the `while True:` loop continue.
                    continue

        # For each diff in `self.diffs`, log successes and errors as applicable, and save errors in `self.errors`.
        for diff in self.diffs:  # type: PacketCmp.Diff
            if diff.error_message:
                if log_error_level is not None:
                    log_runtime.log(log_error_level, str(diff))
                self.errors.append(diff)
            else:
                if log_success_level is not None:
                    log_runtime.log(log_success_level, str(diff))

        return not self.errors

    def _compare_fields(
            self,
            item_name,  # type: str
            compared,  # type: PacketCmp._FieldInfo
            expected,  # type: PacketCmp._FieldInfo
            initial_expected,  # type: PacketCmp._FieldInfo
    ):  # type: (...) -> Sequence[PacketCmp.Diff]
        """
        Field comparison.

        Recursive in case of list fields.

        :param item_name:
            Item name, i.e. field name with identifier prefix, or index suffix in case of lists.
        :param compared:
            Field info for the compared field.
        :param expected:
            Field info for the expected field.
        :param initial_expected:
            Field info for the initial expected field.
        :return:
            Sequence of :class:`PacketCmp.Diff`.
            Single item for simple fields.
            Several items for list or packet fields.
        :raises PacketCmp._RestartCompareException:
            In case an approximate field matched but not exactly, and therefore auto fields must be recomputed.
        """
        self._debug(f"PacketCmp[%s]._compare_fields(item_name=%r, compared=%r, expected=%r, initial_expected=%r)",
                    self.expected.name, item_name, compared, expected, initial_expected)

        # Check field definitions: same layers <=> same field desc instances.
        if compared.desc is not expected.desc:
            diff = PacketCmp.Diff(
                item_name,
                self.compared, self._FieldInfo(name=item_name, desc=None, value=compared.desc),
                self.expected, self._FieldInfo(name=item_name, desc=None, value=expected.desc),
                "Mismatching field definitions",
            )
            self._log_new_diff(diff)
            return [diff]
        self._check_expected_consistency(
            item_name, expected, initial_expected,
            initial_expected.desc is expected.desc,
        )
        # Check field types.
        compared_type = type(compared.value)  # type: type
        expected_type = type(expected.value)  # type: type
        if compared_type != expected_type:
            diff = PacketCmp.Diff(
                item_name,
                self.compared, self._FieldInfo(name=item_name, desc=None, value=compared_type),
                self.expected, self._FieldInfo(name=item_name, desc=None, value=expected_type),
                "Mismatching types",
            )
            self._log_new_diff(diff)
            return [diff]
        # Same field definitions, value types should be consistent.
        # Don't make the verification below, since it's sometimes wrong for auto fields.
        # assert type(initial_expected.value) is expected_type

        # Approximate fields (works with any kind of field).
        if isinstance(compared.desc, ApproximateField) and isinstance(expected.desc, ApproximateField):
            self._debug("Comparing approximate fields %r (compared) with %r (expected)", compared.value, expected.value)
            delta = abs(compared.desc.fld2float(compared.value) - expected.desc.fld2float(expected.value))  # type: float
            self._debug("=> delta=%r", delta)
            if delta == 0.0:
                # Strict equality.
                diff = PacketCmp.Diff(
                    item_name,
                    self.compared, compared,
                    self.expected, expected,
                    error_message="",
                )
                self._log_new_diff(diff)
                return [diff]
            elif abs(delta) <= compared.desc.tolerance:
                # Because of auto fields (like CRC basically), replace expected with compared value, then restart the comparison.
                # Install a copy of the compared value, in case we are working with non-base types (packet fields for instance).
                clone = copy.deepcopy(compared.value)  # type: Any
                self._debug("Copying %r => %r", compared.value, clone)
                self._debug("Installing the copy as %r.%s", self._initial_expected, compared.desc.name)
                setattr(self._initial_expected, compared.desc.name, clone)
                raise self._RestartCompareException(PacketCmp.Diff(
                    item_name,
                    self.compared, compared,
                    self.expected, expected,
                    error_message="",
                    delta=delta, tolerance=compared.desc.tolerance,
                ))
            else:
                # Error.
                diff = PacketCmp.Diff(
                    item_name,
                    self.compared, compared,
                    self.expected, expected,
                    error_message="Mismatching values",
                    delta=delta, tolerance=compared.desc.tolerance,
                )
                self._log_new_diff(diff)
                return [diff]

        # Packet fields => recursive call to `PacketCmp.compare()`.
        elif isinstance(compared.value, Packet) and isinstance(expected.value, Packet):
            field_path = (
                f"{self.field_path}.{expected.name}" if self.field_path
                else f"{self.expected.name}.{expected.name}"
            )  # type: str

            # Memo:
            #   Packet fields should always be set with packets
            #   Nevertheless, when set with `bytes`, automatically parse the buffer with the appropriate packet class.
            initial_expected = initial_expected.value  # type: Union[Packet, bytes]
            if isinstance(initial_expected, bytes):
                fixed = type(expected.value)(initial_expected)  # type: Packet
                log_runtime.warning(
                    f"{field_path}: Packet field badly set with buffer {initial_expected!r}, "
                    f"fixed as {fixed!r}"
                )
                initial_expected = fixed

            # Prepare a `PacketCmp` instance for recursion.
            cmp = PacketCmp(
                compared.value, expected.value,
                field_path=field_path,
                rebuild_expected=False,
                initial_expected=initial_expected,
                debug_logging_level=self._debug_logging_level,
            )

            try:
                with self._debug_indentation_ctx():
                    cmp.compare(
                        # No final logging for recursion `PacketCmp` instances.
                        log_success_level=None,
                        log_error_level=None,
                    )
            except PacketCmp._RestartCompareException as restart:
                # Prefix the item name with `item_name` for the current layer,
                # then let the `compare()` method do its job.
                raise self._RestartCompareException(PacketCmp.Diff(
                    f"{item_name}.{restart.diff.item}",
                    self.compared, restart.diff.compared_info,
                    self.expected, restart.diff.expected_info,
                    error_message=restart.diff.error_message,
                    delta=restart.diff.delta, tolerance=restart.diff.tolerance,
                ))

            # Return the resulting diffs with item names prefixed with `item_name` for the current layer.
            return [
                PacketCmp.Diff(
                    f"{item_name}.{diff.item}",
                    self.compared, diff.compared_info,
                    self.expected, diff.expected_info,
                    error_message=diff.error_message,
                    delta=diff.delta, tolerance=diff.tolerance,
                )
                for diff in cmp.diffs
            ]

        # Lists => N recursive calls to `_compare_fields()` for each item.
        elif isinstance(compared.value, list) and isinstance(expected.value, list):
            # In case of list fields, field definitions should normally be set.
            assert compared.desc
            assert expected.desc
            assert initial_expected.desc

            list_diffs = []  # type: List[PacketCmp.Diff]

            # Check list lengths (don't break if lengths mismatch).
            compared_len = len(compared.value)  # type: int
            expected_len = len(expected.value)  # type: int
            if compared_len != expected_len:
                list_diffs.append(PacketCmp.Diff(
                    item_name,
                    self.compared, self._FieldInfo(name=item_name, desc=None, value=compared_len),
                    self.expected, self._FieldInfo(name=item_name, desc=None, value=expected_len),
                    "Mismatching lengths",
                ))
                self._log_new_diff(list_diffs[-1])
            self._check_expected_consistency(
                item_name, expected.value, initial_expected.value,
                len(initial_expected.value) == expected_len,
            )

            # Compare items till end the shortest list.
            for index in range(min(compared_len, expected_len)):  # type: int
                with self._debug_indentation_ctx():
                    list_diffs.extend(self._compare_fields(
                        item_name=f"{item_name}[{index}]",  # Add suffix with item index.
                        compared=self._FieldInfo(name=compared.desc.name, desc=compared.desc, value=compared.value[index]),
                        expected=self._FieldInfo(name=expected.desc.name, desc=expected.desc, value=expected.value[index]),
                        initial_expected=self._FieldInfo(name=initial_expected.desc.name, desc=initial_expected.desc, value=initial_expected.value[index]),
                    ))

            return list_diffs

        # Simple values.
        else:
            # Case-insensitive comparison for Ethernet MAC addresses.
            if isinstance(self.compared, Ether) and compared.desc and (compared.desc.name in ["dst", "src"]):
                compared.value = compared.value.lower()
                expected.value = expected.value.lower()

            diff = PacketCmp.Diff(
                item_name,
                self.compared, compared,
                self.expected, expected,
                error_message=(
                    "" if (compared.value == expected.value)
                    else "Mismatching values"
                ),
            )
            self._log_new_diff(diff)
            return [diff]

    class _FieldInfo:
        """
        Data class that describes field information as returned by :meth:`PacketCmp._get_fields_info()`.

        .. note:: Module ``dataclass`` not used for Python 2 compatibility.
        """

        def __init__(
                self,
                *,
                name,  # type: str
                desc,  # type: Optional[AnyField]
                value,  # type: Any
        ):  # type: (...) -> None
            #: Field name.
            #: Set to 'payload' for payloads.
            self.name = name  # type: str

            #: Field definition, as set in the ``fields_desc`` list for a given layer.
            #: May be ``None`` for payloads.
            self.desc = desc  # type: Optional[AnyField]

            #: Field value.
            #: May be of any type,
            #: consistent with :attr:`field_def`,
            #: or a packet for payloads.
            self.value = value  # type: Any

    @classmethod
    def _get_fields_info(
            cls,
            pkt,  # type: Packet
            *,
            with_payload=False,  # type: bool
            packet_fields_only=False,  # type: bool
    ):  # type: (...) -> Sequence[PacketCmp._FieldInfo]
        """
        :param pkt: Packet to list fields information for.
        :param with_payload: ``True`` to include a :class:`PacketCmp._FieldInfo` for the payload if any.
        :param packet_fields_only: ``True`` to get packet fields only.
        :return: Ordered sequence of :class:`PacketCmp._FieldInfo`.
        """
        fields_info = []  # type: List[PacketCmp._FieldInfo]

        for field_desc in pkt.fields_desc:  # type: AnyField
            if packet_fields_only:
                # Container fields => check final field definition.
                final_field_def = field_desc  # type: AnyField
                while isinstance(final_field_def, _FieldContainer):
                    final_field_def = final_field_def.fld

                # Skip non packet field definitions.
                if not isinstance(final_field_def, _PacketField):
                    continue

            fields_info.append(cls._FieldInfo(
                name=field_desc.name,
                desc=field_desc,
                value=getattr(pkt, field_desc.name),
            ))

        if with_payload and pkt.payload:
            fields_info.append(cls._FieldInfo(
                name="payload",
                desc=None,
                value=pkt.payload,
            ))

        return fields_info

    class Diff:
        """
        Saves diff information.

        Error if :attr:`error_message` is not empty.
        """

        def __init__(
                self,
                item,  # type: str
                compared_pkt,  # type: Packet
                compared_info,  # type: PacketCmp._FieldInfo
                expected_pkt,  # type: Packet
                expected_info,  # type: PacketCmp._FieldInfo
                error_message,  # type: str
                *,
                delta=None,  # type: Optional[float]
                tolerance=None,  # type: Optional[float]
        ):  # type: (...) -> None
            #: Compared item description: generally a field name.
            self.item = item  # type: str
            #: Compared packet.
            self.compared_pkt = compared_pkt  # type: Packet
            #: Compared field info.
            self.compared_info = compared_info  # type: PacketCmp._FieldInfo
            #: Expected packet.
            self.expected_pkt = expected_pkt  # type: Packet
            #: Expected field info.
            self.expected_info = expected_info  # type: PacketCmp._FieldInfo
            #: Error message.
            #: No error when empty.
            self.error_message = error_message  # type: str
            #: Optional delta.
            self.delta = delta  # type: Optional[float]
            #: Optional tolerance.
            self.tolerance = tolerance  # type: Optional[float]

        def __repr__(self):  # type: () -> str
            """
            `Official` string representation.
            """
            # Rely on `__str__()` for *repr*.
            return f"<PacketCmp.Diff {str(self)!r}>"

        def __str__(self):  # type: () -> str
            """
            `Informal` string representation.
            """
            # Item description.
            s = f"{type(self.compared_pkt).__name__}"  # type: str
            if not isinstance(self.expected_pkt, type(self.compared_pkt)):
                s += f"/{type(self.expected_pkt).__name__}"
            s += f".{self.item}: "

            # Compared value.
            try:
                assert self.compared_info.desc
                s += self.compared_info.desc.i2repr(self.compared_pkt, self.compared_info.value)
            except:  # noqa
                s += repr(self.compared_info.value)
            s += " (compared)"

            # Comparison operator.
            if self.error_message:
                if (self.delta is not None) and (self.tolerance is not None):
                    s += f" != (delta: {self.delta!r} > tolerance: {self.tolerance!r}) "
                else:
                    s += " != "
            else:
                if (self.delta is not None) and (self.tolerance is not None):
                    s += f" ~= (delta: {self.delta!r} <= tolerance: {self.tolerance!r}) "
                else:
                    s += " == "

            # Expected value.
            try:
                assert self.expected_info.desc
                s += self.expected_info.desc.i2repr(self.expected_pkt, self.expected_info.value)
            except:  # noqa
                s += repr(self.expected_info.value)
            s += " (expected)"

            # Error message.
            if self.error_message:
                s += f" -- {self.error_message}"
            elif (self.delta is not None) and (self.tolerance is not None):
                s += " -- comparison restarted"

            return s

    def _log_new_diff(self, diff):  # type: (PacketCmp.Diff) -> None
        """
        Logs a new diff object.

        Uses :meth:`_debug()` for the purpose.
        """
        if self._debug_logging_level is not None:
            self._debug("New diff: %s", diff)

    class _RestartCompareException(Exception):
        """
        Holds a :class:`PacketCmp.Diff` object (normally an approximate diff)
        to be pushed in :attr:`PacketCmp.diffs` by the root :meth:`PacketCmp.compare()` call of recursion.
        """

        def __init__(
                self,
                diff,  # type: PacketCmp.Diff
        ):  # type: (...) -> None
            self.diff = diff

    @staticmethod
    def _check_expected_consistency(
            item_name,  # type: str
            expected_value,  # type: Any
            initial_expected_value,  # type: Any
            good,  # type: bool
    ):  # type: (...) -> None
        """
        Checks consistency between :attr:`expected` and :attr:`initial_expected` data.

        Defensive method: ``good`` should normally be ``True``.

        If ``good`` is ``False``:

        - shows detailed information for analysis,
        - raises an error.
        """
        if not good:
            # Situation that should not happen, but it happens! especially when Scapy packets are not correctly wired.
            # In case something went wrong, display useful information to ease debugging.
            log_runtime.log(logging.ERROR, f"{item_name}: Error between PacketCmp.<expected> versus <initial_expected>")
            log_runtime.log(logging.ERROR, f"          Expected: {expected_value!r}")
            log_runtime.log(logging.ERROR, f"  Initial expected: {initial_expected_value!r}")
            log_runtime.log(logging.ERROR, "Please check possible Scapy parsing errors")
            raise RuntimeError("scapy.PacketCmp internal error")

    def _debug_indentation_ctx(self):  # type: (...) -> ContextManager[None]
        """
        Builds a debug indentation context.

        Used in a ``with`` instruction, pushes indentation on `__enter__()`, then pulls it on `__exit__()`.
        """
        this = self  # type: PacketCmp

        class DebugIndentationContext:
            def __enter__(self):
                this._debug_indentation += "  "  # noqa  ## Access to protected member

            def __exit__(self, exc_type, exc_val, exc_tb):
                this._debug_indentation = this._debug_indentation[:-2]  # noqa  ## Access to protected member

        return DebugIndentationContext()

    def _debug(
            self,
            message,  # type: str
            *args,  # type: Any
    ):  # type: (...) -> None
        """
        Logs a debug message, taking into account :attr:`_debug_logging_level` and :attr:`_debug_indentation`.
        """
        if self._debug_logging_level is not None:
            log_runtime.log(self._debug_logging_level, self._debug_indentation + message, *args)
