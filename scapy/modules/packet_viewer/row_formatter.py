# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from collections import defaultdict
from itertools import count
from typing import Callable, Dict, List, Tuple, Optional, Any

from scapy.config import conf
from scapy.packet import Packet, Packet_metaclass

from scapy.modules.packet_viewer.column_configuration import payload_column, \
    repr_column


class RowFormatter(object):
    """
    Helper class for row formatting of Packet fields
    """
    def __init__(self, columns=None, basecls=None):
        # type: (Optional[List[Tuple[str, int, Callable[[Packet], str]]]], Optional[Packet_metaclass]) -> None  # noqa: E501
        """
        Initialize RowFormatter
        :param columns: List of column description tuples for
                        the generation of formatted rows
        :param basecls: Packet_metaclass for evaluation if a certain Packet
                        is supported by this formatter
        """
        self.basecls = basecls
        self.columns = columns or self.get_all_columns()
        self._format_string = self._create_format_string()
        self._time = -1.0  # type: float

        nr_messages = count()
        self._id_map = \
            defaultdict(lambda: next(nr_messages))  # type: Dict[int, int]
        '''
        holds the mapping of a packet (with its time as key) to the sequential
        number this ensures that a packet, even if "re-rendered", gets the same
        number again. This happens for example after editing a packet
        '''

    def is_pkt_supported(self, packet):
        # type: (Packet) -> bool
        """
        Evaluates if a packet is supported by this formatter
        :param packet: Input packet
        :return: True if supported
        """
        return self.basecls is None or isinstance(packet, self.basecls)

    def get_header_string(self):
        # type: () -> str
        """
        Based on the configured columns, this function returns a string for
        the header column.
        :return: Formatted string containing all column names
        """
        cols = {name: name.upper() for name, _, _ in self.columns}
        return self._format_string.format(**cols)

    def format(self, packet):
        # type: (Packet) -> str
        """
        Returns a formatted string containing all desired values of a packet
        :param packet: Packet containing all values
        :return: Formatted string containing all values formatted in columns
        """
        cols = {name: str(func(packet)) for name, _, func in self.columns}
        return self._format_string.format(**cols)

    def _create_format_string(self):
        # type: () -> str
        """
        Function to create a format string according to the configured columns
        :return:
        """
        format_string = ""
        for name, width, _ in self.columns[:-1]:
            format_string += \
                "{" + name + ":" + str(width) + "." + str(width) + "} "

        # Do not trim last column. Usually it's the data column
        # so allow it to be as long as necessary
        name = self.columns[-1][0]
        format_string += "{" + name + "}"
        return format_string

    def get_all_columns(self):
        # type: () -> List[Tuple[str, int, Callable[[Packet], str]]]  # noqa: E501
        """
        Depending if a basecls filter is configured, this function returns
        either a standard column configuration which uses the packets repr
        function, or a custom column configuration based on the basecls
        :return: A default or a basecls specific column configuration
        """
        if self.basecls is None:
            return self.get_default_columns() + repr_column

        config_columns = self.get_config_columns()

        if config_columns is not None and len(config_columns):
            return self.get_default_columns() + config_columns

        return self.get_default_columns() + self.fields_to_columns() + \
            payload_column

    def get_default_columns(self):
        # type: () -> List[Tuple[str, int, Callable[[Packet], str]]]
        """
        Return the default column configuration
        :return: The default column configuration
        """
        return [
            ("NO", 5, lambda p: str(self._id_map[id(p)])),
            ("TIME", 11, self.relative_time)
        ]

    def get_config_columns(self):
        # type: () -> List[Tuple[str, int, Callable[[Packet], str]]]
        """
        Return all columns from Scapys configuration dependent on the basecls
        :return: A columns configuration from
                 conf.contribs["packet_viewer_columns"] for the current basecls
                 if a configuration is present.
        """
        if self.basecls is None:
            return []
        try:
            config_dict = conf.contribs["packet_viewer_columns"]
            value = config_dict.get(self.basecls.__name__, [])  # type: List[Tuple[str, int, Callable[[Packet], str]]]  # noqa: E501
            return value
        except KeyError:
            return []

    def fields_to_columns(self, width=12):
        # type: (int) -> List[Tuple[str, int, Callable[[Any], str]]]
        """
        Returns a column configuration automatically deduced by the configured
        basecls. All fields of this Packet_metaclass will be returned
        :param width: The width of a field
        :return: A automatically generated column configuration
        """
        columns = []  # type: List[Tuple[str, int, Callable[[Any], str]]]
        if self.basecls is None:
            return columns

        for field_desc in self.basecls.fields_desc:
            # Instantiate a value for the field to check its type
            dummy_field_val = self.basecls().getfieldval(field_desc.name)
            # If byte, python adds quotation marks to the repr
            # bytes_to_repr removes it
            # We use repr() over str() because otherwise byte values
            # like 0x0a ('\n') would change the layout
            f_name = str(field_desc.name)
            if isinstance(dummy_field_val, bytes):
                def callback(p, f=f_name):
                    # type: (Packet, str) -> str
                    return self.text_to_repr(p, f)
            else:
                def callback(p, f=f_name):
                    # type: (Packet, str) -> str
                    return self.field_to_repr(p, f)

            columns.append((f_name, width, callback))
        return columns

    def relative_time(self, packet):
        # type: (Packet) -> str
        """
        Returns the relative time between the given packet and the first packet
        ever received.
        :param packet: Current Packet
        :return: Time difference between received and first Packet
        """
        if self._time == -1.0:
            self._time = packet.time
        return str(packet.time - self._time)

    @staticmethod
    def field_to_repr(p, name):
        # type: (Packet, str) -> str
        """
        Returns the value of a field
        :param p: Packet containing the value
        :param name: Field name of value to return
        :return: Value of field
        """
        repr_val = p.get_field(name).i2repr(p, p.getfieldval(name))
        return repr_val

    @staticmethod
    def text_to_repr(p, name):
        # type: (Packet, str) -> str
        """
        Returns the value of a field without quote symbols
        :param p: Packet containing the value
        :param name: Field name of value to return
        :return: Value of field
        """
        return RowFormatter.field_to_repr(p, name)[1:-1]
