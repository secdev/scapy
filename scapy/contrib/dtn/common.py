# scapy.contrib.description = utility functions and classes for DTN module
# scapy.contrib.status = library

from scapy.packet import Packet, Raw
from scapy.fields import Field
from typing import Dict, List


class NoPayloadPacket(Packet):
    """A packet with no payload layer to bind."""

    def extract_padding(self, s):
        return "", s


    def post_dissect(self, s):
        try:
            if self[Raw].load is not None:
                raise ValueError(f"found payload in {Packet} when none was expected")
        except IndexError:  # No Raw layer found, i.e. no unparsed payload is present
            pass
        return s


class ControlPacket(NoPayloadPacket):
    """A packet containing control data, rather than user data."""


class FieldPacket(NoPayloadPacket):
    """A packet intended for use as a field (i.e. PacketField or PacketListField)
    in another Packet, rather than one sent or received on the wire. Useful when you need
    heterogeneous, compound data similar to a record/struct within another Packet."""


FieldsTemplate = Dict[str, Field]


def template_replace(template: FieldsTemplate, new_values: FieldsTemplate) -> FieldsTemplate:
    return {**template, **new_values}


def make_fields_desc(template: FieldsTemplate) -> List[Field]:
    return list(template.values())
