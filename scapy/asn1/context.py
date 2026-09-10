# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""ASN.1 encoder and decoder contexts."""

from typing import Any, List

from scapy.asn1.asn1 import (
    ASN1_Class_UNIVERSAL,
    ASN1_Codecs,
    ASN1_Error,
    ASN1_Object,
)


class ASN1Encoder(object):
    codec = None  # type: Any

    def finish(self):
        # type: () -> bytes
        raise NotImplementedError


class ASN1Decoder(object):
    codec = None  # type: Any

    def remaining(self):
        # type: () -> bytes
        raise NotImplementedError

    def decode_sequence_children(self, field, pkt, presence, dissect):
        # type: (Any, Any, List[bool], Any) -> None
        from scapy.asn1fields import ASN1F_badsequence, ASN1F_optional

        opt_index = 0
        for obj in field.seq:
            if isinstance(obj, ASN1F_optional):
                if not presence[opt_index]:
                    obj.set_missing(pkt)
                    opt_index += 1
                    continue
                opt_index += 1
            try:
                dissect(obj)
            except ASN1F_badsequence:
                break


class BER_Encoder(ASN1Encoder):
    codec = ASN1_Codecs.BER

    def __init__(self, codec=None):
        # type: (Any) -> None
        self.codec = codec or self.codec
        self._parts = []  # type: list[bytes]

    def write(self, data):
        # type: (bytes) -> None
        self._parts.append(data)

    def finish(self):
        # type: () -> bytes
        return b"".join(self._parts)

    def encode_sequence(self, field, pkt):
        # type: (Any, Any) -> None
        # Byte-oriented codecs call the public child build() so subclasses
        # that override it stay on the encoding path.
        s = b"".join(obj.build(pkt) for obj in field.seq)
        self.write(field.i2m(pkt, s))

    def encode_sequence_of(self, field, pkt):
        # type: (Any, Any) -> None
        val = getattr(pkt, field.name)
        if isinstance(val, ASN1_Object) and val.tag == ASN1_Class_UNIVERSAL.RAW:
            s = val  # type: Any
        elif val is None:
            s = b""
        elif field.holds_packets:
            s = b"".join(bytes(i) for i in val)
        else:
            s = b"".join(field.fld.i2m(pkt, i) for i in val)
        self.write(field.i2m(pkt, s))

    def encode_choice(self, field, pkt, value=None):
        # type: (Any, Any, Any) -> None
        if value is None:
            value = getattr(pkt, field.name)
        if value is None:
            s = b""
        else:
            if isinstance(value, ASN1_Object):
                s = value.enc(pkt.ASN1_codec)
            else:
                s = bytes(value)
            if type(value) in field.pktchoices:
                imp, exp = field.pktchoices[type(value)]
                s = field._tagging_enc(pkt, s, implicit_tag=imp, explicit_tag=exp)
        _imp, exp = field._tagging_tags(pkt)
        self.write(field._tagging_enc(pkt, s, explicit_tag=exp))

    def encode_packet(self, field, pkt, value=None):
        # type: (Any, Any, Any) -> None
        if value is None:
            value = getattr(pkt, field.name)
        if value is None:
            s = b""
        elif isinstance(value, bytes):
            s = value
        elif isinstance(value, ASN1_Object):
            s = bytes(value.val) if value.val else b""
        else:
            s = bytes(value)
            from scapy.asn1packet import ASN1_Packet as _ASN1_Packet
            if not isinstance(value, _ASN1_Packet):
                self.write(s)
                return
        imp, exp = field._tagging_tags(pkt)
        self.write(field._tagging_enc(pkt, s, implicit_tag=imp, explicit_tag=exp))


class BER_Decoder(ASN1Decoder):
    codec = ASN1_Codecs.BER

    def __init__(self, data, codec=None):
        # type: (bytes, Any) -> None
        self.codec = codec or self.codec
        self._data = data

    def remaining(self):
        # type: () -> bytes
        return self._data

    def set_remainder(self, remainder):
        # type: (bytes) -> None
        self._data = remainder

    def decode_sequence(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.ber import BER_Decoding_Error
        from scapy.asn1fields import (
            ASN1F_DEFAULT,
            ASN1F_badsequence,
            ASN1F_optional,
        )

        s = self.remaining()
        s = field._apply_tagging_dec(s, pkt, _fname=pkt.name)
        codec = field.ASN1_tag.get_codec(ASN1_Codecs.BER)
        _i, s, remain = codec.check_type_check_len(s)

        def set_absent(obj):
            # type: (Any) -> None
            if isinstance(obj, (ASN1F_optional, ASN1F_DEFAULT)):
                obj.set_missing(pkt)
            else:
                obj.set_val(pkt, None)

        if len(s) == 0:
            for obj in field.seq:
                set_absent(obj)
        else:
            for idx, obj in enumerate(field.seq):
                try:
                    s = obj.dissect(pkt, s)
                except ASN1F_badsequence:
                    for absent in field.seq[idx:]:
                        set_absent(absent)
                    break
            if len(s) > 0:
                raise BER_Decoding_Error(
                    "unexpected remainder in %s" % pkt.name,
                    remaining=s,
                )
        self.set_remainder(remain)

    def decode_sequence_of(self, field, pkt):
        # type: (Any, Any) -> None
        s = self.remaining()
        s = field._apply_tagging_dec(s, pkt)
        codec = field.ASN1_tag.get_codec(ASN1_Codecs.BER)
        _i, s, remain = codec.check_type_check_len(s)
        lst = []
        while s:
            c, s = field._extract_packet(s, pkt)
            if c:
                lst.append(c)
        field.set_val(pkt, lst)
        self.set_remainder(remain)

    def decode_choice(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.ber import BER_id_dec
        from scapy.asn1fields import ASN1F_field

        s = self.remaining()
        if len(s) == 0:
            raise ASN1_Error("ASN1F_CHOICE: got empty string")
        s = field._apply_tagging_dec(s, pkt)
        tag, _ = BER_id_dec(s)
        if tag in field.choices:
            choice = field.choices[tag]
        elif field.flexible_tag:
            choice = ASN1F_field
        else:
            raise ASN1_Error(
                "ASN1F_CHOICE: unexpected field in '%s' "
                "(tag %s not in possible tags %s)" % (
                    field.name, tag, list(field.choices.keys())
                )
            )
        if hasattr(choice, "ASN1_root"):
            val, remain = field.extract_packet(
                choice, s, _underlayer=pkt, _parent=pkt,
            )
        elif isinstance(choice, type):
            val, remain = choice(field.name, b"").m2i(pkt, s)
        else:
            val, remain = choice.m2i(pkt, s)
        field.set_val(pkt, val)
        self.set_remainder(remain)

    def decode_packet(self, field, pkt):
        # type: (Any, Any) -> None
        cls = (field.next_cls_cb(pkt) or field.cls) if field.next_cls_cb else field.cls
        from scapy.asn1packet import ASN1_Packet as _ASN1_Packet
        s = self.remaining()
        if not issubclass(cls, _ASN1_Packet):
            val, remain = field.extract_packet(
                cls, s, _underlayer=pkt, _parent=pkt,
            )
            field.set_val(pkt, val)
            self.set_remainder(remain)
            return
        s = field._apply_tagging_dec(
            s, pkt,
            hidden_tag=cls.ASN1_root.ASN1_tag,
            _fname=field.name,
        )
        if not s:
            field.set_val(pkt, None)
            self.set_remainder(s)
            return
        val, remain = field.extract_packet(cls, s, _underlayer=pkt, _parent=pkt)
        field.set_val(pkt, val)
        self.set_remainder(remain)


class OER_Encoder(ASN1Encoder):
    codec = ASN1_Codecs.OER

    def __init__(self, codec=None):
        # type: (Any) -> None
        self.codec = codec or self.codec
        self._parts = []  # type: list[bytes]

    def write(self, data):
        # type: (bytes) -> None
        self._parts.append(data)

    def finish(self):
        # type: () -> bytes
        return b"".join(self._parts)

    def encode_packet(self, field, pkt, value=None):
        # type: (Any, Any, Any) -> None
        if value is None:
            value = getattr(pkt, field.name)
        if value is None:
            s = b""
        elif isinstance(value, bytes):
            s = value
        elif isinstance(value, ASN1_Object):
            s = bytes(value.val) if value.val else b""
        else:
            s = bytes(value)
            from scapy.asn1packet import ASN1_Packet as _ASN1_Packet
            if not isinstance(value, _ASN1_Packet):
                self.write(s)
                return
        imp, exp = field._tagging_tags(pkt)
        self.write(field._tagging_enc(pkt, s, implicit_tag=imp, explicit_tag=exp))

    def encode_sequence(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.oer import OER_Encoding_Error
        from scapy.asn1fields import ASN1F_SET, ASN1F_optional

        if isinstance(field, ASN1F_SET):
            raise OER_Encoding_Error("ASN1F_SET is not supported")
        bits = [0] if field.constraints.extensible else []  # type: List[int]
        bits += [1 if opt.is_present(pkt) else 0 for opt in field.optionals]
        if bits:
            number_of_bytes = (len(bits) + 7) // 8
            value = 0
            for bit in bits:
                value = (value << 1) | bit
            value <<= 8 * number_of_bytes - len(bits)
            self.write(value.to_bytes(number_of_bytes, "big"))
        for obj in field.seq:
            if isinstance(obj, ASN1F_optional) and not obj.is_present(pkt):
                continue
            obj.encode_to(pkt, self)

    def encode_sequence_of(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.oer import OER_Encoding_Error, OER_unsigned_integer_enc
        from scapy.asn1fields import ASN1F_SET_OF

        if isinstance(field, ASN1F_SET_OF):
            raise OER_Encoding_Error("ASN1F_SET_OF is not supported")
        val = getattr(pkt, field.name)
        if isinstance(val, ASN1_Object) and val.tag == ASN1_Class_UNIVERSAL.RAW:
            self.write(field.i2m(pkt, val))
            return
        items = val or []
        parts = [OER_unsigned_integer_enc(len(items))]
        parts.extend(
            bytes(item) if field.holds_packets else field.fld.i2m(pkt, item)
            for item in items
        )
        self.write(field.i2m(pkt, b"".join(parts)))

    def encode_choice(self, field, pkt, value=None):
        # type: (Any, Any, Any) -> None
        from scapy.asn1.oer import OER_tag_enc, OER_tag_parts

        if value is None:
            value = getattr(pkt, field.name)
        if value is None:
            s = b""
        else:
            if isinstance(value, ASN1_Object):
                s = value.enc(pkt.ASN1_codec)
            else:
                s = bytes(value)
            tag = field.alternative_tag(value)
            if tag is not None:
                tag_class, tag_number = OER_tag_parts(tag)
                s = OER_tag_enc(tag_number, tag_class) + s
        self.write(field._tagging_enc(pkt, s, explicit_tag=field.explicit_tag))


class OER_Decoder(ASN1Decoder):
    codec = ASN1_Codecs.OER

    def __init__(self, data, codec=None):
        # type: (bytes, Any) -> None
        self.codec = codec or self.codec
        self._data = data

    def remaining(self):
        # type: () -> bytes
        return self._data

    def set_remainder(self, remainder):
        # type: (bytes) -> None
        self._data = remainder

    def decode_packet(self, field, pkt):
        # type: (Any, Any) -> None
        cls = (field.next_cls_cb(pkt) or field.cls) if field.next_cls_cb else field.cls
        from scapy.asn1packet import ASN1_Packet as _ASN1_Packet
        s = self.remaining()
        if not issubclass(cls, _ASN1_Packet):
            val, remain = field.extract_packet(
                cls, s, _underlayer=pkt, _parent=pkt,
            )
            field.set_val(pkt, val)
            self.set_remainder(remain)
            return
        s = field._apply_tagging_dec(
            s, pkt,
            hidden_tag=cls.ASN1_root.ASN1_tag,
            _fname=field.name,
        )
        if not s:
            field.set_val(pkt, None)
            self.set_remainder(s)
            return
        val, remain = field.extract_packet(cls, s, _underlayer=pkt, _parent=pkt)
        field.set_val(pkt, val)
        self.set_remainder(remain)

    def decode_sequence(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.oer import OER_Decoding_Error, _OER_check_len
        from scapy.asn1fields import ASN1F_SET

        if isinstance(field, ASN1F_SET):
            raise OER_Decoding_Error("ASN1F_SET is not supported")
        s = self.remaining()
        s = field._apply_tagging_dec(s, pkt, _fname=pkt.name)
        number_of_optionals = len(field.optionals)
        number_of_bits = (
            (1 if field.constraints.extensible else 0) + number_of_optionals
        )
        if number_of_bits == 0:
            presence = []  # type: List[bool]
        else:
            number_of_bytes = (number_of_bits + 7) // 8
            _OER_check_len("ASN1F_SEQUENCE", s, number_of_bytes)
            value = int.from_bytes(s[:number_of_bytes], "big")
            bits = [
                bool((value >> (8 * number_of_bytes - 1 - i)) & 1)
                for i in range(number_of_bits)
            ]
            if field.constraints.extensible:
                if bits[0]:
                    raise OER_Decoding_Error(
                        "ASN1F_SEQUENCE: extension additions are not supported",
                        remaining=s,
                    )
                bits = bits[1:]
            presence = bits
            s = s[number_of_bytes:]
        child_dec = type(self)(s)
        self.decode_sequence_children(
            field, pkt, presence,
            lambda obj: obj.decode_from(pkt, child_dec),
        )
        self.set_remainder(child_dec.remaining())

    def decode_sequence_of(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.oer import OER_Decoding_Error, OER_unsigned_integer_dec
        from scapy.asn1fields import ASN1F_SET_OF

        if isinstance(field, ASN1F_SET_OF):
            raise OER_Decoding_Error("ASN1F_SET_OF is not supported")
        s = field._apply_tagging_dec(self.remaining(), pkt)
        count, s = OER_unsigned_integer_dec(s)
        lst = []
        for _ in range(count):
            c, s = field._extract_packet(s, pkt)
            if c:
                lst.append(c)
        field.set_val(pkt, lst)
        self.set_remainder(s)

    def decode_choice(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1fields import ASN1F_field
        from scapy.asn1.oer import OER_tag_dec, OER_tag_parts

        s = field._apply_tagging_dec(self.remaining(), pkt)
        tag_class, tag_number, payload = OER_tag_dec(s)
        choice = None
        for key, alternative in field.choices.items():
            if OER_tag_parts(key) == (tag_class, tag_number):
                choice = alternative
                break
        if choice is None:
            if not field.flexible_tag:
                raise ASN1_Error(
                    "ASN1F_CHOICE: unexpected field in '%s' "
                    "(tag %s not in possible tags %s)" % (
                        field.name, tag_class | tag_number,
                        list(field.choices.keys())
                    )
                )
            choice = ASN1F_field
        if hasattr(choice, "ASN1_root"):
            val, remain = field.extract_packet(
                choice, payload, _underlayer=pkt, _parent=pkt,
            )
        elif isinstance(choice, type):
            val, remain = choice(field.name, b"").m2i(pkt, payload)
        else:
            cls = (
                (choice.next_cls_cb(pkt) or choice.cls)
                if choice.next_cls_cb else choice.cls
            )
            val, remain = field.extract_packet(
                cls, payload, _underlayer=pkt, _parent=pkt,
            )
        field.set_val(pkt, val)
        self.set_remainder(remain)


class UPER_EncoderContext(ASN1Encoder):
    codec = ASN1_Codecs.PER

    def __init__(self):
        # type: () -> None
        # Lazy: keep BER/OER paths from importing scapy.asn1.uper.
        from scapy.asn1.uper import UPER_Encoder
        self.bit_encoder = UPER_Encoder()

    def finish(self):
        # type: () -> bytes
        return self.bit_encoder.as_bytes()

    def encode_sequence(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.uper import UPER_Encoding_Error
        from scapy.asn1fields import ASN1F_SET, ASN1F_optional

        if isinstance(field, ASN1F_SET):
            raise UPER_Encoding_Error("ASN1F_SET is not supported")
        bit_enc = self.bit_encoder
        if field.constraints.extensible:
            bit_enc.append_bit(0)
        for opt in field.optionals:
            bit_enc.append_bit(1 if opt.is_present(pkt) else 0)
        for obj in field.seq:
            if isinstance(obj, ASN1F_optional) and not obj.is_present(pkt):
                continue
            obj.encode_to(pkt, self)

    def encode_sequence_of(self, field, pkt, value=None):
        # type: (Any, Any, Any) -> None
        from scapy.asn1.uper import (
            UPER_Encoding_Error,
            UPER_constrained_int_enc,
            uper_uses_constrained_length,
        )
        from scapy.asn1fields import (
            ASN1F_CHOICE,
            ASN1F_PACKET,
            ASN1F_SEQUENCE,
            ASN1F_SEQUENCE_OF,
            ASN1F_SET_OF,
        )

        if isinstance(field, ASN1F_SET_OF):
            raise UPER_Encoding_Error("ASN1F_SET_OF is not supported")

        if (
                not field.holds_packets and
                isinstance(field.fld, (ASN1F_SEQUENCE, ASN1F_CHOICE, ASN1F_SEQUENCE_OF))
        ):
            raise UPER_Encoding_Error(
                "ASN1F_SEQUENCE_OF: compound ASN1F_field elements are not "
                "supported in UPER; use an ASN1_Packet for structured items"
            )

        bit_enc = self.bit_encoder
        if value is None:
            value = getattr(pkt, field.name)
        if value is None:
            value = []
        count = len(value)

        def append_items(offset, size):
            # type: (int, int) -> None
            for i in range(offset, offset + size):
                item = value[i]
                if field.holds_packets:
                    item.ASN1_root.encode_to(item, self)
                elif isinstance(field.fld, ASN1F_PACKET):
                    self.encode_packet(field.fld, pkt, item)
                else:
                    field.fld.encode_into(bit_enc, pkt, item)

        uper_min, uper_max = field.constraints.minimum, field.constraints.maximum
        if field.constraints.extensible:
            if (
                    uper_min is not None and uper_max is not None and
                    uper_min <= count <= uper_max
            ):
                bit_enc.append_bit(0)
            else:
                bit_enc.append_bit(1)
                bit_enc.append_fragmented(count, append_items)
                return
        if uper_uses_constrained_length(uper_min, uper_max):
            UPER_constrained_int_enc(bit_enc, count, uper_min, uper_max)
            append_items(0, count)
        else:
            bit_enc.append_fragmented(count, append_items)

    def encode_choice(self, field, pkt, value=None):
        # type: (Any, Any, Any) -> None
        from scapy.asn1.uper import UPER_choice_index_enc

        bit_enc = self.bit_encoder
        if value is None:
            value = getattr(pkt, field.name)
        if value is None:
            return
        tag = field.alternative_tag(value)
        if tag is None:
            raise ASN1_Error(
                "ASN1F_CHOICE: cannot encode unknown alternative in '%s'" %
                field.name
            )
        if field.constraints.extensible:
            bit_enc.append_bit(0)
        order = field.canonical_order
        canon_idx = field.canonical_index[tag]
        if len(order) > 1:
            UPER_choice_index_enc(bit_enc, canon_idx, len(order))
        choice = order[canon_idx]
        if isinstance(choice, type) and hasattr(choice, "ASN1_root"):
            value.ASN1_root.encode_to(value, self)
        elif hasattr(choice, "cls"):
            self.encode_packet(choice, pkt, value)
        elif isinstance(choice, type):
            choice(field.name, b"").encode_into(bit_enc, pkt, value)
        else:
            choice.encode_into(bit_enc, pkt, value)

    def encode_packet(self, field, pkt, value=None):
        # type: (Any, Any, Any) -> None
        if value is None:
            value = getattr(pkt, field.name)
        if value is None:
            return
        if isinstance(value, ASN1_Object):
            value = value.val
        value.ASN1_root.encode_to(value, self)


class UPER_DecoderContext(ASN1Decoder):
    codec = ASN1_Codecs.PER

    def __init__(self, data):
        # type: (bytes) -> None
        from scapy.asn1.uper import UPER_Decoder
        self.bit_decoder = UPER_Decoder(data)

    def remaining(self):
        # type: () -> bytes
        return self.bit_decoder.remaining_bytes()

    def decode_nested_packet(self, field, pkt):
        # type: (Any, Any) -> Any
        cls = (field.next_cls_cb(pkt) or field.cls) if field.next_cls_cb else field.cls
        p = cls()
        p.add_underlayer(pkt)
        p.add_parent(pkt)
        p.ASN1_root.decode_from(p, self)
        return p

    def decode_sequence(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.uper import UPER_Decoding_Error
        from scapy.asn1fields import ASN1F_SET

        if isinstance(field, ASN1F_SET):
            raise UPER_Decoding_Error("ASN1F_SET is not supported")
        bit_dec = self.bit_decoder
        if field.constraints.extensible:
            if bit_dec.read_bit():
                raise UPER_Decoding_Error(
                    "ASN1F_SEQUENCE: extension additions are not supported"
                )
        presence = [bit_dec.read_bit() for _ in field.optionals]
        self.decode_sequence_children(
            field, pkt, presence,
            lambda obj: obj.decode_from(pkt, self),
        )

    def decode_sequence_of(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.uper import (
            UPER_Decoding_Error,
            UPER_constrained_int_dec,
            uper_uses_constrained_length,
        )
        from scapy.asn1fields import (
            ASN1F_CHOICE,
            ASN1F_PACKET,
            ASN1F_SEQUENCE,
            ASN1F_SEQUENCE_OF,
            ASN1F_SET_OF,
        )

        if isinstance(field, ASN1F_SET_OF):
            raise UPER_Decoding_Error("ASN1F_SET_OF is not supported")
        if (
                not field.holds_packets and
                isinstance(field.fld, (ASN1F_SEQUENCE, ASN1F_CHOICE, ASN1F_SEQUENCE_OF))
        ):
            raise UPER_Decoding_Error(
                "ASN1F_SEQUENCE_OF: compound ASN1F_field elements are not "
                "supported in UPER; use an ASN1_Packet for structured items"
            )

        bit_dec = self.bit_decoder
        lst = []

        def read_items(count):
            # type: (int) -> None
            for _ in range(count):
                if field.holds_packets:
                    p = field.cls()
                    p.add_underlayer(pkt)
                    p.add_parent(pkt)
                    p.ASN1_root.decode_from(p, self)
                    lst.append(p)
                elif isinstance(field.fld, ASN1F_PACKET):
                    lst.append(self.decode_nested_packet(field.fld, pkt))
                else:
                    lst.append(field.fld.m2i_from_decoder(pkt, bit_dec))

        if field.constraints.extensible and bit_dec.read_bit():
            bit_dec.read_fragmented(read_items)
        else:
            uper_min, uper_max = field.constraints.minimum, field.constraints.maximum
            if uper_uses_constrained_length(uper_min, uper_max):
                read_items(UPER_constrained_int_dec(bit_dec, uper_min, uper_max))
            else:
                bit_dec.read_fragmented(read_items)
        field.set_val(pkt, lst)

    def decode_choice(self, field, pkt):
        # type: (Any, Any) -> None
        from scapy.asn1.uper import UPER_Decoding_Error, UPER_choice_index_dec

        bit_dec = self.bit_decoder
        if field.constraints.extensible:
            if bit_dec.read_bit():
                raise UPER_Decoding_Error(
                    "ASN1F_CHOICE: extension additions are not supported"
                )
        order = field.canonical_order
        if len(order) > 1:
            index = UPER_choice_index_dec(bit_dec, len(order))
        else:
            index = 0
        if index >= len(order):
            raise ASN1_Error(
                "ASN1F_CHOICE: unexpected index %s in '%s'" %
                (index, field.name)
            )
        choice = order[index]
        if isinstance(choice, type) and hasattr(choice, "ASN1_root"):
            p = choice()
            p.add_underlayer(pkt)
            p.add_parent(pkt)
            p.ASN1_root.decode_from(p, self)
            field.set_val(pkt, p)
            return
        if hasattr(choice, "cls"):
            field.set_val(pkt, self.decode_nested_packet(choice, pkt))
            return
        if isinstance(choice, type):
            field.set_val(
                pkt, choice(field.name, b"").m2i_from_decoder(pkt, bit_dec),
            )
            return
        field.set_val(pkt, choice.m2i_from_decoder(pkt, bit_dec))

    def decode_packet(self, field, pkt):
        # type: (Any, Any) -> None
        field.set_val(pkt, self.decode_nested_packet(field, pkt))


def new_encoder(codec):
    # type: (Any) -> ASN1Encoder
    if codec is ASN1_Codecs.PER:
        return UPER_EncoderContext()
    if codec is ASN1_Codecs.OER:
        return OER_Encoder()
    return BER_Encoder(codec=codec)


def new_decoder(codec, data):
    # type: (Any, bytes) -> ASN1Decoder
    if codec is ASN1_Codecs.PER:
        return UPER_DecoderContext(data)
    if codec is ASN1_Codecs.OER:
        return OER_Decoder(data)
    return BER_Decoder(data, codec=codec)
