import scapy.all
import scapy.volatile
import scapy.compat
import scapy.layers
import scapy.fields
import scapy.contrib.igmpv3

# def store_defaults_randbin(parent, obj):
#     """ This function fixes the RandBin fields, rand makes them into non-random RandString"""
#     defaults = {}
#     for (obj_name, obj_field) in obj.fields.items():
#         if obj_field is None and obj_name in dir(obj):
#             obj_field = getattr(obj, obj_name)

#         if obj_field is None:
#             continue

#         name = f"{parent}-{obj_name}"
#         defaults[name] = obj_field

#     for (obj_name, obj_field) in obj.default_fields.items():
#         if obj_field is None and obj_name in dir(obj):
#             obj_field = getattr(obj, obj_name)

#         if obj_field is None:
#             continue

#         name = f"{parent}-{obj_name}"
#         if name not in defaults:
#             # Don't override existing values
#             defaults[name] = obj_field

#     if obj.payload:
#         defaults |= store_defaults_randbin(obj.payload.name, obj.payload)

#     return defaults


# def fix_multipletype(obj):
#     new_fields_desc = []
#     for field_desc in obj.fields_desc:
#         if type(field_desc).__name__ == 'MultipleTypeField':
#             field_desc = field_desc.flds[0][0]
#         new_fields_desc.append(field_desc)

#     obj.fields_desc = new_fields_desc

#     new_fieldtype = {}
#     for fieldtype_name in obj.fieldtype:
#         fieldtype = obj.fieldtype[fieldtype_name]
#         if type(fieldtype).__name__ == 'MultipleTypeField':
#             fieldtype = fieldtype.flds[0][0]
#         new_fieldtype[fieldtype_name] = fieldtype

#     obj.fieldtype = new_fieldtype

#     if obj.payload:
#         fix_multipletype(obj.payload)


# packet_fuzz = scapy.all.Ether(dst='00:01:02:03:04:05')/scapy.all.ARP()

# packet_fuzz = scapy.all.ARP()

# packet_fuzz = scapy.all.Ether()/scapy.all.IP(dst='127.0.0.1')/scapy.all.ICMP(type=scapy.all.RandNum( min(scapy.all.ICMP.type.i2s), max(scapy.all.ICMP.type.i2s) ))

# data = scapy.compat.bytes_encode(packet_fuzz)

# if packet_fuzz.name == "ARP":
#     for field_name in ['psrc', 'pdst']:
#         INDEX = 0
#         for field_desc in packet_fuzz.fields_desc:
#             if field_desc.name == field_name:
#                 packet_fuzz.fields_desc[INDEX] = scapy.fields.IPField(field_name, '192.168.1.1')
#             INDEX += 1

#         packet_fuzz.fieldtype[field_name] = scapy.fields.IPField(field_name, '192.168.1.1')

#     for field_name in ['hwsrc', 'hwdst']:
#         INDEX = 0
#         for field_desc in packet_fuzz.fields_desc:
#             if field_desc.name == field_name:
#                 packet_fuzz.fields_desc[INDEX] = \
#                     scapy.fields.MACField(field_name, scapy.data.ETHER_BROADCAST)
#             INDEX += 1

#         packet_fuzz.fieldtype[field_name] = \
#             scapy.fields.MACField(field_name, scapy.data.ETHER_BROADCAST)


# # fix_multipletype(packet_fuzz)
# # default_values = store_defaults_randbin(packet_fuzz.name, packet_fuzz)
# packet_fuzz = scapy.all.fuzz(packet_fuzz)

# data = scapy.compat.bytes_encode(packet_fuzz)

# if packet_fuzz.name == "ARP":
#     hwsrc = f"{packet_fuzz.hwsrc}"

# # packet_fuzz = packet_fuzz.fix_RandBin_fields(packet_fuzz)

# # Check that it works (no exceptions)
# data = scapy.compat.bytes_encode(packet_fuzz)

# # Check the show works
# packet_fuzz.show()

# # Check that show2 works
# packet_fuzz.show2()

# states = packet_fuzz.prepare_combinations(2)

# print(f"{states=}")

# continue_to_fuzz = True
# iterations = 0
# while continue_to_fuzz:
#     (states, continue_to_fuzz) = packet_fuzz.forward(states)

#     try:
#         data = scapy.compat.bytes_encode(packet_fuzz)
#     except Exception as exception:
#         print(f"{exception=}")
#         continue
#     # print(f"{data=}")
#     iterations += 1
#     if iterations % 1000 == 0:
#         print(f"{iterations=}")


# print(f"{iterations=}")

from scapy.contrib.ppm import *

# p_test = scapy.layers.l2.Ether(type=2)
# packet_fuzz = scapy.packet.fuzz(p_test)
# states = packet_fuzz.prepare_combinations(2)
# continue_fuzzing = True
# iterator = 0
# while continue_fuzzing:
#     iterator += 1
#     data = scapy.compat.bytes_encode(packet_fuzz)
#     print(f"{data=}")
#     (states, continue_fuzzing) = packet_fuzz.forward(states)

p_header = PPM()# colors="255", height = "4", width = "3") 
p_header.get_field('height').default = b"4"
p_header.get_field('width').default = b"3"
p_header.get_field('colors').default = b"255"

p_test = p_header

p_triplet = PPMTriplet()
p_triplet.get_field("r").default = b"255"
p_triplet.get_field("g").default = b"255"
p_triplet.get_field("b").default = b"255"

p_test /= p_triplet

p_triplet = PPMTriplet()
p_triplet.get_field("r").default = b"0"
p_triplet.get_field("g").default = b"255"
p_triplet.get_field("b").default = b"255"

p_test /= p_triplet


p_triplet = PPMTriplet()
p_triplet.get_field("r").default = b"0"
p_triplet.get_field("g").default = b"0"
p_triplet.get_field("b").default = b"255"

p_test /= p_triplet

p_triplet = PPMTriplet()
p_triplet.get_field("r").default = b"0"
p_triplet.get_field("g").default = b"0"
p_triplet.get_field("b").default = b"0"

p_test /= p_triplet

p_test.show2()
a = bytes(p_test)
print(f"{a=}")

packet_fuzz = scapy.packet.fuzz(p_test)

a = bytes(packet_fuzz)
print(f"{a=}")

states = packet_fuzz.prepare_combinations(2)
continue_fuzzing = True
iterator = 0
while continue_fuzzing:
    iterator += 1
    if iterator % 1000 == 0:
        print(f"{iterator=}")
    data = scapy.compat.bytes_encode(packet_fuzz)
    # print(f"{data=}")
    (states, continue_fuzzing) = packet_fuzz.forward(states)

print(f"{iterator=}")
packet_fuzz.show()