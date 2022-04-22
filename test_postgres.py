from scapy.contrib.postgres import AuthenticationRequest, BasePacket, Startup, ErrorResponse

ssl_request = "\x00\x00\x00\x08\x04\xd2\x16\x2f"

startup = Startup(b"\x00\x00\x00\x57\x00\x03\x00\x00\x75\x73\x65\x72\x00\x70\x6f\x73" \
b"\x74\x67\x72\x65\x73\x00\x64\x61\x74\x61\x62\x61\x73\x65\x00\x70" \
b"\x6f\x73\x74\x67\x72\x65\x73\x00\x61\x70\x70\x6c\x69\x63\x61\x74" \
b"\x69\x6f\x6e\x5f\x6e\x61\x6d\x65\x00\x70\x73\x71\x6c\x00\x63\x6c" \
b"\x69\x65\x6e\x74\x5f\x65\x6e\x63\x6f\x64\x69\x6e\x67\x00\x57\x49" \
b"\x4e\x31\x32\x35\x32\x00\x00"
)

assert startup.length == 87
# TODO : Fix assert startup.protocol_version_major == 3, startup.options
assert startup.protocol_version_minor == 0x00
assert startup.options == b'user\x00postgres\x00database\x00postgres\x00application_name\x00psql\x00client_encoding\x00WIN1252\x00'

init_packet = b"\x52\x00\x00\x00\x08\x00\x00\x00\x00\x53\x00\x00\x00\x1a\x61\x70" \
b"\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x5f\x6e\x61\x6d\x65\x00\x70" \
b"\x73\x71\x6c\x00\x53\x00\x00\x00\x1c\x63\x6c\x69\x65\x6e\x74\x5f" \
b"\x65\x6e\x63\x6f\x64\x69\x6e\x67\x00\x57\x49\x4e\x31\x32\x35\x32" \
b"\x00\x53\x00\x00\x00\x17\x44\x61\x74\x65\x53\x74\x79\x6c\x65\x00" \
b"\x49\x53\x4f\x2c\x20\x4d\x44\x59\x00\x53\x00\x00\x00\x26\x64\x65" \
b"\x66\x61\x75\x6c\x74\x5f\x74\x72\x61\x6e\x73\x61\x63\x74\x69\x6f" \
b"\x6e\x5f\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x00\x6f\x66\x66\x00" \
b"\x53\x00\x00\x00\x17\x69\x6e\x5f\x68\x6f\x74\x5f\x73\x74\x61\x6e" \
b"\x64\x62\x79\x00\x6f\x66\x66\x00\x53\x00\x00\x00\x19\x69\x6e\x74" \
b"\x65\x67\x65\x72\x5f\x64\x61\x74\x65\x74\x69\x6d\x65\x73\x00\x6f" \
b"\x6e\x00\x53\x00\x00\x00\x1b\x49\x6e\x74\x65\x72\x76\x61\x6c\x53" \
b"\x74\x79\x6c\x65\x00\x70\x6f\x73\x74\x67\x72\x65\x73\x00\x53\x00" \
b"\x00\x00\x14\x69\x73\x5f\x73\x75\x70\x65\x72\x75\x73\x65\x72\x00" \
b"\x6f\x6e\x00\x53\x00\x00\x00\x19\x73\x65\x72\x76\x65\x72\x5f\x65" \
b"\x6e\x63\x6f\x64\x69\x6e\x67\x00\x55\x54\x46\x38\x00\x53\x00\x00" \
b"\x00\x32\x73\x65\x72\x76\x65\x72\x5f\x76\x65\x72\x73\x69\x6f\x6e" \
b"\x00\x31\x34\x2e\x32\x20\x28\x44\x65\x62\x69\x61\x6e\x20\x31\x34" \
b"\x2e\x32\x2d\x31\x2e\x70\x67\x64\x67\x31\x31\x30\x2b\x31\x29\x00" \
b"\x53\x00\x00\x00\x23\x73\x65\x73\x73\x69\x6f\x6e\x5f\x61\x75\x74" \
b"\x68\x6f\x72\x69\x7a\x61\x74\x69\x6f\x6e\x00\x70\x6f\x73\x74\x67" \
b"\x72\x65\x73\x00\x53\x00\x00\x00\x23\x73\x74\x61\x6e\x64\x61\x72" \
b"\x64\x5f\x63\x6f\x6e\x66\x6f\x72\x6d\x69\x6e\x67\x5f\x73\x74\x72" \
b"\x69\x6e\x67\x73\x00\x6f\x6e\x00\x53\x00\x00\x00\x15\x54\x69\x6d" \
b"\x65\x5a\x6f\x6e\x65\x00\x45\x74\x63\x2f\x55\x54\x43\x00\x4b\x00" \
b"\x00\x00\x0c\x00\x00\x01\x7f\x43\x4c\x36\xa5\x5a\x00\x00\x00\x05\x49"


init = BasePacket(init_packet)

assert isinstance(init.contents[0], AuthenticationRequest)
assert init.contents[0].len == 8
assert init.contents[0].method == 0