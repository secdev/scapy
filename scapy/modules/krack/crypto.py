import hashlib
import hmac
from io import BytesIO
from struct import unpack, pack
from zlib import crc32

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend

import scapy.modules.six as six
from scapy.modules.six.moves import range
from scapy.compat import hex_bytes, orb
from scapy.packet import Raw

# ARC4


def ARC4_encrypt(key, data, skip=0):
    """Encrypt data @data with key @key, skipping @skip first bytes of the
    keystream"""

    algorithm = algorithms.ARC4(key)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    if skip:
        encryptor.update("\x00" * skip)
    return encryptor.update(data)


def ARC4_decrypt(key, data, skip=0):
    """Decrypt data @data with key @key, skipping @skip first bytes of the
    keystream"""
    return ARC4_encrypt(key, data, skip)

# Custom WPA PseudoRandomFunction


def customPRF512(key, amac, smac, anonce, snonce):
    """Source https://stackoverflow.com/questions/12018920/"""
    A = "Pairwise key expansion"
    B = "".join(sorted([amac, smac]) + sorted([anonce, snonce]))

    blen = 64
    i = 0
    R = ''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, A + chr(0x00) + B + chr(i), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]

# TKIP - WEPSeed generation
# Tested against pyDot11: tkip.py


# 802.11i p.53-54
_SBOXS = [
    [
        0xC6A5, 0xF884, 0xEE99, 0xF68D, 0xFF0D, 0xD6BD, 0xDEB1, 0x9154,
        0x6050, 0x0203, 0xCEA9, 0x567D, 0xE719, 0xB562, 0x4DE6, 0xEC9A,
        0x8F45, 0x1F9D, 0x8940, 0xFA87, 0xEF15, 0xB2EB, 0x8EC9, 0xFB0B,
        0x41EC, 0xB367, 0x5FFD, 0x45EA, 0x23BF, 0x53F7, 0xE496, 0x9B5B,
        0x75C2, 0xE11C, 0x3DAE, 0x4C6A, 0x6C5A, 0x7E41, 0xF502, 0x834F,
        0x685C, 0x51F4, 0xD134, 0xF908, 0xE293, 0xAB73, 0x6253, 0x2A3F,
        0x080C, 0x9552, 0x4665, 0x9D5E, 0x3028, 0x37A1, 0x0A0F, 0x2FB5,
        0x0E09, 0x2436, 0x1B9B, 0xDF3D, 0xCD26, 0x4E69, 0x7FCD, 0xEA9F,
        0x121B, 0x1D9E, 0x5874, 0x342E, 0x362D, 0xDCB2, 0xB4EE, 0x5BFB,
        0xA4F6, 0x764D, 0xB761, 0x7DCE, 0x527B, 0xDD3E, 0x5E71, 0x1397,
        0xA6F5, 0xB968, 0x0000, 0xC12C, 0x4060, 0xE31F, 0x79C8, 0xB6ED,
        0xD4BE, 0x8D46, 0x67D9, 0x724B, 0x94DE, 0x98D4, 0xB0E8, 0x854A,
        0xBB6B, 0xC52A, 0x4FE5, 0xED16, 0x86C5, 0x9AD7, 0x6655, 0x1194,
        0x8ACF, 0xE910, 0x0406, 0xFE81, 0xA0F0, 0x7844, 0x25BA, 0x4BE3,
        0xA2F3, 0x5DFE, 0x80C0, 0x058A, 0x3FAD, 0x21BC, 0x7048, 0xF104,
        0x63DF, 0x77C1, 0xAF75, 0x4263, 0x2030, 0xE51A, 0xFD0E, 0xBF6D,
        0x814C, 0x1814, 0x2635, 0xC32F, 0xBEE1, 0x35A2, 0x88CC, 0x2E39,
        0x9357, 0x55F2, 0xFC82, 0x7A47, 0xC8AC, 0xBAE7, 0x322B, 0xE695,
        0xC0A0, 0x1998, 0x9ED1, 0xA37F, 0x4466, 0x547E, 0x3BAB, 0x0B83,
        0x8CCA, 0xC729, 0x6BD3, 0x283C, 0xA779, 0xBCE2, 0x161D, 0xAD76,
        0xDB3B, 0x6456, 0x744E, 0x141E, 0x92DB, 0x0C0A, 0x486C, 0xB8E4,
        0x9F5D, 0xBD6E, 0x43EF, 0xC4A6, 0x39A8, 0x31A4, 0xD337, 0xF28B,
        0xD532, 0x8B43, 0x6E59, 0xDAB7, 0x018C, 0xB164, 0x9CD2, 0x49E0,
        0xD8B4, 0xACFA, 0xF307, 0xCF25, 0xCAAF, 0xF48E, 0x47E9, 0x1018,
        0x6FD5, 0xF088, 0x4A6F, 0x5C72, 0x3824, 0x57F1, 0x73C7, 0x9751,
        0xCB23, 0xA17C, 0xE89C, 0x3E21, 0x96DD, 0x61DC, 0x0D86, 0x0F85,
        0xE090, 0x7C42, 0x71C4, 0xCCAA, 0x90D8, 0x0605, 0xF701, 0x1C12,
        0xC2A3, 0x6A5F, 0xAEF9, 0x69D0, 0x1791, 0x9958, 0x3A27, 0x27B9,
        0xD938, 0xEB13, 0x2BB3, 0x2233, 0xD2BB, 0xA970, 0x0789, 0x33A7,
        0x2DB6, 0x3C22, 0x1592, 0xC920, 0x8749, 0xAAFF, 0x5078, 0xA57A,
        0x038F, 0x59F8, 0x0980, 0x1A17, 0x65DA, 0xD731, 0x84C6, 0xD0B8,
        0x82C3, 0x29B0, 0x5A77, 0x1E11, 0x7BCB, 0xA8FC, 0x6DD6, 0x2C3A
    ],
    [
        0xA5C6, 0x84F8, 0x99EE, 0x8DF6, 0x0DFF, 0xBDD6, 0xB1DE, 0x5491,
        0x5060, 0x0302, 0xA9CE, 0x7D56, 0x19E7, 0x62B5, 0xE64D, 0x9AEC,
        0x458F, 0x9D1F, 0x4089, 0x87FA, 0x15EF, 0xEBB2, 0xC98E, 0x0BFB,
        0xEC41, 0x67B3, 0xFD5F, 0xEA45, 0xBF23, 0xF753, 0x96E4, 0x5B9B,
        0xC275, 0x1CE1, 0xAE3D, 0x6A4C, 0x5A6C, 0x417E, 0x02F5, 0x4F83,
        0x5C68, 0xF451, 0x34D1, 0x08F9, 0x93E2, 0x73AB, 0x5362, 0x3F2A,
        0x0C08, 0x5295, 0x6546, 0x5E9D, 0x2830, 0xA137, 0x0F0A, 0xB52F,
        0x090E, 0x3624, 0x9B1B, 0x3DDF, 0x26CD, 0x694E, 0xCD7F, 0x9FEA,
        0x1B12, 0x9E1D, 0x7458, 0x2E34, 0x2D36, 0xB2DC, 0xEEB4, 0xFB5B,
        0xF6A4, 0x4D76, 0x61B7, 0xCE7D, 0x7B52, 0x3EDD, 0x715E, 0x9713,
        0xF5A6, 0x68B9, 0x0000, 0x2CC1, 0x6040, 0x1FE3, 0xC879, 0xEDB6,
        0xBED4, 0x468D, 0xD967, 0x4B72, 0xDE94, 0xD498, 0xE8B0, 0x4A85,
        0x6BBB, 0x2AC5, 0xE54F, 0x16ED, 0xC586, 0xD79A, 0x5566, 0x9411,
        0xCF8A, 0x10E9, 0x0604, 0x81FE, 0xF0A0, 0x4478, 0xBA25, 0xE34B,
        0xF3A2, 0xFE5D, 0xC080, 0x8A05, 0xAD3F, 0xBC21, 0x4870, 0x04F1,
        0xDF63, 0xC177, 0x75AF, 0x6342, 0x3020, 0x1AE5, 0x0EFD, 0x6DBF,
        0x4C81, 0x1418, 0x3526, 0x2FC3, 0xE1BE, 0xA235, 0xCC88, 0x392E,
        0x5793, 0xF255, 0x82FC, 0x477A, 0xACC8, 0xE7BA, 0x2B32, 0x95E6,
        0xA0C0, 0x9819, 0xD19E, 0x7FA3, 0x6644, 0x7E54, 0xAB3B, 0x830B,
        0xCA8C, 0x29C7, 0xD36B, 0x3C28, 0x79A7, 0xE2BC, 0x1D16, 0x76AD,
        0x3BDB, 0x5664, 0x4E74, 0x1E14, 0xDB92, 0x0A0C, 0x6C48, 0xE4B8,
        0x5D9F, 0x6EBD, 0xEF43, 0xA6C4, 0xA839, 0xA431, 0x37D3, 0x8BF2,
        0x32D5, 0x438B, 0x596E, 0xB7DA, 0x8C01, 0x64B1, 0xD29C, 0xE049,
        0xB4D8, 0xFAAC, 0x07F3, 0x25CF, 0xAFCA, 0x8EF4, 0xE947, 0x1810,
        0xD56F, 0x88F0, 0x6F4A, 0x725C, 0x2438, 0xF157, 0xC773, 0x5197,
        0x23CB, 0x7CA1, 0x9CE8, 0x213E, 0xDD96, 0xDC61, 0x860D, 0x850F,
        0x90E0, 0x427C, 0xC471, 0xAACC, 0xD890, 0x0506, 0x01F7, 0x121C,
        0xA3C2, 0x5F6A, 0xF9AE, 0xD069, 0x9117, 0x5899, 0x273A, 0xB927,
        0x38D9, 0x13EB, 0xB32B, 0x3322, 0xBBD2, 0x70A9, 0x8907, 0xA733,
        0xB62D, 0x223C, 0x9215, 0x20C9, 0x4987, 0xFFAA, 0x7850, 0x7AA5,
        0x8F03, 0xF859, 0x8009, 0x171A, 0xDA65, 0x31D7, 0xC684, 0xB8D0,
        0xC382, 0xB029, 0x775A, 0x111E, 0xCB7B, 0xFCA8, 0xD66D, 0x3A2C
    ]
]

# 802.11i Annex H
PHASE1_LOOP_CNT = 8


def _MK16(b1, b2):
    return (b1 << 8) | b2


def _SBOX16(index):
    return _SBOXS[0][index & 0xff] ^ _SBOXS[1][(index >> 8)]


def _CAST16(value):
    return value & 0xffff


def _RotR1(value):
    return ((value >> 1) & 0x7fff) | (value << 15)


def gen_TKIP_RC4_key(TSC, TA, TK):
    """Implement TKIP WEPSeed generation
    TSC: packet IV
    TA: target addr bytes
    TK: temporal key
    """

    assert len(TSC) == 6
    assert len(TA) == 6
    assert len(TK) == 16
    assert all(isinstance(x, six.integer_types) for x in TSC + TA + TK)

    # Phase 1
    # 802.11i p.54

    # Phase 1 - Step 1
    TTAK = []
    TTAK.append(_MK16(TSC[3], TSC[2]))
    TTAK.append(_MK16(TSC[5], TSC[4]))
    TTAK.append(_MK16(TA[1], TA[0]))
    TTAK.append(_MK16(TA[3], TA[2]))
    TTAK.append(_MK16(TA[5], TA[4]))

    # Phase 1 - Step 2
    for i in range(PHASE1_LOOP_CNT):
        j = 2 * (i & 1)
        TTAK[0] = _CAST16(TTAK[0] + _SBOX16(TTAK[4] ^ _MK16(TK[1 + j], TK[0 + j])))  # noqa: E501
        TTAK[1] = _CAST16(TTAK[1] + _SBOX16(TTAK[0] ^ _MK16(TK[5 + j], TK[4 + j])))  # noqa: E501
        TTAK[2] = _CAST16(TTAK[2] + _SBOX16(TTAK[1] ^ _MK16(TK[9 + j], TK[8 + j])))  # noqa: E501
        TTAK[3] = _CAST16(TTAK[3] + _SBOX16(TTAK[2] ^ _MK16(TK[13 + j], TK[12 + j])))  # noqa: E501
        TTAK[4] = _CAST16(TTAK[4] + _SBOX16(TTAK[3] ^ _MK16(TK[1 + j], TK[0 + j])) + i)  # noqa: E501

    # Phase 2
    # 802.11i p.56

    # Phase 2 - Step 1
    PPK = list(TTAK)
    PPK.append(_CAST16(TTAK[4] + _MK16(TSC[1], TSC[0])))

    # Phase 2 - Step 2
    PPK[0] = _CAST16(PPK[0] + _SBOX16(PPK[5] ^ _MK16(TK[1], TK[0])))
    PPK[1] = _CAST16(PPK[1] + _SBOX16(PPK[0] ^ _MK16(TK[3], TK[2])))
    PPK[2] = _CAST16(PPK[2] + _SBOX16(PPK[1] ^ _MK16(TK[5], TK[4])))
    PPK[3] = _CAST16(PPK[3] + _SBOX16(PPK[2] ^ _MK16(TK[7], TK[6])))
    PPK[4] = _CAST16(PPK[4] + _SBOX16(PPK[3] ^ _MK16(TK[9], TK[8])))
    PPK[5] = _CAST16(PPK[5] + _SBOX16(PPK[4] ^ _MK16(TK[11], TK[10])))

    PPK[0] = _CAST16(PPK[0] + _RotR1(PPK[5] ^ _MK16(TK[13], TK[12])))
    PPK[1] = _CAST16(PPK[1] + _RotR1(PPK[0] ^ _MK16(TK[15], TK[14])))
    PPK[2] = _CAST16(PPK[2] + _RotR1(PPK[1]))
    PPK[3] = _CAST16(PPK[3] + _RotR1(PPK[2]))
    PPK[4] = _CAST16(PPK[4] + _RotR1(PPK[3]))
    PPK[5] = _CAST16(PPK[5] + _RotR1(PPK[4]))

    # Phase 2 - Step 3
    WEPSeed = []
    WEPSeed.append(TSC[1])
    WEPSeed.append((TSC[1] | 0x20) & 0x7f)
    WEPSeed.append(TSC[0])
    WEPSeed.append(((PPK[5] ^ _MK16(TK[1], TK[0])) >> 1) & 0xFF)
    for i in range(6):
        WEPSeed.append(PPK[i] & 0xFF)
        WEPSeed.append(PPK[i] >> 8)

    assert len(WEPSeed) == 16

    return "".join([chr(x) for x in WEPSeed])

# TKIP - Michael
# Tested against cryptopy (crypto.keyedHash.michael: Michael)


def _rotate_right32(value, shift):
    return (value >> (shift % 32) | value << ((32 - shift) % 32)) & 0xFFFFFFFF


def _rotate_left32(value, shift):
    return (value << (shift % 32) | value >> ((32 - shift) % 32)) & 0xFFFFFFFF


def _XSWAP(value):
    """Swap 2 least significant bytes of @value"""
    return ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8)


def _michael_b(m_l, m_r):
    """Defined in 802.11i p.49"""
    m_r = m_r ^ _rotate_left32(m_l, 17)
    m_l = (m_l + m_r) % 2**32
    m_r = m_r ^ _XSWAP(m_l)
    m_l = (m_l + m_r) % 2**32
    m_r = m_r ^ _rotate_left32(m_l, 3)
    m_l = (m_l + m_r) % 2**32
    m_r = m_r ^ _rotate_right32(m_l, 2)
    m_l = (m_l + m_r) % 2**32
    return m_l, m_r


def michael(key, to_hash):
    """Defined in 802.11i p.48"""

    # Block size: 4
    nb_block, nb_extra_bytes = divmod(len(to_hash), 4)
    # Add padding
    data = to_hash + chr(0x5a) + "\x00" * (7 - nb_extra_bytes)

    # Hash
    m_l, m_r = unpack('<II', key)
    for i in range(nb_block + 2):
        # Convert i-th block to int
        block_i = unpack('<I', data[i * 4:i * 4 + 4])[0]
        m_l ^= block_i
        m_l, m_r = _michael_b(m_l, m_r)
    return pack('<II', m_l, m_r)

# TKIP packet utils


def parse_TKIP_hdr(pkt):
    """Extract TSCs, TA and encoded-data from a packet @pkt"""
    # Note: FCS bit is not handled
    assert pkt.FCfield.wep

    # 802.11i - 8.3.2.2
    payload = BytesIO(pkt[Raw].load)
    TSC1, WEPseed, TSC0, bitfield = (orb(x) for x in payload.read(4))
    if bitfield & (1 << 5):
        # Extended IV
        TSC2, TSC3, TSC4, TSC5 = (orb(x) for x in payload.read(4))
    else:
        TSC2, TSC3, TSC4, TSC5 = None, None, None, None
        # 802.11i p. 46
        raise ValueError("Extended IV must be set for TKIP")

    # 802.11i p. 46
    assert (TSC1 | 0x20) & 0x7f == WEPseed

    TA = [orb(e) for e in hex_bytes(pkt.addr2.replace(':', ''))]
    TSC = [TSC0, TSC1, TSC2, TSC3, TSC4, TSC5]

    return TSC, TA, payload.read()


def build_TKIP_payload(data, iv, mac, tk):
    """Build a TKIP header for IV @iv and mac @mac, and encrypt @data
    based on temporal key @tk
    """
    TSC5, TSC4, TSC3, TSC2, TSC1, TSC0 = (
        (iv >> 40) & 0xFF,
        (iv >> 32) & 0xFF,
        (iv >> 24) & 0xFF,
        (iv >> 16) & 0xFF,
        (iv >> 8) & 0xFF,
        iv & 0xFF
    )
    bitfield = 1 << 5  # Extended IV
    TKIP_hdr = chr(TSC1) + chr((TSC1 | 0x20) & 0x7f) + chr(TSC0) + chr(bitfield)  # noqa: E501
    TKIP_hdr += chr(TSC2) + chr(TSC3) + chr(TSC4) + chr(TSC5)

    TA = [orb(e) for e in hex_bytes(mac.replace(':', ''))]
    TSC = [TSC0, TSC1, TSC2, TSC3, TSC4, TSC5]
    TK = [orb(x) for x in tk]

    rc4_key = gen_TKIP_RC4_key(TSC, TA, TK)
    return TKIP_hdr + ARC4_encrypt(rc4_key, data)


def parse_data_pkt(pkt, tk):
    """Extract data from a WPA packet @pkt with temporal key @tk"""
    TSC, TA, data = parse_TKIP_hdr(pkt)
    TK = [orb(x) for x in tk]

    rc4_key = gen_TKIP_RC4_key(TSC, TA, TK)
    return ARC4_decrypt(rc4_key, data)


class ICVError(Exception):
    """The expected ICV is not the computed one"""
    pass


class MICError(Exception):
    """The expected MIC is not the computed one"""
    pass


def check_MIC_ICV(data, mic_key, source, dest):
    """Check MIC, ICV & return the data from a decrypted TKIP packet"""
    assert len(data) > 12

    # DATA - MIC(DA - SA - Priority=0 - 0 - 0 - 0 - DATA) - ICV
    # 802.11i p.47

    ICV = data[-4:]
    MIC = data[-12:-4]
    data_clear = data[:-12]

    expected_ICV = pack("<I", crc32(data_clear + MIC) & 0xFFFFFFFF)
    if expected_ICV != ICV:
        raise ICVError()

    sa = hex_bytes(source.replace(":", ""))  # Source MAC
    da = hex_bytes(dest.replace(":", ""))  # Dest MAC

    expected_MIC = michael(mic_key, da + sa + "\x00" + "\x00" * 3 + data_clear)
    if expected_MIC != MIC:
        raise MICError()

    return data_clear


def build_MIC_ICV(data, mic_key, source, dest):
    """Compute and return the data with its MIC and ICV"""
    # DATA - MIC(DA - SA - Priority=0 - 0 - 0 - 0 - DATA) - ICV
    # 802.11i p.47

    sa = hex_bytes(source.replace(":", ""))  # Source MAC
    da = hex_bytes(dest.replace(":", ""))  # Dest MAC
    MIC = michael(mic_key, da + sa + "\x00" + "\x00" * 3 + data)
    ICV = pack("<I", crc32(data + MIC) & 0xFFFFFFFF)

    return data + MIC + ICV
