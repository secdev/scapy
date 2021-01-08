# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Lucas Preston <lucas.preston@infinite.io>
# This program is published under a GPLv2 license

# scapy.contrib.description = Network File System (NFS) v3
# scapy.contrib.status = loads

from scapy.contrib.oncrpc import RPC, RPC_Call, Object_Name
from binascii import unhexlify
from scapy.packet import Packet, bind_layers
from scapy.fields import IntField, IntEnumField, FieldListField, LongField, \
    XIntField, XLongField, ConditionalField, PacketListField, StrLenField, \
    PacketField
from scapy.modules.six import integer_types

nfsstat3 = {
    0: 'NFS3_OK',
    1: 'NFS3ERR_PERM',
    2: 'NFS3ERR_NOENT',
    5: 'NFS3ERR_IO',
    6: 'NFS3ERR_NXIO',
    13: 'NFS3ERR_ACCES',
    17: 'NFS3ERR_EXIST',
    18: 'NFS3ERR_XDEV',
    19: 'NFS3ERR_NODEV',
    20: 'NFS3ERR_NOTDIR',
    21: 'NFS3ERR_ISDIR',
    22: 'NFS3ERR_INVAL',
    27: 'NFS3ERR_FBIG',
    28: 'NFS3ERR_NOSPC',
    30: 'NFS3ERR_ROFS',
    31: 'NFS3ERR_MLINK',
    63: 'NFS3ERR_NAMETOOLONG',
    66: 'NFS3ERR_NOTEMPTY',
    69: 'NFS3ERR_DQUOT',
    70: 'NFS3ERR_STALE',
    71: 'NFS3ERR_REMOTE',
    10001: 'NFS3ERR_BADHANDLE',
    10002: 'NFS3ERR_NOT_SYNC',
    10003: 'NFS3ERR_BAD_COOKIE',
    10004: 'NFS3ERR_NOTSUPP',
    10005: 'NFS3ERR_TOOSMALL',
    10006: 'NFS3ERR_SERVERFAULT',
    10007: 'NFS3ERR_BADTYPE',
    10008: 'NFS3ERR_JUKEBOX'
}

ftype3 = {
    1: 'NF3REG',
    2: 'NF3DIR',
    3: 'NF3BLK',
    4: 'NF3CHR',
    5: 'NF3LNK',
    6: 'NF3SOCK',
    7: 'NF3FIFO'
}


def loct(x):
    if isinstance(x, integer_types):
        return oct(x)
    if isinstance(x, tuple):
        return "(%s)" % ", ".join(map(loct, x))
    if isinstance(x, list):
        return "[%s]" % ", ".join(map(loct, x))
    return x


class OIntField(IntField):
    """IntField child with octal representation"""
    def i2repr(self, pkt, x):
        return loct(self.i2h(pkt, x))


class Fattr3(Packet):
    name = 'File Attributes'
    fields_desc = [
        IntEnumField('type', 0, ftype3),
        OIntField('mode', 0),
        IntField('nlink', 0),
        IntField('uid', 0),
        IntField('gid', 0),
        LongField('size', 0),
        LongField('used', 0),
        FieldListField(
            'rdev', [0, 0], IntField('', None), count_from=lambda x: 2
        ),
        XLongField('fsid', 0),
        XLongField('fileid', 0),
        IntField('atime_s', 0),
        IntField('atime_ns', 0),
        IntField('mtime_s', 0),
        IntField('mtime_ns', 0),
        IntField('ctime_s', 0),
        IntField('ctime_ns', 0)
    ]

    def extract_padding(self, s):
        return '', s


class File_Object(Packet):
    name = 'File Object'
    fields_desc = [
        IntField('length', 0),
        StrLenField('fh', b'', length_from=lambda pkt: pkt.length),
        StrLenField('fill', b'', length_from=lambda pkt: (4 - pkt.length) % 4)
    ]

    def set(self, new_filehandle, length=None, fill=None):
        # convert filehandle to bytes if it was passed as a string
        if new_filehandle.isalnum():
            new_filehandle = unhexlify(new_filehandle)

        if length is None:
            length = len(new_filehandle)
        if fill is None:
            fill = b'\x00' * ((4 - length) % 4)

        self.length = length
        self.fh = new_filehandle
        self.fill = fill

    def extract_padding(self, s):
        return '', s


class WCC_Attr(Packet):
    name = 'File Attributes'
    fields_desc = [
        LongField('size', 0),
        IntField('mtime_s', 0),
        IntField('mtime_ns', 0),
        IntField('ctime_s', 0),
        IntField('ctime_ns', 0)
    ]

    def extract_padding(self, s):
        return '', s


class File_From_Dir_Plus(Packet):
    name = 'File'
    fields_desc = [
        LongField('fileid', 0),
        PacketField('filename', Object_Name(), Object_Name),
        LongField('cookie', 0),
        IntField('attributes_follow', 0),
        ConditionalField(
            PacketField('attributes', Fattr3(), Fattr3),
            lambda pkt: pkt.attributes_follow == 1
        ),
        IntField('handle_follows', 0),
        ConditionalField(
            PacketField('filehandle', File_Object(), File_Object),
            lambda pkt: pkt.handle_follows == 1
        ),
        IntField('value_follows', 0)
    ]

    def extract_padding(self, s):
        return '', s


class File_From_Dir(Packet):
    name = 'File'
    fields_desc = [
        LongField('fileid', 0),
        PacketField('filename', Object_Name(), Object_Name),
        LongField('cookie', 0),
        IntField('value_follows', 0)
    ]

    def extract_padding(self, s):
        return '', s


attrs_enum = {0: 'DONT SET', 1: 'SET'}
times_enum = {0: 'DONT CHANGE', 1: 'SERVER TIME', 2: 'CLIENT TIME'}


class Sattr3(Packet):
    name = 'Setattr3'
    fields_desc = [
        IntEnumField('set_mode', 0, attrs_enum),
        ConditionalField(OIntField('mode', 0), lambda pkt: pkt.set_mode == 1),
        IntEnumField('set_uid', 0, attrs_enum),
        ConditionalField(IntField('uid', 0), lambda pkt: pkt.set_uid == 1),
        IntEnumField('set_gid', 0, attrs_enum),
        ConditionalField(IntField('gid', 0), lambda pkt: pkt.set_gid == 1),
        IntEnumField('set_size', 0, attrs_enum),
        ConditionalField(LongField('size', 0), lambda pkt: pkt.set_size == 1),
        IntEnumField('set_atime', 0, times_enum),
        ConditionalField(
            IntField('atime_s', 0), lambda pkt: pkt.set_atime == 2
        ),
        ConditionalField(
            IntField('atime_ns', 0), lambda pkt: pkt.set_atime == 2
        ),
        IntEnumField('set_mtime', 0, times_enum),
        ConditionalField(
            IntField('mtime_s', 0), lambda pkt: pkt.set_mtime == 2
        ),
        ConditionalField(
            IntField('mtime_ns', 0), lambda pkt: pkt.set_mtime == 2
        )
    ]

    def extract_padding(self, s):
        return '', s


class GETATTR_Call(Packet):
    name = 'GETATTR Call'
    fields_desc = [
        PacketField('filehandle', File_Object(), File_Object)
    ]


class GETATTR_Reply(Packet):
    name = 'GETATTR Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        ConditionalField(
            PacketField('attributes', Fattr3(), Fattr3),
            lambda pkt: pkt.status == 0
        )
    ]

    def extract_padding(self, s):
        return '', None


bind_layers(RPC, GETATTR_Call, mtype=0)
bind_layers(
    RPC_Call, GETATTR_Call, program=100003, pversion=3, procedure=1
)
bind_layers(RPC, GETATTR_Reply, mtype=1)


class LOOKUP_Call(Packet):
    name = 'LOOKUP Call'
    fields_desc = [
        PacketField('dir', File_Object(), File_Object),
        PacketField('filename', Object_Name(), Object_Name)
    ]


class LOOKUP_Reply(Packet):
    name = 'LOOKUP Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        ConditionalField(
            PacketField('filehandle', File_Object(), File_Object),
            lambda pkt: pkt.status == 0
        ),
        ConditionalField(IntField('af_file', 0), lambda pkt: pkt.status == 0),
        ConditionalField(
            PacketField('file_attributes', Fattr3(), Fattr3),
            lambda pkt: pkt.status == 0 and pkt.af_file == 1
        ),
        IntField('af_dir', 0),
        ConditionalField(
            PacketField('dir_attributes', Fattr3(), Fattr3),
            lambda pkt: pkt.af_dir == 1
        )
    ]


bind_layers(RPC, LOOKUP_Call, mtype=0)
bind_layers(RPC, LOOKUP_Reply, mtype=1)
bind_layers(RPC_Call, LOOKUP_Call, program=100003, pversion=3, procedure=3)


class NULL_Call(Packet):
    name = 'NFS NULL Call'
    fields_desc = []


class NULL_Reply(Packet):
    name = 'NFS NULL Reply'
    fields_desc = []


bind_layers(RPC, NULL_Call, mtype=0)
bind_layers(RPC, NULL_Reply, mtype=1)
bind_layers(RPC_Call, NULL_Call, program=100003, pversion=3, procedure=0)


class FSINFO_Call(Packet):
    name = 'FSINFO Call'
    fields_desc = [
        PacketField('filehandle', File_Object(), File_Object)
    ]


class FSINFO_Reply(Packet):
    name = 'FSINFO Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        IntField('attributes_follow', 0),
        ConditionalField(
            PacketField('attributes', Fattr3(), Fattr3),
            lambda pkt: pkt.attributes_follow == 1
        ),
        ConditionalField(IntField('rtmax', 0), lambda pkt: pkt.status == 0),
        ConditionalField(IntField('rtpref', 0), lambda pkt: pkt.status == 0),
        ConditionalField(IntField('rtmult', 0), lambda pkt: pkt.status == 0),
        ConditionalField(IntField('wtmax', 0), lambda pkt: pkt.status == 0),
        ConditionalField(IntField('wtpref', 0), lambda pkt: pkt.status == 0),
        ConditionalField(IntField('wtmult', 0), lambda pkt: pkt.status == 0),
        ConditionalField(IntField('dtpref', 0), lambda pkt: pkt.status == 0),
        ConditionalField(
            LongField('maxfilesize', 0), lambda pkt: pkt.status == 0
        ),
        ConditionalField(
            IntField('timedelta_s', 0), lambda pkt: pkt.status == 0
        ),
        ConditionalField(
            IntField('timedelta_ns', 0), lambda pkt: pkt.status == 0
        ),
        ConditionalField(
            XIntField('properties', 0), lambda pkt: pkt.status == 0
        ),
    ]


bind_layers(RPC, FSINFO_Call, mtype=0)
bind_layers(RPC, FSINFO_Reply, mtype=1)
bind_layers(
    RPC_Call, FSINFO_Call, program=100003, pversion=3, procedure=19
)


class PATHCONF_Call(Packet):
    name = 'PATHCONF Call'
    fields_desc = [
        PacketField('filehandle', File_Object(), File_Object)
    ]


class PATHCONF_Reply(Packet):
    name = 'PATHCONF Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        IntField('attributes_follow', 0),
        ConditionalField(
            PacketField('attributes', Fattr3(), Fattr3),
            lambda pkt: pkt.attributes_follow == 1
        ),
        ConditionalField(IntField('linkmax', 0), lambda pkt: pkt.status == 0),
        ConditionalField(IntField('name_max', 0), lambda pkt: pkt.status == 0),
        ConditionalField(
            IntEnumField('no_trunc', 0, {0: 'NO', 1: 'YES'}),
            lambda pkt: pkt.status == 0
        ),
        ConditionalField(
            IntEnumField('chown_restricted', 0, {0: 'NO', 1: 'YES'}),
            lambda pkt: pkt.status == 0
        ),
        ConditionalField(
            IntEnumField('case_insensitive', 0, {0: 'NO', 1: 'YES'}),
            lambda pkt: pkt.status == 0
        ),
        ConditionalField(
            IntEnumField('case_preserving', 0, {0: 'NO', 1: 'YES'}),
            lambda pkt: pkt.status == 0
        )
    ]


bind_layers(RPC, PATHCONF_Call, mtype=0)
bind_layers(RPC, PATHCONF_Reply, mtype=1)
bind_layers(
    RPC_Call, PATHCONF_Call, program=100003, pversion=3, procedure=20
)

access_specs = {
    0x0001: 'READ',
    0x0002: 'LOOKUP',
    0x0004: 'MODIFY',
    0x0008: 'EXTEND',
    0x0010: 'DELETE',
    0x0020: 'EXECUTE'
}


class ACCESS_Call(Packet):
    name = 'ACCESS Call'
    fields_desc = [
        PacketField('filehandle', File_Object(), File_Object),
        IntEnumField('check_access', 1, access_specs)
    ]


class ACCESS_Reply(Packet):
    name = 'ACCESS Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        IntField('attributes_follow', 0),
        ConditionalField(
            PacketField('attributes', Fattr3(), Fattr3),
            lambda pkt: pkt.attributes_follow == 1
        ),
        ConditionalField(
            XIntField('access_rights', 0), lambda pkt: pkt.status == 0
        )
    ]


bind_layers(RPC, ACCESS_Call, mtype=0)
bind_layers(RPC, ACCESS_Reply, mtype=1)
bind_layers(RPC_Call, ACCESS_Call, program=100003, pversion=3, procedure=4)


class READDIRPLUS_Call(Packet):
    name = 'READDIRPLUS Call'
    fields_desc = [
        PacketField('filehandle', File_Object(), File_Object),
        LongField('cookie', 0),
        LongField('verifier', 0),
        IntField('dircount', 512),
        IntField('maxcount', 4096)
    ]


class READDIRPLUS_Reply(Packet):
    name = 'READDIRPLUS Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        IntField('attributes_follow', 0),
        ConditionalField(
            PacketField('attributes', Fattr3(), Fattr3),
            lambda pkt: pkt.attributes_follow == 1
        ),
        ConditionalField(
            LongField('verifier', 0), lambda pkt: pkt.status == 0
        ),
        ConditionalField(
            IntField('value_follows', 0), lambda pkt: pkt.status == 0
        ),
        ConditionalField(
            PacketListField(
                'files', None, File_From_Dir_Plus,
                next_cls_cb=lambda pkt, lst, cur, remain:
                File_From_Dir_Plus if pkt.value_follows == 1 and
                (len(lst) == 0 or cur.value_follows == 1) and
                len(remain) > 4 else None
            ),
            lambda pkt: pkt.status == 0
        ),
        ConditionalField(IntField('eof', 0), lambda pkt: pkt.status == 0)
    ]

    def extract_padding(self, s):
        return '', s


bind_layers(RPC, READDIRPLUS_Call, mtype=0)
bind_layers(RPC, READDIRPLUS_Reply, mtype=1)
bind_layers(
    RPC_Call, READDIRPLUS_Call, program=100003, pversion=3, procedure=17
)


class WRITE_Call(Packet):
    name = 'WRITE Call'
    fields_desc = [
        PacketField('filehandle', File_Object(), File_Object),
        LongField('offset', 0),
        IntField('count', 0),
        IntEnumField('stable', 0, {0: 'UNSTABLE', 1: 'STABLE'}),
        IntField('length', 0),
        StrLenField('contents', b'', length_from=lambda pkt: pkt.length),
        StrLenField('fill', b'', length_from=lambda pkt: (4 - pkt.length) % 4)
    ]


class WRITE_Reply(Packet):
    name = 'WRITE Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        IntField('af_before', 0),
        ConditionalField(
            PacketField('attributes_before', WCC_Attr(), WCC_Attr),
            lambda pkt: pkt.af_before == 1
        ),
        IntField('af_after', 0),
        ConditionalField(
            PacketField('attributes_after', Fattr3(), Fattr3),
            lambda pkt: pkt.af_after == 1
        ),
        ConditionalField(IntField('count', 0), lambda pkt: pkt.status == 0),
        ConditionalField(
            IntEnumField('committed', 0, {0: 'UNSTABLE', 1: 'STABLE'}),
            lambda pkt: pkt.status == 0
        ),
        ConditionalField(
            XLongField('verifier', 0), lambda pkt: pkt.status == 0
        )
    ]


bind_layers(RPC, WRITE_Call, mtype=0)
bind_layers(RPC, WRITE_Reply, mtype=1)
bind_layers(RPC_Call, WRITE_Call, program=100003, pversion=3, procedure=7)


class COMMIT_Call(Packet):
    name = 'COMMIT Call'
    fields_desc = [
        PacketField('filehandle', File_Object(), File_Object),
        LongField('offset', 0),
        IntField('count', 0)
    ]


class COMMIT_Reply(Packet):
    name = 'COMMIT Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        IntField('af_before', 0),
        ConditionalField(
            PacketField('attributes_before', WCC_Attr(), WCC_Attr),
            lambda pkt: pkt.af_before == 1
        ),
        IntField('af_after', 0),
        ConditionalField(
            PacketField('attributes_after', Fattr3(), Fattr3),
            lambda pkt: pkt.af_after == 1
        ),
        ConditionalField(
            XLongField('verifier', 0), lambda pkt: pkt.status == 0
        )
    ]


bind_layers(RPC, COMMIT_Call, mtype=0)
bind_layers(RPC, COMMIT_Reply, mtype=1)
bind_layers(
    RPC_Call, COMMIT_Call, program=100003, pversion=3, procedure=21
)


class SETATTR_Call(Packet):
    name = 'SETATTR Call'
    fields_desc = [
        PacketField('filehandle', File_Object(), File_Object),
        PacketField('attributes', Sattr3(), Sattr3),
        IntField('check', 0)
    ]


class SETATTR_Reply(Packet):
    name = 'SETATTR Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        IntField('af_before', 0),
        ConditionalField(
            PacketField('attributes_before', WCC_Attr(), WCC_Attr),
            lambda pkt: pkt.af_before == 1
        ),
        IntField('af_after', 0),
        ConditionalField(
            PacketField('attributes_after', Fattr3(), Fattr3),
            lambda pkt: pkt.af_after == 1
        )
    ]


bind_layers(RPC, SETATTR_Call, mtype=0)
bind_layers(RPC, SETATTR_Reply, mtype=1)
bind_layers(
    RPC_Call, SETATTR_Call, program=100003, pversion=3, procedure=2
)


class FSSTAT_Call(Packet):
    name = 'FSSTAT Call'
    fields_desc = [
        PacketField('filehandle', File_Object(), File_Object)
    ]


class FSSTAT_Reply(Packet):
    name = 'FSSTAT Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        IntField('attributes_follow', 0),
        ConditionalField(
            PacketField('attributes', Fattr3(), Fattr3),
            lambda pkt: pkt.attributes_follow == 1
        ),
        ConditionalField(LongField('tbytes', 0), lambda pkt: pkt.status == 0),
        ConditionalField(LongField('fbytes', 0), lambda pkt: pkt.status == 0),
        ConditionalField(LongField('abytes', 0), lambda pkt: pkt.status == 0),
        ConditionalField(LongField('tfiles', 0), lambda pkt: pkt.status == 0),
        ConditionalField(LongField('ffiles', 0), lambda pkt: pkt.status == 0),
        ConditionalField(LongField('afiles', 0), lambda pkt: pkt.status == 0),
        ConditionalField(IntField('invarsec', 0), lambda pkt: pkt.status == 0)
    ]


bind_layers(RPC, FSSTAT_Call, mtype=0)
bind_layers(RPC, FSSTAT_Reply, mtype=1)
bind_layers(
    RPC_Call, FSSTAT_Call, program=100003, pversion=3, procedure=18
)


class CREATE_Call(Packet):
    name = 'CREATE Call'
    fields_desc = [
        PacketField('dir', File_Object(), File_Object),
        PacketField('filename', Object_Name(), Object_Name),
        IntEnumField('create_mode', None, {0: 'UNCHECKED',
                                           1: 'GUARDED',
                                           2: 'EXCLUSIVE'}),
        ConditionalField(
            PacketField('attributes', Sattr3(), Sattr3),
            lambda pkt: pkt.create_mode != 2
        ),
        ConditionalField(
            XLongField('verifier', 0), lambda pkt: pkt.create_mode == 2
        )
    ]


class CREATE_Reply(Packet):
    name = 'CREATE Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        ConditionalField(
            IntField('handle_follows', 0), lambda pkt: pkt.status == 0
        ),
        ConditionalField(
            PacketField('filehandle', File_Object(), File_Object),
            lambda pkt: pkt.status == 0 and pkt.handle_follows == 1
        ),
        ConditionalField(
            IntField('attributes_follow', 0), lambda pkt: pkt.status == 0
        ),
        ConditionalField(
            PacketField('attributes', Fattr3(), Fattr3),
            lambda pkt: pkt.status == 0 and pkt.attributes_follow == 1
        ),
        IntField('af_before', 0),
        ConditionalField(
            PacketField('dir_attributes_before', WCC_Attr(), WCC_Attr),
            lambda pkt: pkt.af_before == 1
        ),
        IntField('af_after', 0),
        ConditionalField(
            PacketField('dir_attributes_after', Fattr3(), Fattr3),
            lambda pkt: pkt.af_after == 1
        )
    ]


bind_layers(RPC, CREATE_Call, mtype=0)
bind_layers(RPC, CREATE_Reply, mtype=1)
bind_layers(RPC_Call, CREATE_Call, program=100003, pversion=3, procedure=8)


class REMOVE_Call(Packet):
    name = 'REMOVE Call'
    fields_desc = [
        PacketField('dir', File_Object(), File_Object),
        PacketField('filename', Object_Name(), Object_Name)
    ]


class REMOVE_Reply(Packet):
    name = 'REMOVE Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        IntField('af_before', 0),
        ConditionalField(
            PacketField('attributes_before', WCC_Attr(), WCC_Attr),
            lambda pkt: pkt.af_before == 1
        ),
        IntField('af_after', 0),
        ConditionalField(
            PacketField('attributes_after', Fattr3(), Fattr3),
            lambda pkt: pkt.af_after == 1
        )
    ]


bind_layers(RPC, REMOVE_Call, mtype=0)
bind_layers(RPC, REMOVE_Reply, mtype=1)
bind_layers(
    RPC_Call, REMOVE_Call, program=100003, pversion=3, procedure=12
)


class READDIR_Call(Packet):
    name = 'READDIR Call'
    fields_desc = [
        PacketField('filehandle', File_Object(), File_Object),
        LongField('cookie', 0),
        XLongField('verifier', 0),
        IntField('count', 0)
    ]


class READDIR_Reply(Packet):
    name = 'READDIR Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        IntField('attributes_follow', 0),
        ConditionalField(
            PacketField('attributes', Fattr3(), Fattr3),
            lambda pkt: pkt.attributes_follow == 1
        ),
        ConditionalField(
            XLongField('verifier', 0), lambda pkt: pkt.status == 0
        ),
        ConditionalField(
            IntField('value_follows', 0), lambda pkt: pkt.status == 0
        ),
        ConditionalField(
            PacketListField(
                'files', None, File_From_Dir,
                next_cls_cb=lambda pkt, lst, cur, remain:
                File_From_Dir if pkt.value_follows == 1 and
                (len(lst) == 0 or cur.value_follows == 1) and
                len(remain) > 4 else None
            ),
            lambda pkt: pkt.status == 0),
        ConditionalField(IntField('eof', 0), lambda pkt: pkt.status == 0)
    ]


bind_layers(RPC, READDIR_Call, mtype=0)
bind_layers(RPC, READDIR_Reply, mtype=1)
bind_layers(
    RPC_Call, READDIR_Call, program=100003, pversion=3, procedure=16
)


class RENAME_Call(Packet):
    name = 'RENAME Call'
    fields_desc = [
        PacketField('dir_from', File_Object(), File_Object),
        PacketField('name_from', Object_Name(), Object_Name),
        PacketField('dir_to', File_Object(), File_Object),
        PacketField('name_to', Object_Name(), Object_Name),
    ]


class RENAME_Reply(Packet):
    name = 'RENAME Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        IntField('af_before_f', 0),
        ConditionalField(
            PacketField('attributes_before_f', WCC_Attr(), WCC_Attr),
            lambda pkt: pkt.af_before_f == 1
        ),
        IntField('af_after_f', 0),
        ConditionalField(
            PacketField('attributes_after_f', Fattr3(), Fattr3),
            lambda pkt: pkt.af_after_f == 1
        ),
        IntField('af_before_t', 0),
        ConditionalField(
            PacketField('attributes_before_t', WCC_Attr(), WCC_Attr),
            lambda pkt: pkt.af_before_t == 1
        ),
        IntField('af_after_t', 0),
        ConditionalField(
            PacketField('attributes_after_t', Fattr3(), Fattr3),
            lambda pkt: pkt.af_after_t == 1
        )
    ]


bind_layers(RPC, RENAME_Call, mtype=0)
bind_layers(RPC, RENAME_Reply, mtype=1)
bind_layers(
    RPC_Call, RENAME_Call, program=100003, pversion=3, procedure=14
)


class LINK_Call(Packet):
    name = 'LINK Call'
    fields_desc = [
        PacketField('filehandle', File_Object(), File_Object),
        PacketField('link_dir', File_Object(), File_Object),
        PacketField('link_name', Object_Name(), Object_Name)
    ]


class LINK_Reply(Packet):
    name = 'LINK Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        IntField('af_file', 0),
        ConditionalField(
            PacketField('file_attributes', Fattr3(), Fattr3),
            lambda pkt: pkt.af_file == 1
        ),
        IntField('af_link_before', 0),
        ConditionalField(
            PacketField('link_attributes_before', WCC_Attr(), WCC_Attr),
            lambda pkt: pkt.af_link_before == 1
        ),
        IntField('af_link_after', 0),
        ConditionalField(
            PacketField('link_attributes_after', Fattr3(), Fattr3),
            lambda pkt: pkt.af_link_after == 1
        )
    ]


bind_layers(RPC, LINK_Call, mtype=0)
bind_layers(RPC, LINK_Reply, mtype=1)
bind_layers(RPC_Call, LINK_Call, program=100003, pversion=3, procedure=15)


class RMDIR_Call(Packet):
    name = 'RMDIR Call'
    fields_desc = [
        PacketField('dir', File_Object(), File_Object),
        PacketField('filename', Object_Name(), Object_Name),
    ]


class RMDIR_Reply(Packet):
    name = 'RMDIR Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        IntField('af_before', 0),
        ConditionalField(
            PacketField('attributes_before', WCC_Attr(), WCC_Attr),
            lambda pkt: pkt.af_before == 1
        ),
        IntField('af_after', 0),
        ConditionalField(
            PacketField('attributes_after', Fattr3(), Fattr3),
            lambda pkt: pkt.af_after == 1
        )
    ]


bind_layers(RPC, RMDIR_Call, mtype=0)
bind_layers(RPC, RMDIR_Reply, mtype=1)
bind_layers(RPC_Call, RMDIR_Call, program=100003, pversion=3, procedure=13)


class READLINK_Call(Packet):
    name = 'READLINK Call'
    fields_desc = [
        PacketField('filehandle', File_Object(), File_Object)
    ]


class READLINK_Reply(Packet):
    name = 'READLINK Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        IntField('attributes_follow', 0),
        ConditionalField(
            PacketField('attributes', Fattr3(), Fattr3),
            lambda pkt: pkt.attributes_follow == 1
        ),
        ConditionalField(
            PacketField('filename', Object_Name(), Object_Name),
            lambda pkt: pkt.status == 0
        )
    ]


bind_layers(RPC, READLINK_Call, mtype=0)
bind_layers(RPC, READLINK_Reply, mtype=1)
bind_layers(
    RPC_Call, READLINK_Call, program=100003, pversion=3, procedure=5
)


class READ_Call(Packet):
    name = 'READ Call'
    fields_desc = [
        PacketField('filehandle', File_Object(), File_Object),
        LongField('offset', 0),
        IntField('count', 0)
    ]


class READ_Reply(Packet):
    name = 'READ Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        IntField('attributes_follow', 0),
        ConditionalField(
            PacketField('attributes', Fattr3(), Fattr3),
            lambda pkt: pkt.attributes_follow == 1
        ),
        ConditionalField(IntField('count', 0), lambda pkt: pkt.status == 0),
        ConditionalField(IntField('eof', 0), lambda pkt: pkt.status == 0),
        ConditionalField(
            IntField('data_length', 0), lambda pkt: pkt.status == 0
        ),
        ConditionalField(
            StrLenField('data', b'', length_from=lambda pkt: pkt.data_length),
            lambda pkt: pkt.status == 0
        ),
        ConditionalField(
            StrLenField(
                'fill', b'', length_from=lambda pkt: (4 - pkt.data_length) % 4
            ),
            lambda pkt: pkt.status == 0
        )
    ]


bind_layers(RPC, READ_Call, mtype=0)
bind_layers(RPC, READ_Reply, mtype=1)
bind_layers(RPC_Call, READ_Call, program=100003, pversion=3, procedure=6)


class MKDIR_Call(Packet):
    name = 'MKDIR Call'
    fields_desc = [
        PacketField('dir', File_Object(), File_Object),
        PacketField('dir_name', Object_Name(), Object_Name),
        PacketField('attributes', Sattr3(), Sattr3)
    ]


class MKDIR_Reply(Packet):
    name = 'MKDIR Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        ConditionalField(
            IntField('handle_follows', 0), lambda pkt: pkt.status == 0
        ),
        ConditionalField(
            PacketField('filehandle', File_Object(), File_Object),
            lambda pkt: pkt.status == 0 and pkt.handle_follows == 1
        ),
        ConditionalField(
            IntField('attributes_follow', 0), lambda pkt: pkt.status == 0
        ),
        ConditionalField(
            PacketField('attributes', Fattr3(), Fattr3),
            lambda pkt: pkt.status == 0 and pkt.attributes_follow == 1
        ),
        IntField('af_before', 0),
        ConditionalField(
            PacketField('dir_attributes_before', WCC_Attr(), WCC_Attr),
            lambda pkt: pkt.af_before == 1
        ),
        IntField('af_after', 0),
        ConditionalField(
            PacketField('dir_attributes_after', Fattr3(), Fattr3),
            lambda pkt: pkt.af_after == 1
        )
    ]


bind_layers(RPC, MKDIR_Call, mtype=0)
bind_layers(RPC, MKDIR_Reply, mtype=1)
bind_layers(RPC_Call, MKDIR_Call, program=100003, pversion=3, procedure=9)


class SYMLINK_Call(Packet):
    name = 'SYMLINK Call'
    fields_desc = [
        PacketField('dir', File_Object(), File_Object),
        PacketField('dir_name', Object_Name(), Object_Name),
        PacketField('attributes', Sattr3(), Sattr3),
        PacketField('link_name', Object_Name(), Object_Name)
    ]


class SYMLINK_Reply(Packet):
    name = 'SYMLINK Reply'
    fields_desc = [
        IntEnumField('status', 0, nfsstat3),
        ConditionalField(
            IntField('handle_follows', 0), lambda pkt: pkt.status == 0
        ),
        ConditionalField(
            PacketField('filehandle', File_Object(), File_Object),
            lambda pkt: pkt.status == 0 and pkt.handle_follows == 1
        ),
        ConditionalField(
            IntField('attributes_follow', 0), lambda pkt: pkt.status == 0
        ),
        ConditionalField(
            PacketField('attributes', Fattr3(), Fattr3),
            lambda pkt: pkt.status == 0 and pkt.attributes_follow == 1
        ),
        IntField('af_before', 0),
        ConditionalField(
            PacketField('dir_attributes_before', WCC_Attr(), WCC_Attr),
            lambda pkt: pkt.af_before == 1
        ),
        IntField('af_after', 0),
        ConditionalField(
            PacketField('dir_attributes_after', Fattr3(), Fattr3),
            lambda pkt: pkt.af_after == 1
        )
    ]


bind_layers(RPC, SYMLINK_Call, mtype=0)
bind_layers(RPC, SYMLINK_Reply, mtype=1)
bind_layers(
    RPC_Call, SYMLINK_Call, program=100003, pversion=3, procedure=10
)
