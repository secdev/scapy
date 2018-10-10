# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# Author: Sylvain SARMEJEANNE

# scapy.contrib.description = Ubberlogger dissectors
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField, ByteField, IntField, ShortField

# Syscalls known by Uberlogger
uberlogger_sys_calls = {0: "READ_ID",
                        1: "OPEN_ID",
                        2: "WRITE_ID",
                        3: "CHMOD_ID",
                        4: "CHOWN_ID",
                        5: "SETUID_ID",
                        6: "CHROOT_ID",
                        7: "CREATE_MODULE_ID",
                        8: "INIT_MODULE_ID",
                        9: "DELETE_MODULE_ID",
                        10: "CAPSET_ID",
                        11: "CAPGET_ID",
                        12: "FORK_ID",
                        13: "EXECVE_ID"}

# First part of the header


class Uberlogger_honeypot_caract(Packet):
    name = "Uberlogger honeypot_caract"
    fields_desc = [ByteField("honeypot_id", 0),
                   ByteField("reserved", 0),
                   ByteField("os_type_and_version", 0)]

# Second part of the header


class Uberlogger_uber_h(Packet):
    name = "Uberlogger uber_h"
    fields_desc = [ByteEnumField("syscall_type", 0, uberlogger_sys_calls),
                   IntField("time_sec", 0),
                   IntField("time_usec", 0),
                   IntField("pid", 0),
                   IntField("uid", 0),
                   IntField("euid", 0),
                   IntField("cap_effective", 0),
                   IntField("cap_inheritable", 0),
                   IntField("cap_permitted", 0),
                   IntField("res", 0),
                   IntField("length", 0)]

# The 9 following classes are options depending on the syscall type


class Uberlogger_capget_data(Packet):
    name = "Uberlogger capget_data"
    fields_desc = [IntField("target_pid", 0)]


class Uberlogger_capset_data(Packet):
    name = "Uberlogger capset_data"
    fields_desc = [IntField("target_pid", 0),
                   IntField("effective_cap", 0),
                   IntField("permitted_cap", 0),
                   IntField("inheritable_cap", 0)]


class Uberlogger_chmod_data(Packet):
    name = "Uberlogger chmod_data"
    fields_desc = [ShortField("mode", 0)]


class Uberlogger_chown_data(Packet):
    name = "Uberlogger chown_data"
    fields_desc = [IntField("uid", 0),
                   IntField("gid", 0)]


class Uberlogger_open_data(Packet):
    name = "Uberlogger open_data"
    fields_desc = [IntField("flags", 0),
                   IntField("mode", 0)]


class Uberlogger_read_data(Packet):
    name = "Uberlogger read_data"
    fields_desc = [IntField("fd", 0),
                   IntField("count", 0)]


class Uberlogger_setuid_data(Packet):
    name = "Uberlogger setuid_data"
    fields_desc = [IntField("uid", 0)]


class Uberlogger_create_module_data(Packet):
    name = "Uberlogger create_module_data"
    fields_desc = [IntField("size", 0)]


class Uberlogger_execve_data(Packet):
    name = "Uberlogger execve_data"
    fields_desc = [IntField("nbarg", 0)]


# Layer bounds for Uberlogger
bind_layers(Uberlogger_honeypot_caract, Uberlogger_uber_h)
bind_layers(Uberlogger_uber_h, Uberlogger_capget_data)
bind_layers(Uberlogger_uber_h, Uberlogger_capset_data)
bind_layers(Uberlogger_uber_h, Uberlogger_chmod_data)
bind_layers(Uberlogger_uber_h, Uberlogger_chown_data)
bind_layers(Uberlogger_uber_h, Uberlogger_open_data)
bind_layers(Uberlogger_uber_h, Uberlogger_read_data)
bind_layers(Uberlogger_uber_h, Uberlogger_setuid_data)
bind_layers(Uberlogger_uber_h, Uberlogger_create_module_data)
bind_layers(Uberlogger_uber_h, Uberlogger_execve_data)
