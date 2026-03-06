#!/bin/bash

# Setup iptables for IP relay by creating an interface configured
# to be the destination of TPROXY rules.

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

if [ "$1" != "setup" ] && [ "$1" != "unsetup" ]; then
    echo -e "Usage: ./vethrelay <setup/unsetup>\n"
    exit 1
fi

IFACE="vethrelay"
IP="2.2.2.2"

# Linux doc about TPROXY and example regarding this:
# https://www.kernel.org/doc/Documentation/networking/tproxy.txt
# https://powerdns.org/tproxydoc/tproxy.md.html

function checkSetup() {
    iptables -t mangle -n --list "DIVERT" >/dev/null 2>&1
    return $?
}

if [ "$1" == "setup" ]; then
    # Add "DIVERT" chain if it doesn't exist
    checkSetup
    if [ $? -eq 0 ]; then
        echo "vethrelay already setup !"
        exit 1
    fi
    # Create an interface tcpreplay dedicated to relay
    ip link add dev $IFACE type dummy
    sysctl net.ipv6.conf.$IFACE.disable_ipv6=1 >/dev/null
    ip link set dev $IFACE up
    ip addr add dev $IFACE $IP/32
    # Create mangle "DIVERT" chain as an optimisation. -m socket matches
    # packets from already established sockets. Those are marked as 1 then
    # accepted directly.
    iptables -t mangle -N DIVERT
    iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
    iptables -t mangle -A DIVERT -j MARK --set-mark 1
    iptables -t mangle -A DIVERT -j ACCEPT
    # Packets marked with 1 are routed through table 100 instead of the
    # default routing table
    ip rule add fwmark 1 lookup 100
    # In routing table 100, all IPs are local to 'vethrelay'
    ip route add local 0.0.0.0/0 dev $IFACE table 100
    echo -e "\x1b[32mInterface $IFACE is now setup with IPv4: $IP !\x1b[0m\n"
    echo -e "Add listening rules as follow:\n"
    echo "# TPROXY incoming TCP packets on port 80 to $IFACE on port 8080"
    echo "iptables -t mangle -A PREROUTING -p tcp --dport 80 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 8080 --on-ip $IP"
    echo
    echo "# Listen on wlp4s0 for incoming packets on port 80 (on the interface where it really comes from)"
    echo "iptables -A INPUT -i wlp4s0 -p tcp --dport 80 -j ACCEPT"
elif [ "$1" == "unsetup" ]; then
    checkSetup
    if [ $? -ne 0 ]; then
        echo "vethrelay not setup !"
        exit 1
    fi
    # Remove all setup rules
    sudo ip rule del fwmark 1 lookup 100
    sudo ip route del local 0.0.0.0/0 dev $IFACE table 100
    sudo iptables -t mangle -D DIVERT -j ACCEPT
    sudo iptables -t mangle -D DIVERT -j MARK --set-mark 1
    sudo iptables -t mangle -D PREROUTING -p tcp -m socket -j DIVERT
    sudo iptables -t mangle -X DIVERT
    sudo ip link del dev $IFACE
    echo -e "\x1b[32mInterface $IFACE unsetup !\x1b[0m"
fi
