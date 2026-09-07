#!/bin/bash

# Setup nftables for IP relay by creating an interface configured
# to be the destination of TPROXY rules. All nft rules live in a
# dedicated 'scapy-tproxy' table.

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
NFT_TABLE="scapy-tproxy"

# Linux doc about TPROXY and example regarding this:
# https://www.kernel.org/doc/Documentation/networking/tproxy.txt
# https://powerdns.org/tproxydoc/tproxy.md.html

function checkSetup() {
    nft list table ip "$NFT_TABLE" >/dev/null 2>&1
    return $?
}

if [ "$1" == "setup" ]; then
    # Add the scapy-tproxy table if it doesn't exist
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
    # All TPROXY rules live in a dedicated nftables table so that
    # iptables-nft (which manages the ip filter/nat/mangle tables)
    # is left untouched.
    # The DIVERT chain is an optimisation. The socket match catches
    # packets from already established sockets. Those are marked as 1
    # then accepted directly so that TPROXY does not run again.
    nft "add table ip "$NFT_TABLE""
    nft "add chain ip "$NFT_TABLE" DIVERT"
    nft "add chain ip "$NFT_TABLE" PREROUTING { type filter hook prerouting priority mangle; policy accept; }"
    nft "add rule ip "$NFT_TABLE" PREROUTING ip protocol tcp socket wildcard 0 jump DIVERT"
    nft "add rule ip "$NFT_TABLE" DIVERT meta mark set 0x1"
    nft "add rule ip "$NFT_TABLE" DIVERT accept"
    # Packets marked with 1 are routed through table 100 instead of the
    # default routing table
    ip rule add fwmark 1 lookup 100
    # In routing table 100, all IPs are local to 'vethrelay'
    ip route add local 0.0.0.0/0 dev $IFACE table 100
    echo -e "\x1b[32mInterface $IFACE is now setup with IPv4: $IP !\x1b[0m\n"
    echo -e "Add listening rules as follow:\n"
    echo "# TPROXY incoming TCP packets on port 80 to $IFACE on port 8080"
    echo "nft add rule ip "$NFT_TABLE" PREROUTING tcp dport 80 meta mark set 0x1 tproxy ip to $IP:8080 accept"
    echo
    echo "# Note: you need to allow INPUT on the port that you are adding a listening rule on. For instance, to listen"
    echo "# on wlp4s0 for incoming packets on port 80 (on the interface where it really comes from), one can do"
    echo "nft add rule ip <mytable> INPUT iifname <wlp4s0 tcp dport 80 accept"
    echo "# or using iptables"
    echo "iptables -A INPUT -i wlp4s0 -p tcp --dport 80 -j ACCEPT"
elif [ "$1" == "unsetup" ]; then
    checkSetup
    if [ $? -ne 0 ]; then
        echo "vethrelay not setup !"
        exit 1
    fi
    # Remove all setup rules by deleting the whole nftables table
    ip rule del fwmark 1 lookup 100
    ip route del local 0.0.0.0/0 dev $IFACE table 100
    nft delete table ip "$NFT_TABLE"
    ip link del dev $IFACE
    echo -e "\x1b[32mInterface $IFACE unsetup !\x1b[0m"
fi
