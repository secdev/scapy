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
NFT_TABLE="scapy-tproxy"

if [ "$1" == "setup" ]; then
    if ! modprobe nft_tproxy; then
        echo -e "\x1b[31mError: nft_tproxy is required for transparent proxying.\x1b[0m" >&2
        exit 1
    fi
    NFT_SOCKET_AVAILABLE=true
    if ! modprobe nft_socket; then
        echo -e "\x1b[33mWarning: nft_socket is unavailable; skipping the socket-match optimisation.\x1b[0m" >&2
        NFT_SOCKET_AVAILABLE=false
    fi
fi

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
    # All TPROXY rules live in a dedicated nftables table so that
    # iptables-nft (which manages the ip filter/nat/mangle tables)
    # is left untouched.
    # The DIVERT chain is an optimisation. The socket match catches
    # packets from already established sockets. Those are marked as 1
    # then accepted directly so that TPROXY does not run again.
    nft add table ip "$NFT_TABLE"
    nft add chain ip "$NFT_TABLE" DIVERT "{ type filter hook prerouting priority -150; }"
    if [ "$NFT_SOCKET_AVAILABLE" == "true" ]; then
        nft add rule ip "$NFT_TABLE" DIVERT meta l4proto tcp socket transparent 1 meta mark set 1 accept
    fi
    # Also add an OUTPUT rule so that we can test from loopback
    nft add chain ip "$NFT_TABLE" OUTPUT "{ type route hook output priority mangle; policy accept; }"
    # Packets marked with 1 -> use table 100
    ip rule add fwmark 1 lookup 100
    # In routing table 100, all IPs are local to 'vethrelay'
    ip route add local 0.0.0.0/0 dev $IFACE table 100

    echo -e "\n\x1b[32mInterface $IFACE is now setup !\x1b[0m"
    echo -e "\n\x1b[1mIncoming (FORWARD) traffic\x1b[0m"
    echo "  Redirect TCP port 80 to the proxy on port 8080:"
    echo
    printf '\033[36m  nft add rule ip %s DIVERT \\\n      tcp dport 80 tproxy to :8080 meta mark set 0x1 accept\033[0m\n' "$NFT_TABLE"
    echo
    echo -e "\x1b[1mOutgoing traffic (optional)\x1b[0m"
    echo "  Outgoing traffic also requires the Incoming (FORWARD) rule above."
    echo "  To redirect outgoing TCP port 80, additionally add:"
    echo "  Priority 1 excludes the proxy's upstream connections."
    echo
    printf '\033[36m  nft add rule ip %s OUTPUT \\\n      meta priority != 0:1 tcp dport 80 meta mark set 0x1\033[0m\n' "$NFT_TABLE"
    echo
    echo -e "\x1b[1mAllow incoming traffic\x1b[0m"
    echo "  Allow INPUT on the original destination port and incoming interface."
    echo "  Example: TCP port 80 arriving on wlp4s0 (replace <mytable>):"
    echo
    printf '\033[36m  nft add rule ip <mytable> INPUT \\\n      iifname wlp4s0 tcp dport 80 accept\033[0m\n'
    echo
    echo "  Or, using iptables:"
    echo
    echo -e "\x1b[36m  iptables -A INPUT -i wlp4s0 -p tcp --dport 80 -j ACCEPT\x1b[0m"
    echo
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
