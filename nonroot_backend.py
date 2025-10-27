import socket, threading, queue, os, sys
from scapy.config import conf
from scapy.data import MTU
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.utils import hexdump

# ===============================================================
#  Non-root compatible backend (UDP-based emulation)
# ===============================================================

class NonRootL3Socket:
    def __init__(self, iface=None, port=55555, debug=False):
        self.port = port
        self.iface = iface or "0.0.0.0"
        self.debug = debug

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.iface, port))

        self.recv_queue = queue.Queue()
        self.running = True
        self.listener = threading.Thread(target=self._recv_loop, daemon=True)
        self.listener.start()

        if self.debug:
            print(f"[+] UDP socket bound on {self.iface}:{self.port}")

    def send(self, pkt):
        """Send a packet using UDP encapsulation."""
        try:
            ip = pkt.getlayer(IP)
            if not ip:
                raise ValueError("Packet has no IP layer")

            dst = ip.dst
            payload = bytes(pkt)

            self.sock.sendto(payload, (dst, self.port))

            if self.debug:
                print(f"[>] Sent {len(payload)} bytes to {dst}:{self.port}")
        except Exception as e:
            if self.debug:
                print(f"[!] Send error: {e}")

    def _recv_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(MTU)
                self.recv_queue.put((data, addr))
            except Exception:
                break

    def recv(self, timeout=None):
        """Receive and return a parsed IP packet."""
        try:
            data, addr = self.recv_queue.get(timeout=timeout)
            pkt = IP(data)
            if self.debug:
                print(f"[<] Received {len(data)} bytes from {addr}")
            return pkt
        except queue.Empty:
            return None
        except Exception:
            return None

    def close(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass

# ===============================================================
#  Root-optional Sniffer
# ===============================================================

def sniff_nonroot(count=0, timeout=None, iface=None, port=55555, debug=False):
    """Emulated sniff() using UDP sockets for non-root."""
    sock = NonRootL3Socket(iface=iface, port=port, debug=debug)
    packets = []

    print(f"[~] Sniffing on {iface or '0.0.0.0'}:{port} ... Ctrl+C to stop")

    try:
        while True:
            pkt = sock.recv(timeout=timeout)
            if pkt:
                packets.append(pkt)
                if debug:
                    print(pkt.summary())
                if count and len(packets) >= count:
                    break
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

    print(f"[+] Captured {len(packets)} packets")
    return packets

# ===============================================================
#  Enable backend (auto root detection)
# ===============================================================

def enable_nonroot_backend(debug=False):
    """Enable safe Scapy backend that works without root."""
    is_root = (os.geteuid() == 0 if hasattr(os, "geteuid") else False)
    conf.use_pcap = False
    conf.use_dnet = False
    conf.L3socket = NonRootL3Socket

    if is_root:
        print("[+] Root privileges detected — full Scapy functionality available.")
    else:
        print("[*] Non-root mode active (UDP emulation)")
        print("    sudo is optional: run with 'sudo python3 script.py' for full access")

    if debug:
        print(f"    [i] Conf: use_pcap={conf.use_pcap}, use_dnet={conf.use_dnet}")

# ===============================================================
#  Example usage
# ===============================================================

if __name__ == "__main__":
    enable_nonroot_backend(debug=True)

    # Example: send & sniff test
    pkt = IP(dst="127.0.0.1") / UDP(dport=55555) / Raw(load="Hello, Scapy!")
    s = NonRootL3Socket(port=55555, debug=True)
    s.send(pkt)

    print("\n--- Sniffing for replies ---")
    pkts = sniff_nonroot(count=2, timeout=3, port=55555, debug=True)
    for p in pkts:
        hexdump(p)
