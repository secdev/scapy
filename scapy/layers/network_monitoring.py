import os
from yattag import Doc, indent
from pathlib import Path

from scapy.config import conf
from scapy.sendrecv import send, sniff
from scapy.layers.inet import IP, TCP


class PktTCP(object):
    def __init__(self, src, dst, tcp_sport, tcp_dport, tcp_seq, tcp_ack, ip_version, ip_ttl):
        self.src = src
        self.dst = dst
        self.tcp_sport = tcp_sport
        self.tcp_dport = tcp_dport
        self.tcp_seq = tcp_seq
        self.tcp_ack = tcp_ack
        self.ip_version = ip_version
        self.ip_ttl = ip_ttl


class NetworkMonitoring(object):
    def __init__(self, protocol="tcp", timeout=10):
        self.protocol = protocol
        self.timeout = timeout
        self.packages = []
        self.path_file = str(Path.home())
        self.name_file = '{}/index.html'.format(self.path_file)

    def get_packages(self, pkt):
        new_pkt = PktTCP(
            pkt.src,
            pkt.dst,
            pkt[TCP].sport,
            pkt[TCP].dport,
            pkt[TCP].seq,
            pkt[TCP].ack,
            pkt[IP].version,
            pkt[IP].ttl
        )

        self.packages.append(new_pkt)

    def get_sniff(self):
        sniff(
           prn=self.get_packages,
           filter=self.protocol,
           timeout=self.timeout
        )
        self.generate_file()

    def generate_file(self):
        doc, tag, text, line = Doc().ttl()

        doc.asis('<!DOCTYPE html>')

        with tag('html'):
            with tag('head'):
                doc.asis('<meta charset="utf-8">')
                doc.asis('<meta name="viewport" content="width=device-width, initial-scale=1">')
                doc.asis('<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css" integrity="sha384-9aIt2nRpC12Uk9gS9baDl411NQApFmC26EwAOH8WgZl5MYYxFfc+NcPb1dKGj7Sk" crossorigin="anonymous">')
            with tag('body'):
                with tag('table', klass="table"):
                    with tag('thead', klass="thead-dark"):
                        with tag('tr'):
                            line('th', 'IP Origem/Porta')
                            line('th', 'IP Destino/Porta')
                            line('th', 'Seq/Ack')
                            line('th', 'Version IP')
                            line('th', 'TTL')
                    with tag('tbody'):
                        for pkt in self.packages:
                            with tag('tr'):
                                line('td', '{}/{}'.format(
                                    pkt.src, pkt.tcp_sport
                                    )
                                )
                                line('td', '{}/{}'.format(
                                    pkt.dst,
                                    pkt.tcp_dport
                                    )
                                )
                                line('td', '{}/{}'.format(
                                    pkt.tcp_seq,
                                    pkt.tcp_ack
                                    )
                                )
                                line('td', '{}'.format(
                                    pkt.ip_version
                                    )
                                )
                                line('td', '{}'.format(
                                    pkt.ip_ttl
                                    )
                                )
        result = indent(
            doc.getvalue(),
            indentation = '    ',
            newline = '\r\n',
            indent_text = True
        )
        arq = open(self.name_file, 'w')
        arq.write(result)
        arq.close()

@conf.commands.register
def monitoring_network(protocol="tcp", timeout=10):
    net = NetworkMonitoring(protocol, timeout)
    net.get_sniff()

if __name__ == '__main__':
    net = NetworkMonitoring("wlp2s0")
    net.get_sniff()
