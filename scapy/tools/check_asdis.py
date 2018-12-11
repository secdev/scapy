#! /usr/bin/env python

from __future__ import print_function
import getopt


def usage():
    print("""Usage: check_asdis -i <pcap_file> [-o <wrong_packets.pcap>]
    -v   increase verbosity
    -d   hexdiff packets that differ
    -z   compress output pcap
    -a   open pcap file in append mode""", file=sys.stderr)


def main(argv):
    PCAP_IN = None
    PCAP_OUT = None
    COMPRESS = False
    APPEND = False
    DIFF = False
    VERBOSE = 0
    try:
        opts = getopt.getopt(argv, "hi:o:azdv")
        for opt, parm in opts[0]:
            if opt == "-h":
                usage()
                raise SystemExit
            elif opt == "-i":
                PCAP_IN = parm
            elif opt == "-o":
                PCAP_OUT = parm
            elif opt == "-v":
                VERBOSE += 1
            elif opt == "-d":
                DIFF = True
            elif opt == "-a":
                APPEND = True
            elif opt == "-z":
                COMPRESS = True

        if PCAP_IN is None:
            raise getopt.GetoptError("Missing pcap file (-i)")

    except getopt.GetoptError as e:
        print("ERROR: %s" % e, file=sys.stderr)
        raise SystemExit

    from scapy.config import conf
    from scapy.utils import RawPcapReader, RawPcapWriter, hexdiff
    from scapy.layers import all  # noqa: F401

    pcap = RawPcapReader(PCAP_IN)
    pcap_out = None
    if PCAP_OUT:
        pcap_out = RawPcapWriter(PCAP_OUT, append=APPEND, gz=COMPRESS, linktype=pcap.linktype)  # noqa: E501
        pcap_out._write_header(None)

    LLcls = conf.l2types.get(pcap.linktype)
    if LLcls is None:
        print(" Unknown link type [%i]. Can't test anything!" % pcap.linktype, file=sys.stderr)  # noqa: E501
        raise SystemExit

    i = -1
    differ = 0
    failed = 0
    for p1, meta in pcap:
        i += 1
        try:
            p2d = LLcls(p1)
            p2 = str(p2d)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print("Dissection error on packet %i: %s" % (i, e))
            failed += 1
        else:
            if p1 == p2:
                if VERBOSE >= 2:
                    print("Packet %i ok" % i)
                continue
            else:
                print("Packet %i differs" % i)
                differ += 1
                if VERBOSE >= 1:
                    print(repr(p2d))
                if DIFF:
                    hexdiff(p1, p2)
        if pcap_out is not None:
            pcap_out.write(p1)
    i += 1
    correct = i - differ - failed
    print("%i total packets. %i ok, %i differed, %i failed. %.2f%% correct." % (i, correct, differ,  # noqa: E501
                                                                                failed, i and 100.0 * (correct) / i))  # noqa: E501


if __name__ == "__main__":
    import sys
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        print("Interrupted by user.", file=sys.stderr)
