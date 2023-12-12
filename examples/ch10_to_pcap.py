#!/usr/bin/env python3

# -*- coding: utf-8 -*-


import AcraNetwork.Chapter10.Chapter10 as ch10
import AcraNetwork.Chapter10.Chapter10UDP as ch10udp
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as eth
import argparse
import sys


def create_parser():
    # ----------------------------------
    # Setup the command line parser
    # ----------------------------------
    parser = argparse.ArgumentParser(description="Covert a chapter 10 file to a pcap")
    parser.add_argument("--pcap", required=True, help="The output pcap file")
    parser.add_argument("--ch10", required=True, help="The input chapter 10 file")
    parser.add_argument("--tmats", required=False, default=None, help="Optional TMATS output file")
    return parser


def encapsulate_udppayload_in_eth(udp_payload: bytes):
    """
    Encapsulte the udp payload in an Ethernet packet
    """
    ethpkt = eth.Ethernet()
    ethpkt.dstmac = 0x01005E000001
    ethpkt.srcmac = 0x000C4DAC7AAA
    ethpkt.type = eth.Ethernet.TYPE_IP
    #
    ippkt = eth.IP()
    ippkt.dstip = "235.0.0.2"
    ippkt.srcip = "127.0.0.1"
    # Stick a UDP packet in the payload
    udppkt = eth.UDP()
    udppkt.dstport = 51001
    udppkt.srcport = 51001

    udppkt.payload = udp_payload
    # packet the udp packet into the ethernet payload
    ippkt.payload = udppkt.pack()
    ethpkt.payload = ippkt.pack()
    return ethpkt.pack()


def main(args):
    pf = pcap.Pcap(args.pcap, mode="w")
    fp = ch10.FileParser(args.ch10)
    if args.tmats is not None:
        tf = open(args.tmats, mode="wb")

    idx = 0
    with fp as ch10file:
        for idx, pkt in enumerate(ch10file):
            if args.tmats is not None and idx == 0:
                tf.write(pkt.pack())
                tf.close()
            pr = pcap.PcapRecord()
            pr.set_current_time()
            udp = ch10udp.Chapter10UDP()
            udp.format = 3
            udp.sourceid_len = 0
            udp.sequence = idx
            udp.offset_pkt_start = 0
            udp.payload = pkt.pack()
            pr.payload = encapsulate_udppayload_in_eth(udp.pack())
            pf.write(pr)

    pf.close()
    print(f"Create a pcap with {idx} records")


if __name__ == "__main__":
    parser = create_parser()
    args = parser.parse_args()
    ret = main(args)
    sys.exit(ret)
