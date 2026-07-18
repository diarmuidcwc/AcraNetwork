#!/usr/bin/env python3

# -*- coding: utf-8 -*-
"""
=====
 Sending UDP packets
=====

Send UDP packets at a specific rate
This can be customised by providing an ini file. Format:

[inetxpayloadlength]
min=1300
max=1400
[randomisation]
#distribution=uniform
distribution=beta
alpha=3
beta=1
[tweaks]
packetbuildtime=0.0000070


"""
__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2018"
__version__ = "0.4.0"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


import sys

sys.path.append("..")
import time
import struct
import AcraNetwork.Chapter10.Chapter10 as ch10
import AcraNetwork.SimpleEthernet as SimpleEthernet
import socket
import random
import signal
import AcraNetwork.Pcap as pcap
import AcraNetwork.Chapter10.Chapter10UDP as ch10udp
import os.path
from collections import defaultdict


def accurate_sleep(duration, get_now=time.perf_counter):
    now = get_now()
    end = now + duration
    while now < end:
        now = get_now()


def getEthernetPacket(data: bytes = b""):
    e = SimpleEthernet.Ethernet()
    e.srcmac = 0x001122334455
    e.dstmac = 0x998877665544
    e.type = SimpleEthernet.Ethernet.TYPE_IP
    i = SimpleEthernet.IP()
    i.dstip = "235.0.0.1"
    i.srcip = "192.168.1.1"
    i.protocol = SimpleEthernet.IP.PROTOCOLS["UDP"]
    u = SimpleEthernet.UDP()
    cu = ch10udp.Chapter10UDP()
    cu.format = 1
    cu.payload = data
    u.dstport = 51000
    u.srcport = 51000
    u.payload = cu.pack()
    i.payload = u.pack()
    e.payload = i.pack()
    return e.pack()


def wrap_in_udp_and_pcap(mybuffer, pcapf):
    if os.path.exists(pcapf):
        mode = "a"
    else:
        mode = "w"
    pcapw = pcap.Pcap(pcapf, mode=mode)
    rec = pcap.PcapRecord()
    rec.payload = getEthernetPacket(mybuffer)
    pcapw.write(rec)
    pcapw.close()
    return True


def get_eth_pkt(ch, dtype, seq):
    mych10 = ch10.Chapter10()
    eth_pkt = SimpleEthernet.Ethernet()
    eth_pkt.srcmac = 0x12345
    eth_pkt.dstmac = 0x1005E000000
    eth_pkt.type = 0x88B5
    mych10.datatype = dtype
    mych10.sequence = 0
    mych10.channelID = ch
    mych10.sequence = seq % 0xFF
    mych10.payload = struct.pack(">I", seq) * random.randint(10, 400) + struct.pack(">H", 0xDEAD)
    eth_pkt.payload = mych10.pack()
    # wrap_in_udp_and_pcap(eth_pkt.payload, "debug.pcap")
    return eth_pkt.pack(fcs=True)


def main():

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind(("lo", 0))

    def signal_handler(*args):
        print(f"Exiting. Sent {packet_count:>12,} packets")
        sys.exit()

    signal.signal(signal.SIGINT, signal_handler)
    run_sec = 0

    gap_per_pkt = 0.0001
    packet_count = 0
    seq = defaultdict(int)
    while True:

        if packet_count % 200 == 0:
            ch = 10
            _pkt = get_eth_pkt(ch, 0x11, seq[ch])
        else:
            ch = 11
            _pkt = get_eth_pkt(ch, 0x9, seq[ch])
        seq[ch] += 1
        # print(f"{seq}")
        sock.send(_pkt)
        accurate_sleep(gap_per_pkt)
        packet_count += 1
        if packet_count % (30) == 0:
            run_sec += 30
            print(f"After {run_sec:>8} seconds : {packet_count:>12,} packets sent..")


if __name__ == "__main__":
    main()
    sys.exit(0)
