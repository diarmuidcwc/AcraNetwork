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
import AcraNetwork.iNetX as inetx
import AcraNetwork.SimpleEthernet as eth
import argparse
import socket
import random
import signal
import configparser
from collections import namedtuple

ConfigSetting = namedtuple("ConfigSetting", ['min', 'max', 'dist', 'alpha', 'beta', 'buildtime'])


def get_default_settings(configfile: str) -> ConfigSetting:
    config = configparser.ConfigParser()
    config.read(configfile)
    min = int(config.get('inetxpayloadlength', 'min', fallback='64'))
    max = int(config.get('inetxpayloadlength', 'max', fallback='1400'))
    dist = (config.get('randomisation', 'distribution', fallback='uniform'))
    alpha = float(config.get('randomisation', 'alpha', fallback='3.0'))
    beta = float(config.get('randomisation', 'beta', fallback='1.0'))
    buildtime = float(config.get('tweaks', 'packetbuildtime', fallback='0.0000070'))
    print(f"Payload Length= {min} to {max}, Distribution={dist} (alpha={alpha} beta={beta}) Tweak={buildtime}")
    return ConfigSetting(min, max, dist, alpha, beta, buildtime)


def create_parser():
    # Argument parser
    parser = argparse.ArgumentParser(description='Send iNetX packets at a specified rate')
    parser.add_argument('--rate', required=False, type=float, default=1.0, help="Packet rate in Mbps")
    parser.add_argument('--ipaddress', required=False, type=str, default="192.168.0.26", help="Destination IP")
    parser.add_argument('--config', required=False, type=str, default="", help="Destination IP")
    parser.add_argument('--datavol', required=False, type=int, default=None, help="Stop after specified bytes")
    parser.add_argument('--sidcount', required=False, type=int, default=1, help="number of stream ids to send")

    return parser


def accurate_sleep(duration, get_now=time.perf_counter):
    now = get_now()
    end = now + duration
    while now < end:
        now = get_now()


def main(args):
    dst_udp_port = 4444
    cfg = get_default_settings(args.config)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    # Create an inetx packet
    myinetx = inetx.iNetX()

    payload_pkts = {}
    bsid = random.randint(0x0, 0xFF) << 8

    FCS_LEN = 4
    PREAMBLE = 8
    hdr_lens = eth.UDP.UDP_HEADER_SIZE + eth.IP.IP_HEADER_SIZE + eth.Ethernet.HEADERLEN + FCS_LEN + PREAMBLE

    tx_pkt_overhead = cfg.buildtime

    total_vol_data = 0
    for idx in range(args.sidcount):
        myinetx.inetxcontrol = inetx.iNetX.DEF_CONTROL_WORD
        myinetx.pif = 0
        myinetx.streamid = bsid + idx
        myinetx.sequence = 0
        if cfg.dist == "beta":
            myinetx.payload = struct.pack(">B", idx+1) * int((cfg.max - cfg.min) * random.betavariate(cfg.alpha, cfg.beta) + cfg.min)
        else:
            myinetx.payload = struct.pack(">B", idx+1) * random.randint(cfg.min, cfg.max)

        myinetx.setPacketTime(int(time.time()))
        packet_payload = myinetx.pack()
        print("iNetX StreamID={:#0X} Length incl headers={}".format(myinetx.streamid, len(packet_payload) + hdr_lens))
        payload_pkts[myinetx.streamid] = {
            'payload': packet_payload, 'length': len(packet_payload) + eth.UDP.UDP_HEADER_SIZE + eth.IP.IP_HEADER_SIZE
                                                 + eth.Ethernet.HEADERLEN}
        pkt_len = len(packet_payload) + 8 + 20 + 14
        total_vol_data += (pkt_len + hdr_lens)

    chunk_count_ps = args.rate * 1e6/(total_vol_data * 8)
    tx_time_vol = total_vol_data * 8 * 1e-9
    gap_per_pkt = (1 - tx_time_vol) / (args.sidcount * chunk_count_ps) - tx_pkt_overhead
    if gap_per_pkt <= 0:
        gap_per_pkt = 0

    pps = int(args.sidcount * chunk_count_ps)
    print("UDP target IP:", args.ipaddress)
    print("UDP target port:", dst_udp_port)
    print("Rate = {} Mbps".format(args.rate))
    print("DLY = {:.6f} s".format(gap_per_pkt))
    print("PPS = {} s".format(pps))

    sequence_roll_over = pow(2, 64)
    pkt_count = {}
    for sid in payload_pkts.keys():
        pkt_count[sid] = 0

    packet_count = 1
    vol_data_sent = 0

    def signal_handler(*args):
        print(f"Exiting. Sent {packet_count:>12,} packets and {vol_data_sent:>15,} bytes")
        sys.exit()

    signal.signal(signal.SIGINT, signal_handler)
    run_sec = 0

    while True:
        random_sid = bsid + (packet_count % args.sidcount)
        random_payload = payload_pkts[random_sid]["payload"]
        # Faster way to build an inetx packet instead of packing the whole header
        mypayload = random_payload[:8] + struct.pack(">I", pkt_count[random_sid]) + random_payload[12:]
        pkt_count[random_sid] = (pkt_count[random_sid] + 1) % sequence_roll_over
        sock.sendto(mypayload, (args.ipaddress, dst_udp_port))
        vol_data_sent += (len(mypayload) + hdr_lens)
        accurate_sleep(gap_per_pkt)
        packet_count += 1
        if packet_count % (pps * 30) == 0:
            run_sec += 30
            print(f"After {run_sec:>8} seconds : {packet_count:>12,} packets sent. {vol_data_sent:>18,} bytes send")
            if args.datavol is not None:
                if vol_data_sent > args.datavol:
                    signal_handler()


if __name__ == '__main__':
    parser = create_parser()
    pargs = parser.parse_args()
    main(pargs)
    sys.exit(0)

