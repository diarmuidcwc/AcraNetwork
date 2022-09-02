#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
===== 
 Sending UDP packets
===== 

Send UDP packets at a specific rate
"""
__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2018"
__version__ = "0.0.5"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


import sys
sys.path.append("..")
import time
import struct
import AcraNetwork.iNetX as inetx
import argparse
import socket
import random
import threading
import queue


parser = argparse.ArgumentParser(description='Send iNetX packets at a specified rate')
parser.add_argument('--rate',required=False, type=int, default=1, help="Packet rate in Mbps")
parser.add_argument('--ipaddress',required=False, type=str, default="192.168.0.26", help="Destination IP")
parser.add_argument('--sidcount',required=False, type=int, default=1, help="number of stream ids to send")
args = parser.parse_args()

# simple application that tests building and sending of iena and inetx packets

UDP_IP = args.ipaddress
UDP_PORT = 4444


def send_to_network(dataq):
    """

    :type dataq: queue.Queue
    :return:
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setblocking(True)
    while True:
        payload = dataq.get(block=True, timeout=5)
        sock.sendto(payload, (UDP_IP, UDP_PORT))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
#sock.mcast_add(UDP_IP)

# Create an inetx packet
myinetx = inetx.iNetX()

payload = struct.pack(">B",0xa5)
sockets = {}
payload_pkts = {}
bsid = random.randint(0x0, 0xFF) << 8
for idx in range(args.sidcount):
    myinetx.inetxcontrol = inetx.iNetX.DEF_CONTROL_WORD
    myinetx.pif = 0
    myinetx.streamid = bsid + idx
    myinetx.sequence = 0
    myinetx.payload = payload * int(1430 * random.betavariate(3, 1))
    print("Sid={:#0X} Len={}".format(myinetx.streamid, len(myinetx.payload)))
    myinetx.setPacketTime(int(time.time()))
    packet_payload = myinetx.pack()
    payload_pkts[myinetx.streamid] = {'payload': packet_payload, 'length': len(packet_payload) + 8 + 20 + 14}
    pkt_len = len(packet_payload) + 8 + 20 + 14

ave_pkt_len = 1000

pps_rate = int(((args.rate * 1024 * 1024) / (ave_pkt_len * 8)) / 100) * 100
if pps_rate < 1:
    pps_rate = 1
burst_length = args.rate // 4
packet_count = 1
data_vol = 0
dly_ms = int((float(burst_length) * ave_pkt_len) / pps_rate)
delta_change_ms = 5

st = time.time()

print("UDP target IP:", UDP_IP)
print("UDP target port:", UDP_PORT)
print("Rate = {} Hz".format(pps_rate))
print("Rate = {} Mbps".format(args.rate))
print("DLY = {} ms".format(dly_ms))

SEQ_ROLL_OVER = pow(2, 64)
pkt_count = {}
for sid in payload_pkts.keys():
    pkt_count[sid] = 0

while True:
    random_sid = bsid + (packet_count % args.sidcount)
    #random_sid = random.randint(0, args.sidcount-1) + bsid
    random_payload = payload_pkts[random_sid]["payload"]
    # Faster way to build an inetx packet instead of packing the whole header
    mypayload = random_payload[:8] + struct.pack(">I", pkt_count[random_sid]) + random_payload[12:]
    pkt_count[random_sid] += 1
    #payloadq.put(mypayload)
    sock.sendto(mypayload, (UDP_IP, UDP_PORT))
    data_vol += (payload_pkts[random_sid]["length"] * 8)
    if packet_count % burst_length == burst_length-1:
        # Report some information
        if dly_ms > 0:
            time.sleep(dly_ms/1e3)
        ct = time.time()
        rate = data_vol / (ct - st) / 1000 / 1000
        pps = int(packet_count // (ct - st))
        #granularity = pps_rate // 10
        error_val = abs(rate - args.rate)
        if packet_count % (burst_length*10) == burst_length-1:
            print("Rate = {:5.1f} Mbps {:6d} pps Dly={:4d}ms Error={:4.1f}".format(rate, pps, dly_ms, error_val))
        # Tweak the delay so we converge to the required pps
        if rate > args.rate:
            dly_ms += int(delta_change_ms * error_val)
        elif rate < args.rate and dly_ms > 0:
            dly_ms -= int(delta_change_ms * error_val)

    packet_count += 1


