#!/usr/bin/env python

import socket
import struct
import time
import sys
import argparse
import subprocess
import os


VERSION = "0.2.0"



def create_parser():
    # Argument parser
    parser = argparse.ArgumentParser(description='Validate inetx sequence numbers quickly')
    # Common
    parser.add_argument('--port',  type=int, required=False, default=8010,
                        help='UDP port to listen to')
    parser.add_argument('--multicastaddr',  type=str, required=False, default="235.0.0.1",
                        help='multicast address to listen to')
    parser.add_argument('--verbose', required=False, action='store_true', default=False,    help="verbose mode")
    parser.add_argument('--version', action='version', version='%(prog)s {}'.format(VERSION))

    return parser

def open_socket(args):
    server_address = ('', args.port)

    # Create the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(10)

    # Bind to the server address
    sock.bind(server_address)
    # Tell the operating system to add the socket to the multicast group
    # on all interfaces.
    group = socket.inet_aton(args.multicastaddr)
    mreq = struct.pack('4sL', group, socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    if os.name != 'nt':
        # Hack to get Limux to deliver mcast packets to python
        subprocess.call(["/sbin/route", "add", args.multicastaddr, "enp2s0"])

    return sock

def main(args):
    sock = open_socket(args)

    # Guts of the program
    sequence_count = {}
    sequence_error_count = {}
    pkt_count = 0
    err_cnt = 0
    seq_rollover = pow(2,32)


    start_time = time.time()
    while True:
        data, address = sock.recvfrom(2048)
        (streamid, sequence) = struct.unpack_from(">II", data, 4)
        if streamid in sequence_count:
            if (sequence_count[streamid] + 1) % seq_rollover != sequence:
                print ("ERROR: Seq error on {:#0X}. Prev={} Current={} Lost={} Time={}".format(
                    streamid, sequence_count[streamid], sequence, sequence-sequence_count[streamid], time.strftime("%X %x")))
                err_cnt += 1
                sequence_error_count[streamid] += 1
        sequence_count[streamid] = sequence
        sequence_error_count[streamid] = 0
        pkt_count += 1

        if pkt_count % 10000 == 0:
            cur_time = time.time()
            print ("INFO: Received {} packets in {:4.0f} seconds. Error Count={}".format(pkt_count, cur_time - start_time, err_cnt))
            for stream, seq in sequence_count.iteritems():
                print ("INFO: StreamID={:#0X} CurSeq={}".format(stream, seq))


            sys.stdout.flush()

if __name__ == '__main__':
    parser = create_parser()
    args = parser.parse_args()
    main(args)
    sys.exit(0)
