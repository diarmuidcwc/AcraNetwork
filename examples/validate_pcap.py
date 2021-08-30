#!/usr/bin/env python


# Very rudimentary (but fast) validation of recorded data
# Tell it what port the iNetX payload is on and it will find and
# validate that no data is dropped

import sys
sys.path.append("..")
import AcraNetwork.Pcap as pcap
import glob
import os.path
import struct
import time
import logging
import argparse

VERSION = "0.1.1"

logging.basicConfig(level=logging.INFO, format='%(levelname)-6s %(asctime)-15s %(message)s')


def create_parser():
    # Argument parser
    parser = argparse.ArgumentParser(description='Validate inetx sequence numbers quickly in a pcap file')
    # Common
    parser.add_argument('--dir',  type=str, required=True, default=None, help='directory to parser for pcap files')
    parser.add_argument('--verbose', required=False, action='store_true', default=False,    help="verbose mode")
    parser.add_argument('--control', type=int, required=False, default=0x11000000, help='control field value')
    parser.add_argument('--version', action='version', version='%(prog)s {}'.format(VERSION))

    return parser

# recorder data
# tcpdump -i eth0 -W 999 -C 1000 -n -K -s 2000 -w rec.pcap.


def main(args):
    roll_over = pow(2, 32)

    # Find all the files and sort by extension
    all_files = glob.glob(os.path.join(args.dir, "*.pcap*"))
    all_files.sort()

    # For recording the data
    stream_ids = {}
    inetx_pkts_validate = 0
    data_count_bytes = 0
    start_t = time.time()
    loss_count = 0

    for pfile in all_files:
        p = pcap.Pcap(pfile)
        for i, r in enumerate(p):
            if len(r.payload) >= (18+0x24):  # For short packets don't try to decode them as inets
                # pull out the key fields
                (dst_port, udp_len, checksum, control, stream_id, seq) = struct.unpack_from(">HHHIII", r.payload, 0x24)
                if control == args.control:
                    if stream_id in stream_ids:
                        if seq != (stream_ids[stream_id] + 1) % roll_over:
                            loss = seq - ((stream_ids[stream_id] + 1) % roll_over)
                            logging.error("File={} PktNum={} StreamID={:#0X} PrevSeq={} CurSeq={} Lost={}".format(pfile, i, stream_id, stream_ids[stream_id], seq, loss))
                            loss_count += loss
                    stream_ids[stream_id] = seq
                    inetx_pkts_validate += 1
                    data_count_bytes += len(r.payload)

        # The data rate at which we are validating
        dr = data_count_bytes/(1e6 * (time.time() - start_t))

        sids = ""
        for s in stream_ids:
            sids += "{:#05X} ".format(s)
        logging.info("{} packets validated at {:.0f}MB/s. Total_data={:.1f}MB Completed file {} Lost={} IDs={}".format(
            inetx_pkts_validate, dr,  data_count_bytes/1e6, pfile, loss_count, sids))


if __name__ == '__main__':
    parser = create_parser()
    args = parser.parse_args()
    main(args)
    sys.exit(0)
