#!/usr/bin/env python


# Very rudimentary (but fast) validation of recorded data
# Finds all inetx packets and validate no missing sequence numbers


import sys
sys.path.append("..")
import AcraNetwork.Pcap as pcap
import glob
import os.path
import struct
import time
import logging
import argparse
import json


VERSION = "0.1.3"

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
    reset_count = {}
    inetx_pkts_validate = 0
    data_count_bytes = 0
    start_t = time.time()
    loss_count = 0

    for pfile in all_files:
        # To calculate the rate per pcap
        first_pcap_time = None
        last_pcap_time = None
        packet_data_vol = 0
        p = pcap.Pcap(pfile)
        for i, r in enumerate(p):
            if first_pcap_time is None:
                first_pcap_time = r.sec + r.usec * 1e-6
            last_pcap_time = r.sec + r.usec * 1e-6
            packet_data_vol += len(r.payload)
            if len(r.payload) >= (18+0x24):  # For short packets don't try to decode them as inetx
                # pull out the key fields
                (dst_port, udp_len, checksum, control, stream_id, seq) = struct.unpack_from(">HHHIII", r.payload, 0x24)
                if control == args.control:
                    if stream_id in stream_ids:
                        if seq != (stream_ids[stream_id] + 1) % roll_over:
                            if seq < stream_ids[stream_id]:
                                logging.warning("Source Restarted. File={} PktNum={} StreamID={:#0X} PrevSeq={} "
                                                "CurSeq={}".format(pfile, i, stream_id, stream_ids[stream_id], seq, ))
                                reset_count[stream_id] += 1
                            else:
                                loss = seq - ((stream_ids[stream_id] + 1) % roll_over)
                                logging.error("File={} PktNum={} StreamID={:#0X} PrevSeq={} CurSeq={} Lost={}".format(
                                    pfile, i, stream_id, stream_ids[stream_id], seq, loss))
                                loss_count += loss
                    stream_ids[stream_id] = seq
                    reset_count[stream_id] = 0
                    inetx_pkts_validate += 1
                    data_count_bytes += len(r.payload)

        # The data rate at which we are validating
        dr = (data_count_bytes * 8)/(1e6 * (time.time() - start_t))
        try:
            ave_rec_rate_mbps = (packet_data_vol * 8) /(last_pcap_time - first_pcap_time) / 1e6
        except:
            ave_rec_rate_mbps = 0
        sids_found = len(stream_ids)
        info_str = "{} packets validated. Total_data={:.1f}MB Completed file {} Lost={} StreamsFound={} " \
                   "RecRate={:.1f}Mbps ValRate={:.1f}Mbps".format(inetx_pkts_validate,  data_count_bytes/1e6, pfile, loss_count, sids_found,
                                       ave_rec_rate_mbps, dr)
        if loss_count > 0:
            logging.error(info_str)
        else:
            logging.info(info_str)
        if args.verbose:
            if len(stream_ids) > 0:
                logging.info("{:>7s} {:>9s} {:>9s}".format("SID", "Seq", "RstCnt"))
            for s in sorted(stream_ids):
                logging.info("{:#07X} {:9d} {:9d}".format(s, stream_ids[s], reset_count[s]))


if __name__ == '__main__':
    parser = create_parser()
    args = parser.parse_args()
    main(args)
    sys.exit(0)
