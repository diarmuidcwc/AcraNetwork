#!/usr/bin/env python


# Very rudimentary (but fast) validation of recorded data
# Finds all inetx packets and validate no missing sequence numbers
# It will also take the url to an axn mem and verify data after downloading


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
from urllib.parse import urlparse
from urllib.request import urlopen
from os import mkdir, remove


VERSION = "0.1.4"

logging.basicConfig(level=logging.INFO, format='%(levelname)-6s %(asctime)-15s %(message)s')


def create_parser():
    # Argument parser
    parser = argparse.ArgumentParser(description='Validate inetx sequence numbers quickly in a pcap file')
    # Common
    parser.add_argument('--folder',  type=str, required=True, default=None, help='folder to parser for pcap files. Can be a URL')
    parser.add_argument('--verbose', required=False, action='store_true', default=False,    help="verbose mode")
    parser.add_argument('--control', type=int, required=False, default=0x11000000, help='control field value')
    parser.add_argument('--version', action='version', version='%(prog)s {}'.format(VERSION))

    return parser

# recorder data
# tcpdump -i eth0 -W 999 -C 1000 -n -K -s 2000 -w rec.pcap.


def uri_validator(x):
    try:
        result = urlparse(x)
        return all([result.scheme, result.netloc])
    except:
        return False


def main(args):
    roll_over = pow(2, 32)
    fnames = {}

    if uri_validator(args.folder):
        is_url = True
        all_files = []
        with urlopen(args.folder) as response:
            response_content = response.read()
            json_resp = json.loads(response_content)
            for f,e in json_resp.items():
                all_files.append(e["url"])
                fnames[e["url"]] = f
    else:
        is_url = False
        # Find all the files and sort by extension
        all_files = glob.glob(os.path.join(args.folder, "*.pcap*"))
    all_files.sort()

    # For recording the data
    stream_ids = {}
    reset_count = {}
    lost_sid_count = {}
    packet_lengths = {}
    inetx_pkts_validate = 0
    data_count_bytes = 0
    start_t = time.time()
    loss_count = 0

    for pfile in all_files:
        # To calculate the rate per pcap
        first_pcap_time = None
        last_pcap_time = None
        packet_data_vol = 0
        tmp_folder = "httpdl"
        loss = 0
        outf = ""

        if is_url:
            CHUNK = 32 * 1024
            if not os.path.exists(tmp_folder):
                mkdir(tmp_folder, 0o755)
            outf = os.path.join(tmp_folder , fnames[pfile])
            sd = time.time()
            with urlopen(pfile) as response, open(outf, 'wb') as out_file:
                data_len = 0
                while True:
                    chunk = response.read(CHUNK)
                    if not chunk:
                        break
                    data_len += len(chunk)
                    out_file.write(chunk)

                dlspeed = data_len * 8 / (time.time() - sd) / 1e6
                logging.info("Downloaded {} at {:.1f}Mbps and wrote to {}".format(pfile, dlspeed, outf))
            p = pcap.Pcap(outf)
        else:
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
                                lost_sid_count[stream_id] += loss
                    if stream_id not in reset_count:
                        reset_count[stream_id] = 0
                        lost_sid_count[stream_id] = 0
                        packet_lengths[stream_id]  = len(r.payload)
                    stream_ids[stream_id] = seq
                    inetx_pkts_validate += 1
                    data_count_bytes += len(r.payload)

        p.close()
        # The data rate at which we are validating
        dr = (data_count_bytes * 8)/(1e6 * (time.time() - start_t))
        try:
            ave_rec_rate_mbps = (packet_data_vol * 8) /(last_pcap_time - first_pcap_time) / 1e6
        except:
            ave_rec_rate_mbps = 0
        sids_found = len(stream_ids)
        info_str = "{} packets validated. Total_data={:.0f}MB Completed file {} Lost={} StreamsFound={} " \
                   "RecordRate={:.0f}Mbps ValRate={:.0f}Mbps".format(inetx_pkts_validate,  data_count_bytes/1e6, pfile, loss_count, sids_found,
                                       ave_rec_rate_mbps, dr)
        if loss > 0:
            logging.error(info_str)
        else:
            logging.info(info_str)
        if args.verbose:
            if len(stream_ids) > 0:
                logging.info("{:>7s} {:>9s} {:>9s} {:>9s} {:>9s}".format("SID", "Seq", "LostCount", "ResetCnt", "Length"))
            for s in sorted(stream_ids):
                logging.info("{:#07X} {:9d} {:9d} {:9d} {:9d}".format(s, stream_ids[s], lost_sid_count[s], reset_count[s], packet_lengths[s]))
        if is_url and loss == 0:
            remove(outf)
        elif is_url and not args.verbose:
            remove(outf)

    if len(stream_ids) > 0:
        logging.info("{:>7s} {:>9s} {:>9s} {:>9s} {:>9s}".format("SID", "Seq", "LostCount", "ResetCnt", "Length"))
    for s in sorted(stream_ids):
        logging.info("{:#07X} {:9d} {:9d} {:9d} {:9d}".format(s, stream_ids[s],  lost_sid_count[s], reset_count[s], packet_lengths[s]))

    print("\nSUMMARY: RXPKTS={} RXBYTES={} LOSTPKTS={}".format(inetx_pkts_validate, data_count_bytes, loss_count))


if __name__ == '__main__':
    parser = create_parser()
    args = parser.parse_args()
    main(args)
    sys.exit(0)
