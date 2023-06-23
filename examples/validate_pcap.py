#!/usr/bin/env python


# Very rudimentary (but fast) validation of recorded data
# Finds all inetx packets and validate no missing sequence numbers
# It will also take the url to an axn mem and verify data after downloading


import sys

sys.path.append("..")
sys.path.append(".")
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
import datetime
from dataclasses import dataclass, field
import typing


VERSION = "0.4.0"

logging.basicConfig(
    level=logging.INFO, format="%(levelname)-6s %(asctime)-15s %(message)s"
)


@dataclass
class Streams:
    streamid: int
    sequence: int
    pkt_count: int
    start_ts: float
    end_ts: float
    dropcnt: int
    rstcnt: int
    length: int
    datavol: int
    sequence_list: typing.List[int] = field(default_factory=list)

    def pps(self) -> int:
        if self.end_ts - self.start_ts <= 0:
            return 0
        return int(self.pkt_count / (self.end_ts - self.start_ts))

    def bitrate(self) -> int:
        if self.end_ts - self.start_ts <= 0:
            return 0
        return int(self.length * 8 * self.pkt_count / (self.end_ts - self.start_ts))

    def timelen(self) ->float:
        return self.end_ts - self.start_ts

    def drops_to_hist(self):
        bins = 30
        start_seq = self.sequence - self.pkt_count - self.dropcnt
        bin_wdth = int((self.sequence - start_seq) / bins)
        bin_cnt = [0] * bins
        for i in range(bins):
            for s in self.sequence_list:
                #print(f"{i}:{start_seq}:{s}:{bin_wdth}")
                if (start_seq + bin_wdth * i) <= s < (start_seq + bin_wdth * (i + 1)):
                    bin_cnt[i] += 1
        rstring = "|"
        for cnt in bin_cnt:
            if cnt == 0:
                rstring += " "
            else:
                if cnt > 9:
                    cnt = "*"
                rstring += f"{cnt}"
        rstring += "|"
        return rstring


def create_parser():
    # Argument parser
    parser = argparse.ArgumentParser(
        description="Validate inetx sequence numbers quickly in a pcap file"
    )
    # Common
    parser.add_argument(
        "--folder",
        type=str,
        required=True,
        default=None,
        help="folder to parser for pcap files. Can be a URL",
    )
    parser.add_argument(
        "--verbose",
        required=False,
        action="store_true",
        default=False,
        help="verbose mode",
    )
    parser.add_argument(
        "--summary",
        required=False,
        action="store_true",
        default=False,
        help="only print summaries per file",
    )
    parser.add_argument(
        "--control",
        type=int,
        required=False,
        default=0x11000000,
        help="control field value",
    )
    parser.add_argument(
        "--histogram",
        required=False,
        action="store_true",
        default=False,
        help="print a rough histogram of where the drops happened",
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s {}".format(VERSION)
    )

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
            for f, e in json_resp.items():
                all_files.append(e["url"])
                fnames[e["url"]] = f
    else:
        is_url = False
        # Find all the files and sort by extension
        all_files = glob.glob(os.path.join(args.folder, "*.pcap*"))
    all_files.sort()

    # For recording the data
    streams: typing.Dict[int, Streams] = {}
    inetx_pkts_validate = 0
    data_count_bytes = 0
    start_t = time.time()
    loss_count = 0
    loss_data = 0
    total_pkt_count = 0

    for pfile in all_files:
        # To calculate the rate per pcap
        first_pcap_time = None
        last_pcap_time = None
        packet_data_vol = 0
        tmp_folder = "httpdl"
        loss = 0
        floss = 0
        outf = ""

        if is_url:
            CHUNK = 32 * 1024
            if not os.path.exists(tmp_folder):
                mkdir(tmp_folder, 0o755)
            outf = os.path.join(tmp_folder, fnames[pfile])
            sd = time.time()
            with urlopen(pfile) as response, open(outf, "wb") as out_file:
                data_len = 0
                while True:
                    chunk = response.read(CHUNK)
                    if not chunk:
                        break
                    data_len += len(chunk)
                    out_file.write(chunk)

                dlspeed = data_len * 8 / (time.time() - sd) / 1e6
                logging.info(
                    "Downloaded {} at {:.1f}Mbps and wrote to {}".format(
                        pfile, dlspeed, outf
                    )
                )
            p = pcap.Pcap(outf)
        else:
            p = pcap.Pcap(pfile)
        prev_rec_ts = None
        for i, r in enumerate(p):

            if first_pcap_time is None:
                first_pcap_time = r.sec + r.usec * 1e-6

            last_pcap_time = r.sec + r.usec * 1e-6

            # Do a check on the record timestamp
            if prev_rec_ts is not None:
                if prev_rec_ts > last_pcap_time:
                    delta = prev_rec_ts - last_pcap_time
                    logging.warning(
                        f"Record={i + 1} Record timestamp negative jump {delta}s")
            prev_rec_ts = last_pcap_time

            packet_data_vol += len(r.payload)
            total_pkt_count += 1
            if len(r.payload) >= (
                26 + 0x28
            ):  # For short packets don't try to decode them as inetx
                # pull out the key fields
                (
                    dst_port,
                    udp_len,
                    checksum,
                    control,
                    stream_id,
                    seq,
                    _len,
                    ptpsec,
                    ptpnsec
                ) = struct.unpack_from(">HHHIIIIII", r.payload, 0x24)
                if control == args.control:
                    if stream_id in streams:
                        stream = streams[stream_id]
                        if seq != (stream.sequence + 1) % roll_over:
                            pkt_ts = datetime.datetime.fromtimestamp(
                                r.sec + r.usec * 1e-6
                            ).strftime("%H:%M:%S.%f %d %b")
                            if seq < stream.sequence:
                                logging.warning(
                                    "Source Restarted. File={} PktNum={} StreamID={:#0X} PrevSeq={} "
                                    "CurSeq={}".format(
                                        pfile,
                                        i,
                                        stream_id,
                                        stream.sequence,
                                        seq,
                                    )
                                )
                                stream.rstcnt += 1
                            else:
                                loss = seq - ((stream.sequence + 1) % roll_over)
                                if not args.summary:
                                    logging.error(
                                        "File={} TS={} PktNum={} StreamID={:#0X} PrevSeq={} CurSeq={} Lost={} Lost={:,} bytes".format(
                                            pfile,
                                            pkt_ts,
                                            i,
                                            stream_id,
                                            stream.sequence,
                                            seq,
                                            loss,
                                            loss * stream.length
                                        )
                                    )
                                loss_count += loss
                                loss_data += (loss * stream.length)
                                stream.dropcnt += loss
                                stream.sequence_list.append(stream.sequence + 1)
                                floss += loss
                        stream.sequence = seq
                        stream.pkt_count += 1
                        stream.end_ts = ptpsec + ptpnsec/1e9
                        stream.datavol += len(r.payload)
                    else:
                        stream = Streams(stream_id, seq, 1, ptpsec + ptpnsec/1e9,
                                         ptpsec + ptpnsec/1e6, 0, 0, len(r.payload),
                                         len(r.payload), [])
                        streams[stream_id] = stream
                    inetx_pkts_validate += 1
                    data_count_bytes += len(r.payload)
        p.close()
        # The data rate at which we are validating

        try:
            dr = (data_count_bytes * 8) / (1e6 * (time.time() - start_t))
        except:
            dr = 100

        try:
            ave_rec_rate_mbps = (
                (packet_data_vol * 8) / (last_pcap_time - first_pcap_time) / 1e6
            )
        except:
            ave_rec_rate_mbps = 0
        sids_found = len(streams)
        if first_pcap_time is not None:
            file_stamp = datetime.datetime.fromtimestamp(first_pcap_time).strftime(
                "%H:%M:%S %d %b"
            )
        else:
            file_stamp = "unknown"
        info_str = (
            f"In {os.path.basename(pfile)} starting at {file_stamp}, {inetx_pkts_validate:10} packets validated. "
            f"Total_data={data_count_bytes/1e6:8.0f}KB  Lost={floss:5} StreamsFound={sids_found:5} "
            f"RecordRate={ave_rec_rate_mbps:5.0f}Mbps ValRate={dr:5.0f}Mbps"
        )
        if loss > 0:
            logging.error(info_str)
        else:
            logging.info(info_str)
        if args.verbose:
            if len(streams) > 0:
                logging.info(
                    "{:>7s} {:>9s} {:>9s} {:>9s} {:>9s}".format(
                        "SID", "Seq", "LostCount", "ResetCnt", "Length"
                    )
                )
            for sid, stream in streams.items():
                logging.info(
                    "{:#07X} {:9d} {:9d} {:9d} {:9d}".format(
                        sid,
                        stream.sequence,
                        stream.dropcnt,
                        stream.rstcnt,
                        stream.length,
                    )
                )
        if is_url and loss == 0:
            remove(outf)
        elif is_url and not args.verbose:
            remove(outf)
    print("\n")
    if len(streams) > 0:
        logging.info(
            "{:>7s} {:>15s} {:>9s} {:>9s} {:>9s} {:>9s} {:>9s} {:>18s} {:>12s} {:>12s} {:>12s}".format(
                "SID", "Cnt", "LostCount", "ResetCnt", "Length", "PPS", "Mbps", "Elapsed Time(s)",
                "DataVol(MB)", "DropVol(Bytes)", "BitRate(Mbps)"
            )
        )
    for sid, stream in sorted(streams.items()):
        if args.histogram:
            _hist = stream.drops_to_hist()
        else:
            _hist = ""
        logging.info(
            "{:#07X} {:15,d} {:9d} {:9d} {:9d} {:9d} {:9.1f} {:18.1f} {:12,.1f} {:12,d} {:12,.1f} {}".format(
                sid, stream.pkt_count, stream.dropcnt, stream.rstcnt, stream.length,
                stream.pps(), stream.bitrate()/1e6, stream.timelen(), stream.datavol/1e6,
                stream.dropcnt * stream.length, stream.datavol * 8 / (stream.timelen() * 1e6), _hist
            )
        )

    print(
        f"\nSUMMARY:  RXPKTS={total_pkt_count:>15,}  RXINETX={inetx_pkts_validate:>15,}  "
        f"RXBYTES={data_count_bytes//1024:>15,.1f} KB LOSTPKTS={loss_count:>15,}  LOSTDATA={loss_data//1024:>15,.1f} KB"
    )


if __name__ == "__main__":
    parser = create_parser()
    args = parser.parse_args()
    main(args)
    sys.exit(0)
