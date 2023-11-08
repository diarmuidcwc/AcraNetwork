import sys
import os

sys.path.append("../")
import AcraNetwork.Chapter10.Chapter10 as ch10
import AcraNetwork.Chapter10.Chapter10UDP as ch10udp
import AcraNetwork.Chapter10.ARINC429 as ch10arinc
import AcraNetwork.Chapter10.UART as ch10uart
import AcraNetwork.Chapter10.PCM as ch10pcm
import AcraNetwork.Chapter10.Analog as ch10analog
import AcraNetwork.Chapter10.MILSTD1553 as ch10mil
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as eth
import argparse
import sys
from dataclasses import dataclass
import logging
from datetime import datetime
import struct
from copy import deepcopy
from AcraNetwork.Chapter10 import (
    DATA_TYPE_ARINC429_FMT0,
    DATA_TYPE_COMPUTER_GENERATED_FORMAT_0,
    DATA_TYPE_COMPUTER_GENERATED_FORMAT_1,
    DATA_TYPE_MILSTD1553_FMT1,
    DATA_TYPE_PCM_DATA_FMT1,
    DATA_TYPE_TIMEFMT_1,
    DATA_TYPE_TIMEFMT_2,
    DATA_TYPE_UART_FMT0,
    DATA_TYPE_ANALOG,
)

import typing


logging.basicConfig(level=logging.DEBUG)


@dataclass
class PTPTime:
    seconds: int
    nanoseconds: int

    def to_rtc(self):
        ptp_as_date = datetime.fromtimestamp(self.seconds)
        start_of_year = datetime(ptp_as_date.year, 1, 1, 0, 0, 0)
        seconds_since_start_year = int((ptp_as_date - start_of_year).total_seconds())
        rtc_time = int(seconds_since_start_year * 1e7 + self.nanoseconds / 100)
        return rtc_time


def create_parser():
    # ----------------------------------
    # Setup the command line parser
    # ----------------------------------
    parser = argparse.ArgumentParser(description="Covert a chapter 10 file to a pcap")
    parser.add_argument("--pcap", required=True, help="The input pcap file")
    parser.add_argument("--ch10", required=True, help="The input chapter 10 file")
    parser.add_argument("--tmats", required=True, help=" TMATS input file")
    return parser


def encapsulate_ch10_ptk(ch10payload: bytes) -> bytes:
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

    fixed_ch10udp = struct.pack(">HH", 0x17C, 0x1911)
    udppkt.payload = fixed_ch10udp + ch10payload
    # packet the udp packet into the ethernet payload
    ippkt.payload = udppkt.pack()
    ethpkt.payload = ippkt.pack()
    return ethpkt.pack()


def encapsulate_tmats(tmats_data: bytes) -> ch10.Chapter10:
    """Wrap the tmats data in a ch10 file for writing to a ch10 file

    Args:
        tmats_data (bytes): _description_

    Returns:
        ch10.Chapter10: _description_
    """
    return ch10.Chapter10()


def get_ch10_time(ptptime: PTPTime, rtctime: int) -> ch10.Chapter10:
    """Return a time packet that maps the seconds / nanoseconds to the rtctime

    Args:
        seconds (int): _description_
        nanoseconds (int): _description_
        rtctime (int): _description_

    Returns:
        ch10.Chapter10: _description_
    """
    return ch10.Chapter10()


def clone_ch10_payload(original_buffer: bytes, datatype: int) -> bytes:
    """Return the payload with the secondary header removed

    Args:
        original_buffer (bytes): _description_

    Returns:
        bytes: _description_
    """
    if datatype == DATA_TYPE_ARINC429_FMT0:
        p = ch10arinc.ARINC429DataPacket()
        p.unpack(original_buffer)
    elif datatype == DATA_TYPE_MILSTD1553_FMT1:
        p = ch10mil.MILSTD1553DataPacket()
        p.unpack(original_buffer)
    elif datatype == DATA_TYPE_UART_FMT0:
        p = ch10uart.UARTDataPacket()
        p.unpack(original_buffer)
    elif datatype == DATA_TYPE_PCM_DATA_FMT1:
        p = ch10pcm.PCMDataPacket(ipts_source=ch10pcm.TS_SECONDARY)
        p.minor_frame_size_bytes = 272
        p.unpack(original_buffer)
        for frame in p:
            logging.debug(f"PCMFrame ipts sec={frame.ipts.sec} nsec={frame.ipts.nanosec}")
            frame_time = PTPTime(frame.ipts.sec, frame.ipts.nanosec)
            frame.ipts = ch10pcm.RTCTime(frame_time.to_rtc())
        return p.pack()
    elif datatype == DATA_TYPE_ANALOG:
        p = ch10analog.Analog()

    else:
        raise Exception(f"Data type {datatype} not supported")


def clone_ch10(original_ch10: ch10.Chapter10) -> ch10.Chapter10:
    """Clone the ch10 packet but remove the secondary header

    Args:
        original_ch10 (ch10.Chapter10): _description_

    Returns:
        ch10.Chapter10: _description_
    """
    new_ch10 = ch10.Chapter10()
    new_ch10.syncpattern = original_ch10.syncpattern
    new_ch10.channelID = original_ch10.channelID
    new_ch10.datatypeversion = original_ch10.datatypeversion
    new_ch10.sequence = original_ch10.sequence
    new_ch10.packetflag = original_ch10.packetflag
    new_ch10.datatype = original_ch10.datatype
    logging.debug(f"Fkags={original_ch10.packetflag:#0X}")
    if original_ch10.packetflag & ch10.Chapter10.PKT_FLAG_SEC_HDR_TIME != 0:
        orig_ptp = PTPTime(original_ch10.ptptimeseconds, original_ch10.ptptimenanoseconds)
        new_ch10.packetflag &= 0x33
        logging.debug(f"Converting time stmaps and overwrite packet flag {new_ch10.packetflag:#0X}")
        new_ch10.relativetimecounter = orig_ptp.to_rtc()
    else:
        new_ch10.relativetimecounter = original_ch10.relativetimecounter
    new_ch10.ts_source = ch10.TS_RTC
    new_ch10.payload = clone_ch10_payload(original_ch10.payload, new_ch10.datatype)
    return new_ch10


def main(args):
    pf = pcap.Pcap(args.pcap, mode="r")
    pf_tmp = pcap.Pcap("temp.pcap", mode="w")
    fp = ch10.FileParser(args.ch10, mode="wb")

    CH10_DATA_OFFSET = 0x2A
    CH10_DATA_LEN_MIN = 30

    prev_time = None
    with fp as ch10file:
        for idx, record in enumerate(pf):
            eth_pkt = record.payload
            if len(eth_pkt) > CH10_DATA_OFFSET + CH10_DATA_LEN_MIN:
                logging.debug(f"Reading record {idx}")
                pkt_payload = eth_pkt[CH10_DATA_OFFSET:]
                ch10udp_pkt = ch10udp.Chapter10UDP()
                ch10_pkt = ch10.Chapter10()
                try:
                    ch10udp_pkt.unpack(pkt_payload)
                    ch10_pkt.unpack(ch10udp_pkt.payload)
                except Exception as e:
                    logging.debug(f"Failed to unpacket record #{idx}. len_buf={len(pkt_payload)} Err={e}")
                    continue
                else:
                    new_ch10_pkt = clone_ch10(ch10_pkt)
                    newrec = pcap.PcapRecord()
                    newrec.sec = record.sec
                    newrec.usec = record.usec
                    newrec.payload = encapsulate_ch10_ptk(new_ch10_pkt.pack())
                    pf_tmp.write(newrec)
                    ch10file.write(new_ch10_pkt)

    pf.close()
    pf_tmp.close()
    fp.close()


if __name__ == "__main__":
    parser = create_parser()
    args = parser.parse_args()
    ret = main(args)
    sys.exit(ret)
