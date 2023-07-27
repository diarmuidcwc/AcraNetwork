#!/usr/bin/env python3

# -*- coding: utf-8 -*-
"""
Generate a chapter10 file emulating a BCU chatper 10 PCM frame and tmats file from TTCWare
"""
__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2018"
__version__ = "0.1.0"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


import sys
sys.path.append("..")
import time
import struct
import AcraNetwork.Chapter10.Chapter10 as ch10
import AcraNetwork.Chapter10.ComputerData as ch10computer
import AcraNetwork.Chapter10.TimeDataFormat as ch10time
import AcraNetwork.Chapter10.PCM as ch10pcm
from AcraNetwork.Chapter10 import DATA_TYPE_COMPUTER_GENERATED_FORMAT_1, DATA_TYPE_TIMEFMT_2, DATA_TYPE_TIMEFMT_1, DATA_TYPE_PCM_DATA_FMT1
import argparse
from collections import namedtuple
from dataclasses import dataclass
import typing
from math import floor
import logging
from decimal import Decimal


logging.basicConfig(level=logging.INFO)


class PTPTime(object):

    def __init__(self, second, nanosecond):
        self.second : int = second
        self.nanosecond: int = nanosecond

    def __add__(self, other):
        if not isinstance(other, PTPTime):
            raise Exception("Add PTPTime ")
        nsn = self.nanosecond + other.nanosecond
        overflow = int(nsn // 1e9)
        remainder = int(nsn % 1e9)
        result = PTPTime(self.second + overflow + other.second, remainder)
        return result
    
    def __eq__(self, __value) -> bool:
        if __value.second == self.second and __value.nanosecond == self.nanosecond:
            return True
        else:
            return False
        
    def __repr__(self) -> str:
        return f"sec={self.second} ns={self.nanosecond}"

ONE_SECOND = PTPTime(1, 0)

class PCMFrame(object):
    def __init__(self, wordcount: int = 32) -> None:
        self.wordcount = wordcount
        self.payload = b''

    def fixed_frame(self, sfid, readcount) -> None:
        """
        Populate a fixed from to look like TTCWare frame
        """
        words = [0xfe6b, 0x2840]  + [sfid, readcount] + list(range(self.wordcount - 4))
        self.payload = struct.pack(f"<{self.wordcount}H", *words)
    
    def pack(self):
        return self.payload



def create_parser():
    # Argument parser
    parser = argparse.ArgumentParser(description='Send iNetX packets at a specified rate')
    parser.add_argument('--tmats', required=True, type=str,  help="TMATs file to include")
    parser.add_argument('--ch10file', required=True, type=str, help="chapter10 file")

    return parser


def ptp_to_rtc(ptp_time_seconds: PTPTime) -> int:
    """
    Convert a time to PTP
    """
    ns_conv = Decimal(ptp_time_seconds.second) * Decimal(1e9) + Decimal(ptp_time_seconds.nanosecond)
    div_conv = ns_conv / Decimal(100)
    conv_int = int(div_conv) & (pow(2,48) - 1)
    #logging.debug(f"{ptp_time_seconds} {ns_conv} {div_conv} {conv_int}")
    #sys.exit(1)
    return conv_int



def get_tmats_ch10(tmatsfname: str, rtctime: int) -> ch10.Chapter10:
    """
    Get a TMATS ch10 packet with the specified rtctime and tmats file embedded
    """
    tmats_record = ch10.Chapter10()
    tmats_record.channelID = 0x0
    tmats_record.datatype = DATA_TYPE_COMPUTER_GENERATED_FORMAT_1
    tmats_record.relativetimecounter = rtctime
    tmats_record.datatypeversion = 0x1
    tmats_payload = ch10computer.ComputerGeneratedFormat1()
    
    with open(tmatsfname, mode='rb') as f:
        tmats_payload.payload = f.read()
    tmats_record.payload = tmats_payload.pack()

    return tmats_record
    
def get_time_pkt(run_time_s: int, starttime: PTPTime, delta_s: PTPTime = ONE_SECOND, 
                 format: int = 1) -> typing.Generator[ch10.Chapter10, None, None]:
    """
    Generate a time packet
    """

    run_time = starttime
    
    for sequence in range(run_time_s):

        rtc_time = ptp_to_rtc(run_time)
        pkt = ch10.Chapter10()
        pkt.sequence = sequence
        if format == 1:
            time_fmt = ch10time.TimeDataFormat1()
            pkt.datatype = DATA_TYPE_TIMEFMT_1
            time_fmt.channel_specific_data = 0x1
        else:
            time_fmt = ch10time.TimeDataFormat2()
            pkt.datatype = DATA_TYPE_TIMEFMT_2
            time_fmt.channel_specific_data = 0x11
        
        time_fmt.seconds = run_time.second
        time_fmt.nanoseconds = run_time.nanosecond
        
        pkt.channelID = 0x280
        pkt.datatypeversion = 0x1
        pkt.relativetimecounter = rtc_time
        
        pkt.payload = time_fmt.pack()
        run_time += delta_s
        yield pkt
            

def get_pcm_pkt(count: int, starttime: PTPTime, subframe_cnt: int, start_seq: int,
                sample_rate: int = 100,
                minor_frm_size: int = 32) -> typing.Generator[ch10.Chapter10, None, None]:
    """
    Generate a time packet
    """

    run_time = starttime
    counter = 0

    minor_dlt_ns = int(1e9/(sample_rate * subframe_cnt))
    minor_frame_delay = PTPTime(0, minor_dlt_ns)
    
    for _i in range(start_seq, count+start_seq):
        rtc_time = ptp_to_rtc(run_time)
        logging.debug(f"Frame={_i} ptp_time={run_time}, rtc_time={rtc_time}")
        pkt = ch10.Chapter10()
        pkt.channelID = 0x1
        pkt.datatypeversion = 0x1
        pkt.relativetimecounter = rtc_time
        pkt.datatype = DATA_TYPE_PCM_DATA_FMT1
        pkt.sequence = _i % 256

        pcm = ch10pcm.PCMDataPacket()
        pcm.channel_specific_word = 0x7f040000
        for frame_count in range(subframe_cnt):
            rtc_time = ptp_to_rtc(run_time)
            minor_frame = ch10pcm.PCMMinorFrame()
            minor_frame.ipts = ch10pcm.RTCTime(rtc_time)
            minor_frame.intra_packet_data_header = 0xf000
            pcm_frame = PCMFrame(minor_frm_size)
            pcm_frame.fixed_frame(frame_count, counter % 65536)
            minor_frame.minor_frame_data = pcm_frame.pack()
            pcm.append(minor_frame)
            run_time += minor_frame_delay
            logging.debug(f"ptp_time={run_time} minor_dlt={minor_frame_delay}")
        pkt.payload = pcm.pack()

        yield pkt
            

def ptp_test():    
    assert ONE_SECOND + ONE_SECOND== PTPTime(2, 0)
    assert PTPTime(1, 99_999_999) + ONE_SECOND == PTPTime(2, 99999999)
    assert PTPTime(1, 999_999_999) + PTPTime(1, 1) == PTPTime(3, 0)


def main(args):

    ptp_test()
    sample_rate = 100
    ptp_start_time = PTPTime(int(time.time()), 0)
    run_for_s = 60
    minor_frm_size = 32
    seq = 0
    time_format_1 = 1
    time_format_2 = 2
    st = ptp_start_time
    
    chf = ch10.FileParser(args.ch10file, mode='wb')
    with chf as ch10file:
        ch10file.write(get_tmats_ch10(args.tmats, ptp_to_rtc(ptp_start_time)))
        for time_pkt in get_time_pkt(run_for_s, ptp_start_time, ONE_SECOND, time_format_1):
            ch10file.write(time_pkt)
            for pcm_pkt in get_pcm_pkt(sample_rate, st, 4, seq, sample_rate, minor_frm_size):
                ch10file.write(pcm_pkt)
            st += ONE_SECOND
            seq = (seq + sample_rate) % 256





if __name__ == '__main__':
    parser = create_parser()
    pargs = parser.parse_args()
    main(pargs)
    sys.exit(0)

