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


def ptp_to_rtc(ptp_time_seconds: float) -> int:
    """
    Convert a time to PTP
    """
    return int((ptp_time_seconds * 1e9) / 100) & (pow(2,48) - 1)



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
    
def get_time_pkt(run_time_s: int, starttime: float, delta_s: float = 1.0, format: int = 1) -> typing.Generator[ch10.Chapter10, None, None]:
    """
    Generate a time packet
    """

    run_time = starttime
    
    for sequence in range(run_time_s):
        sec = int(run_time)
        nsec = int((run_time % 1.0) * 1e9)
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
        
        time_fmt.seconds = sec
        time_fmt.nanoseconds = nsec
        
        pkt.channelID = 0x280
        pkt.datatypeversion = 0x1
        pkt.relativetimecounter = rtc_time
        
        pkt.payload = time_fmt.pack()
        run_time += delta_s
        yield pkt
            

def get_pcm_pkt(count: int, starttime: float, subframe_cnt: int, sample_rate: int = 100,
                minor_frm_size: int = 32) -> typing.Generator[ch10.Chapter10, None, None]:
    """
    Generate a time packet
    """

    run_time = starttime
    counter = 0

    major_frame_delay_seconds = 1.0/sample_rate
    minor_frame_delta_seconds = 1.0/(sample_rate * subframe_cnt)
    ch10_seq = 0
    
    for _i in range(count):
        rtc_time = ptp_to_rtc(run_time)
        pkt = ch10.Chapter10()
        pkt.channelID = 0x1
        pkt.datatypeversion = 0x1
        pkt.relativetimecounter = rtc_time
        pkt.datatype = DATA_TYPE_PCM_DATA_FMT1
        pkt.sequence = ch10_seq
        ch10_seq += 1

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
            run_time += minor_frame_delta_seconds

        pkt.payload = pcm.pack()

        yield pkt
            

def main(args):

    sample_rate = 100
    ptp_start_time = floor(time.time())
    run_for_s = 5
    minor_frm_size = 32
    
    chf = ch10.FileParser(args.ch10file, mode='wb')
    with chf as ch10file:
        ch10file.write(get_tmats_ch10(args.tmats, ptp_to_rtc(ptp_start_time)))
        for time_pkt in get_time_pkt(run_for_s, ptp_start_time, 1.0, 1):
            ch10file.write(time_pkt)
            for pcm_pkt in get_pcm_pkt(sample_rate, ptp_start_time, 4, sample_rate, minor_frm_size):
                ch10file.write(pcm_pkt)





if __name__ == '__main__':
    parser = create_parser()
    pargs = parser.parse_args()
    main(pargs)
    sys.exit(0)

