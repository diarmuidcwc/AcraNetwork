#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
===== 
Parse MPEG TS packets in pcap....
===== 

"""
__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2018"
__version__ = "0.0.1"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


import sys
sys.path.append("..")
import AcraNetwork.Pcap as pcap
import AcraNetwork.iNetX as inetx
import AcraNetwork.MPEGTS as mpegts
import AcraNetwork.SimpleEthernet as eth
from AcraNetwork.MPEGTS import H264
import datetime

# This script shows how to parse either a pcap file or a TS file into the constituent
# NALS and finds the unique STANAG SEI User data with the timestamp


def pcap_to_ts(pcapfile,ts_file,udp_port=8010):
    '''
    Convert a pcap file to a TS file by extracting all data from a specified port
    :param mpegfile: str
    :param ts_file: str
    :param udp_port: int
    :return:
    '''

    mpegpcap = pcap.Pcap(pcapfile, mode='r')

    ts = open(ts_file, mode='wb')
    mpeghex = ""
    rec_count = 0

    for rec in mpegpcap:
        try:
            e = eth.Ethernet()
            e.unpack(rec.packet)
            i = eth.IP()
            i.unpack(e.payload)
            u = eth.UDP()
            u.unpack(i.payload)
            if u.dstport == udp_port:
                rec_count += 1
                inet = inetx.iNetX()
                inet.unpack(u.payload)
                mpegtspackets = mpegts.MPEGTS()
                mpegtspackets.unpack(inet.payload)
                for packet in mpegtspackets.blocks:
                    mpeghex += packet.payload
                ts.write(inet.payload)
        except:
            continue


def parse_ts_file(tsfile):

    ts_file = open(tsfile,mode='rb')
    h264_data = H264()
    h264_data.unpack(ts_file.read())

    nal_counts = {}
    timestamp_count = 0
    for nal in h264_data.nals:

        if not nal.type in nal_counts:
            nal_counts[nal.type] = 1
        else:
            nal_counts[nal.type] += 1

        if nal.type == mpegts.NAL_TYPES["SEI"]:
            if nal.sei.unregdata:
                print("Timestamp={} byte offset={} count ={}".format(datetime.datetime.strftime(nal.sei.time,"%d %b %Y %H:%M:%S.%f"),nal.offset,timestamp_count))
                timestamp_count += 1

        else:
            pass

    print("\n----- SUMMARY -----")
    for type in nal_counts:
        print("{} {} NALs in input".format(nal_counts[type],mpegts.NAL_TYPES_INV[type]))
    print("{} STANAG Timestamps".format(timestamp_count))


def main():
    # Read in a TS file and print out some useful information
    parse_ts_file("../test/stanag_sample.ts")


if __name__ == "__main__":
    main()