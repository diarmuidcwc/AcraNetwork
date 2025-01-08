#!/usr/bin/env python3

# -*- coding: utf-8 -*-
"""

Record ch10 streams to a ch10 file

"""
__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2024"
__version__ = "0.1.0"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


import signal
import struct
import AcraNetwork.McastSocket as mcast
import AcraNetwork.SimpleEthernet as SimpleEthernet
import argparse
import sys
import socket
from AcraNetwork.IRIG106.Chapter11 import DataType
import AcraNetwork.IRIG106.Chapter11.ComputerData as chcomputer
import AcraNetwork.IRIG106.Chapter11 as ch10
import logging
from enum import IntEnum

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(asctime)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


class Format(IntEnum):
    ONE = 1
    TWO = 2
    THREE = 3


class Chapter10FileWriter(object):
    """
    Parse a Chapter10 file. Open the file and iterate through it
    """

    def __init__(self, filename):
        self.filename = filename
        self._mode = "wb"
        self._offset = 0
        self._fd = None

    def write(self, ch10packet: bytes):
        """
        Write a chapter10 packet to the file
        """
        if not self._fd.writable():
            raise Exception("File {} not open for writing".format(self.filename))
        self._fd.write(ch10packet)

    def __enter__(self):
        self._fd = open(self.filename, self._mode)
        return self

    def __exit__(self, type, value, traceback):
        # Exception handling here
        self._fd.close()

    def close(self):
        if self._fd is not None:
            self._fd.close()


def create_parser():
    """Setup a command line parser"""
    description = """Record multicast ch10 packets to a ch10 file. This should be used to capture chapter10 packets. 
    All packets should be setup to transmit using the same format, the same destination multicast IP address and the same destination UDP port"""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--tmats", required=True, help="The TMATs file to place in recorded chapter 10 file")
    parser.add_argument("--ch10", required=True, help="The output chapter 10 filename")
    parser.add_argument("--quiet", required=False, action="store_true", help="Only report error messages")
    parser.add_argument("--udp", required=False, default=51000, type=int, help="The UDP port to capture")
    parser.add_argument(
        "--format",
        required=False,
        default=1,
        choices=[Format.ONE, Format.TWO, Format.THREE],
        type=int,
        help="The chapter 10 format being used. ",
    )
    parser.add_argument("--multicast", required=False, default="235.0.0.1", help="The multicast address to capture")
    return parser


def opensocket(mcast_addr: str, udp_port: int) -> socket.socket:
    """Open a receive UDP socket for packet receiption"""
    try:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        mreq = struct.pack("=4sl", socket.inet_aton(mcast_addr), socket.INADDR_ANY)
        recv_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        recv_socket.bind(("", udp_port))
        recv_socket.settimeout(1)
    except Exception as e:
        raise Exception(f"Can't bind to socket {udp_port} Err={e}")
    else:
        return recv_socket


def encapsulate_tmats(tmats_filename: str, rtctime: int) -> bytes:
    """Wrap the tmats data in a ch10 file for writing to a ch10 file"""
    with open(tmats_filename, mode="rb") as f:
        tmats = f.read()
        c = ch10.Chapter11()
        c.channelID = 0
        c.sequence = 0
        c.packetflag = 0
        c.datatype = DataType.COMPUTER_FORMAT_1
        c.relativetimecounter = rtctime
        ctmats = chcomputer.ComputerGeneratedFormat1()
        ctmats.payload = tmats
        c.payload = ctmats.pack()
        return c.pack()


def main(args):

    if args.quiet:
        logger.setLevel(logging.ERROR)

    MIN_PKT_SIZE = 30
    # Identify chapter 10 packets
    OFFSET_TO_SYNC = {Format.ONE: 4, Format.TWO: 12, Format.THREE: 8}
    OFFSET_TO_TIME = {Format.ONE: 4 + 15, Format.TWO: 12 + 15, Format.THREE: 8 + 15}

    rec_pkt_count = 0
    keep_recording = True
    try:
        rx_socket = opensocket(args.multicast, args.udp)
    except Exception as e:
        logger.error(f"Failed to capture from network. Error={e}")
        return 1
    else:
        ch10_writer = Chapter10FileWriter(args.ch10)

        def signal_handler(*args):
            logger.info(f"Exiting. Recorded {rec_pkt_count:>12,}")
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)

        time_aligned = False  # Align the writing to the time packet
        with ch10_writer as ch10_file:
            logger.info("Waiting to align to a Chapter 10 time packet")
            while keep_recording:
                try:
                    data, addr = rx_socket.recvfrom(2048)  # buffer size is 1500 bytes
                except Exception as e:
                    logger.error(f"timeout on socket. Err={e}")
                    return 1
                else:
                    if len(data) > MIN_PKT_SIZE:
                        (data_type,) = struct.unpack_from("<B", data, OFFSET_TO_TIME[args.format])
                        logger.debug(f"Rx pkt, dt={data_type:#0X}")
                        if not time_aligned:
                            (data_type, lsw, msw) = struct.unpack_from(
                                "<BIH", data, OFFSET_TO_TIME[args.format]
                            )  # Get the time
                            if 0x11 <= data_type <= 0x17:
                                rtc_count = lsw + (msw << 32)
                                time_aligned = True
                                ch10_file.write(encapsulate_tmats(args.tmats, rtc_count))
                                logger.info("Received time packet. Starting recording")
                        if time_aligned:
                            ch10_payload = data[OFFSET_TO_SYNC[args.format] :]
                            ch10_file.write(ch10_payload)
                            rec_pkt_count += 1
                # Reporting
                if rec_pkt_count % 100 == 0 and rec_pkt_count > 0:
                    logger.info(f"Recorded {rec_pkt_count:>12,} packets")


if __name__ == "__main__":
    parser = create_parser()
    args = parser.parse_args()
    ret = main(args)
    sys.exit(ret)
