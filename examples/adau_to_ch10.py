"""
ADAU generates pcap files which contain a chapter10 UDP header, and timestamps as PTP secondard header.
The application creates a new ch10 file, adds in the TMATs file, adds in Time packets ever second
and then converts all PTP timestamps to RTC
"""
__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2018"
__email__ = "dcollins@curtisswright.com"
__status__ = "Prototype"
__version__ = "0.1.1"

import AcraNetwork.Chapter10.Chapter10 as ch10
import AcraNetwork.Chapter10.Chapter10UDP as ch10udp
import AcraNetwork.Chapter10.UART as ch10uart
import AcraNetwork.Chapter10.PCM as ch10pcm
import AcraNetwork.Chapter10.MILSTD1553 as ch10mil
import AcraNetwork.Chapter10.TimeDataFormat as ch10time
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as eth
import argparse
import sys
from dataclasses import dataclass
import logging
import struct
from AcraNetwork.Chapter10 import (
    TS_CH4,
    TS_IEEE1558,
    PTPTime,
    RTCTime,
    DataType,
)
import typing


logging.basicConfig(level=logging.INFO)


@dataclass
class PktDetails:
    """Details to track for each packet"""

    channelid: int
    datatype: DataType

    def __hash__(self) -> int:
        return hash((self.channelid, self.datatype))


def create_parser():
    # ----------------------------------
    # Setup the command line parser
    # ----------------------------------
    parser = argparse.ArgumentParser(
        description="Convert an ADAU pcap to chapter10 file. User must provide the TMATs file. The packet format is converted to RTC time"
    )
    parser.add_argument("--pcap", required=True, help="The input pcap file")
    parser.add_argument("--pcmframelength", required=False, default=272, help="The length of the PCM frame in bytes")
    parser.add_argument("--ch10", required=True, help="The out chapter 10 file")
    parser.add_argument(
        "--pcapdebug", required=False, default=None, help="Create a debug pcap file which matches the chapter 10 file"
    )
    parser.add_argument("--tmats", required=True, help="The TMATS input file")
    parser.add_argument("--version", action="version", version=f"{__version__}")
    return parser


def encapsulate_ch10_ptk(ch10payload: bytes) -> bytes:
    """
    Encapsulte the udp payload in an Ethernet packet for debug puprposes
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


def encapsulate_tmats(tmats_file: str) -> ch10.Chapter10:
    """Wrap the tmats data in a ch10 file for writing to a ch10 file

    Args:
        tmats_data (bytes): _description_

    Returns:
        ch10.Chapter10: _description_
    """
    with open(tmats_file, mode="rb") as f:
        tmats = f.read()
        c = ch10.Chapter10()
        c.channelID = 0
        c.sequence = 123
        c.packetflag = 0
        c.datatype = DataType.COMPUTER_FORMAT_1
        c.relativetimecounter = 0
        c.payload = tmats
        return c


def get_ch10_time(ptptime: PTPTime, sequence: int = 0) -> ch10.Chapter10:
    """Return a time packet that maps the seconds / nanoseconds to the rtctime

    Args:
        seconds (int): _description_
        nanoseconds (int): _description_
        rtctime (int): _description_

    Returns:
        ch10.Chapter10: _description_
    """
    c = ch10.Chapter10()
    c.channelID = 2
    c.sequence = sequence
    c.packetflag = 0
    c.datatype = DataType.TIMEFORMAT_1
    c.relativetimecounter = ptptime.to_rtc()
    time_pkt = ch10time.TimeDataFormat1()
    time_pkt.ptptime = ptptime
    c.payload = time_pkt.pack()
    return c


def clone_ch10_payload(original_buffer: bytes, datatype: int, pcm_payload_size_bytes: int) -> bytes:
    """Return the payload with the secondary header removed

    Args:
        original_buffer (bytes): _description_

    Returns:
        bytes: _description_
    """
    if datatype == DataType.ARINC429:
        return original_buffer
    elif datatype == DataType.MILSTD1553:
        p = ch10mil.MILSTD1553DataPacket()
        p.unpack(original_buffer)
        # Go through each message and conver the timestamp to RTC
        for message in p:
            message.ipts = RTCTime(message.ipts.to_rtc())
        return p.pack()
    elif datatype == DataType.UART:
        p = ch10uart.UARTDataPacket(TS_IEEE1558)
        p.unpack(original_buffer)
        # Go through each message and conver the timestamp to RTC
        for dataword in p:
            if dataword.ipts is not None:
                dataword.ipts = RTCTime(dataword.ipts.to_rtc())
        return p.pack()
    elif datatype == DataType.PCM:
        p = ch10pcm.PCMDataPacket(ipts_source=TS_IEEE1558)
        p.minor_frame_size_bytes = pcm_payload_size_bytes
        p.unpack(original_buffer)
        # p.channel_specific_word = 0x0
        for frame in p:
            logging.debug(f"PCMFrame ipts sec={frame.ipts.seconds} nsec={frame.ipts.nanoseconds}")
            frame.ipts = RTCTime(frame.ipts.to_rtc())
        return p.pack()
    elif datatype == DataType.ANALOG:
        return original_buffer

    else:
        raise Exception(f"Data type {datatype} not supported")


def clone_ch10(original_ch10: ch10.Chapter10, pcm_payload_size_bytes: int) -> ch10.Chapter10:
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
        new_ch10.packetflag &= 0x33
        logging.debug(f"Converting timestamps and overwrite packet flag {new_ch10.packetflag:#0X}")
        new_ch10.relativetimecounter = original_ch10.ptptime.to_rtc()
    else:
        new_ch10.relativetimecounter = original_ch10.relativetimecounter
    new_ch10.ts_source = ch10.TS_RTC
    new_ch10.payload = clone_ch10_payload(original_ch10.payload, new_ch10.datatype, pcm_payload_size_bytes)
    return new_ch10


def update_stats(pkt_details: dict[PktDetails, int], detail: PktDetails) -> None:
    """Keep a count of the packets received

    Args:
        pkt_details (dict[PktDetails, int]): _description_
        detail (PktDetails): _description_
    """
    if detail not in pkt_details:
        pkt_details[detail] = 1
        print(f"Found data type {detail.datatype.name} on channelID {detail.channelid}")
    else:
        pkt_details[detail] += 1


def print_stats(pkt_details: dict[PktDetails, int]):
    """Print the stats at the end

    Args:
        pkt_details (dict[PktDetails, int]): _description_
    """
    for detail, count in pkt_details.items():
        print(f"Packet Type={detail.datatype.name} channelID={detail.channelid} count={count}")


def main(args):
    pf = pcap.Pcap(args.pcap, mode="r")
    if args.pcapdebug is not None:
        pf_tmp = pcap.Pcap(args.pcapdebug, mode="w")
    else:
        pf_tmp = None
    fp = ch10.FileParser(args.ch10, mode="wb")

    CH10_DATA_OFFSET = 0x2A
    CH10_DATA_LEN_MIN = 30

    prev_time = None
    time_sequnece = 0
    pkt_type_count = {}
    aligned_to_10_ms = False

    with fp as ch10file:
        # Generate the TMATs ch10 packet and write to the output file
        tmats_ch10 = encapsulate_tmats(args.tmats)
        fp.write(tmats_ch10)
        for idx, record in enumerate(pf):
            # Pull out the ethernet packet
            eth_pkt = record.payload
            # Debug output record
            newrec = pcap.PcapRecord()
            newrec.sec = record.sec
            newrec.usec = record.usec
            # Write out the TMATS to the debug pcap
            if idx == 0 and pf_tmp is not None:
                newrec.payload = encapsulate_ch10_ptk(tmats_ch10.pack())
                pf_tmp.write(newrec)
            # Sanity check on the input packlet
            if len(eth_pkt) > CH10_DATA_OFFSET + CH10_DATA_LEN_MIN:
                logging.debug(f"Reading record {idx}")
                # Get the UDP payload (ie the chapter10 packet)
                pkt_payload = eth_pkt[CH10_DATA_OFFSET:]
                ch10udp_pkt = ch10udp.Chapter10UDP()
                ch10_pkt = ch10.Chapter10()
                # Unpack the ch10 UDP and ch10 packets
                try:
                    ch10udp_pkt.unpack(pkt_payload)
                    ch10_pkt.unpack(ch10udp_pkt.payload)
                except Exception as e:
                    logging.debug(f"Failed to unpacket record #{idx}. len_buf={len(pkt_payload)} Err={e}")
                    continue
                else:
                    if prev_time is None:
                        time_in_ms = int(ch10_pkt.ptptime.nanoseconds // 1e6)
                        if time_in_ms % 10 == 0:
                            # Get the first timepacket and write it to the ch10 file
                            time_pkt = get_ch10_time(ch10_pkt.ptptime, time_sequnece)
                            ch10file.write(time_pkt)
                            prev_time = ch10_pkt.ptptime
                            time_sequnece += 1
                            if pf_tmp is not None:  # debug
                                newrec.payload = encapsulate_ch10_ptk(time_pkt.pack())
                                pf_tmp.write(newrec)
                            aligned_to_10_ms = True
                    elif prev_time is not None and ch10_pkt.ptptime is not None:
                        # Check if 1 second has elapsed since the previous time packet
                        dlt = ch10_pkt.ptptime - prev_time
                        if dlt >= PTPTime(1, 0):
                            time_pkt = get_ch10_time(ch10_pkt.ptptime, time_sequnece)
                            ch10file.write(time_pkt)
                            prev_time = ch10_pkt.ptptime  #
                            time_sequnece += 1
                            if pf_tmp:  # debug
                                newrec.payload = encapsulate_ch10_ptk(time_pkt.pack())
                                pf_tmp.write(newrec)
                    if aligned_to_10_ms:
                        # Convert the chapter10 packet to the RTC compatiable one
                        new_ch10_pkt = clone_ch10(ch10_pkt, args.pcmframelength)
                        # Update the stats
                        update_stats(
                            pkt_type_count, PktDetails(new_ch10_pkt.channelID, DataType(new_ch10_pkt.datatype))
                        )
                        ch10file.write(new_ch10_pkt)

                    if pf_tmp is not None and aligned_to_10_ms:  # debug
                        newrec.payload = encapsulate_ch10_ptk(new_ch10_pkt.pack())
                        pf_tmp.write(newrec)

    pf.close()
    print_stats(pkt_type_count)
    if pf_tmp is not None:
        pf_tmp.close()
    fp.close()


if __name__ == "__main__":
    parser = create_parser()
    args = parser.parse_args()
    ret = main(args)
    sys.exit(ret)
