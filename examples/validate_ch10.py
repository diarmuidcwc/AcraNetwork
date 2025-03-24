#!/usr/bin/env python

# Requires cryptography
# pip install cryptography
# -*- coding: utf-8 -*-


import AcraNetwork.IRIG106.Chapter11 as ch11
import AcraNetwork.IRIG106.Chapter11.TimeDataFormat as chtime
from AcraNetwork.IRIG106.Chapter10 import FileParser
import AcraNetwork.IRIG106.Chapter10.Chapter10UDP as ch10udp
from AcraNetwork.IRIG106.Chapter11 import PTPTime
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as eth
import argparse
import glob
import os.path
from dataclasses import dataclass, field
import typing
import sys
import logging
import time
from functools import reduce
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from pathlib import Path
import tempfile
from os import remove
from shutil import rmtree
import struct

RED = "\033[31m"
RESET = "\033[0m"
TIME_CHID = 0x1
DATA_TYPE_WRAPPED_ETHERNET = 0x68

logging.basicConfig(level=logging.INFO)

# This will make the validation 10x slower. It validates all the data in the inetx packet
CHECK_INETX_PAYLOAD = False
INETX_PAYLOAD_LEN_WORDS = 722


@dataclass
class Channels:
    channel: int
    sequence: int
    pkt_count: int
    dropcnt: int
    datavol: int

    def __repr__(self):
        if self.dropcnt > 0:
            hi = RED
        else:
            hi = ""
        return f"ChannelID={self.channel:#08X} Count={self.pkt_count:12d} {hi}Drop={self.dropcnt:10d}{RESET}, Vol={self.datavol / 1e6:10.1f}MB"


def create_parser():
    # ----------------------------------
    # Setup the command line parser
    # ----------------------------------
    parser = argparse.ArgumentParser(description="Validate a ch10 recording")
    parser.add_argument("--folder", type=str, required=True, default=None, help="folder to ch10 files")
    parser.add_argument(
        "--unwrap", type=str, required=False, default=None, help="folder to write unwrapped ethernet packets"
    )
    parser.add_argument("--key", type=str, required=False, default=False, help="RSA private key")

    return parser


def decrypt_aes_key(ciphertext: bytes, pem_file: str) -> bytes:
    # Load the private key from a PEM file
    with open(pem_file, "rb") as priv_file:
        private_pem = priv_file.read()

    private_key = serialization.load_pem_private_key(
        private_pem, password=None  # Provide a password if the private key is encrypted
    )
    # Decrypt the data using the private key
    decrypted_data = private_key.decrypt(
        ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
    )
    return decrypted_data


def decrypt_file(input_filename, output_filename, private_key):

    # Open input and output files
    with open(input_filename, "rb") as infile, open(output_filename, "wb") as outfile:
        rsa_encrypted = infile.read(512)
        key = decrypt_aes_key(rsa_encrypted, private_key)
        iv = infile.read(16)
        # Create decryption cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        # Read and decrypt in chunks
        while True:
            chunk = infile.read(4096)
            if len(chunk) == 0:
                break
            decrypted_chunk = decryptor.update(chunk)
            outfile.write(decrypted_chunk)

        # Finalize decryption
        outfile.write(decryptor.finalize())


def enc_to_ch10(encfile, key, tmpdir: str):
    p = Path(encfile)
    newfile = Path(tmpdir, f"{p.stem}.ch10")
    st = time.time()
    decrypt_file(encfile, newfile, key)
    try:
        decrypt_rate = os.path.getsize(encfile) / ((time.time() - st) * 1e6)
    except:
        decrypt_rate = 0.0
    print(f"Decrypted {encfile} to temp file {newfile} at {decrypt_rate:.1f}MBps")
    return newfile


def print_summary(channels: typing.Dict[int, Channels]):
    for id, ch in sorted(channels.items()):
        print(repr(ch))


def process_speed(channels: typing.Dict[int, Channels], start_time: float, end_time: float) -> float:
    """Return the processing speed in MBps"""
    total_data = 0.0
    for id, ch in sorted(channels.items()):
        total_data += ch.datavol
    rate = total_data * 8 / (1e6 * (end_time - start_time))
    return rate


def get_recording_rate(channels: typing.Dict[int, Channels], start_time: PTPTime, end_time: PTPTime) -> float:
    """Return the recording rate in Mbps"""
    if start_time is None or end_time is None:
        return 0.0

    total_data = 0.0
    for id, ch in sorted(channels.items()):
        total_data += ch.datavol
    time_delta = (end_time.seconds + end_time.nanoseconds / 1e9) - (start_time.seconds + start_time.nanoseconds / 1e9)
    if time_delta <= 0:
        return 0
    rate = total_data * 8 / (1e6 * time_delta)
    return rate


def ch10_to_pcap(ch10fname: str, folder: str) -> str:
    p = Path(ch10fname)
    return f"{folder}/{p.stem}.pcap"


def get_streamid_and_seq_of_inetx(buffer: bytes) -> typing.Tuple[int, int]:
    (ctrl, stream, seq) = struct.unpack_from(">III", buffer, 0x2A)
    if ctrl != 0x11000000:
        raise Exception("Packet is not inetx")
    return (stream, seq)


def validate_inetx_payload(buffer: bytes, expected_payload_len_words: int) -> bool:
    (first_word,) = struct.unpack_from(">H", buffer, 0x46)
    exp_buffer = struct.pack(
        f">{expected_payload_len_words}H",
        *list(map(lambda x: x % 65536, list(range(first_word, first_word + expected_payload_len_words)))),
    )
    return exp_buffer == buffer[0x46:]


def quick_check_inetx(buffer: bytes, expected_payload_len_words: int) -> bool:
    (first_word,) = struct.unpack_from(">H", buffer, 0x46)
    (last_word,) = struct.unpack(">H", buffer[-2:])
    expected_last_word = (first_word + expected_payload_len_words) % 65536
    return last_word == expected_last_word


def main(args):
    if args.key:
        all_files = glob.glob(os.path.join(args.folder, "*.enc"))
        dir = tempfile.mkdtemp()
    else:
        all_files = glob.glob(os.path.join(args.folder, "*.ch10"))
        dir = None

    channels: typing.Dict[int, Channels] = {}
    roll_over = 256

    all_files.sort()
    st = time.time()
    first_ts = None
    latest_ts = None
    pkts = 0
    inetx_seq = {}
    wrapped_valid_count = 0
    for _file in all_files:
        if args.key:
            chfile = enc_to_ch10(_file, args.key, dir)
        else:
            chfile = _file
        if args.unwrap:
            pf = pcap.Pcap(ch10_to_pcap(chfile, args.unwrap), mode="w")
            prec = pcap.PcapRecord()
            prec.set_current_time()

        print(f"Reading in {chfile}")
        fp = FileParser.FileParser(chfile)
        with fp as ch10file:
            for idx, _payload in enumerate(ch10file):
                pkts += 1
                pkt = ch11.Chapter11()
                try:
                    pkt.unpack(_payload)
                except Exception as e:
                    logging.error(
                        f"Failed to unpack data len={len(_payload)} as ch11. Error={e} Count={pkts}. Pkt {idx + 1} in file "
                    )

                else:
                    # Get the time to work out the data rate of the incoming packets

                    if pkt.datatype == DATA_TYPE_WRAPPED_ETHERNET:

                        if args.unwrap:
                            prec.payload = pkt.payload[16:]
                            pf.write(prec)
                        try:
                            (_sid, _seq) = get_streamid_and_seq_of_inetx(pkt.payload[16:])
                        except Exception as e:
                            logging.debug(f"Failed to unpacket wrapped packet. err={e}")
                        else:
                            if _sid in inetx_seq:
                                if inetx_seq[_sid] + 1 != _seq:
                                    logging.error(f"Unwrapped error. SID={_sid:#0X} seq={_seq} prev={inetx_seq[_sid]}")
                                else:
                                    wrapped_valid_count += 1
                            inetx_seq[_sid] = _seq
                            if CHECK_INETX_PAYLOAD:
                                if not quick_check_inetx(pkt.payload[16:], INETX_PAYLOAD_LEN_WORDS):
                                    logging.error("Inetx paylaod was corrupted")

                    if pkt.channelID == TIME_CHID:
                        time_pkt = chtime.TimeDataFormat1()
                        try:
                            time_pkt.unpack(pkt.payload)
                        except Exception as e:
                            logging.error(e)
                        else:
                            if first_ts is None:
                                first_ts = time_pkt.ptptime
                            else:
                                latest_ts = time_pkt.ptptime

                    if pkt.channelID in channels:
                        _ch = channels[pkt.channelID]
                        if (_ch.sequence + 1) % roll_over != pkt.sequence:
                            loss = pkt.sequence - ((_ch.sequence + 1) % roll_over)
                            _ch.dropcnt += loss
                            logging.error(
                                f"Dropped {loss} packets on channelID={pkt.channelID:#0X}. prev={_ch.sequence} cur={pkt.sequence}. pkt={pkts}"
                            )
                        _ch.pkt_count += 1
                        _ch.datavol += len(_payload)
                        _ch.sequence = pkt.sequence
                    else:
                        channels[pkt.channelID] = Channels(pkt.channelID, pkt.sequence, 0, 0, 0)
        if args.key:
            os.remove(chfile)

        print_summary(channels)
        rate = process_speed(channels, st, time.time())
        recrate = get_recording_rate(channels, first_ts, latest_ts)
        print(f"Validating at {rate:6.1f}MBps. Recording at {recrate:6.1f}Mbps")
        print(f"Validated wrapped inetx = {wrapped_valid_count}")

    print(f"---------- Result after {pkts} -----------")
    print_summary(channels)
    if args.key:
        rmtree(dir)
    print(f"Validated wrapped inetx = {wrapped_valid_count}")


if __name__ == "__main__":
    parser = create_parser()
    args = parser.parse_args()
    main(args)
    sys.exit(0)
