#!/usr/bin/env python3
"""
Script to regenerate test binary files with the new CRC format.
This should be run by the test suite when CRC support is enabled.
"""

import AcraNetwork.IRIG106.Chapter7 as ch7
import socket
import os

THIS_DIR = os.path.dirname(os.path.abspath(__file__))

def corruptllm_data():
    """Generate test data for test_llp_missing_packet with new format"""

    # Simple test frames - create a few PTFR frames with various content types
    frames = []

    # Frame 1: Some ETH packets
    for i in range(3):
        # Create a PTFR packet with ETHERNET_MAC content
        ptfr = ch7.PTFR()

        # Create a PTDP with ETHERNET_MAC content (not ILLEGAL anymore since content is at bits [10:5])
        ptdp_eth = ch7.PTDP()
        ptdp_eth.content = ch7.PTDPContent.ETHERNET_MAC
        ptdp_eth.fragment = ch7.PTDPFragment.COMPLETE
        ptdp_eth.payload = bytearray(b"eth_packet_data" * 20)
        ptdp_eth.crc = False  # No CRC for test data
        ptdp_eth.low_latency = True

        # Pack and add to PTFR
        ptfr.length = 500  # Arbitrary frame length
        ptfr.pack()  # Reset
        ptfr.add_payload(ptdp_eth.pack(), ptdp_eth.low_latency)

        frames.append(ptfr.pack())

    return frames


if __name__ == "__main__":
    # Generate new data
    new_frames = corruptllm_data()

    # Save to file
    output_file = f"{THIS_DIR}/corruptllm.bin"
    with open(output_file, "wb") as f:
        for frame in new_frames:
            f.write(frame)

    print(f"Generated new test {output_file}")
    print(f"Total frames: {len(new_frames)}")
    print(f"Total bytes: {sum(len(f) for f in new_frames)}")