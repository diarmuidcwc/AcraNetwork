

# Very rudimentary (but fast) validation of recorded data
# Tell it what port the iNetX payload is on and it will find and
# validate that no data is dropped

import sys
sys.path.append("..")
import AcraNetwork.Pcap as pcap
import glob
import os.path
import struct
import time


udp_port = 8888  # UDP port for inetx data
dir = "ssd/rec"  # Directory of recorded data

# recorder data
# tcpdump -i eth0 -W 999 -C 1000 -n -K -s 2000 -w rec.pcap.

roll_over = pow(2, 32)

# Find all the files and sort by extension
all_files = glob.glob(os.path.join(dir, "*.pcap*"))
all_files.sort(key=lambda f: os.path.splitext(f)[1])

# For recording the data
stream_ids = {}
inetx_pkts_validate = 0
data_count_bytes = 0
start_t = time.time()

for file in all_files:
    p = pcap.Pcap(file)
    for r in p:
        if len(r.payload) >= (18+0x24):  # For short packets don't try to decode them as inets
            # pull out the key fields
            (dst_port,udp_len, checksum, control, stream_id, seq) = struct.unpack_from(">HHHIII", r.payload, 0x24)

            if dst_port == udp_port:
                if stream_id in stream_ids:
                    if seq != (stream_ids[stream_id] + 1) % roll_over:
                        print("ERROR: StreamID={:#0X} Prev={} Cur={}".format(stream_id, stream_ids[stream_id], seq))
                stream_ids[stream_id] = seq
                inetx_pkts_validate += 1
                data_count_bytes += len(r.payload)

    # The data rate at which we are validating
    dr = data_count_bytes*60/(1e6 * (time.time() - start_t))

    print("{} packets validated at {:.0f}MB/s. Total_data={:.1f}MB Completed file {}".format(inetx_pkts_validate, dr,
                                                                                     data_count_bytes/1e6, file))
    for s in stream_ids:
        print("Found StreamID={:#0X}".format(s))

