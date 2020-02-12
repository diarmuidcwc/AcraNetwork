

import sys
sys.path.append("..")

import AcraNetwork.Pcap as pcap
import csv
import AcraNetwork.iNetX as inetx


# Modify this
pcapf = "../test/inetx_test.pcap"
streamid = 0xca
csv_output = "ts.csv"

csvfile = open(csv_output, 'w')
csvwriter = csv.writer(csvfile)
csvwriter.writerow(["Packet Number", "Seconds", "Nanoseconds"])

pcapfile = pcap.Pcap(pcapf, mode="r")
for idx, record in enumerate(pcapfile):
    inetx_pkt = inetx.iNetX()
    try:
        inetx_pkt.unpack(record.payload[0x2a:])
    except:
        pass
    else:
        if inetx_pkt.streamid == streamid:
            csvwriter.writerow([idx+1, inetx_pkt.ptptimeseconds, inetx_pkt.ptptimenanoseconds])