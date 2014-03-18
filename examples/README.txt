------------- ########################## --------------------
simple_parser_packets_from_pcap.py

Run:
$ python ./simple_parser_packets_from_pcap.py

Simpler version of parser_aligned_pcap_example/py

------------- ########################## --------------------

parser_aligned_pcap_example.py


Run:
$ python ./parser_aligned_pcap_example.py --pcap SSR_ABM_102_capture_example1.pcap

This will go though the pcap file, reporting all the packet ip addresses and for certain streamids it will unpack
the parser aligned data returning some of that information

This is a simple example of what can be done with the modules



------------- ########################## --------------------

live_monitoring.py


Run:
$ python ./live_monitoring.py --inetx 8011

This example requires colorama. 
https://pypi.python.org/pypi/colorama Install using easy_install or download the zip file, unzip it, and install it (python ./setup.py install)

This is a very useful script. It will monitor reception of inetx or iena packets on a specified udp port. It will
discover all the stream ids and print them out to the screen. Any backplane resets will be high ligheded
This could easily be modified to not use the coloured output or to analyse the packets more thoroughly



------------- ########################## --------------------

pcap_monitor.py

Run:
$ python ./pcap_monitor.py  --pcap dump.pcap

This example requires colorama. 
https://pypi.python.org/pypi/colorama Install using easy_install or download the zip file, unzip it, and install it (python ./setup.py install)


This script loops through a pcap file pulling out any inetx packets it finds and then reporting that to the screen
It will visually highligh any dropped packets and it's quite easy to see what's happening in the pcap file from a 
big picture view.
It's not recommende to us the ReadNextPacket method that is described here. Better to use the methods from parser_aligned_pcap_example

------------- ########################## --------------------
pcap_to_ascii.py

Run:
$ python  pcap_to_ascii.py --pcap Internal_Test_Packets_From_Test_Before_and_After_DAU_Fail.pcap  --hex --out test2

Dump out ascii represenations of iNetX payloads



