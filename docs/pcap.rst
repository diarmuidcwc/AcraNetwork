Pcap Documentation
*****************************

.. py:currentmodule:: AcraNetwork.Pcap

The libpcap file format is the main capture file format used in TcpDump/WinDump, snort, and many other networking tools.
It is fully supported by Wireshark/TShark

This file format is a very basic format to save captured network data. The file consists of a fixed length GlobalHeader
followed by multiple Pcap records. Each record consists of a fixed length header followed by a variable length payload.

As there are no offsets or indices, the file has to be loaded one record at a time

The file format is fully documented here https://wiki.wireshark.org/Development/LibpcapFileFormat

Read a Pcap File
=======================
Pass in the pcap filename to the Pcap class, then iterate through the pcap object to get the records

Writing a Pcap File
=======================
Open the file in mode='w'. Then each record is written using :meth:`Pcap.write` and finally close the file using :meth:`Pcap.close`


:class:`Pcap` Objects
=======================================
.. autoclass:: Pcap
   :members:


:class:`PcapRecord` Objects
=============================================
.. autoclass:: PcapRecord
   :members: