Pcap Documentation
*****************************

.. py:currentmodule:: Pcap

The libpcap file format is the main capture file format used in TcpDump/WinDump, snort, and many other networking tools.
It is fully supported by Wireshark/TShark

This file format is a very basic format to save captured network data. The file consists of a fixed length GlobalHeader
followed by multiple Pcap records. Each record consists of a fixed length header followed by a variable length payload.

As there are no offsets or indices, the file has to be loaded one record at a time

The file format is fully documented here https://wiki.wireshark.org/Development/LibpcapFileFormat

Read a Pcap File
=======================
The file is opened using the :meth:`Pcap.__init__` method with mode='r'. The global header is automatically read.
The rest of the file is then read by iterating through the pcap object using a for loop.

Writing a Pcap File
=======================
The file is opened using the :meth:`Pcap.__init__` method with mode='w' or mode='a'. The global header is written using
:meth:`Pcap.write_global_header`. Each record is written using :meth:`Pcap.write` and the file is :meth:`Pcap.close`


:class:`Pcap` Objects
=======================================
.. autoclass:: Pcap
   :members:


:class:`PcapRecord` Objects
=============================================
.. autoclass:: PcapRecord
   :members: