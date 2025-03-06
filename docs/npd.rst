NPD Documentation
***************************

.. py:currentmodule:: AcraNetwork.NPD

NPD is a TTC payload format usual encapsulated in UDP payloads. It is commonly known as DARv3

This module supports the creating and analysis of NPD packets

In typical use, a UDP payload is captured from the network or read from a PCAP file. This is then passed to the
:meth:`NPD.unpack` method which converts it into an NPD packet

NPD packets consists of NPD Segments which are handled by :class:`NPDSegment`

Examples and details are available below


:class:`NPD` Objects
=======================
.. autoclass:: NPD
   :members:


:class:`NPDSegment` Objects
=============================
.. autoclass:: NPDSegment
   :members:

:class:`ACQSegment` Objects
=============================
.. autoclass:: ACQSegment
   :members:

:class:`PCMPacketizer` Objects
===============================
.. autoclass:: PCMPacketizer
   :members:

:class:`A429Segment` Objects
=============================
.. autoclass:: A429Segment
   :members:

:class:`RS232Segment` Objects
==============================
.. autoclass:: RS232Segment
   :members:

:class:`MIL1553Segment` Objects
================================
.. autoclass:: MIL1553Segment
   :members: