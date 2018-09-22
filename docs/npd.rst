:class:`NDP` Documentation
***************************

.. py:currentmodule:: NDP

NDP is a TTC payload format usual encapsulated in UDP payloads

This module supports the creating and analysis of NDP packets

In typical use, a UDP payload is captured from the network or read from a PCAP file. This is then passed to the
:meth:`NPD.unpack` method which converts it into an NPD packet

NDP packets consists of NDP Segments which are handled by :class:`NPDSegment`

Examples and details are available below


:class:`NPD` Objects
=======================
.. autoclass:: NDP
   :members:


:class:`NPDSegment` Objects
=============================
.. autoclass:: NDPSegment
   :members: