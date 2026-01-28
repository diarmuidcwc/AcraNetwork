Chapter 24 Documentation
**************************


Chapter24 is a IRIG106 payload format encapsulating acquisition data. The full standard is defined in https://www.irig106.org/docs/106-17/chapter24.pdf

This module supports the creating and analysis of TmNSMessages

In typical use, a UDP payload is captured from the network or read from a PCAP file. This is then passed to the
:meth:`AcraNetwork.IRIG106.Chapter24.TmNSMessage.unpack` method which converts it into an Chapter11 object

The payload of the UDP wrapper contains a Data Format packet (described in 10.6.1 of the spec) which is handled by the
TmNSMessage object :class:`AcraNetwork.IRIG106.Chapter24.TmNSMessage`


Examples and details are available below

.. py:currentmodule:: AcraNetwork.IRIG106.Chapter24

:class:`TmNSMessage` Objects
===========================
.. autoclass:: TmNSMessage
   :members:
