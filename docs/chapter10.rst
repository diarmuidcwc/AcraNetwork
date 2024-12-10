Chapter 10 Documentation
**************************


Chapter10 is a IRIG106 payload format usual encapsulated in UDP payloads. The full standard is defined in http://www.irig106.org/docs/106-11/chapter10.pdf

This module supports the creating and analysis of Chapter10 packets

In typical use, a UDP payload is captured from the network or read from a PCAP file. This is then passed to the
:meth:`Chapter10.Chapter10UDP.unpack` method which converts it into an Chapter10 object

The payload of the UDP wrapper contains a Data Format packet (described in 10.6.1 of the spec) which is handled by the
Chapter10 object :class:`Chapter10.Chapter10`


Examples and details are available below

.. py:currentmodule:: Chapter10.Chapter10

:class:`Chapter10` Objects
===========================
.. autoclass:: Chapter10
   :members:

   
.. py:currentmodule:: Chapter10.Chapter10UDP


:class:`Chapter10UDP` Objects
==============================
.. autoclass:: Chapter10UDP
   :members:

.. py:currentmodule:: Chapter10.ARINC429

:class:`ARINC429DataPacket` Objects
====================================
.. autoclass:: ARINC429DataPacket
   :members:


:class:`ARINC429DataWord` Objects
==================================
.. autoclass:: ARINC429DataWord
   :members:
