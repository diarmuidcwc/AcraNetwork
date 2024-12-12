iNET Documentation
********************

.. py:currentmodule:: AcraNetwork.iNET

iNET is a FTI packet format that is decribed in IRIG106 standard, http://www.irig106.org/docs/106-17/Chapter24.pdf

It is typically encapsulated in a UDP payload. This module supports the creating and analysis of iNET packets

In typical use, a UDP payload is captured from the network or read from a PCAP file. This is then passed to the
:meth:`iNET.unpack` method which converts it into an :class:`iNET` object

The payload of the iNET packet, is a list of :class:`iNETPackage` objects

Examples and details are available below


:class:`iNET` Objects
=======================
.. autoclass:: iNET
   :members:

:class:`iNETPackage` Objects
=============================
.. autoclass:: iNETPackage
   :members:
