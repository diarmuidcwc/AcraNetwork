iNetX Documentation
********************

.. py:currentmodule:: AcraNetwork.iNetX

iNetX is a FTI packet format that is decribed in Tech Note 69. It is typically encapsulated in a UDP payload.

This module supports the creating and analysis of iNetX packets

In typical use, a UDP payload is captured from the network or read from a PCAP file. This is then passed to the
:meth:`iNetX.unpack` method which converts it into an iNetX packet

Examples and details are available below


:class:`iNetX` Objects
=======================
.. autoclass:: iNetX
   :members:
