SimpleEthernet Documentation
*****************************

.. py:currentmodule:: AcraNetwork.SimpleEthernet

This module containts a number of simple classes than can be used to create Ethernet, IP and UDP packets. The basic functionality
of these packet formats are supported which should cover 95% of the use cases.

You should understand the :func:`struct.pack` and :func:`struct.unpack` functions in python before using this module

When reading a packet, typically a new instance of the class is created and the source of data is passed to the :meth:`Ethernet.pack` method.

For writing a packet, the various attributes of the packets are created and the packed. This returns a string buffer which
is the byte representation of the packet.

Packet types which encapsulate other packets are unpacked by passing the payload of the outter packet to the inner packet. For example

>>> import AcraNetwork.SimpleEthernet as se
>>> ip_pkt = se.IP()
>>> ip_pkt.payload = b"\xFF"
>>> ip_pkt.dstip = "192.168.28.2"
>>> ip_pkt.srcip = "192.168.28.1"
>>> eth_pkt = se.Ethernet()
>>> eth_pkt.dstmac = 0x1
>>> eth_pkt.srcmac = 0x2
>>> #At this point we have the bones of two packets. Now to encapsulate the IP packet in the Ethernet packet
>>> eth_pkt.payload = ip_pkt.pack()


:class:`Ethernet` Objects
===========================

Used to build Ethernet packets. Payload encapsulated is typically the output of :meth:`IP.pack`

.. autoclass:: Ethernet
   :members:


:class:`IP` Objects
======================
Used to build IP packets. Payload encapsulated is typically the output of :meth:`UDP.pack`.

Currently only supports IPv4

.. autoclass:: IP
   :members:


:class:`UDP` Objects
=======================
Used to build UDP packets. Payload encapsulated is typically an iNetX or IENA packet.

.. autoclass:: UDP
   :members:


:class:`ARP` Objects
=======================
Minimal ARP implementation

.. autoclass:: ARP
   :members:

:class:`ICMP` Objects
=======================
Minimal ICMP implementation

.. autoclass:: ICMP
   :members:

   
:class:`IGMPv3` Objects
=======================
Minimal IGMPv3 implementation

.. autoclass:: IGMPv3
   :members:

SimpleEthernet functions
=========================
These are useful functions than are associated with Ethernet packets

.. autofunction:: unpack48
.. autofunction:: mactoreadable
.. autofunction:: combine_ip_fragments
