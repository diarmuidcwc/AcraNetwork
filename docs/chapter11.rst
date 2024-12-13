Chapter 11 Documentation
**************************


Chapter11 is a IRIG106 payload format encapsulating acquisition data. The full standard is defined in http://www.irig106.org/docs/106-11/chapter11.pdf

This module supports the creating and analysis of Chapter11 packets

In typical use, a UDP payload is captured from the network or read from a PCAP file. This is then passed to the
:meth:`AcraNetwork.IRIG106.Chapter11.Chapter11.unpack` method which converts it into an Chapter11 object

The payload of the UDP wrapper contains a Data Format packet (described in 10.6.1 of the spec) which is handled by the
Chapter10 object :class:`AcraNetwork.IRIG106.Chapter11.Chapter11`


Examples and details are available below

.. py:currentmodule:: AcraNetwork.IRIG106.Chapter11

:class:`Chapter11` Objects
===========================
.. autoclass:: Chapter11
   :members:



Chapter11 functions
=========================
These are useful functions than are associated with Chapter11 packets

.. autofunction:: get_checksum_buf
.. autofunction:: get_checksum_byte_buf


.. py:currentmodule:: AcraNetwork.IRIG106.Chapter11.Analog

:class:`Analog` Objects
===========================
.. autoclass:: Analog
   :members:

.. py:currentmodule:: AcraNetwork.IRIG106.Chapter11.ARINC429

:class:`ARINC429DataPacket` Objects
====================================
.. autoclass:: ARINC429DataPacket
   :members:


:class:`ARINC429DataWord` Objects
==================================
.. autoclass:: ARINC429DataWord
   :members:

.. py:currentmodule:: AcraNetwork.IRIG106.Chapter11.CAN

:class:`CANDataPacket` Objects
=================================
.. autoclass:: CANDataPacket
   :members:

.. py:currentmodule:: AcraNetwork.IRIG106.Chapter11.ComputerData

:class:`ComputerGeneratedFormat0` Objects
==========================================
.. autoclass:: ComputerGeneratedFormat0
   :members:

:class:`ComputerGeneratedFormat1` Objects
==========================================
.. autoclass:: ComputerGeneratedFormat1
   :members:

.. py:currentmodule:: AcraNetwork.IRIG106.Chapter11.MILSTD1553

:class:`MILSTD1553DataPacket` Objects
======================================
.. autoclass:: MILSTD1553DataPacket
   :members:

:class:`MILSTD1553Message` Objects
==================================
.. autoclass:: MILSTD1553Message
   :members:


.. py:currentmodule:: AcraNetwork.IRIG106.Chapter11.PCM
   
:class:`PCMDataPacket` Objects
==================================
.. autoclass:: PCMDataPacket
   :members:

.. py:currentmodule:: AcraNetwork.IRIG106.Chapter11.TimeDataFormat
   
:class:`TimeDataFormat1` Objects
==================================
.. autoclass:: TimeDataFormat1
   :members:

:class:`TimeDataFormat2` Objects
==================================
.. autoclass:: TimeDataFormat2
   :members:

Chapter11.TimeDataFormat functions
===================================
These are useful functions than are associated with Time packets

.. autofunction:: double_digits_to_bcd
.. autofunction:: bcd_to_int

.. py:currentmodule:: AcraNetwork.IRIG106.Chapter11.UART
   
:class:`UARTDataPacket` Objects
==================================
.. autoclass:: UARTDataPacket
   :members:
   
:class:`UARTDataWord` Objects
==================================
.. autoclass:: UARTDataWord
   :members:

.. py:currentmodule:: AcraNetwork.IRIG106.Chapter11.Video
   
:class:`VideoFormat2` Objects
==================================
.. autoclass:: VideoFormat2
   :members: