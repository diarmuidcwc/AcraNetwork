Chapter 10 Documentation
**************************


Chapter10 is a IRIG106 payload format usual encapsulated in UDP payloads. The full standard is defined in http://www.irig106.org/docs/106-11/chapter10.pdf

This module supports the creating and analysis of Chapter10 packets

In typical use, a UDP payload is captured from the network or read from a PCAP file. This is then passed to the
:meth:`Chapter10.Chapter10UDP.unpack` method which converts it into an Chapter10 object

The payload of the UDP wrapper contains a Data Format packet (described in 10.6.1 of the spec) which is handled by the
Chapter10 object :class:`Chapter10.Chapter10`


Examples and details are available below

.. py:currentmodule:: AcraNetwork.Chapter10.Chapter10UDP

:class:`Chapter10UDP` Objects
==============================
.. autoclass:: Chapter10UDP
   :members:


.. py:currentmodule:: AcraNetwork.Chapter10.Chapter10

:class:`Chapter10` Objects
===========================
.. autoclass:: Chapter10
   :members:

:class:`FileParser` Objects
===========================
.. autoclass:: FileParser
   :members:

Chapter10 functions
=========================
These are useful functions than are associated with Chapter10 packets

.. autofunction:: get_checksum_buf
.. autofunction:: get_checksum_byte_buf


.. py:currentmodule:: AcraNetwork.Chapter10.Analog

:class:`Analog` Objects
===========================
.. autoclass:: Analog
   :members:

.. py:currentmodule:: AcraNetwork.Chapter10.ARINC429

:class:`ARINC429DataPacket` Objects
====================================
.. autoclass:: ARINC429DataPacket
   :members:


:class:`ARINC429DataWord` Objects
==================================
.. autoclass:: ARINC429DataWord
   :members:

.. py:currentmodule:: AcraNetwork.Chapter10.CAN

:class:`CANDataPacket` Objects
=================================
.. autoclass:: CANDataPacket
   :members:

.. py:currentmodule:: AcraNetwork.Chapter10.ComputerData

:class:`ComputerGeneratedFormat0` Objects
==========================================
.. autoclass:: ComputerGeneratedFormat0
   :members:

:class:`ComputerGeneratedFormat1` Objects
==========================================
.. autoclass:: ComputerGeneratedFormat1
   :members:

.. py:currentmodule:: AcraNetwork.Chapter10.MILSTD1553

:class:`MILSTD1553DataPacket` Objects
======================================
.. autoclass:: MILSTD1553DataPacket
   :members:

:class:`MILSTD1553Message` Objects
==================================
.. autoclass:: MILSTD1553Message
   :members:


.. py:currentmodule:: AcraNetwork.Chapter10.PCM
   
:class:`PCMDataPacket` Objects
==================================
.. autoclass:: PCMDataPacket
   :members:

.. py:currentmodule:: AcraNetwork.Chapter10.TimeDataFormat
   
:class:`TimeDataFormat1` Objects
==================================
.. autoclass:: TimeDataFormat1
   :members:

:class:`TimeDataFormat2` Objects
==================================
.. autoclass:: TimeDataFormat2
   :members:

Chapter10.TimeDataFormat functions
===================================
These are useful functions than are associated with Time packets

.. autofunction:: double_digits_to_bcd
.. autofunction:: bcd_to_int

.. py:currentmodule:: AcraNetwork.Chapter10.UART
   
:class:`UARTDataPacket` Objects
==================================
.. autoclass:: UARTDataPacket
   :members:
   
:class:`UARTDataWord` Objects
==================================
.. autoclass:: UARTDataWord
   :members:

.. py:currentmodule:: AcraNetwork.Chapter10.Video
   
:class:`VideoFormat2` Objects
==================================
.. autoclass:: VideoFormat2
   :members: