AcraNetwork 
===========

A collection of classes that can be used to decom network or PCM based FTI traffic


Summary
~~~~~~~


* iNetX : Class for packing and unpacking iNetX objects
* IENA  : Class for packing and unpacking IENA objects
* SimpleEthernet : A  simplified set of classes for Ethernet, IP and UDP packets. These are not fully featured is sufficient for the network systems used in the KAM500 networks
* Pcap : Class and helper methods for reading pcap files
* McastSocket : Class to bind to ports to capture multicast packets

Install
~~~~~~~

Install using the standard setuptools install method

.. code-block::

	python setup.py install


or clone this repository to your local directory

.. code-block::

	git clone https://github.com/diarmuidcwc/AcraNetwork.git


Usage
~~~~~

Here are two brief examples on how to create and read a pcap file. Further examples can be viewed in the examples
directory or in the unittest folder

To read in a pcap file with multiple ethernet packets all containing an iNetX packet wrapped in UDP

.. code-block:: python

	import AcraNetwork.iNetX as inetx
	import AcraNetwork.SimpleEthernet as SimpleEthernet
	import AcraNetwork.Pcap as pcap

	import struct
	mypcap = pcap.Pcap("inetx_test.pcap")       # Read the pcap file
	for mypcaprecord in mypcap:

		ethpacket = SimpleEthernet.Ethernet()   # Create an Ethernet object
		ethpacket.unpack(mypcaprecord.packet)   # Unpack the pcap record into the eth object
		ippacket =  SimpleEthernet.IP()         # Create an IP packet
		ippacket.unpack(ethpacket.payload)      # Unpack the ethernet payload into the IP packet
		udppacket = SimpleEthernet.UDP()        # Create a UDP packet
		udppacket.unpack(ippacket.payload)      # Unpack the IP payload into the UDP packet
		inetxpacket = inetx.iNetX()             # Create an iNetx object
		inetxpacket.unpack(udppacket.payload)   # Unpack the UDP payload into this iNetX object
		print("INETX: StreamID ={:08X} Sequence = {:8d} PTP Seconds = {}".format(inetxpacket.streamid,inetxpacket.sequence,inetxpacket.ptptimeseconds))


To Make a Distribution
~~~~~~~~~~~~~~~~~~~~~~

.. code-block::

	pip  install --upgrade pip wheel setuptools twine
	rm dist/*
	python ./setup.py bdist_wheel --universal sdist
	twine upload dist/*
