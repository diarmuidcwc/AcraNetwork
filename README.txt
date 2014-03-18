AcraNetwork
===========

Summary
~~~~~~~~
A collection of classes for use in de-com of iNetX packets. Applies to both pcap files and straight from the network
* iNetX : Class for packing and unpacking iNetX packets
* IENA  : Class for packing and unpacking IENA packets
* SimpleEthernet : A very simplified set of classes for Ethernet, IP, UDP, AFDX packets. These are not fully featured but
	can do the job for what we need
* Pcap : Class and helper methods for reading pcap files
* McastSocket : Class to bind to ports to capture multicast packets

INSTALL
~~~~~~~~
Install using the standard setuptools install method
> python setup.py install


USAGE
~~~~~~~~~
The examples show some basic usage of the Classes.
pcap_to_ascii.py will read in pcap files and dump out ascii representations of the module
