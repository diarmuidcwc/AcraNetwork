AcraNetwork [![Build Status](https://travis-ci.org/diarmuidcwc/AcraNetwork.svg?branch=master)](https://travis-ci.org/diarmuidcwc/AcraNetwork)
===========

A collection of classes that can be used to decom network or PCM based FTI traffic

#Summary

* iNetX : Class for packing and unpacking iNetX objects
* IENA  : Class for packing and unpacking IENA objects
* SimpleEthernet : A  simplified set of classes for Ethernet, IP and UDP packets. These are not fully featured is
sufficient for the network systems used in the KAM500 networks
* Pcap : Class and helper methods for reading pcap files
* McastSocket : Class to bind to ports to capture multicast packets

#Install
Install using the standard setuptools install method
```shell
python setup.py install
```
or clone this repository to your local directory

```shell
git clone https://github.com/diarmuidcwc/AcraNetwork.git
```

#Classes

##iNetx
This will create an iNetx object. Once you have an iNetX object you can then either
* assign values to the various fields and then convert(pack) the object into a buffer that is suitable for transmission
or writing to a file or
* convert (unpack) a buffer containing an iNetX packet

###Methods

####pack()

This method will take an iNetX object and return a string buffer containing the binary representation of the iNetX packet
This method is typically run if you want to write an iNetX packet to a file or to transmit over the network

####unpack(buffer)

This method will convert a binary buffer into an iNetX object. This is typically used to convert some data read from a
pcap file or captured from the network into the iNetX object.

####setPacketTime(utctimeinseconds,timeinmicroseconds)

This method will accept two arguments, utctimeinseconds and nanoseconds and assign the time to the iNetX object


##IENA

This will create an IENA object. Once you have an IENA object you can then either
* assign values to the various fields and then convert(pack) the object into a buffer that is suitable for transmission
or writing to a file or
* convert (unpack) a buffer containing an IENA packet

###Methods

####pack()

This method will take an IENA object and return a string buffer containing the binary representation of the IENA packet.
This method is typically run if you want to write an IENA packet to a file or to transmit over the network

####unpack(buffer)

This method will convert a binary buffer into an IENA object. This is typically used to convert some data read from a
pcap file or captured from the network into the IENA object.

####setPacketTime(utctimeinseconds,timeinnanoseconds)

This method will accept two arguments, utctimeinseconds and microseconds and assign the time to the IENA object

##Ethernet / IP / UDP

Each of these classes will create the corresponding object. Once you create this object you can then either
* assign values to the various fields and then convert(pack) the object into a buffer that is suitable for transmission
or writing to a file or
* convert (unpack) a buffer containing the packet

###Methods

####pack()

This method will take the object and return a string buffer containing the binary representation of the packet.
This method is typically run if you want to write a packet to a file or to transmit over the network

####unpack(buffer)

This method will convert a binary buffer into an object. This is typically used to convert some data read from a
pcap file or captured from the network into the IENA object.

##Pcap

This class will allow you to read and write to a Pcap file. Due to the potentially large size of pcap files, the complete
file is not read or written in one operation but in pieces. This keeps the memory usage to a minimum

###Methods

####__init__()

To create a new pcap object you need to supply a filename and a flag to indicate if you want to read or write to this
file. eg
```python
pcap_for_reading = pcap.Pcap("input.pcap") 						# Create a new Pcap object based on reading from the file
pcap_for_writing = pcap.Pcap("output.pcap",mode='w')	# Create a new Pcap object that will be writing to a file
pcap_for_appending = pcap.Pcap("output.pcap",mode='a')	# Open an existing pcap file for appending
```

####readGlobalHeader()

When reading a pcap file this should be the first method called. This method will populate the fields in the Pcap object
as described in the [Pcap Wiki](http://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header)

####readAPacket()

This method is called when reading a pcap file. It can be called repeatedly until the end of the file is reached and
the method raises an IOError exception
This method will return a PcapRecord object which will contain one pcap record, containing the header and payload

####writeGlobalHeader()

When creating a new pcap file, this method should be called first. It will write a valid global header to the file.
When creating a new Pcap object the defaults used in the object will generate a standard pcap file that will support
Ethernet packets

####writeARecord(pcaprecord)

Write out one pcap record to the file. The argument is required to be a PcapRecord object

####close()

Close the pcap file




#Usage
Here are two brief examples on how to create and read a pcap file. Further examples can be viewed in the examples
directory or in the unittest folder

To read in a pcap file with multiple ethernet packets all containing an iNetX packet wrapped in UDP

```python
import sys
sys.path.append("..")

import AcraNetwork.iNetX as inetx
import AcraNetwork.SimpleEthernet as SimpleEthernet
import AcraNetwork.Pcap as pcap

import struct
mypcap = pcap.Pcap("inetx_test.pcap")       # Read the pcap file
mypcap.readGlobalHeader()
while True:
	# Loop through the pcap file reading one packet at a time
	try:
		mypcaprecord = mypcap.readAPacket()
	except IOError:
		# End of file reached
		break

	ethpacket = SimpleEthernet.Ethernet()   # Create an Ethernet object
	ethpacket.unpack(mypcaprecord.packet)   # Unpack the pcap record into the eth object
	ippacket =  SimpleEthernet.IP()         # Create an IP packet
	ippacket.unpack(ethpacket.payload)      # Unpack the ethernet payload into the IP packet
	udppacket = SimpleEthernet.UDP()        # Create a UDP packet
	udppacket.unpack(ippacket.payload)      # Unpack the IP payload into the UDP packet
	inetxpacket = inetx.iNetX()             # Create an iNetx object
	inetxpacket.unpack(udppacket.payload)   # Unpack the UDP payload into this iNetX object
	print "INETX: StreamID ={:08X} Sequence = {:8d} PTP Seconds = {}".format(inetxpacket.streamid,inetxpacket.sequence,inetxpacket.ptptimeseconds)
```

#To Make a Distribution
```
python setup.py sdist bdist_wininst upload
```