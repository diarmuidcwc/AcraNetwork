# AcraNetwork 


[![Documentation Status](https://readthedocs.org/projects/acranetwork/badge/?version=latest)](https://acranetwork.readthedocs.io/en/latest/?badge=latest)

![Python App](https://github.com/diarmuidcwc/AcraNetwork/actions/workflows/python-app.yml/badge.svg)

A collection of classes that can be used to decom network or PCM based FTI traffic. This module contains classes to handle various packet formats like, iNetX, IENA, Chapter10, DARv3 (NPD).

It also contains a class to decom data from a SAM/DEC/008

Full documentation is available here https://acranetwork.readthedocs.io/en/latest/

## Summary

* iNetX : Class for packing and unpacking iNetX objects
* IENA  : Class for packing and unpacking IENA objects
* SimpleEthernet : A  simplified set of classes for Ethernet, IP and UDP packets. These are not fully featured is sufficient for the network systems used in the KAM500 networks
* Pcap : Class and helper methods for reading pcap files
* Chapter10: Class for chapter10 and chapter11 packets
* MPEGTS: MpegTransport stream packets


## Install

Install using pip

```bash
pip install AcraNetwork
```

## Usage

Browse the example folder for some example usage


## To Make a Distribution

```bash
pip  install --upgrade pip wheel setuptools twine
rm dist/*
python ./setup.py sdist bdist_wheel --universal sdist
twine upload dist/*
```