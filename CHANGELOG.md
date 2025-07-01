# Changelog

## 1.2.8   

(FJP 2025-07-01)
- Added Context Manager support to Pcap.py
- Allow Golay.decode() to accept bytearray or other bytes-like object 
  instead of only bytes (if not int)
- simplified Golay.py; removed some redundant checks

## 1.2.7   

Changed setup so as not to break if extension cannot be compiled

## 1.2.6   

Further optimisation of the C Golay implementation

## 1.2.5   

Added C implementation of Golay. Also improved the existing python impl

## 1.2.4   

Removed exit in the ch7

## 1.2.3   

Last release was not successful

## 1.2.2   

Fixed chapter 7 packet generation

## 1.2.1   

Fixed logging in IP error message

## 1.2.0   

Moved Chapter 7 into the IRIG106 folder. Removed old Chapter10 directory

## 1.1.9   

Fixed ARINC ch10 intra packet header

## 1.1.8   

No change but tagging as 1.1.8

## 1.1.7   

Added logging error for incorrect IP checksum

## 1.1.6   

No change but tagging as 1.1.6

## 1.1.5   

Missing ut file added

## 1.1.4   

Updates to the MPEGTS packets to build and decom a PTS / DTS packet

## 1.1.2   

Fixed the ch10 examples

## 1.1.1   

Version tag not updates

## 1.1.0

This is a significant change to how the Chapter10 modules are organised. The previous organisation reflected the common
useage of the term Chapter10 to mean Chapter10 and Chapter11

This change moves all Chapter10 into IRIG106 namespace and then based on their location in the IRIG spec, namely Chapter10 or Chapter11

The existing structure will be supported but with a Deprecation warning

## 1.0.0

No changes from 0.17.17

## 0.17.17

Docstring updates

## 0.17.16

Added documentation details

## 0.17.15

Added support for reading SamDec pcap files

## 0.17.14

Fixed the PMT packet in MPEGTS

## 0.17.13

Added chapter 10 recorder script.

## 0.17.11

Added the SamDec class to support capturing live data from a SamDec

## 0.17.10

Added support for ARP in SimpleEthernet

## Older

Review __version__.py


