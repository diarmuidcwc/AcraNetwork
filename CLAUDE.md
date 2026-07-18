# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AcraNetwork is a Python library for parsing and reconstructing Flight Test Instrumentation (FTI) network traffic and packet formats. It handles various proprietary and standard formats including iNetX, IENA, IRIG106 Chapter10/11/7/24, DARv3 (NPD), SAM/DEC/008, and MPEG-2 transport streams.

## Build and Test Commands

### Install Dependencies
```bash
pip install -e .
```

### Run Tests
```bash
pytest -v
pytest --doctest-modules AcraNetwork
coverage run -m pytest
coverage html  # Generates coverage report
```

### Lint
```bash
flake8 . --count --max-complexity=10 --max-line-length=127 --statistics
```

### Build Distribution
```bash
python setup.py sdist bdist_wheel --universal
twine upload dist/*
```

## High-Level Architecture

### Core Packet Format Modules

**Main packet parsing classes** (each provides `pack()` and `unpack()` methods):
- `iNetX.py` - iNetX protocol (often used as container format)
- `IENA.py` - IENA payloads (D, M, N, Q variants)
- `iNET.py` - Lightweight network protocol
- `NPD.py` - DARv3 NPD packets
- `SimpleEthernet.py` - Simplified Ethernet/IP/UDP stacks (includes VLAN, ARP, FCS)
- `Pcap.py` - PCAP file I/O iterator model with context manager support

### IRIG106 Standard Submodule

The IRIG106 module follows the IRIG106 standard organization, with separate directories for each chapter:

- `IRIG106/Chapter7/` - PTDP (Packetized Time Data Protocol) with optional C extension for Golay decoding
- `IRIG106/Chapter10/` - Packetized time data, including UART payloads, PCM throughput mode, secondary headers
- `IRIG106/Chapter11/` - Time data payloads for various protocols:
  - `Analog.py` - Analog signal handling
  - `ARINC429.py` - ARINC 429 data
  - `CAN.py` - CAN bus data
  - `UART.py` - Serial UART data
  - `PCM.py` - PCM samples
  - `MILSTD1553.py` - MIL-STD-1553 data
  - `Video.py` - Video payloads
  - `ComputerData.py` - Generic computer data
- `IRIG106/Chapter24/` - Extended time data

**Note:** Chapter10 moved to IRIG106 in v1.1.0. Code from the old root-level module will still work but shows a deprecation warning.

### Network Protocol Modules

- `GRE.py` - Generic Routing Encapsulation
- `McastSocket.py` - Multicast socket utilities
- `MPEGTS.py` - MPEG-2 transport stream parsing

### Utilities

- `ParserAligned.py` - Parser-aligned packet blocks (quad-byte aligned)
- `nanotime.py` - Nanosecond time utilities
- `ptptime.py` - Precision time protocol utilities
- `SamDec008.py` - SAM/DEC/008 packet handling

### Key Design Patterns

1. **Binary Data Handling**: Uses `struct` module with explicit byte ordering (`>`, `<`, `!`). Most protocols use big-endian, but Chapter10 can be little-endian.

2. **Graceful C Extension Fallback**: The setup.py uses `OptionalBuildExt` to attempt building C extensions (Chapter7 Golay) without failing. If the C extension builds fail, Python fallback is used.

3. **Pcap Iterator Model**: `Pcap` class returns iterator with context manager support. Each iteration yields a `PcapRecord` object with `sec`, `usec`, `incl_len`, `orig_len`, and `packet`/`payload` properties.

4. **Multiprotocol Support**: Each main protocol class (IENA, Chapter10, etc.) supports multiple variants. Version history in `__version__.py` tracks protocol changes.

5. **Endianness Support**: The `endianness_swap()` utility in `__init__.py` provides manual byte order swapping.

## Common Workflows

### Reading and Parsing a PCAP File
```python
import AcraNetwork.Pcap as pcap

with pcap.Pcap("test/input.pcap") as pcap_file:
    for record in pcap_file:
        # Record has sec, usec, incl_len, payload
        # Process payload with appropriate packet parser
```

### Creating a Chapter10 Packet
```python
from AcraNetwork.IRIG106.Chapter10 import Chapter10UDP

ch10 = Chapter10UDP()
ch10.timeid = 0
ch10.payload = b'\x01\x02\x03'
ch10.packet = ch10.pack()
```

### Using the C-Optimized Chapter7
The Chapter7 module will automatically use C extensions if they build successfully:
```python
from AcraNetwork.IRIG106.Chapter7 import Chapter7

# Will use C golay_c module if available, otherwise Python fallback
packet = Chapter7()
packet.unpack(golay_data)
```

## Testing Strategy

Tests are organized in the `test/` directory with specific files for each major module. Test data (.pcap files) is included for validation. Test examples use the actual test files:
```bash
pytest test/test_ch10.py
pytest test/test_iena.py
```

## Protocol-Specific Notes

- **IENA**: Supports D (data), M (mixed), N (no parameter data), Q (quad). Must have integer number of D/N parameters in payload.
- **ParserAligned**: Requires quad-byte aligned payloads; throws exception for illegal quadbyte counts.
- **Chapter10**: Endianness changed in v0.11.0; some payloads may be little-endian.
- **SimpleEthernet**: Has been expanded to handle VLANs more completely and ARP.

## Dependencies

- Standard library only (no external dependencies for main functionality)
- Development dependencies: flake8, pytest, coverage
