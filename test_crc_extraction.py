#!/usr/bin/env python3
"""Test script to verify CRC field extraction from PTDP header"""

from AcraNetwork.IRIG106.Chapter7 import PTDP, PTDPContent, PTDPFragment

def test_crc_extraction():
    """Test that CRC field is correctly extracted from PTDP header"""

    # Test 1: Packet with CRC disabled (crc=False)
    print("Test 1: Packet with CRC disabled")
    ptdp_crc_off = PTDP()
    ptdp_crc_off.content = PTDPContent.CHAPTER_10
    ptdp_crc_off.payload = bytearray(b"TEST DATA")
    ptdp_crc_off.crc = False

    packed = ptdp_crc_off.pack()
    print(f"  Packed length: {len(packed)} bytes")

    # Decode it back
    unpacked = PTDP()
    result = unpacked.unpack(packed)

    print(f"  CRC field: {unpacked.crc}")
    assert unpacked.crc == False, "CRC should be False when not set in packet"
    assert unpacked.content == PTDPContent.CHAPTER_10
    print("  ✓ CRC correctly extracted as False")

    # Test 2: Packet with CRC enabled (crc=True)
    print("\nTest 2: Packet with CRC enabled")
    ptdp_crc_on = PTDP()
    ptdp_crc_on.content = PTDPContent.CHAPTER_10
    ptdp_crc_on.payload = bytearray(b"TEST DATA")
    ptdp_crc_on.crc = True

    packed = ptdp_crc_on.pack()
    print(f"  Packed length: {len(packed)} bytes")
    print(f"  CRC flag set in packet: {ptdp_crc_on.crc}")

    # Decode it back
    unpacked = PTDP()
    result = unpacked.unpack(packed)

    print(f"  CRC field: {unpacked.crc}")
    assert unpacked.crc == True, "CRC should be True when set in packet"
    assert unpacked.content == PTDPContent.CHAPTER_10
    print("  ✓ CRC correctly extracted as True")

    # Test 3: Python unpack path with CRC enabled
    print("\nTest 3: Python unpack path with CRC enabled")
    ptdp = PTDP()
    ptdp.content = PTDPContent.ASP
    ptdp.payload = bytearray(b"\x01\x02\x03")
    ptdp.crc = True

    packed = ptdp.pack()
    unpacked = PTDP()

    # Manually decode the header to check bit 11
    import struct
    import AcraNetwork.IRIG106.Chapter7 as ch7

    mv = memoryview(packed)
    lsw = ch7.Golay.Golay().decode(mv[:3])
    msw = ch7.Golay.Golay().decode(mv[3:6])

    # According to the spec, bit 11 of decoded LSW should indicate CRC
    extracted_crc = bool((lsw >> 11) & 0x1)
    print(f"  Bit 11 of decoded LSW: {extracted_crc}")

    # Now unpack with the regular method
    unpacked.unpack(packed)
    print(f"  CRC from unpack: {unpacked.crc}")
    assert unpacked.crc == extracted_crc, "CRC should match bit 11"
    print("  ✓ CRC matches bit 11 of LSW")

    print("\n✅ All CRC extraction tests passed!")

if __name__ == "__main__":
    test_crc_extraction()