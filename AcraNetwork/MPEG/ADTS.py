import struct


class ADTS(object):
    def __init__(self) -> None:
        self.aac: bytes = bytes()
        self.version: int = 0
        self.sampling_freq: int = 0
        self._length: int = 0
        self.no_crc: bool = True

    def unpack(self, buffer):
        words = struct.unpack_from(">7B", buffer)
        sw = ((words[1] >> 4) << 8) + words[0]
        if sw != 0xFFF:
            raise Exception(f"Sync word = {sw:#0X}")
        self.sampling_freq = (words[2] >> 2) & 0xF
        self.no_crc = bool(words[1] & 0x1)
        self._length = (words[5] >> 5) + (words[4] << 3) + ((words[3] & 0x3) << 11)
        if self.no_crc:
            self.aac = buffer[7:]
        else:
            self.aac = buffer[9:]

    def __repr__(self) -> str:
        return f"ADTS: NoCRC={self.no_crc} SamplFreq={self.sampling_freq} len={self._length} lenaac={len(self.aac)}"
