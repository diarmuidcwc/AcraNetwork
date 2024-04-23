import struct
import datetime


SEI_UNREG_DATA = 5


class STANAG4609_SEI(object):
    """
    Handle the SEI NAL and more specifically this will handle SEIs defined in 3.14.3.5 of the STANAG standard
    http://www.gwg.nga.mil/misb/docs/nato_docs/STANAG_4609_Ed3.pdf
    """

    def __init__(self):
        self.payloadtype = None
        self.payloadsize = None
        self.unregdata = False
        self.status = None
        self.seconds = None
        self.microseconds = None
        self.nanoseconds = None
        self.time = None
        self.stanag = False

    def unpack(self, buf):
        """
        Unpack the NAL _payload as an STANAG4609_SEI

        :param buf: The buffer to unpack into an STANAG4609_SEI
        :type buf: str
        :rtype: bool
        """

        (self.payloadtype, self.payloadsize) = struct.unpack(">BB", buf[0:2])
        if self.payloadtype == SEI_UNREG_DATA:
            self.unregdata = True
            (
                sig1,
                sig2,
                self.status,
                ms1,
                _fix1,
                ms2,
                _fix2,
                ms3,
                _fix3,
                ms4,
            ) = struct.unpack_from(">QQBHBHBHBH", buf[2:])
            # combine the time fields (cf  http://www.gwg.nga.mil/misb/docs/nato_docs/STANAG_4609_Ed3.pdf 3.14.3.4 )
            # Verify the signature and if it's good then convert to a time
            if (
                sig1 == 0x4D4953506D696372
                and sig2 == 0x6F73656374696D65
                and _fix1 == 0xFF
                and _fix2 == 0xFF
                and _fix3 == 0xFF
            ):
                useconds = (ms1 << 48) + (ms2 << 32) + (ms3 << 16) + ms4
                self.seconds = float(useconds) / 1.0e6
                self.nanoseconds = (ms3 << 16) + ms4
                self.time = datetime.datetime.fromtimestamp(self.seconds)
                self.stanag = True
