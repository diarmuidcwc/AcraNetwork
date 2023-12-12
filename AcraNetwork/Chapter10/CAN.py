import typing
import struct
from AcraNetwork.Chapter10 import TS_CH4, TS_IEEE1558, RTCTime, PTPTime


class CANMessage(object):
    def __init__(self, ipts_source=TS_CH4):
        if ipts_source == TS_CH4:
            self.ipts = RTCTime()
        elif ipts_source == TS_IEEE1558:
            self.ipts = PTPTime()
        elif ipts_source is None:
            raise Exception("Time stamp is not option for CAN Bus")

        self.subchannel: int = 0
        self.data_error: bool = False
        self.format_error: bool = False


class CANDataPacket(object):
    def __init__(self, ipts_source=TS_CH4) -> None:
        self.messages: typing.List[CANMessage] = []
