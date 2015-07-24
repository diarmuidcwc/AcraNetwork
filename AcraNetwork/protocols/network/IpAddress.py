from AcraNetwork.protocols.network.BaseAddress import BaseAddress
class IpAddress(BaseAddress):
    
    
    def intToAddr(self, i):
        o = i
        a = []
        for i in range(4):
            a.append('{:d}'.format(o & 0xff))
            o >>= 8
        return '.'.join(a[::-1])

    
    def addrToInt(self, i):
        r = 0
        for a in i.split('.'):
            r = (r << 8) + int(a)
        return r
