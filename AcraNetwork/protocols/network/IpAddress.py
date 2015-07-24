class IpAddress():
    _str = ''
    
    @property
    def str(self):
        if None == self.int:
            return None
        else:
            return self.intToIp(self.int)
    
    def __init__(self, i=None):
        if None == i:
            self.int = None
        elif isinstance(i, int):
            self.int = i
        elif isinstance(i, str):
            self.int = self.ipToInt(i)
    
    def set(self, i):
        return self.__init__(i)    
    
    def __str__(self):
        return '{:s}'.format(self.str)
    
    def __eq__(self, o):
        if o == None and self.int == o:
            return True
        elif isinstance(o, int) and self.int == o:
            return True
        elif isinstance(o, str) and self.str == o:
            return True
        return False
    
    def __ne__(self, o):
        return not self.__eq__(o)    
    
    def __add__(self, o):
        if isinstance(o, int) :
            self.int += o
        return self
    
    def __sub__(self, o):
        return self.__add__(o*-1)    
    
    def intToIp(self, i):
        o = i
        a = []
        for i in range(4):
            a.append('{:d}'.format(o & 0xff))
            o >>= 8
        return '.'.join(a[::-1])

    def ipToInt(self, i):
        r = 0
        for a in i.split('.'):
            r = (r << 8) + int(a)
        return r
