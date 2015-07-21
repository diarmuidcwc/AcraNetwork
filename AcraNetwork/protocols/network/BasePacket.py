import struct

class BasePacket(object):
    '''Class to build and unpack a Base packet'''
    
    HEADER = []
    
    def calcHeaderFormat(self, header=None):
        if not None == header:
            self.HEADER = header
        self.HEADER_FORMAT = '>'
        for i in self.HEADER:
            for j in i['w']:
                self.HEADER_FORMAT += j
        self.HEADER_SIZE = struct.calcsize(self.HEADER_FORMAT)
    
    def __init__(self, buf=None, debug=False):
        self.offset = 0
        self.debug = debug
        self.calcHeaderFormat()
        for i in self.HEADER:
            if not hasattr(self, i['n']):
                if 'd' in i.keys():
                    setattr(self, i['n'], i['d'])
                else:
                    setattr(self, i['n'], 0)
            else:
                raise ValueError("Attribute {} already exists!".format(i['n']))

#         for i in self.HEADER:
#             print('a', i['n'], getattr(self, i['n']))
        if buf != None:
            self.unpack(buf)
           
    def unpack(self, buf, header=None):
        '''Unpack a buffer into a object'''
        self.calcHeaderFormat(header)
        if len(buf[self.offset:]) < self.HEADER_SIZE:
            raise ValueError("Buffer too short to fill remaining packet")
        
        fields = struct.unpack_from(self.HEADER_FORMAT, buf[self.offset:])
        j = 0
        for i in self.HEADER:
            if not isinstance(i['w'], list):
                r = fields[j]
                j += 1
            else:
                r = 0
                for k in i['w']:
                    if 'B' == k.upper():
                        o = 4
                    elif 'H' == k.upper():
                        o = 8
                    elif 'I' == k.upper():
                        o = 16
                    elif 'Q' == k.upper():
                        o = 32
                    r = (r << o) + fields[j]
                    j += 1
            
            setattr(self, i['n'], r)
        
        if self.debug:
            for i in self.HEADER:
                print('b', i['n'], getattr(self, i['n']))
        self.offset += self.HEADER_SIZE
        self.payload = buf[self.HEADER_SIZE:]
        
        if None == header:
            self.unpack_local(buf)
    
    def unpack_local(self, buf=None):
        pass

#     def pack(self):
#         '''Pack a UDP object into a buffer
#         :rtype :str
#         '''
#         if self.srcport == None or self.dstport == None or self.payload == None:
#             raise ValueError("All UDP fields need to be defined to pack the payload")
# 
#         self.len = len(self.payload) + UDP.UDP_HEADER_SIZE
#         return struct.pack(UDP.UDP_HEADER_FORMAT,self.srcport,self.dstport,self.len,0) + self.payload
