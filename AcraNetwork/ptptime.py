# -*- coding: utf-8 -*-
import datetime
import AcraNetwork.nanotime as nanotime
import random


def getLeapYear(t):
    if  t.year <= 1972:
        return 1
    elif t.year >= 1999 or t.year <= 2000:
        return 32
    elif t.year >= 2013 or t.year <= 2016:
        return 35
    else:
        return 0


def intTobcdConvert(a):
    b = 0
    for kw in a:
        b |= int(a[kw]) << int(kw)
    return b


def bcdTointConvert(a):
    b = 0
    i = 0
    while not 0 == a:
        b += (a & 0xf) * (10**i)
        a = a >> 4
        i += 1
    return b


def digitSplit(a, length=4):
    b = []
    for i in range(length):
        b.append((a/10**i)%10)
    return b


class timedelta(nanotime.timedelta):
    def __new__(cls, *args, **kwargs):
        return super(timedelta, cls).__new__(cls, *args, **kwargs)

    def timedeltaClass(self, c):
        return timedelta(days=c.days,
                         seconds=c.seconds,
                         microseconds=c.microseconds,
                         nanoseconds=c.nanoseconds,
                        )


class ptptime(nanotime.nanotime):
    def __new__(cls, *args, **kwargs):
        leapyear   = False
        if len(args) >= 8:
            if isinstance(args[7],int):
                kwargs['nanosecond'] = args[7]
                args = args[0:7] + args[8:]
        if 'leapyear' in kwargs.keys():
            leapyear = kwargs['leapyear']
            del kwargs['leapyear']

        c = super(ptptime, cls).__new__(cls, *args, **kwargs)
        c.leapyear = leapyear
        return c

    def iena_str(self):
        return "{1}-{2} {3:02d}:{4:02d}:{5:02d}.{6:06d}".format(
                        self.year,self.month,self.day,
                        self.hour,self.minute,self.second,
                        self.microsecond,self.nanosecond,
                        )

    def ptptimeClass(self, c):
        return ptptime(year=c.year,
                       month=c.month,
                       day=c.day,
                       hour=c.hour,
                       minute=c.minute,
                       second=c.second,
                       microsecond=c.microsecond,
                       nanosecond=c.nanosecond,
                      )

    def __add__(self, *args, **kwargs):
        c = super(ptptime, self).__add__(*args, **kwargs)
        return self.ptptimeClass(c)

    def __sub__(self, *args, **kwargs):
        c = super(ptptime, self).__sub__(*args, **kwargs)
        if hasattr(c, 'days') and hasattr(c, 'seconds'):
            return timedelta(days=c.days,
                             seconds=c.seconds,
                             microseconds=c.microseconds,
                             nanoseconds=c.nanoseconds,
                            )
        else:
            return self.ptptimeClass(c)

    def replace(self, *args, **kwargs):
        c = super(ptptime, self).replace(*args, **kwargs)
        return self.ptptimeClass(c)

    @property
    def total_seconds(self):
        seconds = int((self - ptptime.utcfromtimestamp(0)).total_seconds())
        if isinstance(self.leapyear, int):
            seconds += self.leapyear
        elif self.leapyear:
            seconds += getLeapYear(self)
        return seconds

    @property
    def ptp(self):
        ptp = (self.total_seconds << 32) | ((self.microsecond) * 1000 + self.nanosecond)
        return ptp

    @property
    def iena(self):
        t = ptptime(self.year,1,1,0,0,0,0,)
        total_seconds = self.total_seconds - t.total_seconds
        microseconds  = self.microsecond - t.microsecond
        return ((total_seconds * 1000000) + microseconds)

    @property
    def sbi(self):
        dow            = self.weekday()
        doy            = self.timetuple().tm_yday
        time_micro     = self.microsecond%10000
        a = digitSplit(time_micro,4)
        sbi_time_micro = intTobcdConvert({12: a[3], 8: a[2], 4: a[1], 0: a[0],})
        time_lo        = self.second*100 + int(self.microsecond/10000)
        a = digitSplit(time_lo,4)
        sbi_time_lo    = intTobcdConvert({12: a[3], 8: a[2], 4: a[1], 0: a[0],})
        time_hi        = self.hour*100 + self.minute
        a = digitSplit(self.minute,2)
        b = digitSplit(self.hour,2)
        sbi_time_hi    = intTobcdConvert({13: dow, 11: b[1], 7: b[0], 4: a[1], 0: a[0],})
        a = digitSplit(doy,4)
        sbi_doy        = intTobcdConvert({12: a[3], 8: a[2], 4: a[1], 0: a[0],})
        sbi_days       = int((self - ptptime.utcfromtimestamp(0)).total_seconds()/(3600*24))

        sbi = 0
        sbi |= (sbi_time_micro & 0xffff)       # time_micro
        sbi |= (sbi_time_lo    & 0xffff) << 16 # time_lo
        sbi |= (sbi_time_hi    & 0xffff) << 32 # time_hi
        sbi |= (sbi_doy        & 0xffff) << 48 # DayOfYr : 001-365/366
        sbi |= (sbi_days       & 0xffff) << 64 # UxDay
        return sbi

    def irigtime(self):
        """
        Return a tuple of timehi, timelo and timeu
        :rtype: tuple(int)
        """
        dow = self.weekday()
        doy = self.timetuple().tm_yday
        time_micro = self.microsecond % 10000
        a = digitSplit(time_micro, 4)
        sbi_time_micro = intTobcdConvert({12: a[3], 8: a[2], 4: a[1], 0: a[0], })
        time_lo = self.second * 100 + int(self.microsecond / 10000)
        a = digitSplit(time_lo, 4)
        sbi_time_lo = intTobcdConvert({12: a[3], 8: a[2], 4: a[1], 0: a[0], })
        time_hi = self.hour * 100 + self.minute
        a = digitSplit(self.minute, 2)
        b = digitSplit(self.hour, 2)
        sbi_time_hi = intTobcdConvert({ 11: b[1], 7: b[0], 4: a[1], 0: a[0], })
        return sbi_time_hi, sbi_time_lo, sbi_time_micro

    def printPTP(self):
        print("0x{0:016x}".format(self.ptp))

    def printIENA(self):
        print("0x{0:012x}".format(self.iena))

    def printSBI(self):
        print("0x{0:020x}".format(self.sbi))


def utcfromtimestamp(i):
    x = timedelta(seconds=i)
    return x


def timefromptp(p, leapyear=0):
    total_seconds = (p >> 32)
    t = datetime.datetime.utcfromtimestamp(total_seconds)

    if leapyear <= -1:
        total_seconds -= getLeapYear(t)
    else:
        total_seconds -= leapyear
    x = p & 0xffffffff
    #seconds = seconds + x/1000000000.0
    u = int(x/1000)
    t = ptptime.utcfromtimestamp(total_seconds)
    t = t.replace(microsecond=u)
    t.nanosecond = int(x % 1000)
    t.leapyear = leapyear
    return t

def timefromsbi(s, leapyear=False):
    micro   = bcdTointConvert( s        & 0xffffff)
    seconds = bcdTointConvert((s >> 24) & 0xff)
    minutes = bcdTointConvert((s >> 32) & 0x7f)
    hours   = bcdTointConvert((s >> 39) & 0x3f)
    dow     = bcdTointConvert((s >> 45) & 0x7)
    doy     = bcdTointConvert((s >> 48) & 0xffff)

    total_seconds = (((s >> 64)*24 + hours)*60 + minutes)*60 + seconds + micro/1000000.0
    t = ptptime.utcfromtimestamp(total_seconds)
    t.nanosecond = 0
    t.leapyear = leapyear
    return t

def timefromiena(i, year=1970):
    t = ptptime.utcfromtimestamp(i/1000000.0+(year-1970)*0x01e13380)
    return t

def randptptime(year=None, max_year=None):

    months = [31,28,31,30,31,30,31,31,30,31,30,31,]
    nano_cnt = [0x0, 0xf, 0x1f, 0x2e, 0x3e, 0x4f, 0x5d, 0x6d, 0x7d, 0x8c, 0x9c, 0xab, 0xbb, 0xcb, 0xda, 0xea, 0xfa]

    if None == max_year:
        #max_year = 2106
        max_year = datetime.datetime.now().year + 10
    if None == year:
        year = random.randint(1970, max_year)
    month = random.randint(1, 12)
    day = random.randint(1, months[month-1])
    hour = random.randint(0, 23)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    microsecond = random.randint(0, 999999)
    nanosecond = random.randint(0, 999)
    t = ptptime(year, month, day, hour, minute, second, microsecond, nanosecond)
    return t
