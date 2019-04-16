# -*- coding: utf-8 -*-
import datetime


class timedelta(datetime.timedelta):
    def __new__(cls, *args, **kwargs):
        nanoseconds = 0
        if 'nanoseconds' in kwargs.keys():
            nanoseconds = kwargs['nanoseconds']
            del kwargs['nanoseconds']
        if not 'microseconds' in kwargs.keys():
            kwargs['microseconds'] = 0

        if nanoseconds < 0:
            kwargs['microseconds'] -= 1

        kwargs['microseconds'] += int(nanoseconds / 1000.0)
        nanoseconds = nanoseconds % 1000

        c = super(timedelta, cls).__new__(cls, *args, **kwargs)
        c.nanoseconds = nanoseconds

        return c

    @property
    def _hour(self):
        return int(self.seconds / 3600)

    @property
    def _minute(self):
        return int(self.seconds / 60) % 60

    @property
    def _second(self):
        return self.seconds % 60

    def __str__(self, *args, **kwargs):
        days = ""
        micros = ""
        nanos = ""
        if not self.days == 0:
            pural = ""
            if abs(self.days) > 1:
                pural = "s"
            days = "{0:d} day{1}, ".format(self.days, pural)
        if not self.microseconds == 0 or not self.nanoseconds == 0:
            micros = ".{0:06d}".format(self.microseconds)
        if not self.nanoseconds == 0:
            nanos = ":{0:03d}".format(self.nanoseconds)
        return "{0}{1:d}:{2:02d}:{3:02d}{4}{5}".format(
            days,
            self._hour, self._minute, self._second,
            micros, nanos
        )


class nanotime(datetime.datetime):
    def __new__(cls, *args, **kwargs):
        nanosecond = 0
        if len(args) >= 8:
            if isinstance(args[7], int):
                nanosecond = args[7]
                args = args[0:7] + args[8:]
        if 'nanosecond' in kwargs.keys():
            nanosecond = kwargs['nanosecond']
            del kwargs['nanosecond']

        c = super(nanotime, cls).__new__(cls, *args, **kwargs)
        c.nanosecond = nanosecond
        return c

    def nanotimeClass(self, c):
        return nanotime(year=c.year,
                        month=c.month,
                        day=c.day,
                        hour=c.hour,
                        minute=c.minute,
                        second=c.second,
                        microsecond=c.microsecond,
                        nanosecond=c.nanosecond,
                        )

    def __str__(self):
        return "{0}-{1}-{2} {3:02d}:{4:02d}:{5:02d}.{6:06d}:{7:03d}".format(
            self.year, self.month, self.day,
            self.hour, self.minute, self.second,
            self.microsecond, self.nanosecond,
        )

    def __add__(self, *args, **kwargs):
        try:
            nanoseconds = args[0].nanoseconds
        except AttributeError:
            nanoseconds = 0

        if hasattr(args[0], 'days') and hasattr(args[0], 'seconds'):
            pass
        else:
            raise TypeError("unsupported operand type(s) for +: '{0}' and '{1}'".format(self.__class__.__name__,
                                                                                        args[0].__class__.__name__))

        c = super(nanotime, self).__add__(*args, **kwargs)

        nanoseconds += self.nanosecond
        microsecond = c.microsecond + int(nanoseconds / 1000.0)
        nanoseconds %= 1000
        # return self.nanotimeClass(c)

        return nanotime(c.year,
                        c.month,
                        c.day,
                        c.hour,
                        c.minute,
                        c.second,
                        microsecond,
                        nanoseconds,
                        )

    def __sub__(self, *args, **kwargs):
        if hasattr(args[0], 'days') and hasattr(args[0], 'seconds'):
            days = args[0].days
            seconds = args[0].seconds
            microseconds = args[0].microseconds
            try:
                nanoseconds = args[0].nanoseconds
            except AttributeError:
                nanoseconds = 0
            x = timedelta(days=-days,
                          seconds=-seconds,
                          microseconds=-microseconds,
                          nanoseconds=-nanoseconds,
                          )
            args = [x]
        elif hasattr(args[0], 'day') and hasattr(args[0], 'second'):
            t0 = self
            t1 = args[0]
            d0 = datetime.datetime(t0.year, t0.month, t0.day, t0.hour, t0.minute, t0.second)
            d1 = datetime.datetime(t1.year, t1.month, t1.day, t1.hour, t1.minute, t1.second)
            total_seconds = (d0 - d1).total_seconds()
            attr_list = ('year', 'month', 'day', 'hour', 'minute', 'second', 'microsecond', 'nanosecond',)
            b = {}
            for a in attr_list:
                try:
                    b[a] = getattr(self, a) - getattr(args[0], a)
                except AttributeError:
                    b[a] = getattr(self, a)
            return timedelta(seconds=total_seconds,
                             microseconds=b['microsecond'],
                             nanoseconds=b['nanosecond'],
                             )
        else:
            raise TypeError("unsupported operand type(s) for +: '{0}' and '{1}'".format(self.__class__.__name__,
                                                                                        args[0].__class__.__name__))

        return self.__add__(*args, **kwargs)

    def replace(self, *args, **kwargs):
        attr_list = ['year', 'month', 'day', 'hour', 'minute', 'second', 'microsecond', 'nanosecond']
        new_dict = {}
        for attr in attr_list:
            new_dict[attr] = getattr(self, attr)
        for kw in kwargs:
            if not kw in attr_list:
                raise NameError("Unknown attr: {0}".format(kw))
            new_dict[kw] = kwargs[kw]
        if new_dict['nanosecond'] >= 1000:
            raise ValueError("nanosecond must be in 0..999")
        return nanotime(new_dict['year'],
                        new_dict['month'],
                        new_dict['day'],
                        new_dict['hour'],
                        new_dict['minute'],
                        new_dict['second'],
                        new_dict['microsecond'],
                        new_dict['nanosecond'],
                        )

    @property
    def total_seconds(self):
        seconds = int((self - nanotime.utcfromtimestamp(0)).total_seconds())
        return seconds
