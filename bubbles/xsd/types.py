#####################################################
#
# copyright.txt
#
# Copyright 2012 Hewlett-Packard Development Company, L.P.
#
# Hewlett-Packard and the Hewlett-Packard logo are trademarks of
# Hewlett-Packard Development Company, L.P. in the U.S. and/or other countries.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#
# Author:
#    Chris Frantz
# 
# Description:
#     Type converters for various basic types in the XS namespace
#
#####################################################
import re
from datetime import datetime, timedelta, date, time

class xs_type:
    @classmethod
    def check(cls, value):
        raise NotImplementedError
    @classmethod
    def fromstr(cls, value):
        raise NotImplementedError
    @classmethod
    def tostr(cls, value):
        if value is None:
            return None
        return unicode(value)

class xs_string(xs_type):
    @classmethod
    def check(cls, value):
        return isinstance(value, basestring)
    @classmethod
    def fromstr(cls, value):
        return unicode(value)

class xs_boolean(xs_type):
    values = {'true': True, 'false': False}
    @classmethod
    def check(cls, value):
        return value in (True, False)
    @classmethod
    def fromstr(cls, value):
        return cls.values[value]
    @classmethod
    def tostr(cls, value):
        if value is None:
            return None
        return str(value).lower()

class xs_integer(xs_type):
    bounds = None
    @classmethod
    def check(cls, value):
        ret = isinstance(value, int)
        if ret and cls.bounds:
            ret = (value >= cls.bounds[0] and value <= cls.bounds[1])
        return ret

    @classmethod
    def fromstr(cls, value):
        return int(value)

class xs_byte(xs_integer):
    bounds = (-2**7, 2**7-1)
class xs_short(xs_integer):
    bounds = (-2**15, 2**15-1)
class xs_int(xs_integer):
    bounds = (-2**31, 2**31-1)
class xs_long(xs_integer):
    bounds = (-2**63, 2**63-1)

class xs_unsignedByte(xs_integer):
    bounds = (0, 2**8-1)
class xs_unsignedShort(xs_integer):
    bounds = (0, 2**16-1)
class xs_unsignedInt(xs_integer):
    bounds = (0, 2**32-1)
class xs_unsignedLong(xs_integer):
    bounds = (0, 2**64-1)

class xs_float(xs_type):
    @classmethod
    def check(cls, value):
        return isinstance(value, float)
    @classmethod
    def fromstr(cls, value):
        return float(value)

class xs_decimal(xs_float):
    pass

class xs_double(xs_float):
    pass

_dt = re.compile(r'(\d{4})-?(\d{2})-?(\d{2})T(\d{2}):?(\d{2}):?(\d{2})(?:\.(\d{6}))?(?:Z|(?:([+-]\d{2}):?(\d{2})))?')
class xs_dateTime(xs_type):
    @classmethod
    def check(cls, value):
        return isinstance(value, datetime)

    @classmethod
    def fromstr(cls, value):
        try:
            match = _dt.match(value)
            if match:
                # ISO string matches the basic format. See if we have any "extra" bits
                # group 1 is the year
                #       2        month
                #       3        day of month
                #       4        hours
                #       5        minutes
                #       6        seconds
                #       7        microseconds (optional) - will NOT have leading decimal
                #       8        timezone offset hours (optional) - WILL have leading sign character
                #       9        timezone offset minutes (optional,but must exist if group 8 exists)

                tm = datetime(int(match.group(1),10),
                             int(match.group(2),10),
                             int(match.group(3),10),
                             int(match.group(4),10),
                             int(match.group(5),10),
                             int(match.group(6),10))

                if match.group(7) is not None:
                    # microseconds provided 
                    tm += timedelta(microseconds = int(match.group(7),10))
            
                if match.group(8) is not None:
                    # if group 8 is present, then group 9 is also
                    tm += timedelta(hours=int(match.group(8),10),minutes=int(match.group(9),10))
                return tm
        except:
            pass
        return None

    @classmethod
    def tostr(cls, value):
        if value is None:
            return None
        return value.isoformat()

_date = re.compile(r'(\d{4})-?(\d{2})-?(\d{2})(?:Z|(?:([+-]\d{2}):?(\d{2})))?')
class xs_date(xs_type):
    @classmethod
    def check(cls, value):
        return isinstance(value, date)

    @classmethod
    def fromstr(cls, value):
        try:
            match = _date.match(value)
            if match:
                # ISO string matches the basic format. See if we have any "extra" bits
                # group 1 is the year
                #       2        month
                #       3        day of month
                #       4        timezone offset hours (optional) - WILL have leading sign character
                #       5        timezone offset minutes (optional,but must exist if group 4 exists)
                d = date(int(match.group(1), 10),
                        int(match.group(2), 10),
                        int(match.group(3), 10))

                # FIXME: Ignore timezone for now
                return d
        except Exception:
            pass
        return None

    @classmethod
    def tostr(cls, value):
        if value is None:
            return None
        return value.isoformat()

_time = re.compile(r'(\d{2}):?(\d{2}):?(\d{2})(?:\.(\d{6}))?(?:Z|(?:([+-]\d{2}):?(\d{2})))?')
class xs_time(xs_type):
    @classmethod
    def check(cls, value):
        return isinstance(value, time)

    @classmethod
    def fromstr(cls, value):
        try:
            match = _time.match(value)
            if match:
                # ISO string matches the basic format. See if we have any "extra" bits
                # group 
                #       1        hours
                #       2        minutes
                #       3        seconds
                #       4        microseconds (optional) - will NOT have leading decimal
                #       5        timezone offset hours (optional) - WILL have leading sign character
                #       6        timezone offset minutes (optional,but must exist if group 5 exists)
                microseconds = 0
                if match.group(4) is not None:
                    microseconds = int(match.group(4),10)
            
                tm = time(int(match.group(1),10),
                             int(match.group(2),10),
                             int(match.group(3),10),
                             microseconds)

                # FIXME: Ignore timezone for now
                #if match.group(5) is not None:
                #    # if group 5 is present, then group 6 is also
                #    tm += timedelta(hours=int(match.group(5),10),minutes=int(match.group(6),10))
                return tm
        except:
            pass
        return None

    @classmethod
    def tostr(cls, value):
        if value is None:
            return None
        return value.isoformat()


converters = {
        'xs:string': xs_string,
        'xs:boolean': xs_boolean,
        'xs:integer': xs_integer,
        'xs:byte': xs_byte,
        'xs:short': xs_short,
        'xs:int': xs_int,
        'xs:long': xs_long,
        'xs:unsignedByte': xs_unsignedByte,
        'xs:unsignedShort': xs_unsignedShort,
        'xs:unsignedInt': xs_unsignedInt,
        'xs:unsignedLong': xs_unsignedLong,
        'xs:decimal': xs_decimal,
        'xs:float': xs_float,
        'xs:double': xs_double,
        'xs:dateTime': xs_dateTime,
        'xs:date': xs_date,
        'xs:time': xs_time,
}

def converter(typestr):
    '''
    Get a converter for the requested xs:type.

    @type typestr: str
    @param typestr: Name of an xs:type like xs:string or xs:int.
    @rtype: subclass of xs_type
    @return: An object that can convert the type to/from string.
    '''
    try:
        return converters[typestr]
    except:
        return xs_string

# VIM options (place at end of file)
# vim: ts=4 sts=4 sw=4 expandtab:
