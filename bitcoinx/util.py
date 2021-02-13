# Copyright (c) 2018-2021, Neil Booth
#
# All rights reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#

'''Internal utilities'''

import mmap


def map_file(file_name, new_size=None):
    '''Map an existing file into memory.  If new_size is specified the
    file is truncated or extended to that size.

    Returns a Python mmap object.
    '''
    with open(file_name, 'rb+') as f:
        if new_size is not None:
            f.truncate(new_size)
        return mmap.mmap(f.fileno(), 0)


# Method decorator.  To be used for calculations that will always deliver the same result.
# The method cannot take any arguments and should be accessed as an attribute.
class cachedproperty:

    def __init__(self, f):
        self.f = f

    def __get__(self, obj, type_):
        obj = obj or type_
        value = self.f(obj)
        setattr(obj, self.f.__name__, value)
        return value
