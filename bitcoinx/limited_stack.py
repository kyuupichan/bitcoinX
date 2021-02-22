# Copyright (c) 2021, Neil Booth
#
# All rights reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#

'''Bitcoin stack with size limits.'''


from .errors import StackMemoryUsageError


class LimitedStack:

    # Memory usage of one stack element (without data). This is a consensus rule.  It
    # prevents someone from creating stack with millions of empty elements.
    ELEMENT_OVERHEAD = 32

    def __init__(self, size_limit):
        self.size_limit = size_limit
        self.parent = None
        self._size = 0
        self._items = []

    def __len__(self):
        return len(self._items)

    def __getitem__(self, x):
        return self._items[x]

    def __eq__(self, other):
        if isinstance(other, LimitedStack):
            other = other._items
        return self._items == other

    def _decrease_size(self, delta):
        if self.parent is None:
            assert delta >= 0
            self._size -= delta
            assert self._size >= 0
        else:
            self.parent._decrease_size(delta)

    def _increase_size(self, delta):
        if self.parent is None:
            if self._size + delta > self.size_limit:
                raise StackMemoryUsageError(f'stack memory limit of {self.size_limit} bytes '
                                            f'exceeded adding item of {delta:,d} bytes')
            self._size += delta
        else:
            self.parent._increase_size(delta)

    def make_child_stack(self):
        result = LimitedStack(0)
        result.parent = self
        return result

    def make_copy(self):
        assert self.parent is None
        result = LimitedStack(self.size_limit)
        result._size = self._size
        result._items = self._items.copy()
        return result

    def restore_copy(self, copy):
        self._size = copy._size
        self._items = copy._items
        copy._items = []
        copy._size = 0

    def combined_size(self):
        if self.parent is None:
            return self._size
        return self.parent.combined_size()

    def append(self, item):
        self._increase_size(self.ELEMENT_OVERHEAD + len(item))
        self._items.append(item)

    def __setitem__(self, key, item):
        assert isinstance(key, int)  # Don't support slicing
        old = self[key]
        delta = len(item) - len(old)
        self._increase_size(delta)
        self._items[key] = item

    def insert(self, index, item):
        self._increase_size(self.ELEMENT_OVERHEAD + len(item))
        self._items.insert(index, item)

    def pop(self, index=-1):
        item = self._items.pop(index)
        self._decrease_size(self.ELEMENT_OVERHEAD + len(item))
        return item

    def extend(self, items):
        for item in items:
            self.append(item)

    def clear(self):
        while self._items:
            self.pop()
