from bitcoinx import StackMemoryUsageError

from bitcoinx.limited_stack import LimitedStack

import pytest


class TestLimitedStack:

    def test_append(self):
        item = b'\xab'
        count = 3
        stack = LimitedStack(100)

        assert len(stack) == 0

        for _ in range(count):
            stack.append(item)

        assert len(stack) == 3
        assert stack[0] == item
        assert stack[-1] == item
        assert stack.combined_size() == count * (LimitedStack.ELEMENT_OVERHEAD + len(item))
        with pytest.raises(StackMemoryUsageError):
            stack.append(item)

    def test_extend(self):
        stack = LimitedStack(100)

        assert len(stack) == 0

        stack.extend((b'foo', b'bar'))

        assert len(stack) == 2
        assert stack[0] == b'foo'
        assert stack[1] == b'bar'
        assert stack.combined_size() == 2 * (LimitedStack.ELEMENT_OVERHEAD + 3)

    def test_insert(self):
        item = b'\xab'
        stack = LimitedStack(100)

        stack.append(item)
        assert stack.combined_size() == LimitedStack.ELEMENT_OVERHEAD + len(item)

        stack.insert(-1, item)
        stack.insert(-1, item)
        assert stack.combined_size() == 3 * (LimitedStack.ELEMENT_OVERHEAD + len(item))

        with pytest.raises(StackMemoryUsageError):
            stack.insert(-1, item)

    def test_pop(self):
        stack = LimitedStack(200)
        for item in (b'\xab', b'\xcd', b'\xef', b'\xab'):
            stack.append(item)

        assert len(stack) == 4
        item = stack.pop(1)
        assert item == b'\xcd'

        assert len(stack) == 3

        assert stack[0] == b'\xab'
        assert stack[1] == b'\xef'
        assert stack[2] == b'\xab'

        assert stack.combined_size() == 3 * (LimitedStack.ELEMENT_OVERHEAD + 1)

    def test_empty(self):
        stack = LimitedStack(100)

        assert not stack
        assert len(stack) == 0

    def test_set_item(self):
        stack = LimitedStack(100)
        item1 = b'foo'
        item2 = b'foobar'

        stack.append(item1)
        assert stack.combined_size() == LimitedStack.ELEMENT_OVERHEAD + len(item1)
        stack[0] = item2
        assert stack.combined_size() == LimitedStack.ELEMENT_OVERHEAD + len(item2)
        stack[0] = item1
        assert stack.combined_size() == LimitedStack.ELEMENT_OVERHEAD + len(item1)

    def test_child(self):
        parent = LimitedStack(100)
        child = parent.make_child_stack()

        assert parent.parent is None
        assert child.parent is parent

        assert parent.size_limit == 100
        assert child.size_limit == 0

        parent.append(b'foo')
        child.append(b'foobar')

        size = parent.combined_size()
        assert size == 2 * LimitedStack.ELEMENT_OVERHEAD + 3 + 6
        assert size == child.combined_size()

        child.append(parent.pop())

        assert len(child) == 2
        assert len(parent) == 0

        assert size == parent.combined_size()
        assert size == child.combined_size()

        assert child[0] == b'foobar'
        assert child[1] == b'foo'

        parent.append(child.pop())
        parent.append(child.pop())

        assert len(child) == 0
        assert len(parent) == 2

        assert size == parent.combined_size()
        assert size == child.combined_size()

        assert parent[0] == b'foo'
        assert parent[1] == b'foobar'
