import sys
from asyncio import sleep, CancelledError, current_task, get_running_loop

import pytest

from bitcoinx.aiolib import (
    TimeoutCancellationError, UncaughtTimeoutError, timeout_at, timeout_after,
    ignore_at, ignore_after, ExceptionGroup, BaseExceptionGroup, TaskGroup
)


if sys.version_info < (3, 11):

    class TestBaseExceptionGroup:

        def test_includes_base(self):
            excs = [KeyboardInterrupt(), Exception()]
            e = BaseExceptionGroup('msg', excs)
            assert isinstance(e, BaseExceptionGroup)
            assert e.message == 'msg'
            assert e.exceptions == tuple(excs)

        def test_not_includes_base(self):
            excs = [MemoryError(), Exception()]
            e = BaseExceptionGroup('msg', excs)
            assert isinstance(e, ExceptionGroup)
            assert e.message == 'msg'
            assert e.exceptions == tuple(excs)

    class TestExceptionGroup:

        def test_includes_base(self):
            excs = [KeyboardInterrupt(), Exception()]
            with pytest.raises(TypeError):
                ExceptionGroup('msg', excs)

        def test_not_includes_base(self):
            excs = [MemoryError(), Exception()]
            e = ExceptionGroup('msg', excs)
            assert isinstance(e, ExceptionGroup)
            assert e.message == 'msg'
            assert e.exceptions == tuple(excs)


def assert_clean():
    task = current_task()
    if hasattr(task, '_deadlines'):
        assert not task._deadlines
        assert not task._timeout_handler
    if hasattr(task, 'cancelling'):
        assert not task.cancelling()


class TestTaskgroup:

    @pytest.mark.asyncio
    async def test_simple(self):
        async with TaskGroup() as group:
            group.create_task(sleep(0.002))
            group.create_task(sleep(0.001))
        assert group.joined

    @pytest.mark.asyncio
    async def test_simple_cancel_one(self):
        async with TaskGroup() as group:
            group.create_task(sleep(0.002))
            t = group.create_task(sleep(1))
            t.cancel()
        assert group.joined

    @pytest.mark.asyncio
    async def test_simple_cancel_remaining(self):
        async with TaskGroup() as group:
            group.create_task(sleep(0.002))
            group.create_task(sleep(1))
            await group.cancel_remaining()
        assert group.joined

    @pytest.mark.asyncio
    async def test_simple_group_cancelled(self):
        async def cancel_task(task):
            task.cancel()

        with pytest.raises(CancelledError):
            async with TaskGroup() as group:
                group.create_task(sleep(0.002))
                group.create_task(sleep(1))
                group.create_task(cancel_task(current_task()))

        assert group.joined

    @pytest.mark.asyncio
    async def test_simple_group_raises(self):
        v1 = ValueError(2)
        v2 = ValueError(3)

        async def raise_exc(secs, exc):
            await sleep(secs)
            raise exc

        with pytest.raises(ExceptionGroup) as e:
            async with TaskGroup() as group:
                group.create_task(raise_exc(0.02, v1))
                group.create_task(raise_exc(0.002, v2))

        assert e.value.exceptions == (v2, )
        assert group.joined

    @pytest.mark.asyncio
    async def test_simple_group_raises_2(self):
        v1 = ValueError(2)
        v2 = ValueError(3)

        async def raise_exc(secs, exc):
            await sleep(secs)
            raise exc

        with pytest.raises(ExceptionGroup) as e:
            async with TaskGroup() as group:
                group.create_task(raise_exc(0.005, v1))
                group.create_task(raise_exc(0.002, v2))
                await sleep(0.01)

        assert e.value.exceptions == (v2, v1)
        assert group.joined

    @pytest.mark.asyncio
    async def test_simple_group_timeout(self):
        async def raise_exc(secs, exc):
            await sleep(secs)
            raise exc

        async with ignore_after(0.001):
            async with TaskGroup() as group:
                group.create_task(sleep(1))
                group.create_task(raise_exc(0.01, ValueError()))

        assert not group._errors
        assert group.joined


class TestTimeout:

    @pytest.mark.asyncio
    async def test_timeout_expires(self):
        with pytest.raises(TimeoutError):
            async with timeout_after(0.01) as t:
                await sleep(0.1)
        assert t.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_timeout_doesnt_expire(self):
        async with timeout_after(0.01) as t:
            pass
        assert not t.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_timeout_immediate(self):
        body_ran = False
        with pytest.raises(TimeoutError):
            async with timeout_after(0) as t:
                body_ran = True
                await sleep(0)
                assert False
        assert body_ran
        assert t.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_timeout_at_immediate(self):
        body_ran = False
        with pytest.raises(TimeoutError):
            async with timeout_at(get_running_loop().time()) as t:
                body_ran = True
                await sleep(0)
                assert False
        assert body_ran
        assert t.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_nested_outer_expires_first(self):
        with pytest.raises(TimeoutError):
            async with timeout_after(0.001) as outer:
                with pytest.raises(TimeoutCancellationError) as e:
                    async with timeout_after(0.01) as inner:
                        await sleep(0.02)
                raise e.value
        assert outer.expired
        assert not inner.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_nested_inner_expires_first(self):
        async with timeout_after(0.01) as outer:
            with pytest.raises(TimeoutError):
                async with timeout_after(0.001) as inner:
                    await sleep(0.02)
        assert not outer.expired
        assert inner.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_nested_inner_expires_first_and_uncaught(self):
        with pytest.raises(UncaughtTimeoutError):
            async with timeout_after(0.01) as outer:
                async with timeout_after(0.001) as inner:
                    await sleep(0.02)
        assert not outer.expired
        assert inner.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_no_timeout_but_raises_IndexError(self):
        with pytest.raises(IndexError):
            async with timeout_after(0.01) as t:
                raise IndexError
        assert not t.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_no_timeout_but_raises_CancelledError(self):
        with pytest.raises(CancelledError):
            async with timeout_after(0.01) as t:
                raise CancelledError
        assert not t.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_timeout_reuse_bad(self):
        timeout = timeout_after(0.01)
        async with timeout as outer:
            with pytest.raises(RuntimeError) as e:
                async with timeout:
                    pass
            assert str(e.value) == 'timeout already in use'
        assert not outer.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_timeout_reuse_good(self):
        timeout = timeout_after(0.01)
        assert not timeout.expired

        async with timeout:
            deadline = timeout._deadline
        assert not timeout.expired

        # Windows event loops seem to have coarse time measures
        await sleep(0.001)

        async with timeout:
            assert timeout._deadline > deadline
            deadline = timeout._deadline
        assert not timeout.expired

        with pytest.raises(TimeoutError):
            async with timeout:
                assert timeout._deadline > deadline
                deadline = timeout._deadline
                await sleep(1)
        assert timeout.expired

        async with timeout:
            assert timeout._deadline > deadline
            assert not timeout.expired
        assert not timeout.expired

        assert_clean()

    @pytest.mark.asyncio
    async def test_timeout_never(self):
        async with timeout_after(None) as t:
            await sleep(0.1)
        assert not t.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_timeout_outer_never(self):
        with pytest.raises(UncaughtTimeoutError):
            async with timeout_after(None) as outer:
                async with timeout_after(0.01) as inner:
                    await sleep(0.1)
        assert not outer.expired
        assert inner.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_timeout_inner_never(self):
        with pytest.raises(TimeoutError):
            async with timeout_after(0.01) as outer:
                with pytest.raises(TimeoutCancellationError) as e:
                    async with timeout_after(None) as inner:
                        await sleep(0.1)
                raise e.value
        assert outer.expired
        assert not inner.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_timeout_at(self):
        with pytest.raises(TimeoutError):
            clock = get_running_loop().time()
            async with timeout_at(clock + 0.01) as t:
                await sleep(0.1)
        assert t.expired
        assert_clean()


class TestIgnore:

    @pytest.mark.asyncio
    async def test_timeout_expires(self):
        async with ignore_after(0.01) as t:
            await sleep(0.1)
        assert t.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_timeout_doesnt_expire(self):
        async with ignore_after(0.01) as t:
            pass
        assert not t.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_timeout_immediate(self):
        body_ran = False
        async with ignore_after(0) as t:
            body_ran = True
            await sleep(0)
            assert False
        assert body_ran
        assert t.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_timeout_at_immediate(self):
        body_ran = False
        async with ignore_at(get_running_loop().time()) as t:
            body_ran = True
            await sleep(0)
            assert False
        assert body_ran
        assert t.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_nested_outer_expires_first(self):
        async with ignore_after(0.001) as outer:
            with pytest.raises(TimeoutCancellationError) as e:
                async with ignore_after(0.01) as inner:
                    await sleep(0.02)
            raise e.value
        assert outer.expired
        assert not inner.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_nested_inner_expires_first(self):
        async with ignore_after(0.01) as outer:
            async with ignore_after(0.001) as inner:
                await sleep(0.02)
        assert not outer.expired
        assert inner.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_no_timeout_but_raises_IndexError(self):
        with pytest.raises(IndexError):
            async with ignore_after(0.01) as t:
                raise IndexError
        assert not t.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_no_timeout_but_raises_CancelledError(self):
        with pytest.raises(CancelledError):
            async with ignore_after(0.01) as t:
                raise CancelledError
        assert not t.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_timeout_reuse_bad(self):
        timeout = ignore_after(0.01)
        async with timeout as outer:
            with pytest.raises(RuntimeError) as e:
                async with timeout:
                    pass
            assert str(e.value) == 'timeout already in use'
        assert not outer.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_timeout_reuse_good(self):
        timeout = ignore_after(0.01)
        assert not timeout.expired

        async with timeout:
            deadline = timeout._deadline
        assert not timeout.expired

        # Windows event loops seem to have coarse time measures
        await sleep(0.001)

        async with timeout:
            assert timeout._deadline > deadline
            deadline = timeout._deadline
        assert not timeout.expired

        async with timeout:
            assert timeout._deadline > deadline
            deadline = timeout._deadline
            await sleep(1)
        assert timeout.expired

        async with timeout:
            assert timeout._deadline > deadline
            assert not timeout.expired
        assert not timeout.expired

        assert_clean()

    @pytest.mark.asyncio
    async def test_timeout_outer_never(self):
        with pytest.raises(ValueError):
            async with ignore_after(None) as outer:
                async with ignore_after(0.01) as inner:
                    await sleep(0.1)
                raise ValueError
        assert not outer.expired
        assert inner.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_timeout_inner_never(self):
        async with ignore_after(0.01) as outer:
            with pytest.raises(TimeoutCancellationError) as e:
                async with ignore_after(None) as inner:
                    await sleep(0.1)
            raise e.value
        assert outer.expired
        assert not inner.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_ignore_at(self):
        clock = get_running_loop().time()
        async with ignore_at(clock + 0.01) as t:
            await sleep(0.1)
        assert t.expired
        assert_clean()


class TestMixedNested:

    @pytest.mark.asyncio
    async def test_nested_outer_expires_first(self):
        async with ignore_after(0.001) as outer:
            with pytest.raises(TimeoutCancellationError) as e:
                async with timeout_after(0.01) as inner:
                    await sleep(0.02)
            raise e.value
        assert outer.expired
        assert not inner.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_nested_outer_expires_first_reversed(self):
        with pytest.raises(TimeoutError):
            async with timeout_after(0.001) as outer:
                with pytest.raises(TimeoutCancellationError) as e:
                    async with ignore_after(0.01) as inner:
                        await sleep(0.02)
                raise e.value
        assert outer.expired
        assert not inner.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_nested_inner_expires_first(self):
        async with timeout_after(0.01) as outer:
            async with ignore_after(0.001) as inner:
                await sleep(0.02)
        assert not outer.expired
        assert inner.expired
        assert_clean()

    @pytest.mark.asyncio
    async def test_nested_inner_expires_first_reversed(self):
        async with ignore_after(0.01) as outer:
            with pytest.raises(TimeoutError):
                async with timeout_after(0.001) as inner:
                    await sleep(0.02)
        assert not outer.expired
        assert inner.expired
        assert_clean()
