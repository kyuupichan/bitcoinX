# Provide timeouts similar to curio, code based on aiorpcX.  They are more useful than
# those introduced in Python 3.11.

# Provide slightly degraded TaskGroup functions for Python 3.10 and earlier.
# Taken from Lib/asyncio/taskgroups.py, Lib/asyncio/timeouts.py.
# Adapted with permission from the EdgeDB project; license: PSFL.

import sys
from asyncio import get_running_loop, CancelledError, current_task


if sys.version_info >= (3, 11):

    from asyncio import TaskGroup
    ExceptionGroup = ExceptionGroup   # noqa: F821

else:
    import enum
    from types import TracebackType
    from typing import final, Optional, Type

    class ExceptionGroup(Exception):
        pass

    class TaskGroup:
        # parent cancelling is removed....

        def __init__(self):
            self._entered = False
            self._exiting = False
            self._aborting = False
            self._loop = None
            self._parent_task = None
            self._parent_cancel_requested = False
            self._tasks = set()
            self._errors = []
            self._base_error = None
            self._on_completed_fut = None

        def __repr__(self):
            info = ['']
            if self._tasks:
                info.append(f'tasks={len(self._tasks)}')
            if self._errors:
                info.append(f'errors={len(self._errors)}')
            if self._aborting:
                info.append('cancelling')
            elif self._entered:
                info.append('entered')

            info_str = ' '.join(info)
            return f'<TaskGroup{info_str}>'

        async def __aenter__(self):
            if self._entered:
                raise RuntimeError(
                    f"TaskGroup {self!r} has already been entered")
            if self._loop is None:
                self._loop = get_running_loop()
            self._parent_task = current_task(self._loop)
            if self._parent_task is None:
                raise RuntimeError(
                    f'TaskGroup {self!r} cannot determine the parent task')
            self._entered = True

            return self

        async def __aexit__(self, et, exc, tb):
            self._exiting = True

            if (exc is not None and
                    self._is_base_error(exc) and
                    self._base_error is None):
                self._base_error = exc

            if et is not None and issubclass(et, CancelledError):
                propagate_cancellation_error = exc
            else:
                propagate_cancellation_error = None

            if et is not None:
                if not self._aborting:
                    # Our parent task is being cancelled:
                    #
                    #    async with TaskGroup() as g:
                    #        g.create_task(...)
                    #        await ...  # <- CancelledError
                    #
                    # or there's an exception in "async with":
                    #
                    #    async with TaskGroup() as g:
                    #        g.create_task(...)
                    #        1 / 0
                    #
                    self._abort()

            # We use while-loop here because "self._on_completed_fut"
            # can be cancelled multiple times if our parent task
            # is being cancelled repeatedly (or even once, when
            # our own cancellation is already in progress)
            while self._tasks:
                if self._on_completed_fut is None:
                    self._on_completed_fut = self._loop.create_future()

                try:
                    await self._on_completed_fut
                except CancelledError as ex:
                    if not self._aborting:
                        # Our parent task is being cancelled:
                        #
                        #    async def wrapper():
                        #        async with TaskGroup() as g:
                        #            g.create_task(foo)
                        #
                        # "wrapper" is being cancelled while "foo" is
                        # still running.
                        propagate_cancellation_error = ex
                        self._abort()
                self._on_completed_fut = None

            assert not self._tasks

            if self._base_error is not None:
                raise self._base_error

            # Propagate CancelledError if there is one, except if there
            # are other errors -- those have priority.
            if propagate_cancellation_error is not None and not self._errors:
                raise propagate_cancellation_error

            if et is not None and not issubclass(et, CancelledError):
                self._errors.append(exc)

            if self._errors:
                # Exceptions are heavy objects that can have object
                # cycles (bad for GC); let's not keep a reference to
                # a bunch of them.
                try:
                    me = self._errors[0]
                    raise me from None
                finally:
                    self._errors = None

        def create_task(self, coro, *, name=None, context=None):
            """Create a new task in this group and return it.

            Similar to `asyncio.create_task`.
            """
            if not self._entered:
                raise RuntimeError(f"TaskGroup {self!r} has not been entered")
            if self._exiting and not self._tasks:
                raise RuntimeError(f"TaskGroup {self!r} is finished")
            if self._aborting:
                raise RuntimeError(f"TaskGroup {self!r} is shutting down")
            if context is None:
                task = self._loop.create_task(coro, name=name)
            else:
                task = self._loop.create_task(coro, name=name, context=context)

            # optimization: Immediately call the done callback if the task is
            # already done (e.g. if the coro was able to complete eagerly),
            # and skip scheduling a done callback
            if task.done():
                self._on_task_done(task)
            else:
                self._tasks.add(task)
                task.add_done_callback(self._on_task_done)
            return task

        # Since Python 3.8 Tasks propagate all exceptions correctly,
        # except for KeyboardInterrupt and SystemExit which are
        # still considered special.

        def _is_base_error(self, exc: BaseException) -> bool:
            assert isinstance(exc, BaseException)
            return isinstance(exc, (SystemExit, KeyboardInterrupt))

        def _abort(self):
            self._aborting = True

            for t in self._tasks:
                if not t.done():
                    t.cancel()

        def _on_task_done(self, task):
            self._tasks.discard(task)

            if self._on_completed_fut is not None and not self._tasks:
                if not self._on_completed_fut.done():
                    self._on_completed_fut.set_result(True)
            if task.cancelled():
                return

            exc = task.exception()
            if exc is None:
                return

            self._errors.append(exc)
            if self._is_base_error(exc) and self._base_error is None:
                self._base_error = exc

            if self._parent_task.done():
                # Not sure if this case is possible, but we want to handle
                # it anyways.
                self._loop.call_exception_handler({
                    'message': f'Task {task!r} has errored out but its parent '
                               f'task {self._parent_task} is already completed',
                    'exception': exc,
                    'task': task,
                })
                return

            if not self._aborting:
                # If parent task *is not* being cancelled, it means that we want
                # to manually cancel it to abort whatever is being run right now
                # in the TaskGroup.  But we want to mark parent task as
                # "not cancelled" later in __aexit__.  Example situation that
                # we need to handle:
                #
                #    async def foo():
                #        try:
                #            async with TaskGroup() as g:
                #                g.create_task(crash_soon())
                #                await something  # <- this needs to be canceled
                #                                 #    by the TaskGroup, e.g.
                #                                 #    foo() needs to be cancelled
                #        except Exception:
                #            # Ignore any exceptions raised in the TaskGroup
                #            pass
                #        await something_else     # this line has to be called
                #                                 # after TaskGroup is finished.
                self._abort()
                self._parent_cancel_requested = True
                self._parent_task.cancel()


class TimeoutCancellationError(Exception):
    '''Raised on an inner timeout context when an outer timeout expires first.'''


class UncaughtTimeoutError(Exception):
    '''Raised when an inner timeout expires, is not handled, and filters through to an outer
    context.'''


class Deadline:

    def __init__(self, when, *, raise_timeout=True, is_relative=True):
        self._when = when
        self._raise = raise_timeout
        self._is_relative = is_relative
        self._deadline = None
        self._in_use = False
        self.expired = False

    @staticmethod
    def reset_timeout(task):
        def on_timeout(task):
            cause = task._timeout_setter
            assert cause is not None
            task.cancel()
            task._timeout_handler = None
            cause.expired = True

        # Find out what cause has the earliest deadline
        cause = None
        for deadline in task._deadlines:
            if not cause or deadline._deadline < cause._deadline:
                cause = deadline

        if task._timeout_handler:
            # Optimisation only - leave the handler if the cause hasn't changed
            if task._timeout_setter is cause:
                return
            task._timeout_handler.cancel()
            task._timeout_handler = None
            task._timeout_setter = None

        if cause:
            task._timeout_setter = cause
            loop = get_running_loop()
            if cause._deadline <= loop.time():
                on_timeout(task)
            else:
                task._timeout_handler = loop.call_at(cause._deadline, on_timeout, task)

    async def __aenter__(self):
        if self._in_use:
            raise RuntimeError('timeout already in use')
        self._in_use = True
        self.expired = False
        if self._when is not None:
            self._deadline = self._when
            if self._is_relative:
                self._deadline += get_running_loop().time()
            # Add ourself to the task's deadlines
            task = current_task()
            if not hasattr(task, '_deadlines'):
                task._deadlines = set()
                task._timeout_handler = None
                task._timeout_setter = None
            task._deadlines.add(self)
            self.reset_timeout(task)
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        self._in_use = False
        task = current_task()

        if self._deadline is not None:
            # Remove our deadline regardless of cause.
            task._deadlines.remove(self)

            # If we set the current timeout, it needs to be reset
            if task._timeout_setter is self:
                self.reset_timeout(task)

        if exc_type is TimeoutError:
            raise UncaughtTimeoutError

        # If a race condition caused an exception to be raised before our cancellation
        # was processed, let that through
        if self.expired and exc_type in (CancelledError, TimeoutCancellationError):
            if exc_type is CancelledError and hasattr(task, 'uncancel'):
                task.uncancel()
            if self._raise:
                raise TimeoutError from None
            return True

        # Did an outer timeout trigger?
        if exc_type is CancelledError and task._timeout_setter:
            if hasattr(task, 'uncancel'):
                task.uncancel()
            raise TimeoutCancellationError


def timeout_after(seconds):
    '''Execute the specified coroutine and return its result. However,
    issue a cancellation request to the calling task after seconds
    have elapsed.  When this happens, a TaskTimeout exception is
    raised.  If coro is None, the result of this function serves
    as an asynchronous context manager that applies a timeout to a
    block of statements.

    timeout_after() may be composed with other timeout_after()
    operations (i.e., nested timeouts).  If an outer timeout expires
    first, then TimeoutCancellationError is raised instead of
    TaskTimeout.  If an inner timeout expires and fails to properly
    TaskTimeout, a UncaughtTimeoutError is raised in the outer
    timeout.

    '''
    return Deadline(seconds)


def timeout_at(clock):
    '''Execute the specified coroutine and return its result. However,
    issue a cancellation request to the calling task after seconds
    have elapsed.  When this happens, a TaskTimeout exception is
    raised.  If coro is None, the result of this function serves
    as an asynchronous context manager that applies a timeout to a
    block of statements.

    timeout_after() may be composed with other timeout_after()
    operations (i.e., nested timeouts).  If an outer timeout expires
    first, then TimeoutCancellationError is raised instead of
    TaskTimeout.  If an inner timeout expires and fails to properly
    TaskTimeout, a UncaughtTimeoutError is raised in the outer
    timeout.

    '''
    return Deadline(clock, is_relative=False)


def ignore_after(seconds):
    '''Execute the specified coroutine and return its result. Issue a
    cancellation request after seconds have elapsed. When a timeout
    occurs, no exception is raised. Instead, timeout_result is
    returned.

    If coro is None, the result is an asynchronous context manager
    that applies a timeout to a block of statements. For the context
    manager case, the resulting context manager object has an expired
    attribute set to True if time expired.

    Note: ignore_after() may also be composed with other timeout
    operations. TimeoutCancellationError and UncaughtTimeoutError
    exceptions might be raised according to the same rules as for
    timeout_after().
    '''
    return Deadline(seconds, raise_timeout=False)


def ignore_at(clock):
    '''
    Stop the enclosed task or block of code at an absolute
    clock value. Same usage as ignore_after().
    '''
    return Deadline(clock, raise_timeout=False, is_relative=False)
