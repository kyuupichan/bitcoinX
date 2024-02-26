# Provide timeouts similar to curio, code based on aiorpcX.  They are more useful than
# those introduced in Python 3.11.
#
# Also provide a TaskGroup that is similar to that in Python 3.11, but has slightly
# better semantics.  I'm not a fan of those in curio or Python 3.11.

import sys
from asyncio import get_running_loop, CancelledError, current_task, Semaphore, Event, create_task
from collections import deque


if sys.version_info < (3, 11):

    class BaseExceptionGroup(BaseException):
        def __new__(cls, msg, excs):
            if not excs:
                raise ValueError('exceptions must be a non-empty sequence')
            if not all(isinstance(exc, BaseException) for exc in excs):
                raise ValueError('exceptions must be instances of BaseException')
            is_eg = issubclass(cls, ExceptionGroup)
            if all(isinstance(exc, Exception) for exc in excs):
                if not is_eg:
                    cls = ExceptionGroup
            elif is_eg:
                raise TypeError('exceptions must all be instances of Exception')
            return super().__new__(cls, msg, excs)

        def __init__(self, msg, excs):
            self._msg = msg
            self._excs = tuple(excs)

        @property
        def message(self):
            return self._msg

        @property
        def exceptions(self):
            return self._excs

    class ExceptionGroup(BaseExceptionGroup, Exception):
        pass

else:
    BaseExceptionGroup = BaseExceptionGroup
    ExceptionGroup = ExceptionGroup


class TaskGroup:
    '''A class representing a group of executing tasks. New tasks can be added using the
    create_task() or add_task() methods below.

    When join() is called, any task that raises an exception other than CancelledError
    causes the all the other tasks in the group to be cancelled.  Similarly, if the join()
    operation itself is cancelled then all running tasks in the group are cancelled.  Once
    join() returns all tasks have completed and new tasks may not be added.  Tasks can be
    added while join() is waiting.

    A TaskGroup is normally used as a context manager, which calls the join() method on
    context-exit.  Each TaskGroup is an independent entity.  Task groups do not form a
    hierarchy or any kind of relationship to other previously created task groups or
    tasks.

    A TaskGroup can be used as an asynchronous iterator, where each task is returned as it
    completes.

    All still-running tasks can be cancelled by calling cancel_remaining().  It waits for
    the tasks to be cancelled and then returns.  If any task blocks cancellation, this
    routine will not return - a similar caution applies to join().

    The public attribute joined is True if the task group join() operation has completed.
    New tasks cannot be added to a joined task group.

    Once all tasks are done, if any raised an exception then those are raised in a
    BaseExceptionGroup.  If the task group itself raised an error (other than an instance
    of CancelledError) then that is included.
    '''

    def __init__(self):
        # Tasks that have not yet finished
        self._pending = set()
        # Tasks that have completed and whose results have not yet been processed
        self._done = deque()
        self._semaphore = Semaphore(0)
        self._errors = []
        self.joined = False

    def _on_done(self, task):
        task._task_group = None
        self._pending.discard(task)
        self._done.append(task)
        self._semaphore.release()
        if not task.cancelled():
            exc = task.exception()
            if exc:
                self._errors.append(exc)

    def _add_task(self, task):
        '''Add an already existing task to the task group.'''
        if hasattr(task, '_task_group'):
            raise RuntimeError('task is already part of a group')
        task._task_group = self
        if task.done():
            self._on_done(task)
        else:
            self._pending.add(task)
            task.add_done_callback(self._on_done)

    def create_task(self, coro, *, name=None, context=None):
        '''Create a new task and put it in the group. Returns a Task instance.'''
        if self.joined:
            raise RuntimeError('task group terminated')
        if context:
            task = create_task(coro, name=name, context=context)
        else:
            task = create_task(coro, name=name)
        self._add_task(task)
        return task

    async def add_task(self, task):
        '''Add an already existing task to the task group.'''
        if self.joined:
            raise RuntimeError('task group terminated')
        self._add_task(task)

    async def next_done(self):
        '''Return the next completed task and remove it from the group.  Return None if no more
        tasks remain. A TaskGroup may also be used as an asynchronous iterator.
        '''
        if self._done or self._pending:
            await self._semaphore.acquire()
        if self._done:
            return self._done.popleft()
        return None

    async def next_result(self):
        '''Return the result of the next completed task and remove it from the group. If the task
        failed with an exception, that exception is raised. A RuntimeError exception is
        raised if no tasks remain.
        '''
        task = await self.next_done()
        if not task:
            raise RuntimeError('no tasks remain')
        return task.result()

    def _maybe_raise_error(self, exc):
        assert exc is None or isinstance(exc, CancelledError)
        # First priority: put the task errors in a group
        if self._errors:
            beg = BaseExceptionGroup('unhandled errors in a TaskGroup', self._errors)
            self._errors = None
            raise beg from None

        # Second: the cancellation error
        if exc is not None:
            raise exc

    async def join(self, *, exc=None):
        '''Wait for tasks in the group to terminate according to the wait policy for the group.
        '''
        try:
            if exc is None:
                while not self._errors and await self.next_done():
                    pass
        except BaseException as e:
            exc = e
        finally:
            if exc:
                if not isinstance(exc, CancelledError):
                    self._errors.append(exc)
                    exc = None
            self.joined = True
            await self.cancel_remaining()
            self._maybe_raise_error(exc)

    async def _cancel_tasks(self, tasks):
        '''Cancel the passed set of tasks.  Wait for them to complete.'''
        for task in tasks:
            task.cancel()

        if tasks:
            def pop_task(task):
                unfinished.remove(task)
                if not unfinished:
                    all_done.set()

            unfinished = set(tasks)
            all_done = Event()
            for task in tasks:
                task.add_done_callback(pop_task)
            await all_done.wait()

    async def cancel_remaining(self):
        '''Cancel all remaining tasks and wait for them to complete.
        If any task blocks cancellation this routine will not return.
        '''
        await self._cancel_tasks(self._pending)

    def __aiter__(self):
        return self

    async def __anext__(self):
        task = await self.next_done()
        if task:
            return task
        raise StopAsyncIteration

    async def __aenter__(self):
        return self

    async def __aexit__(self, et, exc, _traceback):
        await self.join(exc=exc)


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
        if exc_type is CancelledError and getattr(task, '_timeout_setter', None):
            if hasattr(task, 'uncancel'):
                task.uncancel()
            raise TimeoutCancellationError


def timeout_after(seconds):
    '''The result of this function serves as an asynchronous context manager that applies a
    timeout to a block of statements.  It issues a cancellation request to the calling
    task after seconds have elapsed.  When this leaves the context manager, a TimeoutError
    exception is raised.

    timeout_after() may be composed with other timeout or ignore operations (i.e., nested
    timeouts).  If an outer timeout expires first, then TimeoutCancellationError is raised
    instead of TaskTimeout.  If an inner timeout expires and its TakeTimeout is uncaught
    and propagates to an outer timeout, an UncaughtTimeoutError is raised in the outer
    timeout.
    '''
    return Deadline(seconds)


def timeout_at(clock):
    '''The same as timeout_after, except an absolute time (in terms of loop.time()) is given,
    rather than a relative time.
    '''
    return Deadline(clock, is_relative=False)


def ignore_after(seconds):
    '''The same as timeout_after, except that on timing out no exception is raised.'''
    return Deadline(seconds, raise_timeout=False)


def ignore_at(clock):
    '''The same as timeout_at, except that on timing out no exception is raised.'''
    return Deadline(clock, raise_timeout=False, is_relative=False)
