# Provide slightly degraded TaskGroup and Timeout functions for Python 3.10 and earlier.
# Taken from Lib/asyncio/taskgroups.py, Lib/asyncio/timeouts.py.
# Adapted with permission from the EdgeDB project; license: PSFL.

import sys

if sys.version_info >= (3, 11):

    from asyncio import TaskGroup, timeout, timeout_at, Timeout
    ExceptionGroup = ExceptionGroup   # noqa: F821

else:
    import enum
    from asyncio import get_running_loop, CancelledError, current_task, TimerHandle, Task
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

    class _State(enum.Enum):
        CREATED = "created"
        ENTERED = "active"
        EXPIRING = "expiring"
        EXPIRED = "expired"
        EXITED = "finished"

    @final
    class Timeout:
        """Asynchronous context manager for cancelling overdue coroutines.

        Use `timeout()` or `timeout_at()` rather than instantiating this class directly.
        """

        def __init__(self, when: Optional[float]) -> None:
            """Schedule a timeout that will trigger at a given loop time.

            - If `when` is `None`, the timeout will never trigger.
            - If `when < loop.time()`, the timeout will trigger on the next
              iteration of the event loop.
            """
            self._state = _State.CREATED

            self._timeout_handler: Optional[TimerHandle] = None
            self._task: Optional[Task] = None
            self._when = when

        def when(self) -> Optional[float]:
            """Return the current deadline."""
            return self._when

        def reschedule(self, when: Optional[float]) -> None:
            """Reschedule the timeout."""
            if self._state is not _State.ENTERED:
                if self._state is _State.CREATED:
                    raise RuntimeError("Timeout has not been entered")
                raise RuntimeError(
                    f"Cannot change state of {self._state.value} Timeout",
                )

            self._when = when

            if self._timeout_handler is not None:
                self._timeout_handler.cancel()

            if when is None:
                self._timeout_handler = None
            else:
                loop = get_running_loop()
                if when <= loop.time():
                    self._timeout_handler = loop.call_soon(self._on_timeout)
                else:
                    self._timeout_handler = loop.call_at(when, self._on_timeout)

        def expired(self) -> bool:
            """Is timeout expired during execution?"""
            return self._state in (_State.EXPIRING, _State.EXPIRED)

        def __repr__(self) -> str:
            info = ['']
            if self._state is _State.ENTERED:
                when = round(self._when, 3) if self._when is not None else None
                info.append(f"when={when}")
            info_str = ' '.join(info)
            return f"<Timeout [{self._state.value}]{info_str}>"

        async def __aenter__(self) -> "Timeout":
            if self._state is not _State.CREATED:
                raise RuntimeError("Timeout has already been entered")
            task = current_task()
            if task is None:
                raise RuntimeError("Timeout should be used inside a task")
            self._state = _State.ENTERED
            self._task = task
            self.reschedule(self._when)
            return self

        async def __aexit__(
            self,
            exc_type: Optional[Type[BaseException]],
            exc_val: Optional[BaseException],
            exc_tb: Optional[TracebackType],
        ) -> Optional[bool]:
            assert self._state in (_State.ENTERED, _State.EXPIRING)

            if self._timeout_handler is not None:
                self._timeout_handler.cancel()
                self._timeout_handler = None

            if self._state is _State.EXPIRING:
                self._state = _State.EXPIRED

                if exc_type is not None:
                    # Since there are no new cancel requests, we're
                    # handling this.
                    if issubclass(exc_type, CancelledError):
                        raise TimeoutError from exc_val
                    elif exc_val is not None:
                        self._insert_timeout_error(exc_val)
            elif self._state is _State.ENTERED:
                self._state = _State.EXITED

            return None

        def _on_timeout(self) -> None:
            assert self._state is _State.ENTERED
            self._task.cancel()
            self._state = _State.EXPIRING
            # drop the reference early
            self._timeout_handler = None

        @staticmethod
        def _insert_timeout_error(exc_val: BaseException) -> None:
            while exc_val.__context__ is not None:
                if isinstance(exc_val.__context__, CancelledError):
                    te = TimeoutError()
                    te.__context__ = te.__cause__ = exc_val.__context__
                    exc_val.__context__ = te
                    break
                exc_val = exc_val.__context__

    def timeout(delay: Optional[float]) -> Timeout:
        """Timeout async context manager.

        Useful in cases when you want to apply timeout logic around block
        of code or in cases when asyncio.wait_for is not suitable. For example:

        >>> async with asyncio.timeout(10):  # 10 seconds timeout
        ...     await long_running_task()


        delay - value in seconds or None to disable timeout logic

        long_running_task() is interrupted by raising asyncio.CancelledError,
        the top-most affected timeout() context manager converts CancelledError
        into TimeoutError.
        """
        loop = get_running_loop()
        return Timeout(loop.time() + delay if delay is not None else None)

    def timeout_at(when: Optional[float]) -> Timeout:
        """Schedule the timeout at absolute time.

        Like timeout() but argument gives absolute time in the same clock system
        as loop.time().

        Please note: it is not POSIX time but a time with
        undefined starting base, e.g. the time of the system power on.

        >>> async with asyncio.timeout_at(loop.time() + 10):
        ...     await long_running_task()


        when - a deadline when timeout occurs or None to disable timeout logic

        long_running_task() is interrupted by raising asyncio.CancelledError,
        the top-most affected timeout() context manager converts CancelledError
        into TimeoutError.
        """
        return Timeout(when)
