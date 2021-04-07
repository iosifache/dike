"""Scheduling operations.

Usage example:

    # Create and start a scheduler
    scheduler = ReplicatedDailyScheduler(8, "00:00", print, ["hello", "hi"])
    scheduler.start()
"""
import queue
import threading
import time
import typing
from collections.abc import Callable

import schedule
from modules.utils.logger import Logger
from modules.utils.types import LoggedMessageTypes


class ReplicatedDailyScheduler:
    """Class implementing a daily scheduler that uses replicated workers.

    The workers consume tasks from a tasks list.
    """

    _workers_count: int
    _task_function: Callable
    _tasks_list: typing.List[typing.Any]
    _scheduler_thread: threading.Thread
    _stop_needed: bool

    def __init__(self, workers_count: int, execution_time: str,
                 task_function: Callable,
                 tasks_list: typing.List[typing.Any]) -> None:
        """Initializes the ReplicatedDailyScheduler instance.

        Args:
            workers_count (int): Number of replicated workers to launch
            execution_time  (str): Stringified time, in the HH:MM format
            task_function (Callable): Function called repeatedly by the
                replicated workers, for each task extracted from the queue
            tasks_list (typing.List[typing.Any]): List of tasks, in which each
                task is passed as an argument to the called function
        """
        self._workers_count = workers_count
        self._task_function = task_function
        self._tasks_list = tasks_list

        # Schedule the tasks
        schedule.every().day.at(execution_time).do(
            ReplicatedDailyScheduler._setup_workers, self._workers_count,
            self._task_function, self._tasks_list)

        self._scheduler_thread = None
        self._stop_needed = False

    @staticmethod
    def _run_worker(job: Callable, tasks: queue) -> None:
        while not tasks.empty():
            task = tasks.get()
            job(task)
            tasks.task_done()

    @staticmethod
    def _setup_workers(workers_count: int, job: Callable,
                       tasks_list: typing.List[typing.Any]):
        # Convert the list to a queue to be shared by the threads
        tasks_queue = queue.Queue()
        for task in tasks_list:
            tasks_queue.put(task)

        Logger().log(
            ("The workers of the replicated daily scheduler were started to "
             "consume the available jobs."), LoggedMessageTypes.SUCCESS)

        for _ in range(workers_count):
            thread = threading.Thread(
                target=ReplicatedDailyScheduler._run_worker,
                args=(job, tasks_queue))
            thread.start()

    def _launch_workers(self):
        while not self._stop_needed:
            schedule.run_pending()
            time.sleep(1)

    def start(self) -> None:
        """Starts the scheduler."""
        self._scheduler_thread = threading.Thread(target=self._launch_workers)
        self._scheduler_thread.start()

        Logger().log("The replicated daily scheduler started.",
                     LoggedMessageTypes.BEGINNING)

    def stop(self) -> None:
        """Stops the scheduler."""
        self._stop_needed = True

        schedule.clear()

        Logger().log("The replicated daily scheduler stopped.",
                     LoggedMessageTypes.END)
