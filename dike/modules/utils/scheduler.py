"""Module implementing scheduling functionalities

Usage example:

    scheduler = ReplicatedDailyScheduler(8, "00:00", print, ["hello", "hi"])
    scheduler.start()
"""
import queue
import threading
import time
import typing
from collections.abc import Callable

import schedule


class ReplicatedDailyScheduler:
    """Class implementing a scheduler that runs every day a given number of
    replicated workers, which consumes tasks from a queue
    """
    _workers_count: int
    _task_function: Callable
    _tasks_list: typing.List[typing.Any]
    _scheduler_thread: threading.Thread
    _stop_signal: bool

    def __init__(self, workers_count: int, stringified_time: str,
                 task_function: Callable,
                 tasks_list: typing.List[typing.Any]) -> None:
        """Initializes the ReplicatedDailyScheduler instance.

        Args:
            workers_count (int): Number of replicated workers to launch
            stringified_time (str): Stringified time, in the HH:MM format
            task_function (Callable): Function called by the replicated workers,
                for each task extracted from queue
            tasks_list (typing.List[typing.Any]): List of tasks, in which each
                task is passed as argument to the called function
        """
        self._workers_count = workers_count
        self._task_function = task_function
        self._tasks_list = tasks_list

        # Schedule the tasks
        schedule.every().day.at(stringified_time).do(
            ReplicatedDailyScheduler._launch_workers, self._workers_count,
            self._task_function, self._tasks_list)

        # Default values of members
        self._scheduler_thread = None
        self._stop_signal = False

    @staticmethod
    def _launch_workers(workers_count: int, job: Callable,
                        tasks_list: typing.List[typing.Any]):
        # Convert the list to a queue to be shared by the threads
        working_tasks_queue = queue.Queue()
        for task in tasks_list:
            working_tasks_queue.put(task)

        for _ in range(workers_count):
            thread = threading.Thread(
                target=ReplicatedDailyScheduler._worker_job,
                args=(job, working_tasks_queue))
            thread.start()

    @staticmethod
    def _worker_job(job: Callable, tasks_queue: queue) -> None:
        while (not tasks_queue.empty()):
            task = tasks_queue.get()
            job(task)
            tasks_queue.task_done()

    def _threaded_run(self):
        while (not self._stop_signal):
            schedule.run_pending()
            time.sleep(1)

    def start(self) -> None:
        """Starts the scheduler."""
        self._scheduler_thread = threading.Thread(target=self._threaded_run)
        self._scheduler_thread.start()

    def stop(self) -> None:
        """Stops the scheduler."""
        # Stop the scheduler thread
        self._stop_signal = True

        # Cancel all jobs
        schedule.clear()