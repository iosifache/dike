"""Program testing the scheduling module"""
import datetime
import threading
import time

import pytest
from modules.utils.scheduler import ReplicatedDailyScheduler


def _threaded_barrier_wait(barrier: threading.Barrier):
    barrier.wait()


def test_scheduling_execution():
    """Tests the execution of a scheduled test."""
    replicated_workers_count = 2

    # Get execution time
    now = datetime.datetime.now()
    now += datetime.timedelta(minutes=1)
    execution_time = "{}:{:02d}".format(now.hour, now.minute)

    # Create a semaphore
    barrier = threading.Barrier(replicated_workers_count + 1)

    # Create and start the scheduler
    tasks_list = replicated_workers_count * [barrier]
    scheduler = ReplicatedDailyScheduler(replicated_workers_count,
                                         execution_time,
                                         _threaded_barrier_wait, tasks_list)
    scheduler.start()

    # After 60 seconds, try to stop the scheduler
    time.sleep(60)
    if (barrier.n_waiting == replicated_workers_count):
        barrier.wait()
        scheduler.stop()
    else:
        pytest.fail(
            "After 60 seconds, the workers does not finished their jobs correctly."
        )
