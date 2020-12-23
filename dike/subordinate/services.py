import rpyc
from threading import Lock
import subprocess
from utils.logger import Logger
import time


class ModelBuilderService(rpyc.Service):
    busy: bool = False
    busy_mutex: Lock = Lock()
    ALIASES: list = []

    def on_connect(self, connection: rpyc.Connection) -> None:
        Logger.print_on_screen(":on: Master server is now connected")

    def on_disconnect(self, connection: rpyc.Connection) -> None:
        Logger.print_on_screen(":end: Master server is now disconnected")

    def is_busy(self) -> bool:
        return self.busy

    def train_new_model(self) -> bool:
        # Enter critical section (one model training at a time)
        self.busy_mutex.acquire()
        self.busy = True

        # Print message
        Logger.print_on_screen(":hammer: Starting a model training")

        # Sleep to emulate intensive computin
        time.sleep(10)

        # End critical section
        self.busy = False
        self.busy_mutex.release()

        return True