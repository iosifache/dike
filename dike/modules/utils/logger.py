"""Logging operations.

Usage example:

    # Log a message
    Logger().log("This success message will be logged.",
        LoggedMessageTypes.SUCCESS)
"""
from threading import Lock

import emojis
from modules.utils.types import LoggedMessageTypes
from pypattyrn.creational.singleton import Singleton


class Logger(metaclass=Singleton):
    """Singleton class for logging messages with emojis on screen."""

    _is_enabled: bool
    _internal_buffering: bool
    _buffer: str
    _mutex: Lock

    def __init__(self, is_enabled: bool = False) -> None:
        """Initializes the Logger instance.

        Args:
            is_enabled (bool): Boolean indicating if the logger is enabled by
                the creation
        """
        self._is_enabled = is_enabled
        self._internal_buffering = False
        self._buffer = ""
        self._mutex = Lock()

    def enable(self, is_enabled: bool = True) -> None:
        """Enables (or disables) the logging.

        Args:
            is_enabled (bool): Boolean indicating if the logger is enabled.
                Defaults to True.
        """
        self._is_enabled = is_enabled

    def log(self,
            message: str,
            message_type: LoggedMessageTypes = LoggedMessageTypes.STANDARD,
            end: str = "\n") -> None:
        r"""Logs a message on the screen.

        Args:
            message (str): Message text
            message_type (LoggedMessageTypes): Message type. Defaults to the
                type of standard message.
            end (str): String appended at the end of the message. Defaults to
                "\n".
        """
        if self._is_enabled:
            if message_type != LoggedMessageTypes.STANDARD:
                message = emojis.encode(message_type.value + " " + message)

            self._mutex.acquire()
            if self._internal_buffering:
                self._buffer += message + end
            else:
                print(message, end=end)
            self._mutex.release()

    def set_internal_buffering(self) -> None:
        """Activates the internal buffering of the logger."""
        self._internal_buffering = True

    def get_buffer(self, empty: bool = False) -> str:
        """Gets the internal buffer of the buffer.

        Args:
            empty (bool): Boolean indicating if the internal buffer needs to be
                emptied

        Returns:
            str: Content of the internal buffer
        """
        self._mutex.acquire()
        content = self._buffer
        self._mutex.release()

        if empty:
            self._buffer = ""

        if self._internal_buffering:
            return content

        return None
