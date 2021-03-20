"""Module logging information on screen

Usage example:

    Logger().log("This message will be logged.", LoggedMessageType.NEW_MESSAGE)
"""
from enum import Enum
from threading import Lock

import emojis
from pypattyrn.creational.singleton import Singleton


class LoggedMessageType(Enum):
    """Enumeration for message types, each one having a specific emoji attached
    """
    STANDARD = ""
    BEGINNING = ":on:"
    END = ":end:"
    WORK = ":hammer:"
    SUCCESS = ":white_check_mark:"
    FAIL = ":no_entry_sign:"
    ERROR = ":boom:"
    NEW = ":new:"
    NEW_MESSAGE = ":email:"
    INFORMATION = ":page_facing_up:"
    CONNECTIONS = ":link:"
    QUESTION = ":information_source:"


class Logger(metaclass=Singleton):
    """Class for logging messages (that can contain emojis =) on screen"""
    _enable: bool
    _internal_buffering: bool
    _buffer: str
    _mutex: Lock

    def __init__(self, enable: bool = False) -> None:
        """Initializes the Logger instance.
        
        Args:
            enable(bool): Boolean indicating if the logger is enabled by
                creation
        """
        # Default values of members
        self._enable = enable
        self._internal_buffering = False
        self._buffer = ""
        self._mutex = Lock()

    def set_enable(self, enable: bool) -> None:
        """Set the enabling of the logger.

        Args:
            enable (bool): Boolean indicating if the logger is enabled
        """
        self._enable = enable

    def log(self,
            message: str,
            message_type: LoggedMessageType = LoggedMessageType.STANDARD,
            end: str = "\n") -> None:
        """Logs a message on screen.

        Args:
            message (str): Message text
            message_type (LoggedMessageType, optional): Message type. Defaults
                to LoggedMessageType.STANDARD.
            end (str, optional): String appended at the end of the message.
                Defaults to "\n".
        """
        if self._enable:
            if (message_type != LoggedMessageType.STANDARD):
                message = emojis.encode(message_type.value + " " + message)

            self._mutex.acquire()
            if self._internal_buffering:
                self._buffer += message + end
            else:
                print(message, end=end)
            self._mutex.release()

    def set_internal_buffering(self) -> None:
        """Activates the internal buffering of the logger.
        """
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
        else:
            return None
