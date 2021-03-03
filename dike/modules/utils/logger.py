"""Module logging information on screen

Usage example:

    Logger.log("This message will be logged.", LoggedMessageType.NEW_MESSAGE)
"""
from enum import Enum

import emojis


class LoggedMessageType(Enum):
    """Enumeration for message types, each one having a specific emoji attached
    """
    STANDARD = ""
    BEGINNING = ":on:"
    END = ":end:"
    WORK = ":hammer:"
    SUCCESS = ":white_check_mark:"
    FAIL = ":no_entry_sign:"
    NEW = ":new:"
    NEW_MESSAGE = ":email:"
    CONNECTIONS = ":link:"
    QUESTION = ":information_source:"


class Logger:
    """Class for logging messages (that can contain emojis =) on screen"""
    @staticmethod
    def log(message: str,
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
        if (message_type != LoggedMessageType.STANDARD):
            message = emojis.encode(message_type.value + " " + message)
        print(message, end=end)
