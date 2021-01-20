import emojis
from enum import Enum


class LoggedMessageType(Enum):
    """Enumeration for message types, each one having a specific emoji attached
    """
    STANDARD = ""
    BEGINNING = ":on:"
    END = ":end:"
    WORK = ":hammer"
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
            end="\n") -> None:
        """Logs a message on screen.

        Args:
            message (str): Message text
            message_type (LoggedMessageType, optional): Message type. Defaults
                                                        to LoggedMessageType.STANDARD.
            end (str, optional): String appended at the end of the message.
                                 Defaults to "\n".
        """
        message = emojis.encode(message)
        print(message_type.value + " " + message, end=end)