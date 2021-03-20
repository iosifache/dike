"""Program testing the logging module"""
from modules.utils.logger import LoggedMessageType, Logger


def test_logged_message(capsys: "Fixture"):
    """Tests the logging of a message.

    Args:
        capsys (Fixture): Capture fixture passed by pytest
    """
    message = "This message will be logged."
    Logger().log(message, LoggedMessageType.STANDARD)

    captured = capsys.readouterr()
    assert captured.out == message + "\n", "The logged message is malformated."
