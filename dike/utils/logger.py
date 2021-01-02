import emojis


class Logger:
    @staticmethod
    def log(message: str) -> None:
        message = emojis.encode(message)
        print(message)

    @staticmethod
    def log_beginning(message: str) -> None:
        Logger.log(":on: " + message)

    @staticmethod
    def log_end(message: str) -> None:
        Logger.log(":end: " + message)

    @staticmethod
    def log_work(message: str) -> None:
        Logger.log(":hammer: " + message)

    @staticmethod
    def log_success(message: str) -> None:
        Logger.log(":white_check_mark: " + message)

    @staticmethod
    def log_fail(message: str) -> None:
        Logger.log(":no_entry_sign: " + message)

    @staticmethod
    def log_new(message: str) -> None:
        Logger.log(":new: " + message)

    @staticmethod
    def log_new_message(message: str) -> None:
        Logger.log(":email: " + message)

    @staticmethod
    def log_connections(message: str) -> None:
        Logger.log(":link: " + message)