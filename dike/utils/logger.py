import emojis


class Logger:
    @staticmethod
    def log(message: str, end="\n") -> None:
        message = emojis.encode(message)
        print(message, end=end)

    @staticmethod
    def log_beginning(message: str, end="\n") -> None:
        Logger.log(":on: " + message, end)

    @staticmethod
    def log_end(message: str, end="\n") -> None:
        Logger.log(":end: " + message, end)

    @staticmethod
    def log_work(message: str, end="\n") -> None:
        Logger.log(":hammer: " + message, end)

    @staticmethod
    def log_success(message: str, end="\n") -> None:
        Logger.log(":white_check_mark: " + message, end)

    @staticmethod
    def log_fail(message: str, end="\n") -> None:
        Logger.log(":no_entry_sign: " + message, end)

    @staticmethod
    def log_new(message: str, end="\n") -> None:
        Logger.log(":new: " + message, end)

    @staticmethod
    def log_new_message(message: str, end="\n") -> None:
        Logger.log(":email: " + message, end)

    @staticmethod
    def log_connections(message: str, end="\n") -> None:
        Logger.log(":link: " + message, end)

    @staticmethod
    def log_question(message: str, end="\n") -> None:
        Logger.log(":information_source: " + message, end)