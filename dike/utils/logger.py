import emojis


class Logger:
    @staticmethod
    def print_on_screen(message):
        print(emojis.encode(message))