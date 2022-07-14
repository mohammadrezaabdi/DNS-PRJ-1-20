import logging

loggers = ["server", "client"]
STD_LOG_LEVEL = logging.DEBUG

lock = 0


class LoggerFormatter(logging.Formatter):
    name_just = 20
    level_just = 15

    def format(self, record):
        time = self.formatTime(record, self.datefmt)
        return (
                f"===[{time}]===[{record.name}]".ljust(self.name_just, "=")
                + f"===[{record.levelname}]===".ljust(self.level_just, "=")
                + f" {record.getMessage()} :: ({record.filename}:{record.lineno})"
        )


default_format = LoggerFormatter()


def init():
    global lock
    lock += 1
    if lock == 2:
        return
    # setting logger
    stdout_h = logging.StreamHandler()
    stdout_h.setLevel(STD_LOG_LEVEL)
    stdout_h.setFormatter(default_format)

    for logger_name in loggers:
        logger = logging.getLogger(logger_name)
        logger.setLevel(STD_LOG_LEVEL)
        logger.addHandler(stdout_h)
