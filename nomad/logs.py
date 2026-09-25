"""Logging to a rotating file, the console (when there is one), and an in-memory buffer for the log viewer."""
import logging
import sys
import threading
from collections import deque
from logging.handlers import RotatingFileHandler

from .system import log_dir

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"


class MemoryLogHandler(logging.Handler):
    """Keeps recent log lines and notifies listeners (which may run on any thread)."""

    def __init__(self, capacity=5000):
        super().__init__()
        self.lines = deque(maxlen=capacity)
        self.listeners = []
        self.lock_listeners = threading.Lock()

    def emit(self, record):
        line = self.format(record)
        self.lines.append(line)
        with self.lock_listeners:
            listeners = list(self.listeners)
        for listener in listeners:
            listener(line)

    def add_listener(self, listener):
        with self.lock_listeners:
            self.listeners.append(listener)

    def remove_listener(self, listener):
        with self.lock_listeners:
            if listener in self.listeners:
                self.listeners.remove(listener)


def log_file_path():
    return log_dir() / "nomad.log"


def setup_logging():
    """Configure logging and return the in-memory handler used by the log viewer."""
    formatter = logging.Formatter(LOG_FORMAT)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    file_handler = RotatingFileHandler(log_file_path(), maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    if sys.stderr is not None:  # pythonw and --noconsole builds have no console
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        root.addHandler(console_handler)

    memory_handler = MemoryLogHandler()
    memory_handler.setFormatter(formatter)
    root.addHandler(memory_handler)
    return memory_handler
