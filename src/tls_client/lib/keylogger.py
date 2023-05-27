# -*- coding: UTF-8 -*-
import sys

from pathlib import Path
from contextlib import contextmanager


class KeyLogger:
    def __init__(self, filename: str = None, log_to_stderr: bool = True) -> None:
        self.filename = filename
        self.log_to_stderr = log_to_stderr

        self._output = None

    @contextmanager
    def start_logging(self):
        try:
            if self.filename:
                fp = Path(self.filename)
                if not fp.parent.exists():
                    fp.parent.mkdir(parents=True)

                self._output = open(fp, mode="+a")
            elif self.log_to_stderr:
                self._output = sys.stderr

            yield
        finally:
            if self.filename:
                self._output.close()

    def write(self, connection, key):
        if cipher := connection.get_cipher_name():
            self._output.write(f"{cipher}\n")
        self._output.write(f"{key.decode()}\n")
        
    def write_info(self, connection, a, b):
        pass
        
