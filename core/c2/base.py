from __future__ import annotations
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable


class C2Backend(ABC):
    """Base for C2 integrations.

    Each backend polls its source and writes formatted log entries to a file
    in the op logs directory, which LogWatcher picks up normally.
    """

    def __init__(self, log_dir: Path, on_activity: Callable[[str], None]) -> None:
        self._log_dir    = log_dir
        self._on_activity = on_activity

    @abstractmethod
    def start(self) -> None: ...

    @abstractmethod
    def stop(self) -> None: ...

    def _write_log(self, filename: str, entry: str) -> None:
        log_path = self._log_dir / filename
        with open(log_path, "a") as f:
            f.write(entry + "\n")
