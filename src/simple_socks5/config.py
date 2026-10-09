"""
This file contains the configuration for the proxy server set at runtime.
"""

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal, TypeAlias

from .models import BaseAddress

LoggingLevelName: TypeAlias = Literal["disabled", "debug", "info", "warning", "error", "critical"]

LOGGING_LEVELS: Final[Mapping[LoggingLevelName, int]] = {
    "disabled": logging.NOTSET,
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}


@dataclass(frozen=True)
class ProxyConfiguration:
    host: str
    port: int
    logging_level: LoggingLevelName

    @property
    def level(self) -> int:
        """The numeric logging level; logging.NOTSET means logging is disabled."""
        return LOGGING_LEVELS[self.logging_level]

    @property
    def address(self) -> BaseAddress:
        return BaseAddress(self.host, self.port)
