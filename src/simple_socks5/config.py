"""
This file contains the configuration for the proxy server set at runtime.
"""
import logging

from .models import BaseAddress


class ProxyConfiguration:
    _host: str
    _port: int
    _logging_level: str

    _logging_level_str_to_level = {
        "disabled": logging.NOTSET,
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL,
    }

    @classmethod
    def initialize(
        cls, host: str, port: int, logging_level: int, use_tor: bool = False
    ) -> None:
        cls._host = host
        cls._port = port
        cls._logging_level = logging_level
        cls._use_tor = use_tor

    @classmethod
    def is_initialized(cls) -> bool:
        return (
            hasattr(cls, "_host")
            and hasattr(cls, "_port")
            and hasattr(cls, "_logging_level")
        )

    @classmethod
    def get_logging_level(cls):
        return cls._logging_level_str_to_level.get(cls._logging_level, logging.NOTSET)

    @classmethod
    def get_host(cls) -> str:
        return cls._host

    @classmethod
    def get_port(cls) -> int:
        return cls._port

    @classmethod
    def get_address(cls) -> BaseAddress:
        return BaseAddress(cls._host, cls._port)
