"""
Logger
日志工具
"""

import logging
import os
from typing import Optional


class Logger:
    """日志工具类"""

    def __init__(
        self,
        name: str = "APKAgent",
        level: str = "INFO",
        log_file: Optional[str] = None
    ):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))

        # 清除已有的handlers
        self.logger.handlers = []

        # 控制台handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, level.upper()))
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)

        # 文件handler
        if log_file:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(getattr(logging, level.upper()))
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)

    def get_logger(self) -> logging.Logger:
        """获取logger对象"""
        return self.logger

    def debug(self, message: str):
        self.logger.debug(message)

    def info(self, message: str):
        self.logger.info(message)

    def warning(self, message: str):
        self.logger.warning(message)

    def error(self, message: str):
        self.logger.error(message)

    def critical(self, message: str):
        self.logger.critical(message)


# 全局logger缓存
_loggers = {}


def get_logger(name: str = "APKAgent") -> logging.Logger:
    """
    获取全局logger

    Args:
        name: logger名称

    Returns:
        Logger对象
    """
    if name not in _loggers:
        _loggers[name] = Logger(name).get_logger()
    return _loggers[name]