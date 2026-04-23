"""
Path Utilities
路径处理工具函数
"""

import os
from datetime import datetime
from typing import Optional


def get_apk_name(apk_path: str) -> str:
    """
    获取APK名称（不含扩展名）

    Args:
        apk_path: APK文件路径

    Returns:
        APK名称
    """
    basename = os.path.basename(apk_path)
    return os.path.splitext(basename)[0]


def get_output_path(apk_path: str, base_output: str = "output") -> str:
    """
    生成输出路径

    Args:
        apk_path: APK文件路径
        base_output: 输出基础目录

    Returns:
        输出目录路径
    """
    apk_name = get_apk_name(apk_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(base_output, f"{apk_name}_{timestamp}")


def create_task_dir(base_dir: str, task_name: str) -> str:
    """
    创建任务目录

    Args:
        base_dir: 基础目录
        task_name: 任务名称

    Returns:
        创建的目录路径
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    task_dir = os.path.join(base_dir, f"{task_name}_{timestamp}")
    os.makedirs(task_dir, exist_ok=True)
    return task_dir


def normalize_path(path: str) -> str:
    """
    规范化路径（统一分隔符）

    Args:
        path: 路径

    Returns:
        规范化后的路径
    """
    return os.path.normpath(path).replace("\\", "/")


def get_relative_path(full_path: str, base_path: str) -> str:
    """
    获取相对路径

    Args:
        full_path: 完整路径
        base_path: 基础路径

    Returns:
        相对路径
    """
    return os.path.relpath(full_path, base_path)


def safe_filename(filename: str) -> str:
    """
    转换为安全的文件名

    Args:
        filename: 原始文件名

    Returns:
        安全的文件名
    """
    # 替换不合法字符
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, "_")
    return filename