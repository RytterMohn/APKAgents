"""
File Utilities
文件操作工具函数
"""

import os
import shutil
import hashlib
from typing import Optional


def ensure_dir(directory: str) -> str:
    """
    确保目录存在，不存在则创建

    Args:
        directory: 目录路径

    Returns:
        目录路径
    """
    os.makedirs(directory, exist_ok=True)
    return directory


def copy_file(src: str, dst: str) -> bool:
    """
    复制文件

    Args:
        src: 源文件路径
        dst: 目标文件路径

    Returns:
        是否成功
    """
    try:
        ensure_dir(os.path.dirname(dst))
        shutil.copy2(src, dst)
        return True
    except Exception:
        return False


def get_file_hash(file_path: str, algorithm: str = "md5") -> Optional[str]:
    """
    计算文件哈希

    Args:
        file_path: 文件路径
        algorithm: 算法 (md5, sha1, sha256)

    Returns:
        哈希值，失败返回None
    """
    try:
        if algorithm == "md5":
            hasher = hashlib.md5()
        elif algorithm == "sha1":
            hasher = hashlib.sha1()
        elif algorithm == "sha256":
            hasher = hashlib.sha256()
        else:
            return None

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)

        return hasher.hexdigest()
    except Exception:
        return None


def calculate_apk_size(file_path: str) -> str:
    """
    计算并格式化APK文件大小

    Args:
        file_path: APK文件路径

    Returns:
        格式化后的大小字符串，如 "15.2 MB"
    """
    try:
        size = os.path.getsize(file_path)

        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024

        return f"{size:.1f} TB"
    except Exception:
        return "Unknown"


def delete_dir(directory: str) -> bool:
    """
    删除目录

    Args:
        directory: 目录路径

    Returns:
        是否成功
    """
    try:
        if os.path.exists(directory):
            shutil.rmtree(directory)
        return True
    except Exception:
        return False


def list_files(directory: str, pattern: str = "*") -> list:
    """
    列出目录下的文件

    Args:
        directory: 目录路径
        pattern: 文件模式

    Returns:
        文件列表
    """
    import fnmatch

    files = []
    for root, dirs, filenames in os.walk(directory):
        for filename in filenames:
            if fnmatch.fnmatch(filename, pattern):
                files.append(os.path.join(root, filename))
    return files