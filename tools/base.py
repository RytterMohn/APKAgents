"""
Base Tool Class
所有工具封装的基类
"""

from abc import ABC, abstractmethod
import subprocess
import shutil
from typing import Dict, List, Optional


class BaseTool(ABC):
    """工具基类"""

    def __init__(self, tool_path: str = None):
        self.tool_path = tool_path or self._get_default_path()

    @abstractmethod
    def _get_default_path(self) -> str:
        """获取默认工具路径"""
        pass

    def is_available(self) -> bool:
        """检查工具是否可用"""
        if self.tool_path:
            return shutil.which(self.tool_path) is not None
        return False

    def get_version(self) -> str:
        """获取工具版本"""
        if not self.is_available():
            return ""

        try:
            result = subprocess.run(
                [self.tool_path, self._get_version_flag()],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout.strip()
        except Exception:
            return ""

    @abstractmethod
    def _get_version_flag(self) -> str:
        """获取版本命令 flag"""
        pass

    def run_command(self, args: List[str], timeout: int = 60) -> Dict:
        """
        运行工具命令

        Args:
            args: 命令参数列表
            timeout: 超时时间(秒)

        Returns:
            {"success": bool, "output": str, "error": str, "returncode": int}
        """
        cmd = [self.tool_path] + args

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "output": "",
                "error": "Command timeout",
                "returncode": -1
            }
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": str(e),
                "returncode": -1
            }