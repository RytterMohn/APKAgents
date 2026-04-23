"""
Jadx Wrapper
jadx反编译工具封装
"""

import os
from typing import Dict, List
from .base import BaseTool


class JadxWrapper(BaseTool):
    """jadx反编译工具封装"""

    def _get_default_path(self) -> str:
        return "jadx"

    def _get_version_flag(self) -> str:
        return "--version"

    def decompile(
        self,
        apk_path: str,
        output_dir: str,
        sources: bool = True,
        deobf: bool = False,
        respect_renaming: bool = True
    ) -> Dict:
        """
        反编译APK/DEX

        Args:
            apk_path: APK/DEX文件路径
            output_dir: 输出目录
            sources: 是否保留源码
            deobf: 是否反混淆
            respect_renaming: 是否尊重重命名

        Returns:
            {"success": bool, "output_dir": str, "files": List[str], "error": str}
        """
        args = [
            "-d", output_dir,
            apk_path
        ]

        if not sources:
            args.append("--no-src")
        if deobf:
            args.append("--deobf")
        if not respect_renaming:
            args.append("--no-res-name-r")

        result = self.run_command(args, timeout=600)

        if result["success"]:
            files = self._list_java_files(output_dir)
            return {
                "success": True,
                "output_dir": output_dir,
                "files": files
            }
        else:
            return {
                "success": False,
                "error": result["error"]
            }

    def decompile_dex(
        self,
        dex_path: str,
        output_dir: str,
        sources: bool = True
    ) -> Dict:
        """单独反编译DEX文件"""
        return self.decompile(dex_path, output_dir, sources=sources)

    def _list_java_files(self, directory: str) -> List[str]:
        """列出Java源文件"""
        files = []
        for root, dirs, filenames in os.walk(directory):
            for f in filenames:
                if f.endswith(".java"):
                    rel_path = os.path.relpath(os.path.join(root, f), directory)
                    files.append(rel_path)
        return files