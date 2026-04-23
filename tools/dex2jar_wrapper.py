"""
Dex2Jar Wrapper
dex2jar工具封装
"""

import os
from typing import Dict
from .base import BaseTool


class Dex2JarWrapper(BaseTool):
    """dex2jar工具封装"""

    def _get_default_path(self) -> str:
        return "d2j-dex2jar"

    def _get_version_flag(self) -> str:
        return "--version"

    def dex2jar(
        self,
        dex_path: str,
        output_jar: str = None,
        force: bool = False
    ) -> Dict:
        """
        DEX转JAR

        Args:
            dex_path: DEX文件路径
            output_jar: 输出JAR路径(可选)
            force: 是否覆盖

        Returns:
            {"success": bool, "output_jar": str, "error": str}
        """
        if not output_jar:
            base_name = os.path.splitext(os.path.basename(dex_path))[0]
            output_jar = f"{base_name}.jar"

        args = ["-o", output_jar, dex_path]

        if force:
            args.insert(0, "-f")

        result = self.run_command(args, timeout=120)

        if result["success"]:
            return {
                "success": True,
                "output_jar": output_jar
            }
        else:
            return {
                "success": False,
                "error": result["error"]
            }

    def jar2dex(
        self,
        jar_path: str,
        output_dex: str = None
    ) -> Dict:
        """
        JAR转DEX

        Args:
            jar_path: JAR文件路径
            output_dex: 输出DEX路径

        Returns:
            {"success": bool, "output_dex": str, "error": str}
        """
        if not output_dex:
            base_name = os.path.splitext(os.path.basename(jar_path))[0]
            output_dex = f"{base_name}.dex"

        args = ["-o", output_dex, jar_path]
        result = self.run_command(args, timeout=120)

        if result["success"]:
            return {
                "success": True,
                "output_dex": output_dex
            }
        else:
            return {
                "success": False,
                "error": result["error"]
            }