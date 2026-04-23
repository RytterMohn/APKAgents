"""
Apktool Wrapper
apktool封装，提供APK解包和重打包功能
"""

import os
from typing import Dict, List
from .base import BaseTool


class ApktoolWrapper(BaseTool):
    """apktool封装"""

    def _get_default_path(self) -> str:
        return "apktool"

    def _get_version_flag(self) -> str:
        return "version"

    def decode(
        self,
        apk_path: str,
        output_dir: str,
        force: bool = False,
        decode_sources: bool = False,
        decode_resources: bool = True
    ) -> Dict:
        """
        解包APK

        Args:
            apk_path: APK文件路径
            output_dir: 输出目录
            force: 是否强制覆盖
            decode_sources: 是否解码源码
            decode_resources: 是否解码资源

        Returns:
            {"success": bool, "output_dir": str, "files": List[str], "error": str}
        """
        args = ["d", apk_path, "-o", output_dir]

        if force:
            args.append("-f")
        if decode_sources:
            args.append("-s")
        if not decode_resources:
            args.append("--no-res")

        result = self.run_command(args, timeout=120)

        if result["success"]:
            files = self._list_decoded_files(output_dir)
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

    def build(
        self,
        decoded_dir: str,
        output_apk: str,
        use_aapt2: bool = True
    ) -> Dict:
        """
        重新打包APK

        Args:
            decoded_dir: 解包目录
            output_apk: 输出APK路径
            use_aapt2: 是否使用aapt2

        Returns:
            {"success": bool, "output_apk": str, "error": str}
        """
        args = ["b", decoded_dir, "-o", output_apk]

        if not use_aapt2:
            args.append("--use-aapt2")

        result = self.run_command(args, timeout=180)

        if result["success"]:
            return {
                "success": True,
                "output_apk": output_apk
            }
        else:
            return {
                "success": False,
                "error": result["error"]
            }

    def _list_decoded_files(self, directory: str) -> List[str]:
        """列出解码后的文件"""
        files = []
        for root, dirs, filenames in os.walk(directory):
            for f in filenames:
                rel_path = os.path.relpath(os.path.join(root, f), directory)
                files.append(rel_path)
        return files