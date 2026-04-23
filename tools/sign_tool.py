"""
Sign Tool
APK签名和验签工具封装
"""

import os
from typing import Dict
from .base import BaseTool


class SignTool(BaseTool):
    """APK签名工具封装"""

    def _get_default_path(self) -> str:
        return "apksigner"

    def _get_version_flag(self) -> str:
        return "--version"

    def sign(
        self,
        apk_path: str,
        keystore: str,
        key_alias: str,
        store_password: str,
        key_password: str,
        v1_signing: bool = True,
        v2_signing: bool = True,
        v3_signing: bool = False
    ) -> Dict:
        """
        签名APK

        Args:
            apk_path: APK路径
            keystore: keystore路径
            key_alias: 密钥别名
            store_password: keystore密码
            key_password: 密钥密码
            v1_signing: 是否使用V1签名
            v2_signing: 是否使用V2签名
            v3_signing: 是否使用V3签名

        Returns:
            {"success": bool, "signed_apk": str, "error": str}
        """
        args = [
            "sign",
            "--ks", keystore,
            "--ks-key-alias", key_alias,
            "--ks-pass", f"pass:{store_password}",
            "--key-pass", f"pass:{key_password}",
            "--out", f"{apk_path}.signed",
            apk_path
        ]

        if v1_signing:
            args.append("--min-sdk-version", "18")
        if not v2_signing:
            args.append("--v2-signing-enabled")
            args.append("false")
        if v3_signing:
            args.append("--v3-signing-enabled")
            args.append("true")

        result = self.run_command(args, timeout=60)

        if result["success"]:
            return {
                "success": True,
                "signed_apk": f"{apk_path}.signed"
            }
        else:
            return {
                "success": False,
                "error": result["error"]
            }

    def verify(self, apk_path: str, verbose: bool = True) -> Dict:
        """
        验证签名

        Args:
            apk_path: APK路径
            verbose: 是否详细输出

        Returns:
            {"valid": bool, "signers": List, "details": Dict, "error": str}
        """
        args = ["verify", apk_path]

        if verbose:
            args.append("-v")

        result = self.run_command(args, timeout=30)

        output = result.get("output", "")
        error = result.get("error", "")

        # 解析输出
        is_valid = "Verified" in output or "verified" in output.lower()

        signers = []
        if is_valid:
            # 提取签名者信息
            for line in output.split("\n"):
                if "Signer #1" in line:
                    signers.append(line.strip())

        return {
            "valid": is_valid,
            "signers": signers,
            "details": {"output": output},
            "error": error if not is_valid else ""
        }

    def info(self, apk_path: str) -> Dict:
        """
        获取签名信息

        Returns:
            {signers, scheme, algorithm, created, expires}
        """
        args = ["verify", "--print-certs", apk_path]
        result = self.run_command(args, timeout=30)

        # 简化解析
        return {
            "output": result.get("output", ""),
            "error": result.get("error", "")
        }