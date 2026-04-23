"""
Extractor Agent - 解包Agent
负责解包APK文件，提取所有资源
"""

import os
import subprocess
from typing import List, Dict
from .base import BaseAgent, AgentContext, AgentResult


class ExtractorAgent(BaseAgent):
    """
    解包Agent
    负责:
    - 验证APK文件格式
    - 使用apktool解包APK
    - 提取AndroidManifest.xml
    - 提取资源文件(assets, res, lib等)
    - 提取DEX文件
    - 验证签名信息
    """

    def __init__(self, config: Dict = None):
        super().__init__("Extractor", config)
        self.apktool_path = config.get("apktool_path", "apktool")
        self.aapt_path = config.get("aapt_path", "aapt")

    def get_required_inputs(self) -> List[str]:
        """需要的输入"""
        return ["apk_path", "output_dir"]

    def get_output_schema(self) -> Dict:
        """输出schema"""
        return {
            "extracted_dir": "str",
            "manifest_data": "dict",
            "manifest_xml": "str",
            "dex_files": "list",
            "signature_info": "dict",
            "resource_files": "list"
        }

    def execute(self, context: AgentContext) -> AgentResult:
        """
        执行解包

        使用工具:
        - apktool: 解包APK
        - aapt: 提取APK基础信息
        - apksigner: 验证签名
        """
        self.log_info(context, f"Extracting APK: {context.apk_path}")

        # 验证APK文件
        if not os.path.exists(context.apk_path):
            return AgentResult.error_result(f"APK file not found: {context.apk_path}")

        # 创建输出目录
        apk_name = os.path.splitext(os.path.basename(context.apk_path))[0]
        extracted_dir = os.path.join(context.output_dir, f"{apk_name}_extracted")
        os.makedirs(extracted_dir, exist_ok=True)

        try:
            # 1. 使用aapt获取APK基本信息
            manifest_data = self._get_apk_info(context)
            if not manifest_data:
                context.add_warning("Failed to get APK info with aapt")

            # 2. 使用apktool解包
            self._decode_apk(context, extracted_dir)

            # 3. 提取DEX文件
            dex_files = self._extract_dex_files(extracted_dir)

            # 4. 获取签名信息
            signature_info = self._get_signature_info(context)

            # 5. 列出资源文件
            resource_files = self._list_resource_files(extracted_dir)

            # 更新context
            context.extracted_dir = extracted_dir
            context.manifest_data = manifest_data
            context.dex_files = dex_files
            context.signature_info = signature_info
            context.resource_files = resource_files

            return AgentResult.success_result(
                message="Extraction completed",
                data={
                    "extracted_dir": extracted_dir,
                    "manifest_data": manifest_data,
                    "manifest_xml": os.path.join(extracted_dir, "AndroidManifest.xml"),
                    "dex_files": dex_files,
                    "signature_info": signature_info,
                    "resource_files": resource_files
                },
                artifacts=[extracted_dir]
            )

        except Exception as e:
            self.log_error(context, f"Extraction failed: {str(e)}")
            return AgentResult.error_result(f"Extraction failed: {str(e)}")

    def _get_apk_info(self, context: AgentContext) -> Dict:
        """使用aapt获取APK信息"""
        import re
        try:
            result = subprocess.run(
                [self.aapt_path, "dump", "badging", context.apk_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                self.log_warning(context, f"aapt failed: {result.stderr}")
                return {}

            output = result.stdout
            info = {}

            # 解析包名
            match = re.search(r"package: name='([^']+)'", output)
            if match:
                info["package"] = match.group(1)

            # 解析版本名
            match = re.search(r"versionName='([^']+)'", output)
            if match:
                info["versionName"] = match.group(1)

            # 解析版本号
            match = re.search(r"versionCode='([^']+)'", output)
            if match:
                info["versionCode"] = match.group(1)

            # 解析SDK版本
            match = re.search(r"sdkVersion:'(\d+)'", output)
            if match:
                info["minSdkVersion"] = int(match.group(1))

            # 解析目标SDK版本
            match = re.search(r"targetSdkVersion:'(\d+)'", output)
            if match:
                info["targetSdkVersion"] = int(match.group(1))

            # 解析应用标签
            match = re.search(r"application-label:'([^']+)'", output)
            if match:
                info["label"] = match.group(1)

            # 解析图标
            match = re.search(r"application-icon-(\d+):'([^']+)'", output)
            if match:
                info["icon_density"] = match.group(1)
                info["icon_path"] = match.group(2)

            return info
        except subprocess.TimeoutExpired:
            self.log_warning(context, "aapt command timeout")
            return {}
        except Exception as e:
            self.log_warning(context, f"aapt error: {str(e)}")
            return {}

    def _decode_apk(self, context: AgentContext, output_dir: str):
        """使用apktool解包APK"""
        try:
            result = subprocess.run(
                [self.apktool_path, "d", context.apk_path, "-o", output_dir, "-f"],
                capture_output=True,
                text=True,
                timeout=180
            )
            if result.returncode != 0:
                raise RuntimeError(f"apktool failed: {result.stderr}")
            self.log_info(context, f"APK decoded to: {output_dir}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("apktool command timeout")
        except Exception as e:
            raise RuntimeError(f"apktool error: {str(e)}")

    def _extract_dex_files(self, extracted_dir: str) -> List[str]:
        """提取DEX文件列表"""
        dex_files = []
        smali_dir = os.path.join(extracted_dir, "smali")
        smali_classes_dir = os.path.join(extracted_dir, "smali_classes")

        # 扫描smali目录（单个DEX）
        if os.path.exists(smali_dir):
            for root, dirs, files in os.walk(smali_dir):
                for f in files:
                    if f.endswith(".dex"):
                        dex_files.append(os.path.relpath(os.path.join(root, f), extracted_dir))

        # 扫描smali_classes目录（多DEX）
        if os.path.exists(smali_classes_dir):
            for root, dirs, files in os.walk(smali_classes_dir):
                for f in files:
                    if f.endswith(".dex"):
                        dex_files.append(os.path.relpath(os.path.join(root, f), extracted_dir))

        # 也检查根目录下的DEX文件
        for f in os.listdir(extracted_dir):
            if f.endswith(".dex"):
                dex_files.append(f)

        return sorted(dex_files)

    def _get_signature_info(self, context: AgentContext) -> Dict:
        """获取签名信息"""
        import re
        try:
            result = subprocess.run(
                ["apksigner", "verify", "--print-certs", context.apk_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            info = {
                "valid": result.returncode == 0,
                "signers": [],
                "algorithm": None,
                "md5": None,
                "sha1": None,
                "sha256": None
            }

            if result.returncode == 0:
                output = result.stdout
                # 解析签名者
                signer_match = re.search(r"Signer #1 certificate DN: (.+)", output)
                if signer_match:
                    info["signers"].append(signer_match.group(1))

                # 解析算法
                algo_match = re.search(r"Signature algorithm: (.+)", output)
                if algo_match:
                    info["algorithm"] = algo_match.group(1).strip()

                # 解析证书指纹
                md5_match = re.search(r"MD5: ([A-Fa-f0-9:]+)", output)
                if md5_match:
                    info["md5"] = md5_match.group(1)

                sha1_match = re.search(r"SHA1: ([A-Fa-f0-9:]+)", output)
                if sha1_match:
                    info["sha1"] = sha1_match.group(1)

                sha256_match = re.search(r"SHA-256: ([A-Fa-f0-9:]+)", output)
                if sha256_match:
                    info["sha256"] = sha256_match.group(1)
            else:
                info["error"] = result.stderr

            return info
        except subprocess.TimeoutExpired:
            return {"valid": False, "error": "apksigner timeout"}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def _list_resource_files(self, extracted_dir: str) -> List[str]:
        """列出资源文件"""
        resource_files = []

        # 定义需要列出的资源目录
        resource_dirs = ["assets", "res", "lib", "original", "root"]

        for res_dir in resource_dirs:
            full_path = os.path.join(extracted_dir, res_dir)
            if os.path.exists(full_path):
                for root, dirs, files in os.walk(full_path):
                    for f in files:
                        rel_path = os.path.relpath(os.path.join(root, f), extracted_dir)
                        resource_files.append(rel_path)

        # 检查是否有其他根级文件
        for f in os.listdir(extracted_dir):
            full_path = os.path.join(extracted_dir, f)
            if os.path.isfile(full_path):
                resource_files.append(f)

        return sorted(resource_files)