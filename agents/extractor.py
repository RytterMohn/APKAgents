"""
Extractor Agent.
"""

import os
import re
import subprocess
from typing import Dict, List

from .base import AgentContext, AgentResult, BaseAgent


class ExtractorAgent(BaseAgent):
    """Extract APK metadata and decoded files."""

    def __init__(self, config: Dict = None):
        super().__init__("Extractor", config)
        config = config or {}
        self.apktool_path = config.get("apktool_path", "apktool")
        self.aapt_path = config.get("aapt_path", "aapt")
        self.apksigner_path = config.get("apksigner_path", "apksigner")

    def get_required_inputs(self) -> List[str]:
        return ["apk_path", "output_dir"]

    def get_output_schema(self) -> Dict:
        return {
            "extracted_dir": "str",
            "manifest_data": "dict",
            "manifest_xml": "str",
            "dex_files": "list",
            "signature_info": "dict",
            "resource_files": "list",
        }

    def execute(self, context: AgentContext) -> AgentResult:
        self.log_info(context, f"Extracting APK: {context.apk_path}")

        if not os.path.exists(context.apk_path):
            return AgentResult.error_result(f"APK file not found: {context.apk_path}")

        apk_name = os.path.splitext(os.path.basename(context.apk_path))[0]
        extracted_dir = os.path.join(context.output_dir, f"{apk_name}_extracted")
        os.makedirs(extracted_dir, exist_ok=True)

        try:
            manifest_data = self._get_apk_info(context)
            if not manifest_data:
                context.add_warning("Failed to get APK info with aapt")

            self._decode_apk(context, extracted_dir)
            dex_files = self._extract_dex_files(context, extracted_dir)
            signature_info = self._get_signature_info(context)
            resource_files = self._list_resource_files(extracted_dir)

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
                    "resource_files": resource_files,
                },
                artifacts=[extracted_dir],
            )
        except Exception as exc:
            self.log_error(context, f"Extraction failed: {exc}")
            return AgentResult.error_result(f"Extraction failed: {exc}")

    def _run(self, command: List[str], timeout: int):
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout)

    def _get_apktool_command(self, apk_path: str, output_dir: str) -> List[str]:
        if self.apktool_path.lower().endswith(".jar"):
            return ["java", "-Xmx512m", "-jar", self.apktool_path, "d", apk_path, "-o", output_dir, "-f"]
        return [self.apktool_path, "d", apk_path, "-o", output_dir, "-f"]

    def _get_apk_info(self, context: AgentContext) -> Dict:
        try:
            result = self._run([self.aapt_path, "dump", "badging", context.apk_path], timeout=30)
            if result.returncode != 0:
                self.log_warning(context, f"aapt failed: {result.stderr}")
                return {}

            output = result.stdout
            info = {}

            match = re.search(r"package: name='([^']+)'", output)
            if match:
                info["package"] = match.group(1)

            match = re.search(r"versionName='([^']+)'", output)
            if match:
                info["versionName"] = match.group(1)

            match = re.search(r"versionCode='([^']+)'", output)
            if match:
                info["versionCode"] = match.group(1)

            match = re.search(r"sdkVersion:'(\d+)'", output)
            if match:
                info["minSdkVersion"] = int(match.group(1))

            match = re.search(r"targetSdkVersion:'(\d+)'", output)
            if match:
                info["targetSdkVersion"] = int(match.group(1))

            match = re.search(r"application-label:'([^']+)'", output)
            if match:
                info["label"] = match.group(1)

            match = re.search(r"application-icon-(\d+):'([^']+)'", output)
            if match:
                info["icon_density"] = match.group(1)
                info["icon_path"] = match.group(2)

            return info
        except subprocess.TimeoutExpired:
            self.log_warning(context, "aapt command timeout")
            return {}
        except Exception as exc:
            self.log_warning(context, f"aapt error: {exc}")
            return {}

    def _decode_apk(self, context: AgentContext, output_dir: str):
        try:
            result = self._run(self._get_apktool_command(context.apk_path, output_dir), timeout=180)
            if result.returncode != 0:
                raise RuntimeError(f"apktool failed: {result.stderr}")
            self.log_info(context, f"APK decoded to: {output_dir}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("apktool command timeout")
        except Exception as exc:
            raise RuntimeError(f"apktool error: {exc}")

    def _extract_dex_files(self, context: AgentContext, extracted_dir: str) -> List[str]:
        dex_files = []

        for filename in os.listdir(extracted_dir):
            if filename.endswith(".dex"):
                dex_files.append(os.path.join(extracted_dir, filename))

        if not dex_files and os.path.exists(context.apk_path):
            dex_files.append(context.apk_path)

        return sorted(set(dex_files))

    def _get_signature_info(self, context: AgentContext) -> Dict:
        try:
            result = self._run(
                [self.apksigner_path, "verify", "--print-certs", context.apk_path],
                timeout=30,
            )
            info = {
                "valid": result.returncode == 0,
                "signers": [],
                "algorithm": None,
                "md5": None,
                "sha1": None,
                "sha256": None,
            }

            if result.returncode == 0:
                output = result.stdout
                signer_match = re.search(r"Signer #1 certificate DN: (.+)", output)
                if signer_match:
                    info["signers"].append(signer_match.group(1))

                algo_match = re.search(r"Signature algorithm: (.+)", output)
                if algo_match:
                    info["algorithm"] = algo_match.group(1).strip()

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
                info["error"] = result.stderr.strip()

            return info
        except subprocess.TimeoutExpired:
            return {"valid": False, "error": "apksigner timeout"}
        except Exception as exc:
            return {"valid": False, "error": str(exc)}

    def _list_resource_files(self, extracted_dir: str) -> List[str]:
        resource_files = []
        for resource_dir in ["assets", "res", "lib", "original", "root"]:
            full_path = os.path.join(extracted_dir, resource_dir)
            if not os.path.exists(full_path):
                continue
            for root, _, files in os.walk(full_path):
                for filename in files:
                    resource_files.append(os.path.relpath(os.path.join(root, filename), extracted_dir))

        for filename in os.listdir(extracted_dir):
            full_path = os.path.join(extracted_dir, filename)
            if os.path.isfile(full_path):
                resource_files.append(filename)

        return sorted(resource_files)
