"""
Decompiler Agent.
"""

import os
import re
import subprocess
from typing import Dict, List

from .base import AgentContext, AgentResult, BaseAgent


class DecompilerAgent(BaseAgent):
    """Decompile an APK or DEX input into source artifacts."""

    def __init__(self, config: Dict = None):
        super().__init__("Decompiler", config)
        config = config or {}
        self.jadx_path = config.get("jadx_path", "jadx")
        self.dex2jar_path = config.get("dex2jar_path", "d2j-dex2jar")
        self.baksmali_path = config.get("baksmali_path", "baksmali")

    def get_required_inputs(self) -> List[str]:
        return ["output_dir"]

    def get_output_schema(self) -> Dict:
        return {
            "decompiled_dir": "str",
            "java_sources": "list",
            "smali_files": "list",
            "jar_files": "list",
        }

    def execute(self, context: AgentContext) -> AgentResult:
        self.log_info(context, "Starting decompilation")

        inputs = list(context.dex_files or [])
        if not inputs and context.apk_path:
            inputs = [context.apk_path]
        if not inputs:
            return AgentResult.error_result("No APK or DEX files to decompile")

        apk_name = os.path.splitext(os.path.basename(context.apk_path))[0]
        decompiled_dir = os.path.join(context.output_dir, f"{apk_name}_decompiled")
        os.makedirs(decompiled_dir, exist_ok=True)

        java_sources: List[str] = []
        smali_files: List[str] = []
        jar_files: List[str] = []

        try:
            for input_file in inputs:
                self.log_info(context, f"Decompiling: {input_file}")

                java_dir = self._decompile_with_jadx(input_file, decompiled_dir)
                if java_dir:
                    java_sources.append(java_dir)

                if self.config.get("generate_jar", False):
                    jar_file = self._dex2jar(input_file, decompiled_dir)
                    if jar_file:
                        jar_files.append(jar_file)

                if self.config.get("generate_smali", False):
                    smali_dir = self._dex2smali(input_file, decompiled_dir)
                    if smali_dir:
                        smali_files.append(smali_dir)

            context.decompiled_dir = decompiled_dir
            context.java_sources = java_sources
            context.smali_files = smali_files
            context.jar_files = jar_files

            return AgentResult.success_result(
                message="Decompilation completed",
                data={
                    "decompiled_dir": decompiled_dir,
                    "java_sources": java_sources,
                    "smali_files": smali_files,
                    "jar_files": jar_files,
                },
                artifacts=[decompiled_dir],
            )
        except Exception as exc:
            self.log_error(context, f"Decompilation failed: {exc}")
            return AgentResult.error_result(f"Decompilation failed: {exc}")

    def _decompile_with_jadx(self, input_file: str, output_dir: str) -> str:
        base_name = os.path.splitext(os.path.basename(input_file))[0]
        java_dir = os.path.join(output_dir, f"{base_name}_java")
        os.makedirs(java_dir, exist_ok=True)
        env = os.environ.copy()
        env.setdefault("JADX_OPTS", "-Xmx512M -XX:MaxRAMPercentage=20.0")

        try:
            result = subprocess.run(
                [self.jadx_path, "-d", java_dir, input_file, "--no-res"],
                capture_output=True,
                text=True,
                timeout=600,
                env=env,
            )
            if result.returncode != 0:
                has_output = any(True for _, _, files in os.walk(java_dir) if files)
                if has_output:
                    self.log_warning(None, f"jadx returned non-zero but produced output: {result.stderr.strip()}")
                    return java_dir
                self.log_warning(None, f"jadx failed: {result.stderr.strip()}")
                return ""
            return java_dir
        except subprocess.TimeoutExpired:
            self.log_warning(None, "jadx timeout")
            return ""
        except Exception as exc:
            self.log_warning(None, f"jadx error: {exc}")
            return ""

    def _dex2jar(self, input_file: str, output_dir: str) -> str:
        base_name = os.path.splitext(os.path.basename(input_file))[0]
        jar_file = os.path.join(output_dir, f"{base_name}.jar")

        try:
            result = subprocess.run(
                [self.dex2jar_path, "-o", jar_file, input_file],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                self.log_warning(None, f"dex2jar failed: {result.stderr}")
                return ""
            return jar_file
        except subprocess.TimeoutExpired:
            self.log_warning(None, "dex2jar timeout")
            return ""
        except Exception as exc:
            self.log_warning(None, f"dex2jar error: {exc}")
            return ""

    def _dex2smali(self, input_file: str, output_dir: str) -> str:
        base_name = os.path.splitext(os.path.basename(input_file))[0]
        smali_dir = os.path.join(output_dir, f"{base_name}_smali")
        os.makedirs(smali_dir, exist_ok=True)

        try:
            result = subprocess.run(
                [self.baksmali_path, "d", "-o", smali_dir, input_file],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                self.log_warning(None, f"baksmali failed: {result.stderr}")
                return ""
            return smali_dir
        except subprocess.TimeoutExpired:
            self.log_warning(None, "baksmali timeout")
            return ""
        except Exception as exc:
            self.log_warning(None, f"baksmali error: {exc}")
            return ""

    def get_class_tree(self, java_sources: List[str]) -> Dict:
        class_tree = {}

        for source_dir in java_sources:
            if not os.path.exists(source_dir):
                continue

            for root, _, files in os.walk(source_dir):
                for filename in files:
                    if not filename.endswith(".java"):
                        continue

                    java_file = os.path.join(root, filename)
                    try:
                        with open(java_file, "r", encoding="utf-8", errors="ignore") as handle:
                            content = handle.read()

                        pattern = (
                            r"(?:public\s+|private\s+|protected\s+)?"
                            r"(class|interface|enum)\s+(\w+)\s*"
                            r"(?:extends\s+(\w+))?\s*"
                            r"(?:implements\s+([\w,\s]+))?"
                        )
                        for match in re.finditer(pattern, content):
                            class_name = match.group(2)
                            interfaces = match.group(4)
                            class_tree[class_name] = {
                                "type": match.group(1),
                                "parent": match.group(3),
                                "interfaces": [i.strip() for i in interfaces.split(",")] if interfaces else [],
                                "children": [],
                                "file": os.path.relpath(java_file, source_dir),
                            }
                    except Exception:
                        continue

        for class_name, info in class_tree.items():
            parent = info.get("parent")
            if parent and parent in class_tree and class_name not in class_tree[parent]["children"]:
                class_tree[parent]["children"].append(class_name)

        return class_tree
