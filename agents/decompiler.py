"""
Decompiler Agent - 反编译Agent
负责将DEX文件反编译为可读源码
"""

import os
import subprocess
import re
from typing import List, Dict
from .base import BaseAgent, AgentContext, AgentResult


class DecompilerAgent(BaseAgent):
    """
    反编译Agent
    负责:
    - 将DEX文件转换为JAR
    - 使用jadx反编译为Java源码
    - 提取Smali代码
    - 识别代码结构和类继承关系
    """

    def __init__(self, config: Dict = None):
        super().__init__("Decompiler", config)
        self.jadx_path = config.get("jadx_path", "jadx")
        self.dex2jar_path = config.get("dex2jar_path", "d2j-dex2jar")
        self.baksmali_path = config.get("baksmali_path", "baksmali")

    def get_required_inputs(self) -> List[str]:
        """需要的输入"""
        return ["dex_files", "output_dir"]

    def get_output_schema(self) -> Dict:
        """输出schema"""
        return {
            "decompiled_dir": "str",
            "java_sources": "list",
            "smali_files": "list",
            "jar_files": "list"
        }

    def execute(self, context: AgentContext) -> AgentResult:
        """
        执行反编译

        使用工具:
        - jadx: DEX反编译为Java
        - dex2jar: DEX转JAR
        - baksmali: DEX转Smali
        """
        self.log_info(context, "Starting decompilation")

        if not context.dex_files:
            return AgentResult.error_result("No DEX files to decompile")

        # 创建输出目录
        apk_name = os.path.splitext(os.path.basename(context.apk_path))[0]
        decompiled_dir = os.path.join(context.output_dir, f"{apk_name}_decompiled")
        os.makedirs(decompiled_dir, exist_ok=True)

        java_sources = []
        smali_files = []
        jar_files = []

        try:
            # 对每个DEX文件进行反编译
            for dex_file in context.dex_files:
                self.log_info(context, f"Decompiling: {dex_file}")

                # 1. 使用jadx反编译为Java
                java_dir = self._decompile_with_jadx(dex_file, decompiled_dir)
                if java_dir:
                    java_sources.append(java_dir)

                # 2. 转换为JAR（可选）
                if self.config.get("generate_jar", False):
                    jar_file = self._dex2jar(dex_file, decompiled_dir)
                    if jar_file:
                        jar_files.append(jar_file)

                # 3. 转换为Smali（可选）
                if self.config.get("generate_smali", False):
                    smali_dir = self._dex2smali(dex_file, decompiled_dir)
                    if smali_dir:
                        smali_files.append(smali_dir)

            # 更新context
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
                    "jar_files": jar_files
                },
                artifacts=[decompiled_dir]
            )

        except Exception as e:
            self.log_error(context, f"Decompilation failed: {str(e)}")
            return AgentResult.error_result(f"Decompilation failed: {str(e)}")

    def _decompile_with_jadx(self, dex_file: str, output_dir: str) -> str:
        """使用jadx反编译DEX"""
        dex_name = os.path.splitext(os.path.basename(dex_file))[0]
        java_dir = os.path.join(output_dir, f"{dex_name}_java")
        os.makedirs(java_dir, exist_ok=True)

        try:
            result = subprocess.run(
                [self.jadx_path, "-d", java_dir, dex_file, "--no-res"],
                capture_output=True,
                text=True,
                timeout=600
            )
            if result.returncode != 0:
                self.log_warning(None, f"jadx failed: {result.stderr}")
                return ""
            return java_dir
        except subprocess.TimeoutExpired:
            self.log_warning(None, "jadx timeout")
            return ""
        except Exception as e:
            self.log_warning(None, f"jadx error: {str(e)}")
            return ""

    def _dex2jar(self, dex_file: str, output_dir: str) -> str:
        """DEX转JAR"""
        dex_name = os.path.splitext(os.path.basename(dex_file))[0]
        jar_file = os.path.join(output_dir, f"{dex_name}.jar")

        try:
            result = subprocess.run(
                [self.dex2jar_path, "-o", jar_file, dex_file],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode != 0:
                self.log_warning(None, f"dex2jar failed: {result.stderr}")
                return ""
            return jar_file
        except subprocess.TimeoutExpired:
            self.log_warning(None, "dex2jar timeout")
            return ""
        except Exception as e:
            self.log_warning(None, f"dex2jar error: {str(e)}")
            return ""

    def _dex2smali(self, dex_file: str, output_dir: str) -> str:
        """DEX转Smali"""
        dex_name = os.path.splitext(os.path.basename(dex_file))[0]
        smali_dir = os.path.join(output_dir, f"{dex_name}_smali")
        os.makedirs(smali_dir, exist_ok=True)

        try:
            result = subprocess.run(
                [self.baksmali_path, "d", "-o", smali_dir, dex_file],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode != 0:
                self.log_warning(None, f"baksmali failed: {result.stderr}")
                return ""
            return smali_dir
        except subprocess.TimeoutExpired:
            self.log_warning(None, "baksmali timeout")
            return ""
        except Exception as e:
            self.log_warning(None, f"baksmali error: {str(e)}")
            return ""

    def get_class_tree(self, java_sources: List[str]) -> Dict:
        """获取类继承结构树"""
        class_tree = {}

        for source_dir in java_sources:
            if not os.path.exists(source_dir):
                continue

            for root, dirs, files in os.walk(source_dir):
                for f in files:
                    if not f.endswith(".java"):
                        continue

                    java_file = os.path.join(root, f)
                    try:
                        with open(java_file, "r", encoding="utf-8", errors="ignore") as fp:
                            content = fp.read()

                        class_pattern = r"(?:public\s+|private\s+|protected\s+)?(class|interface|enum)\s+(\w+)\s*(?:extends\s+(\w+))?\s*(?:implements\s+([\w,\s]+))?"
                        matches = re.finditer(class_pattern, content)

                        for match in matches:
                            class_type = match.group(1)
                            class_name = match.group(2)
                            parent = match.group(3)
                            interfaces = match.group(4)

                            interface_list = []
                            if interfaces:
                                interface_list = [i.strip() for i in interfaces.split(",")]

                            class_tree[class_name] = {
                                "type": class_type,
                                "parent": parent,
                                "interfaces": interface_list,
                                "children": [],
                                "file": os.path.relpath(java_file, source_dir)
                            }
                    except Exception:
                        continue

        for class_name, info in class_tree.items():
            parent = info.get("parent")
            if parent and parent in class_tree:
                if class_name not in class_tree[parent]["children"]:
                    class_tree[parent]["children"].append(class_name)

        return class_tree