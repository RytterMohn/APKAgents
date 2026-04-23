"""
Analyzer Agent - 分析Agent
负责静态分析APK
"""

import os
from typing import List, Dict
from .base import BaseAgent, AgentContext, AgentResult
from tools.androguard_wrapper import AndroguardWrapper


class AnalyzerAgent(BaseAgent):
    """
    分析Agent
    负责:
    - 分析AndroidManifest.xml中的组件
    - 检测声明的权限列表
    - 识别Activity、Service、BroadcastReceiver、ContentProvider
    - 分析代码中的敏感API调用
    - 检测Intent通信安全
    - 分析加密/解密实现
    """

    def __init__(self, config: Dict = None):
        super().__init__("Analyzer", config)
        self.deep_analysis = config.get("deep_analysis", True)
        self.androguard = AndroguardWrapper()

    def get_required_inputs(self) -> List[str]:
        """需要的输入"""
        return ["extracted_dir", "manifest_data", "apk_path"]

    def get_output_schema(self) -> Dict:
        """输出schema"""
        return {
            "apk_info": "dict",
            "components": "dict",
            "permissions": "list",
            "sensitive_apis": "list",
            "network_calls": "list",
            "crypto_usage": "list"
        }

    def _get_apk_path(self, context: AgentContext) -> str:
        """获取APK路径"""
        if hasattr(context, "apk_path") and context.apk_path:
            return context.apk_path
        extracted_dir = context.extracted_dir
        apk_name = os.path.basename(os.path.dirname(extracted_dir)).replace("_extracted", "")
        for f in os.listdir(os.path.dirname(extracted_dir)):
            if f.endswith(".apk"):
                return os.path.join(os.path.dirname(extracted_dir), f)
        return ""

    def execute(self, context: AgentContext) -> AgentResult:
        """执行静态分析"""
        self.log_info(context, "Starting static analysis")

        if not context.extracted_dir:
            return AgentResult.error_result("No extracted directory found")

        apk_path = self._get_apk_path(context)
        if not apk_path or not os.path.exists(apk_path):
            return AgentResult.error_result(f"APK file not found: {apk_path}")

        try:
            self.apk = self.androguard.load_apk(apk_path)

            # 1. 解析APK基本信息
            apk_info = self._analyze_apk_info(context)

            # 2. 解析Manifest获取组件
            components = self._analyze_components(context)

            # 3. 分析权限
            permissions = self._analyze_permissions(context)

            # 4. 分析敏感API调用
            sensitive_apis = []
            if self.config.get("check_sensitive_apis", True):
                sensitive_apis = self._analyze_sensitive_apis(context)

            # 5. 分析网络通信
            network_calls = []
            if self.config.get("check_network", True):
                network_calls = self._analyze_network(context)

            # 6. 分析加密使用
            crypto_usage = []
            if self.config.get("check_crypto", True):
                crypto_usage = self._analyze_crypto(context)

            # 更新context
            context.apk_info = apk_info
            context.components = components
            context.permissions = permissions
            context.sensitive_apis = sensitive_apis
            context.network_calls = network_calls
            context.crypto_usage = crypto_usage

            return AgentResult.success_result(
                message="Analysis completed",
                data={
                    "apk_info": apk_info,
                    "components": components,
                    "permissions": permissions,
                    "sensitive_apis": sensitive_apis,
                    "network_calls": network_calls,
                    "crypto_usage": crypto_usage
                }
            )

        except Exception as e:
            self.log_error(context, f"Analysis failed: {str(e)}")
            return AgentResult.error_result(f"Analysis failed: {str(e)}")

    def _analyze_apk_info(self, context: AgentContext) -> Dict:
        """分析APK基本信息"""
        try:
            info = self.androguard.get_basic_info(self.apk)
            info["permissions"] = self.androguard.get_permissions(self.apk)
            info["package_name"] = info.get("package", "")
            info["version_name"] = info.get("version", "")
            info["version_code"] = info.get("version_code", "")
            info["min_sdk"] = info.get("min_sdk", "")
            info["target_sdk"] = info.get("target_sdk", "")
            return info
        except Exception as e:
            self.log_warning(context, f"Failed to analyze APK info: {str(e)}")
            return {}

    def _analyze_components(self, context: AgentContext) -> Dict:
        """分析组件"""
        try:
            components = self.androguard.get_components(self.apk)

            # 获取详细信息
            result = {
                "activities": self.androguard.get_activities(self.apk),
                "services": self.androguard.get_services(self.apk),
                "receivers": self.androguard.get_receivers(self.apk),
                "providers": self.androguard.get_providers(self.apk)
            }

            # 统计exported组件
            result["exported_counts"] = {
                "activities": sum(1 for a in result["activities"] if a.get("exported")),
                "services": sum(1 for s in result["services"] if s.get("exported")),
                "receivers": sum(1 for r in result["receivers"] if r.get("exported")),
                "providers": sum(1 for p in result["providers"] if p.get("exported"))
            }

            return result
        except Exception as e:
            self.log_warning(context, f"Failed to analyze components: {str(e)}")
            return {"activities": [], "services": [], "receivers": [], "providers": []}

    def _analyze_permissions(self, context: AgentContext) -> List[str]:
        """分析权限列表"""
        try:
            permissions = self.androguard.get_permissions(self.apk)
            return sorted(set(permissions))
        except Exception as e:
            self.log_warning(context, f"Failed to analyze permissions: {str(e)}")
            return []

    def _analyze_sensitive_apis(self, context: AgentContext) -> List[Dict]:
        """分析敏感API调用"""
        sensitive_patterns = [
            "getDeviceId", "getSubscriberId", "getSimSerialNumber",
            "getLastKnownLocation", "requestLocationUpdates",
            "openCamera", "Camera.open", "takePicture",
            "AudioRecord", "MediaRecorder.start",
            "FileInputStream", "FileOutputStream", "openFileInput", "openFileOutput",
            "WebView.loadUrl", "evaluateJavascript",
            "getSharedPreferences", "DatabaseUtils",
            "Runtime.exec", "ProcessBuilder",
            "DexClassLoader", "URLClassLoader",
            "encrypt", "decrypt", "Cipher",
            "sendTextMessage", "sendMultipartTextMessage"
        ]

        findings = self.androguard.find_sensitive_apis(self.apk, sensitive_patterns)

        result = []
        for finding in findings:
            result.append({
                "class": finding.get("class", ""),
                "method": finding.get("method", ""),
                "descriptor": finding.get("descriptor", ""),
                "risk": self._assess_api_risk(finding.get("class", ""), finding.get("method", ""))
            })

        return result

    def _assess_api_risk(self, class_name: str, method_name: str) -> str:
        """评估API风险等级"""
        high_risk = ["getDeviceId", "getSubscriberId", "Runtime.exec", "DexClassLoader"]
        medium_risk = ["getLastKnownLocation", "openCamera", "AudioRecord", "WebView.loadUrl"]
        low_risk = ["FileInputStream", "getSharedPreferences"]

        full_method = f"{class_name}->{method_name}"
        for pattern in high_risk:
            if pattern in full_method:
                return "high"
        for pattern in medium_risk:
            if pattern in full_method:
                return "medium"
        for pattern in low_risk:
            if pattern in full_method:
                return "low"
        return "info"

    def _analyze_network(self, context: AgentContext) -> List[Dict]:
        """分析网络通信"""
        network_patterns = [
            "http://", "https://", "HttpURLConnection", "OkHttpClient",
            "Retrofit", "Volley", "HttpClient", "URLEncoder"
        ]

        findings = self.androguard.analyze_network_calls(self.apk)

        result = []
        for finding in findings:
            url = finding.get("url", "")
            if url:
                result.append({
                    "url": url,
                    "class": finding.get("class", ""),
                    "method": finding.get("method", ""),
                    "encryption": "https" if url.startswith("https") else "http"
                })

        return result

    def _analyze_crypto(self, context: AgentContext) -> List[Dict]:
        """分析加密使用"""
        crypto_patterns = [
            "Cipher", "MessageDigest", "KeyStore", "KeyPairGenerator",
            "SecretKey", "IvParameterSpec", "AlgorithmParameters",
            "SSLContext", "TrustManager", "X509TrustManager"
        ]

        findings = self.androguard.find_sensitive_apis(self.apk, crypto_patterns)

        result = []
        for finding in findings:
            class_name = finding.get("class", "")
            method_name = finding.get("method", "")

            crypto_type = "unknown"
            if "Cipher" in class_name:
                crypto_type = "Cipher"
            elif "MessageDigest" in class_name:
                crypto_type = "MessageDigest"
            elif "KeyStore" in class_name:
                crypto_type = "KeyStore"
            elif "SSLContext" in class_name or "TrustManager" in class_name:
                crypto_type = "TLS/SSL"

            result.append({
                "type": crypto_type,
                "class": class_name,
                "method": method_name,
                "descriptor": finding.get("descriptor", "")
            })

        return result

    def analyze_intent_security(self, context: AgentContext) -> Dict:
        """分析Intent通信安全"""
        result = {
            "implicit_intents": [],
            "intent_filters": [],
            "exported_components": [],
            "security_issues": []
        }

        try:
            components = self._analyze_components(context)

            # 检查exported组件
            for comp_type in ["activities", "services", "receivers", "providers"]:
                for comp in components.get(comp_type, []):
                    if comp.get("exported"):
                        result["exported_components"].append({
                            "type": comp_type,
                            "name": comp.get("name", ""),
                            "permission": comp.get("permission", "")
                        })

                        if not comp.get("permission"):
                            result["security_issues"].append({
                                "type": "exported_without_permission",
                                "component": comp.get("name", ""),
                                "component_type": comp_type,
                                "severity": "medium",
                                "description": f"Exported {comp_type[:-1]} has no permission protection"
                            })

            # 检查intent filter
            for comp_type in ["activities", "services", "receivers"]:
                for comp in components.get(comp_type, []):
                    name = comp.get("name", "")
                    if name and self._has_intent_filter(context, name):
                        result["intent_filters"].append({
                            "type": comp_type,
                            "name": name
                        })

            return result

        except Exception as e:
            self.log_warning(context, f"Failed to analyze intent security: {str(e)}")
            return result

    def _has_intent_filter(self, context: AgentContext, component_name: str) -> bool:
        """检查组件是否有intent filter"""
        try:
            for activity in self.apk.get_activities():
                if component_name in activity:
                    return self.apk.is_activity_exported(activity)
        except Exception:
            pass
        return False