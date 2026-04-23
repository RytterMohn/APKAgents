"""
Androguard Wrapper
Androguard静态分析工具封装
"""

from typing import Dict, List
from .base import BaseTool


class AndroguardWrapper(BaseTool):
    """Androguard静态分析工具封装"""

    def __init__(self, tool_path: str = None):
        self.androguard = None
        self.apk = None
        self.tool_path = tool_path or self._get_default_path()
        self._check_installation()

    def _get_default_path(self) -> str:
        return "python"

    def _get_version_flag(self) -> str:
        return "-m androguard --version"

    def is_available(self) -> bool:
        """检查Androguard是否可用"""
        try:
            from androguard import __version__
            return True
        except ImportError:
            return False

    def _check_installation(self):
        """检查Androguard是否安装"""
        try:
            from androguard.misc import AnalyzeAPK
            self._analyze_apk_func = AnalyzeAPK
        except ImportError:
            raise ImportError("androguard not installed. Run: pip install androguard")

    def load_apk(self, apk_path: str) -> "APK":
        """
        加载APK文件

        Args:
            apk_path: APK文件路径

        Returns:
            APK对象
        """
        from androguard.core.bytecodes.apk import APK
        self.apk = APK(apk_path)
        return self.apk

    def get_basic_info(self, apk) -> Dict:
        """
        获取APK基本信息

        Returns:
            {package, version, version_code, min_sdk, target_sdk}
        """
        return {
            "package": apk.get_package(),
            "version": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version()
        }

    def get_permissions(self, apk) -> List[str]:
        """
        获取权限列表

        Returns:
            ["android.permission.INTERNET", ...]
        """
        return apk.get_permissions()

    def get_components(self, apk) -> Dict:
        """
        获取四大组件

        Returns:
            {
                "activities": [...],
                "services": [...],
                "receivers": [...],
                "providers": [...]
            }
        """
        return {
            "activities": apk.get_activities(),
            "services": apk.get_services(),
            "receivers": apk.get_receivers(),
            "providers": apk.get_providers()
        }

    def get_activities(self, apk) -> List[Dict]:
        """获取Activity详情"""
        activities = []
        for activity in apk.get_activities():
            activities.append({
                "name": activity,
                "exported": apk.is_activity_exported(activity),
                "permission": apk.get_activity_permission(activity)
            })
        return activities

    def get_services(self, apk) -> List[Dict]:
        """获取Service详情"""
        services = []
        for service in apk.get_services():
            services.append({
                "name": service,
                "exported": apk.is_service_exported(service),
                "permission": apk.get_service_permission(service)
            })
        return services

    def get_receivers(self, apk) -> List[Dict]:
        """获取BroadcastReceiver详情"""
        receivers = []
        for receiver in apk.get_receivers():
            receivers.append({
                "name": receiver,
                "exported": apk.is_receiver_exported(receiver),
                "permission": apk.get_receiver_permission(receiver)
            })
        return receivers

    def get_providers(self, apk) -> List[Dict]:
        """获取ContentProvider详情"""
        providers = []
        for provider in apk.get_providers():
            providers.append({
                "name": provider,
                "exported": apk.is_provider_exported(provider),
                "permission": apk.get_provider_permission(provider)
            })
        return providers

    def find_sensitive_apis(
        self,
        apk,
        patterns: List[str],
        decompiler=None
    ) -> List[Dict]:
        """
        搜索敏感API调用

        Args:
            apk: APK对象
            patterns: API模式列表
            decompiler: 反编译器对象(可选)

        Returns:
            [{class, method, params, location}, ...]
        """
        # 简化实现
        findings = []

        # 获取所有类
        for klass in apk.get_classes():
            # 检查每个方法
            for method in klass.get_methods():
                method_name = method.get_name()
                class_name = klass.get_name()

                # 检查是否匹配敏感模式
                for pattern in patterns:
                    if pattern in f"{class_name}->{method_name}":
                        findings.append({
                            "class": class_name,
                            "method": method_name,
                            "descriptor": method.get_descriptor()
                        })

        return findings

    def search_strings(self, apk, keyword: str) -> List[Dict]:
        """
        搜索字符串

        Args:
            apk: APK对象
            keyword: 搜索关键字

        Returns:
            [{file, strings}, ...]
        """
        results = []
        for klass in apk.get_classes():
            for method in klass.get_methods():
                for string in method.get_strings():
                    if keyword.lower() in string.lower():
                        results.append({
                            "class": klass.get_name(),
                            "method": method.get_name(),
                            "string": string
                        })
        return results

    def analyze_network_calls(self, apk) -> List[Dict]:
        """
        分析网络通信

        Returns:
            [{url, method, class, encryption}, ...]
        """
        # 分析HTTP URL
        network_patterns = ["http://", "https://", "HttpURL", "OkHttp", "Retrofit"]

        findings = []
        for klass in apk.get_classes():
            class_name = klass.get_name()
            for method in klass.get_methods():
                for string in method.get_strings():
                    for pattern in network_patterns:
                        if pattern in string:
                            findings.append({
                                "url": string if "http" in string else None,
                                "class": class_name,
                                "method": method.get_name()
                            })

        return findings