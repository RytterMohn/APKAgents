"""
Androguard wrapper.
"""

from typing import Dict, List

from .base import BaseTool


class AndroguardWrapper(BaseTool):
    """Small compatibility layer over androguard."""

    def __init__(self, tool_path: str = None):
        self.androguard = None
        self.apk = None
        self.tool_path = tool_path or self._get_default_path()
        self._check_installation()

    def _get_default_path(self) -> str:
        return "python"

    def _get_version_flag(self) -> str:
        return "-m"

    def is_available(self) -> bool:
        try:
            import androguard  # noqa: F401
            return True
        except ImportError:
            return False

    def _check_installation(self):
        try:
            from androguard.misc import AnalyzeAPK  # noqa: F401
        except ImportError:
            raise ImportError("androguard not installed. Run: pip install androguard")

    def load_apk(self, apk_path: str):
        from androguard.core.bytecodes.apk import APK

        self.apk = APK(apk_path)
        return self.apk

    def get_basic_info(self, apk) -> Dict:
        return {
            "package": apk.get_package(),
            "version": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
        }

    def get_permissions(self, apk) -> List[str]:
        return apk.get_permissions()

    def get_components(self, apk) -> Dict:
        return {
            "activities": apk.get_activities(),
            "services": apk.get_services(),
            "receivers": apk.get_receivers(),
            "providers": apk.get_providers(),
        }

    def get_activities(self, apk) -> List[Dict]:
        return [self._build_component_info(apk, "activity", activity) for activity in apk.get_activities()]

    def get_services(self, apk) -> List[Dict]:
        return [self._build_component_info(apk, "service", service) for service in apk.get_services()]

    def get_receivers(self, apk) -> List[Dict]:
        return [self._build_component_info(apk, "receiver", receiver) for receiver in apk.get_receivers()]

    def get_providers(self, apk) -> List[Dict]:
        return [self._build_component_info(apk, "provider", provider) for provider in apk.get_providers()]

    def _build_component_info(self, apk, tag_name: str, component_name: str) -> Dict:
        exported = self._get_manifest_attribute(apk, tag_name, component_name, "exported")
        permission = self._get_manifest_attribute(apk, tag_name, component_name, "permission")
        return {
            "name": component_name,
            "exported": str(exported).lower() == "true" if exported is not None else False,
            "permission": permission or "",
        }

    def _get_manifest_attribute(self, apk, tag_name: str, component_name: str, attribute: str):
        try:
            return apk.get_attribute_value(tag_name, attribute, name=component_name)
        except Exception:
            return None

    def find_sensitive_apis(self, apk, patterns: List[str], decompiler=None) -> List[Dict]:
        if not hasattr(apk, "get_classes"):
            return []

        findings = []
        for klass in apk.get_classes():
            for method in klass.get_methods():
                method_name = method.get_name()
                class_name = klass.get_name()
                full_name = f"{class_name}->{method_name}"
                for pattern in patterns:
                    if pattern in full_name:
                        findings.append(
                            {
                                "class": class_name,
                                "method": method_name,
                                "descriptor": method.get_descriptor(),
                            }
                        )
        return findings

    def search_strings(self, apk, keyword: str) -> List[Dict]:
        if not hasattr(apk, "get_classes"):
            return []

        results = []
        for klass in apk.get_classes():
            for method in klass.get_methods():
                for value in method.get_strings():
                    if keyword.lower() in value.lower():
                        results.append(
                            {
                                "class": klass.get_name(),
                                "method": method.get_name(),
                                "string": value,
                            }
                        )
        return results

    def analyze_network_calls(self, apk) -> List[Dict]:
        if not hasattr(apk, "get_classes"):
            return []

        findings = []
        network_patterns = ["http://", "https://", "HttpURL", "OkHttp", "Retrofit"]
        for klass in apk.get_classes():
            for method in klass.get_methods():
                for value in method.get_strings():
                    for pattern in network_patterns:
                        if pattern in value:
                            findings.append(
                                {
                                    "url": value if "http" in value else None,
                                    "class": klass.get_name(),
                                    "method": method.get_name(),
                                }
                            )
        return findings
