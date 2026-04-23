"""
Constants
常量定义
"""

from enum import Enum


class RiskLevel(str, Enum):
    """风险等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"
    UNKNOWN = "unknown"

    @classmethod
    def from_score(cls, score: float) -> "RiskLevel":
        """根据评分返回风险等级"""
        if score >= 80:
            return cls.CRITICAL
        elif score >= 60:
            return cls.HIGH
        elif score >= 40:
            return cls.MEDIUM
        elif score >= 20:
            return cls.LOW
        else:
            return cls.NONE


class Severity(str, Enum):
    """严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FileType(str, Enum):
    """文件类型"""
    APK = "apk"
    DEX = "dex"
    JAR = "jar"
    SMALI = "smali"
    JAVA = "java"
    XML = "xml"
    ARSC = "arsc"
    SO = "so"


class ComponentType(str, Enum):
    """组件类型"""
    ACTIVITY = "activity"
    SERVICE = "service"
    RECEIVER = "receiver"
    PROVIDER = "provider"


class PermissionCategory(str, Enum):
    """权限类别"""
    DANGEROUS = "dangerous"
    NORMAL = "normal"
    SIGNATURE = "signature"


# 常见危险权限列表
DANGEROUS_PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
]

# 常见敏感API模式
SENSITIVE_API_PATTERNS = [
    "Landroid/telephony/TelephonyManager;->getDeviceId",
    "Landroid/telephony/TelephonyManager;->getSimSerialNumber",
    "Landroid/telephony/SmsManager;->sendTextMessage",
    "Landroid/location/LocationManager;->getLastKnownLocation",
    "Landroid/hardware/Camera;->open",
    "Landroid/media/AudioRecord;->startRecording",
    "Ljavax/crypto/Cipher;->getInstance",
    "Ljava/security/MessageDigest;->getInstance",
    "Landroid/webkit/WebView;->loadUrl",
    "Ljava/lang/Runtime;->exec",
]