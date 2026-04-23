"""
Configuration
配置加载和管理
"""

import os
import yaml
from typing import Any, Dict, Optional


class Config:
    """配置管理类"""

    def __init__(self, config_file: str = None):
        self.config_file = config_file
        self.data: Dict[str, Any] = {}

        if config_file and os.path.exists(config_file):
            self.load(config_file)

    def load(self, config_file: str) -> bool:
        """
        加载配置文件

        Args:
            config_file: 配置文件路径

        Returns:
            是否成功
        """
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                self.data = yaml.safe_load(f) or {}
            self.config_file = config_file
            return True
        except Exception as e:
            print(f"Failed to load config: {e}")
            return False

    def save(self, config_file: str = None) -> bool:
        """
        保存配置文件

        Args:
            config_file: 配置文件路径

        Returns:
            是否成功
        """
        try:
            file_path = config_file or self.config_file
            with open(file_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.data, f, allow_unicode=True)
            return True
        except Exception as e:
            print(f"Failed to save config: {e}")
            return False

    def get(self, key: str, default: Any = None) -> Any:
        """
        获取配置值

        Args:
            key: 键（支持点号分隔，如 "app.name"）
            default: 默认值

        Returns:
            配置值
        """
        keys = key.split('.')
        value = self.data

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: Any):
        """
        设置配置值

        Args:
            key: 键
            value: 值
        """
        keys = key.split('.')
        data = self.data

        for k in keys[:-1]:
            if k not in data:
                data[k] = {}
            data = data[k]

        data[keys[-1]] = value

    def get_section(self, section: str) -> Dict:
        """
        获取配置节

        Args:
            section: 节名

        Returns:
            配置节字典
        """
        return self.get(section, {})

    def merge(self, config_file: str) -> bool:
        """
        合并另一个配置文件

        Args:
            config_file: 配置文件路径

        Returns:
            是否成功
        """
        other = Config(config_file)
        if other.data:
            self._merge_dict(self.data, other.data)
            return True
        return False

    def _merge_dict(self, base: Dict, override: Dict):
        """递归合并字典"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_dict(base[key], value)
            else:
                base[key] = value


def load_config(config_file: str) -> Config:
    """
    加载配置文件的便捷函数

    Args:
        config_file: 配置文件路径

    Returns:
        Config对象
    """
    return Config(config_file)