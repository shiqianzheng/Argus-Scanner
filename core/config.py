"""
配置管理模块
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional

class Config:
    """配置管理类"""
    
    DEFAULT_CONFIG = {
        'system': {
            'name': 'Argus-Scanner',
            'version': '1.0.0',
            'log_level': 'INFO',
            'output_dir': './reports',
            'temp_dir': './temp'
        },
        'languages': ['python', 'java', 'go', 'c', 'cpp'],
        'static_analysis': {
            'enabled': True,
            'pattern_matching': {'enabled': True},
            'dataflow_analysis': {'enabled': True, 'max_depth': 10},
            'controlflow_analysis': {'enabled': True},
            'taint_analysis': {'enabled': True},
            'dependency_check': {'enabled': True}
        },
        'dynamic_analysis': {
            'enabled': True,
            'timeout': 10
        }
    }
    
    def __init__(self, config_path: Optional[str] = None):
        """初始化配置"""
        self._config = self.DEFAULT_CONFIG.copy()
        
        if config_path and os.path.exists(config_path):
            self._load_from_file(config_path)
        else:
            # 尝试从默认位置加载
            default_paths = [
                'config.yaml',
                'config.yml',
                os.path.join(os.path.dirname(__file__), '..', 'config.yaml')
            ]
            for path in default_paths:
                if os.path.exists(path):
                    self._load_from_file(path)
                    break
    
    def _load_from_file(self, path: str):
        """从文件加载配置"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                file_config = yaml.safe_load(f)
                if file_config:
                    self._merge_config(self._config, file_config)
        except Exception as e:
            print(f"警告: 无法加载配置文件 {path}: {e}")
    
    def _merge_config(self, base: Dict, override: Dict):
        """递归合并配置"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值，支持点号分隔的键"""
        keys = key.split('.')
        value = self._config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default
        return value
    
    def set(self, key: str, value: Any):
        """设置配置值"""
        keys = key.split('.')
        config = self._config
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value
    
    @property
    def static_analysis_enabled(self) -> bool:
        return self.get('static_analysis.enabled', True)
    
    @property
    def dynamic_analysis_enabled(self) -> bool:
        return self.get('dynamic_analysis.enabled', True)
    
    @property
    def supported_languages(self) -> list:
        return self.get('languages', ['python', 'java', 'go', 'c', 'cpp'])
    
    @property
    def output_dir(self) -> str:
        return self.get('system.output_dir', './reports')
    
    def to_dict(self) -> Dict:
        """导出为字典"""
        return self._config.copy()
