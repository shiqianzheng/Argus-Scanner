"""
文件活动监控器
监控程序的文件操作行为
"""

import os
import re
from typing import Dict, List, Any, Set
from pathlib import Path

from utils.logger import get_logger
from utils.helpers import read_file_content


class FileMonitor:
    """文件活动监控器 - 检测可疑文件操作"""
    
    def __init__(self, config):
        self.config = config
        self.logger = get_logger()
        
        # 敏感文件路径
        self.sensitive_paths = config.get('dynamic_analysis.file_monitor.sensitive_paths', [
            # Linux敏感文件
            '/etc/passwd', '/etc/shadow', '/etc/sudoers',
            '/etc/ssh/', '/root/.ssh/', '~/.ssh/',
            '/etc/crontab', '/var/spool/cron/',
            '/etc/hosts', '/etc/resolv.conf',
            '/etc/ld.so.preload', '/etc/ld.so.conf',
            '/proc/self/', '/proc/1/',
            # Windows敏感文件
            'C:\\Windows\\System32\\config\\',
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
            'C:\\Users\\*\\AppData\\',
            # 通用敏感路径
            '.bashrc', '.bash_profile', '.profile',
            '.zshrc', '.config/',
            'id_rsa', 'id_dsa', 'known_hosts',
        ])
        
        # 可疑文件操作模式
        self.suspicious_operations = [
            {
                'pattern': r'open\s*\([^)]*["\'][wab]["\']',
                'title': '文件写入操作',
                'severity': 'medium',
                'description': '代码以写入模式打开文件'
            },
            {
                'pattern': r'chmod\s*\([^)]*0?7[0-7][0-7]',
                'title': '可执行权限设置',
                'severity': 'high',
                'description': '代码设置文件为可执行权限'
            },
            {
                'pattern': r'os\.remove|os\.unlink|shutil\.rmtree',
                'title': '文件删除操作',
                'severity': 'medium',
                'description': '代码删除文件或目录'
            },
            {
                'pattern': r'shutil\.copy|shutil\.move|os\.rename',
                'title': '文件复制/移动',
                'severity': 'low',
                'description': '代码复制或移动文件'
            },
            {
                'pattern': r'tempfile\.|/tmp/|\\temp\\',
                'title': '临时文件操作',
                'severity': 'low',
                'description': '代码操作临时文件'
            },
            {
                'pattern': r'base64.*write|write.*base64',
                'title': 'Base64数据写入',
                'severity': 'high',
                'description': '代码将Base64编码数据写入文件，可能是恶意负载'
            },
            {
                'pattern': r'zipfile|tarfile|gzip|bz2',
                'title': '压缩文件操作',
                'severity': 'low',
                'description': '代码操作压缩文件'
            },
            {
                'pattern': r'ctypes\.windll|win32api|winreg',
                'title': 'Windows系统操作',
                'severity': 'high',
                'description': '代码直接操作Windows系统API'
            },
        ]
        
        # 危险文件扩展名
        self.dangerous_extensions = [
            '.exe', '.dll', '.so', '.dylib',  # 可执行文件
            '.bat', '.cmd', '.ps1', '.vbs', '.js',  # 脚本文件
            '.sh', '.bash', '.zsh',  # Shell脚本
            '.pem', '.key', '.cer', '.crt',  # 证书/密钥
            '.db', '.sqlite', '.sql',  # 数据库
        ]
    
    def monitor(self, target: str, files: List[str]) -> Dict[str, Any]:
        """
        监控文件操作
        
        Args:
            target: 目标路径
            files: 文件列表
        
        Returns:
            监控结果
        """
        findings = []
        file_operations = []
        
        # 分析代码中的文件操作
        for file_path in files:
            try:
                content = read_file_content(file_path)
                if not content:
                    continue
                
                # 检测文件操作模式
                operation_findings = self._analyze_file_operations(file_path, content)
                findings.extend(operation_findings)
                
                # 提取文件路径
                paths = self._extract_file_paths(file_path, content)
                file_operations.extend(paths)
                
                # 分析提取的路径
                path_findings = self._analyze_paths(paths)
                findings.extend(path_findings)
            
            except Exception as e:
                self.logger.debug(f"分析文件 {file_path} 时出错: {e}")
        
        return {
            'findings': findings,
            'file_operations': file_operations,
            'paths_found': len(file_operations)
        }
    
    def _analyze_file_operations(self, file_path: str, content: str) -> List[Dict]:
        """分析文件操作模式"""
        findings = []
        lines = content.split('\n')
        
        for pattern_info in self.suspicious_operations:
            for i, line in enumerate(lines, 1):
                if re.search(pattern_info['pattern'], line, re.IGNORECASE):
                    findings.append({
                        'id': 'FILE-OP-001',
                        'title': pattern_info['title'],
                        'severity': pattern_info['severity'],
                        'category': '文件系统',
                        'description': pattern_info['description'],
                        'recommendation': '审查此文件操作的目的',
                        'file': file_path,
                        'line': i,
                        'matched_line': line.strip()[:100],
                        'evidence': line.strip()[:100],
                        'analyzer': '文件监控器'
                    })
        
        return findings
    
    def _extract_file_paths(self, source_file: str, content: str) -> List[Dict]:
        """从代码中提取文件路径"""
        paths = []
        lines = content.split('\n')
        
        # 文件路径模式
        path_patterns = [
            # Unix路径
            r'["\'](/[a-zA-Z0-9_./\-~]+)["\']',
            # Windows路径
            r'["\']([A-Za-z]:\\[^"\']+)["\']',
            # 相对路径
            r'["\'](\.\./[^"\']+)["\']',
            r'["\'](\./[^"\']+)["\']',
        ]
        
        for i, line in enumerate(lines, 1):
            # 跳过注释
            if line.strip().startswith('#') or line.strip().startswith('//'):
                continue
            
            for pattern in path_patterns:
                for match in re.finditer(pattern, line):
                    path = match.group(1)
                    # 过滤掉URL
                    if not path.startswith('http'):
                        paths.append({
                            'path': path,
                            'source_file': source_file,
                            'line': i,
                            'context': line.strip()[:100]
                        })
        
        return paths
    
    def _analyze_paths(self, paths: List[Dict]) -> List[Dict]:
        """分析提取的文件路径"""
        findings = []
        
        for path_info in paths:
            path = path_info['path']
            
            # 检查敏感路径
            for sensitive in self.sensitive_paths:
                if sensitive in path or path in sensitive:
                    findings.append({
                        'id': 'FILE-PATH-001',
                        'title': '访问敏感文件路径',
                        'severity': 'high',
                        'category': '文件系统',
                        'description': f'代码访问敏感路径: {path}',
                        'recommendation': '确认此文件访问的必要性',
                        'file': path_info['source_file'],
                        'line': path_info['line'],
                        'target_path': path,
                        'evidence': path,
                        'analyzer': '文件监控器'
                    })
                    break
            
            # 检查危险扩展名
            for ext in self.dangerous_extensions:
                if path.lower().endswith(ext):
                    severity = 'high' if ext in ['.exe', '.dll', '.so'] else 'medium'
                    findings.append({
                        'id': 'FILE-EXT-001',
                        'title': f'操作危险文件类型 ({ext})',
                        'severity': severity,
                        'category': '文件系统',
                        'description': f'代码操作危险类型文件: {path}',
                        'recommendation': '审查此文件操作的安全性',
                        'file': path_info['source_file'],
                        'line': path_info['line'],
                        'target_path': path,
                        'evidence': path,
                        'analyzer': '文件监控器'
                    })
                    break
            
            # 检查路径遍历
            if '..' in path:
                findings.append({
                    'id': 'FILE-TRAVERSAL-001',
                    'title': '路径遍历风险',
                    'severity': 'medium',
                    'category': '文件系统',
                    'description': f'代码使用相对路径遍历: {path}',
                    'recommendation': '确保路径已经过验证和规范化',
                    'file': path_info['source_file'],
                    'line': path_info['line'],
                    'target_path': path,
                    'evidence': path,
                    'analyzer': '文件监控器'
                })
            
            # 检查隐藏文件操作
            path_parts = path.replace('\\', '/').split('/')
            for part in path_parts:
                if part.startswith('.') and part not in ['.', '..']:
                    findings.append({
                        'id': 'FILE-HIDDEN-001',
                        'title': '操作隐藏文件/目录',
                        'severity': 'medium',
                        'category': '文件系统',
                        'description': f'代码操作隐藏文件或目录: {path}',
                        'recommendation': '确认操作隐藏文件的必要性',
                        'file': path_info['source_file'],
                        'line': path_info['line'],
                        'target_path': path,
                        'evidence': path,
                        'analyzer': '文件监控器'
                    })
                    break
        
        return findings
