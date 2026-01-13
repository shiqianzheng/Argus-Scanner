"""
网络活动监控器
监控程序的网络连接行为
"""

import os
import re
import socket
import threading
import time
from typing import Dict, List, Any, Set, Optional
from pathlib import Path

from utils.logger import get_logger
from utils.helpers import read_file_content


class NetworkMonitor:
    """网络活动监控器 - 检测可疑网络连接"""
    
    def __init__(self, config):
        self.config = config
        self.logger = get_logger()
        
        # 可疑端口
        self.suspicious_ports = set(config.get('dynamic_analysis.network_monitor.suspicious_ports', [
            4444, 5555, 6666, 31337, 12345,  # 常见后门端口
            1234, 9999, 8888, 7777,  # 其他可疑端口
            22, 23, 3389,  # 远程访问端口
            135, 139, 445,  # Windows共享端口
        ]))
        
        # 可疑域名/IP模式
        self.suspicious_hosts = [
            r'(\d{1,3}\.){3}\d{1,3}',  # 直接IP地址
            r'(ngrok|serveo|localtunnel|pagekite)\.io',
            r'(pastebin|hastebin|paste\.ee)',
            r'(transfer\.sh|file\.io)',
            r'(dnslog|ceye|burpcollaborator)',
            r'\.onion$',  # Tor地址
            r'\.tk$|\.ml$|\.ga$|\.cf$',  # 免费域名
        ]
        
        # 已知恶意C2域名（示例）
        self.known_c2_domains = [
            'evil.com', 'malware.net', 'c2server.org'
        ]
        
        # 已知恶意IP范围（示例）
        self.known_malicious_ip_ranges = [
            # 这里可以添加已知的恶意IP范围
        ]
    
    def monitor(self, target: str, files: List[str]) -> Dict[str, Any]:
        """
        监控网络活动
        
        Args:
            target: 目标路径
            files: 文件列表
        
        Returns:
            监控结果
        """
        findings = []
        network_activity = []
        
        # 静态分析：扫描代码中的网络操作
        static_findings = self._analyze_network_code(files)
        findings.extend(static_findings)
        
        # 提取代码中的网络目标
        targets = self._extract_network_targets(files)
        network_activity.extend(targets)
        
        # 分析提取到的网络目标
        for target_info in targets:
            analysis = self._analyze_target(target_info)
            if analysis:
                findings.extend(analysis)
        
        return {
            'findings': findings,
            'network_activity': network_activity,
            'targets_found': len(targets)
        }
    
    def _analyze_network_code(self, files: List[str]) -> List[Dict]:
        """分析代码中的网络操作"""
        findings = []
        
        # 可疑网络模式
        patterns = [
            {
                'pattern': r'socket\.socket.*SOCK_STREAM',
                'title': 'TCP Socket创建',
                'severity': 'medium',
                'description': '代码创建TCP Socket连接'
            },
            {
                'pattern': r'socket\.socket.*SOCK_RAW',
                'title': '原始Socket创建',
                'severity': 'high',
                'description': '代码创建原始Socket，可能用于网络嗅探或攻击'
            },
            {
                'pattern': r'\.connect\s*\(\s*\([\'"][\d.]+[\'"]',
                'title': '直接IP连接',
                'severity': 'high',
                'description': '代码直接连接到IP地址，可能是C2服务器'
            },
            {
                'pattern': r'reverse.*shell|shell.*reverse',
                'title': '反向Shell关键字',
                'severity': 'critical',
                'description': '代码中包含反向Shell相关关键字'
            },
            {
                'pattern': r'bind.*shell|shell.*bind',
                'title': '绑定Shell关键字',
                'severity': 'critical',
                'description': '代码中包含绑定Shell相关关键字'
            },
            {
                'pattern': r'nc\s+-[el]|netcat.*-[el]',
                'title': 'Netcat命令',
                'severity': 'critical',
                'description': '代码调用netcat命令，可能用于建立后门'
            },
            {
                'pattern': r'urllib|requests\.get|http\.client|aiohttp',
                'title': 'HTTP请求库',
                'severity': 'low',
                'description': '代码使用HTTP请求库（需进一步分析目标URL）'
            },
            {
                'pattern': r'paramiko|fabric|ssh',
                'title': 'SSH连接',
                'severity': 'medium',
                'description': '代码包含SSH连接功能'
            },
            {
                'pattern': r'ftplib|pysftp',
                'title': 'FTP连接',
                'severity': 'medium',
                'description': '代码包含FTP连接功能'
            },
            {
                'pattern': r'smtplib|imaplib|poplib',
                'title': '邮件协议',
                'severity': 'medium',
                'description': '代码使用邮件协议，可能用于数据外传'
            },
            {
                'pattern': r'dns\.resolver|dnslib|dnspython',
                'title': 'DNS操作',
                'severity': 'medium',
                'description': '代码进行DNS操作，可能用于DNS隧道'
            },
        ]
        
        for file_path in files:
            try:
                content = read_file_content(file_path)
                if not content:
                    continue
                
                lines = content.split('\n')
                
                for pattern_info in patterns:
                    for i, line in enumerate(lines, 1):
                        if re.search(pattern_info['pattern'], line, re.IGNORECASE):
                            findings.append({
                                'id': 'NET-CODE-001',
                                'title': pattern_info['title'],
                                'severity': pattern_info['severity'],
                                'category': '网络安全',
                                'description': pattern_info['description'],
                                'recommendation': '审查此网络操作的目的',
                                'file': file_path,
                                'line': i,
                                'matched_line': line.strip()[:100],
                                'evidence': line.strip()[:100],
                                'analyzer': '网络监控器'
                            })
            
            except Exception as e:
                self.logger.debug(f"分析文件 {file_path} 时出错: {e}")
        
        return findings
    
    def _extract_network_targets(self, files: List[str]) -> List[Dict]:
        """从代码中提取网络目标（IP、域名、URL）"""
        targets = []
        
        # 匹配模式
        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        port_pattern = r':(\d{1,5})\b'
        url_pattern = r'https?://[^\s\'"<>]+'
        domain_pattern = r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b'
        
        for file_path in files:
            try:
                content = read_file_content(file_path)
                if not content:
                    continue
                
                lines = content.split('\n')
                
                for i, line in enumerate(lines, 1):
                    # 跳过注释
                    if line.strip().startswith('#') or line.strip().startswith('//'):
                        continue
                    
                    # 提取IP地址
                    for match in re.finditer(ip_pattern, line):
                        ip = match.group(1)
                        # 排除本地和保留IP
                        if not self._is_local_ip(ip):
                            port_match = re.search(ip + port_pattern, line)
                            port = int(port_match.group(1)) if port_match else None
                            targets.append({
                                'type': 'ip',
                                'value': ip,
                                'port': port,
                                'file': file_path,
                                'line': i
                            })
                    
                    # 提取URL
                    for match in re.finditer(url_pattern, line):
                        url = match.group()
                        targets.append({
                            'type': 'url',
                            'value': url,
                            'file': file_path,
                            'line': i
                        })
                    
                    # 提取域名
                    for match in re.finditer(domain_pattern, line):
                        domain = match.group(1)
                        # 排除常见的安全域名
                        if not self._is_safe_domain(domain):
                            targets.append({
                                'type': 'domain',
                                'value': domain,
                                'file': file_path,
                                'line': i
                            })
            
            except Exception as e:
                self.logger.debug(f"提取网络目标时出错: {e}")
        
        # 去重
        seen = set()
        unique_targets = []
        for t in targets:
            key = f"{t['type']}:{t['value']}"
            if key not in seen:
                seen.add(key)
                unique_targets.append(t)
        
        return unique_targets
    
    def _analyze_target(self, target_info: Dict) -> List[Dict]:
        """分析网络目标的安全性"""
        findings = []
        
        target_type = target_info['type']
        value = target_info['value']
        
        if target_type == 'ip':
            # 检查可疑IP
            if self._is_suspicious_ip(value):
                findings.append({
                    'id': 'NET-IP-001',
                    'title': '可疑IP地址',
                    'severity': 'high',
                    'category': '网络安全',
                    'description': f'代码连接到可疑IP地址: {value}',
                    'recommendation': '验证此IP地址的合法性',
                    'file': target_info['file'],
                    'line': target_info['line'],
                    'target': value,
                    'evidence': value,
                    'analyzer': '网络监控器'
                })
            
            # 检查可疑端口
            port = target_info.get('port')
            if port and port in self.suspicious_ports:
                findings.append({
                    'id': 'NET-PORT-001',
                    'title': '可疑端口',
                    'severity': 'high',
                    'category': '网络安全',
                    'description': f'代码连接到可疑端口: {value}:{port}',
                    'recommendation': '此端口常被恶意软件使用',
                    'file': target_info['file'],
                    'line': target_info['line'],
                    'target': f'{value}:{port}',
                    'evidence': f'{value}:{port}',
                    'analyzer': '网络监控器'
                })
        
        elif target_type == 'url':
            # 检查可疑URL
            for pattern in self.suspicious_hosts:
                if re.search(pattern, value, re.IGNORECASE):
                    findings.append({
                        'id': 'NET-URL-001',
                        'title': '可疑URL',
                        'severity': 'high',
                        'category': '网络安全',
                        'description': f'代码访问可疑URL: {value}',
                        'recommendation': '审查此URL的用途',
                        'file': target_info['file'],
                        'line': target_info['line'],
                        'target': value,
                        'evidence': value,
                        'analyzer': '网络监控器'
                    })
                    break
        
        elif target_type == 'domain':
            # 检查可疑域名
            for pattern in self.suspicious_hosts:
                if re.search(pattern, value, re.IGNORECASE):
                    findings.append({
                        'id': 'NET-DOMAIN-001',
                        'title': '可疑域名',
                        'severity': 'medium',
                        'category': '网络安全',
                        'description': f'代码连接到可疑域名: {value}',
                        'recommendation': '验证此域名的合法性',
                        'file': target_info['file'],
                        'line': target_info['line'],
                        'target': value,
                        'evidence': value,
                        'analyzer': '网络监控器'
                    })
                    break
        
        return findings
    
    def _is_local_ip(self, ip: str) -> bool:
        """检查是否为本地/保留IP"""
        local_ranges = [
            '127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.',
            '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
            '172.29.', '172.30.', '172.31.', '0.', '255.', '224.'
        ]
        return any(ip.startswith(r) for r in local_ranges)
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """检查是否为可疑IP"""
        # 这里可以添加更多检测逻辑
        # 例如查询威胁情报API
        return False
    
    def _is_safe_domain(self, domain: str) -> bool:
        """检查是否为已知安全域名"""
        safe_domains = [
            'google.com', 'github.com', 'microsoft.com', 'python.org',
            'pypi.org', 'npmjs.com', 'maven.org', 'golang.org',
            'stackoverflow.com', 'example.com', 'localhost'
        ]
        return any(domain.endswith(d) or domain == d for d in safe_domains)
