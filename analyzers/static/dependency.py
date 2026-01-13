"""
依赖检查器
分析项目依赖并与 OSV (Open Source Vulnerabilities) 数据库实时比对
"""

import os
import re
import json
import math
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

from utils.helpers import read_file_content
from utils.logger import get_logger

# 尝试导入requests，如果失败则使用urllib
try:
    import requests
    # 禁用 urllib3 的 InsecureRequestWarning，如果需要的話
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False


class DependencyChecker:
    """依赖检查器 - 检测依赖中的已知漏洞 (SCA)"""
    
    def __init__(self, config):
        self.config = config
        self.logger = get_logger()
        
        # 漏洞数据库 API (Batch)
        self.osv_batch_url = "https://api.osv.dev/v1/querybatch"
        
        # 生态系统映射
        self.ecosystem_map = {
            'python': 'PyPI',
            'java': 'Maven',
            'go': 'Go',
            'javascript': 'npm'
        }
        
    def analyze(self, files: List[str]) -> Dict[str, Any]:
        """分析依赖文件"""
        findings = []
        all_dependencies = []
        
        # 1. 解析所有依赖文件
        for file_path in files:
            # Python依赖文件
            if 'requirements' in file_path and file_path.endswith('.txt'):
                deps = self._parse_requirements_txt(file_path)
                all_dependencies.extend(deps)
            
            # Pipfile
            elif file_path.endswith('Pipfile'):
                deps = self._parse_pipfile(file_path)
                all_dependencies.extend(deps)
            
            # pyproject.toml
            elif file_path.endswith('pyproject.toml'):
                deps = self._parse_pyproject_toml(file_path)
                all_dependencies.extend(deps)
            
            # Java Maven pom.xml
            elif file_path.endswith('pom.xml'):
                deps = self._parse_pom_xml(file_path)
                all_dependencies.extend(deps)
            
            # Java Gradle build.gradle
            elif file_path.endswith('build.gradle'):
                deps = self._parse_build_gradle(file_path)
                all_dependencies.extend(deps)
            
            # Go go.mod
            elif file_path.endswith('go.mod'):
                deps = self._parse_go_mod(file_path)
                all_dependencies.extend(deps)
            
            # Node.js package.json
            elif file_path.endswith('package.json'):
                deps = self._parse_package_json(file_path)
                all_dependencies.extend(deps)
        
        # 2. 批量查询漏洞
        if all_dependencies:
            self.logger.info(f"提取到 {len(all_dependencies)} 个依赖项，正在查询 OSV 数据库...")
            vuln_findings = self._query_osv_batch(all_dependencies)
            findings.extend(vuln_findings)
        
        # 去重用于统计
        unique_deps = {f"{d['name']}@{d.get('version', 'unknown')}": d for d in all_dependencies}
        
        return {
            'analyzer': 'DependencyChecker',
            'dependencies_found': len(unique_deps),
            'findings': findings,
            'dependencies': list(unique_deps.values())
        }
    
    def _query_osv_batch(self, dependencies: List[Dict]) -> List[Dict]:
        """批量查询 OSV 数据库"""
        findings = []
        
        # 过滤掉版本未知的依赖，OSV 需要版本号才能准确查询 (虽然也支持仅包名，但太宽泛)
        valid_deps = [d for d in dependencies if d['version'] != 'unknown']
        
        if not valid_deps:
            return []

        # 分批处理，每批 50 个 (OSV API 限制或最佳实践)
        batch_size = 50
        total_batches = math.ceil(len(valid_deps) / batch_size)
        
        for i in range(total_batches):
            batch = valid_deps[i*batch_size : (i+1)*batch_size]
            queries = []
            
            for dep in batch:
                ecosystem = self.ecosystem_map.get(dep['language'], '')
                if not ecosystem:
                    continue
                    
                queries.append({
                    "package": {
                        "name": dep['name'],
                        "ecosystem": ecosystem
                    },
                    "version": dep['version']
                })
            
            if not queries:
                continue

            try:
                payload = {"queries": queries}
                results = []
                
                if HAS_REQUESTS:
                    try:
                        response = requests.post(self.config.get('sca.osv_url', self.osv_batch_url), json=payload, timeout=30)
                        if response.status_code == 200:
                            results = response.json().get('results', [])
                    except Exception as req_err:
                        self.logger.warning(f"OSV Request Error: {req_err}. Switching to urllib.")
                        # Fallback to urllib if requests fails
                        req = urllib.request.Request(
                            self.osv_batch_url,
                            data=json.dumps(payload).encode(),
                            headers={'Content-Type': 'application/json', 'User-Agent': 'Argus-Scanner/1.0'}
                        )
                        with urllib.request.urlopen(req, timeout=30) as response:
                             results = json.loads(response.read()).get('results', [])
                else:
                    req = urllib.request.Request(
                        self.osv_batch_url,
                        data=json.dumps(payload).encode(),
                        headers={'Content-Type': 'application/json', 'User-Agent': 'Argus-Scanner/1.0'}
                    )
                    with urllib.request.urlopen(req, timeout=30) as response:
                        results = json.loads(response.read()).get('results', [])
                
                # 处理结果 (results 数组与 queries 数组一一对应)
                for idx, result in enumerate(results):
                    vulns = result.get('vulns', [])
                    if vulns:
                        dep = batch[idx]
                        for vuln in vulns:
                            findings.append(self._format_finding(dep, vuln))
                            
            except Exception as e:
                self.logger.error(f"OSV Batch Query 出错: {e}")
                
        return findings

    def _format_finding(self, dep: Dict, vuln: Dict) -> Dict:
        """格式化漏洞发现"""
        vuln_id = vuln.get('id', 'UNKNOWN')
        summary = vuln.get('summary', 'No summary provided')
        details = vuln.get('details', '')
        
        # 确定严重程度
        # OSV 通常只提供 DATABASE_SPECIFIC 或 CVSS，需要尝试提取
        # 若无 CVSS，默认为 HIGH 以引起注意
        severity = 'medium' # 默认
        
        # 尝试从 severity 字段提取 (CVSS v3)
        # 格式通常是 [{"type": "CVSS_V3", "score": "CVSS:3.1/..."}]
        severities = vuln.get('severity', [])
        if severities:
            for s in severities:
                if s.get('type') == 'CVSS_V3':
                    # 这里简化处理，不计算 CVSS Score，直接设为 high，后续可完善
                    severity = 'high' 
                    break
        
        # 提取受影响版本范围作为参考
        affected = vuln.get('affected', [])
        affected_versions = []
        for a in affected:
            ranges = a.get('ranges', [])
            for r in ranges:
                events = r.get('events', [])
                # 简单拼接一下
                ver_str = ", ".join([f"{k} {v}" for e in events for k, v in e.items()])
                affected_versions.append(ver_str)
        
        return {
            'id': f'SCA-{vuln_id}',
            'title': f'依赖漏洞: {dep["name"]} ({vuln_id})',
            'severity': severity,
            'category': 'vulnerable_dependency',
            'description': f"依赖包 {dep['name']} (版本 {dep['version']}) 存在已知漏洞。\n{summary}\n受影响版本: {'; '.join(affected_versions)[:100]}...",
            'recommendation': f"升级 {dep['name']} 到修复版本。详情: https://osv.dev/vulnerability/{vuln_id}",
            'file': dep['source'],
            'line': 1, # 默认为文件头，因为无法精确到行
            'dependency': dep['name'],
            'version': dep['version'],
            'cve': vuln_id,
            'analyzer': 'OSV-Scanner'
        }

    # ================= 解析器逻辑 =================

    def _parse_requirements_txt(self, file_path: str) -> List[Dict]:
        """解析requirements.txt"""
        dependencies = []
        try:
            content = read_file_content(file_path)
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('-'):
                    # 匹配 name==version (简单版)
                    # 处理 requests==2.20.0
                    if '==' in line:
                        parts = line.split('==')
                        name = parts[0].strip().lower()
                        ver = parts[1].split()[0].strip()
                        dependencies.append({
                            'name': name,
                            'version': ver,
                            'language': 'python',
                            'source': file_path
                        })
        except Exception as e:
            self.logger.error(f"解析 {file_path} 时出错: {e}")
        return dependencies
    
    def _parse_pipfile(self, file_path: str) -> List[Dict]:
        """解析Pipfile (简化版)"""
        dependencies = []
        try:
            content = read_file_content(file_path)
            in_packages = False
            for line in content.split('\n'):
                line = line.strip()
                if line == '[packages]':
                    in_packages = True
                    continue
                elif line.startswith('['):
                    in_packages = False
                    continue
                
                if in_packages and '=' in line:
                    parts = line.split('=', 1)
                    name = parts[0].strip().strip('"\'')
                    version = parts[1].strip().strip('"\'')
                    if version != '*':
                        dependencies.append({
                            'name': name.lower(),
                            'version': version,
                            'language': 'python',
                            'source': file_path
                        })
        except Exception:
            pass
        return dependencies

    def _parse_pyproject_toml(self, file_path: str) -> List[Dict]:
        """解析pyproject.toml"""
        dependencies = []
        try:
            content = read_file_content(file_path)
            match = re.search(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if match:
                for dep in re.findall(r'"([^"]+)"', match.group(1)):
                    if '==' in dep:
                        parts = dep.split('==')
                        dependencies.append({
                            'name': parts[0].strip().lower(),
                            'version': parts[1].strip(),
                            'language': 'python',
                            'source': file_path
                        })
        except Exception:
            pass
        return dependencies

    def _parse_pom_xml(self, file_path: str) -> List[Dict]:
        """解析Maven pom.xml"""
        dependencies = []
        try:
            content = read_file_content(file_path)
            # 简化 regex
            deps = re.findall(
                r'<dependency>.*?<artifactId>([^<]+)</artifactId>.*?(?:<version>([^<]+)</version>)?.*?</dependency>',
                content, re.DOTALL
            )
            for artifact_id, version in deps:
                if version and '$' not in version: 
                    # Maven 包名通常是 GroupId:ArtifactId
                    # 这里简化为 artifactId，OSV 可能查不到，但这是暂时的妥协
                    dependencies.append({
                        'name': artifact_id.strip(), 
                        'version': version.strip(),
                        'language': 'java',
                        'source': file_path
                    })
        except Exception:
            pass
        return dependencies

    def _parse_build_gradle(self, file_path: str) -> List[Dict]:
        return []

    def _parse_go_mod(self, file_path: str) -> List[Dict]:
        """解析 go.mod"""
        dependencies = []
        try:
            content = read_file_content(file_path)
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('//') or line.startswith('module') or line.startswith('go '):
                    continue
                parts = line.split()
                if len(parts) >= 2 and '.' in parts[0] and parts[1].startswith('v'):
                    dependencies.append({
                        'name': parts[0],
                        'version': parts[1],
                        'language': 'go',
                        'source': file_path
                    })
        except Exception:
            pass
        return dependencies
        
    def _parse_package_json(self, file_path: str) -> List[Dict]:
        """解析 package.json"""
        dependencies = []
        try:
            content = read_file_content(file_path)
            data = json.loads(content)
            for section in ['dependencies', 'devDependencies']:
                if section in data:
                    for name, ver in data[section].items():
                        clean_ver = ver.lstrip('^~v')
                        if clean_ver and clean_ver[0].isdigit():
                             dependencies.append({
                                'name': name,
                                'version': clean_ver,
                                'language': 'javascript',
                                'source': file_path
                            })
        except Exception:
            pass
        return dependencies
