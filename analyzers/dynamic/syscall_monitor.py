"""
系统调用监控器
监控程序运行时的系统调用行为 (基于 Falco-lite 规则)
"""

import os
import sys
import subprocess
import threading
import time
import re
import platform
import yaml
from typing import Dict, List, Any, Optional
from pathlib import Path

from utils.logger import get_logger
from analyzers.dynamic.sandbox import Sandbox

class SyscallMonitor:
    """系统调用监控器 - 基于规则实时监控行为"""
    
    def __init__(self, config, sandbox_manager=None):
        self.config = config
        self.logger = get_logger()
        self.platform = platform.system().lower()
        self.sandbox = sandbox_manager # 使用共享的沙箱管理器
        self.rules = self._load_rules()
        
    def _load_rules(self) -> List[Dict]:
        """加载动态检测规则"""
        # analyzers/dynamic -> Argus-Scanner/rules
        current_dir = Path(os.path.dirname(__file__))
        rules_path = current_dir.parent.parent / 'rules' / 'dynamic_rules.yaml'
        
        rules = []
        try:
            if rules_path.exists():
                with open(rules_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if data and 'rules' in data:
                        rules = data['rules']
                        self.logger.info(f"成功加载 {len(rules)} 条动态监控规则")
            else:
                self.logger.warning(f"动态规则文件不存在: {rules_path}")
        except Exception as e:
            self.logger.error(f"加载动态规则失败: {e}")
            
        # 预编译正则
        for rule in rules:
            if 'pattern' in rule:
                try:
                    rule['regex_compiled'] = re.compile(rule['pattern'])
                except re.error as e:
                    self.logger.error(f"动态规则 {rule['id']} 正则编译失败: {e}")
        return rules
    
    def monitor(self, target: str, files: List[str], exec_cmd: str = None) -> Dict[str, Any]:
        """监控目标程序的系统调用"""
        
        # 0. 预检: 检查 Docker 是否可用
        if not self.sandbox or not self.sandbox.is_available():
            self.logger.warning("Docker 服务不可用，跳过动态系统调用分析 (SyscallMonitor)")
            return {
                'analyzer': 'SyscallMonitor',
                'executed_command': None,
                'findings': [],
                'log_snippet': [],
                'error': 'Docker unavailable'
            }

        # 确定可执行文件或脚本
        executable = self._find_executable(target, files, exec_cmd=exec_cmd)
        
        if not executable:
            self.logger.info("未找到可执行文件，跳过系统调用监控")
            return {
                'analyzer': 'SyscallMonitor',
                'executed_command': None,
                'findings': [],
                'log_snippet': []
            }

        # 优先使用 Docker Sandbox
<<<<<<< Updated upstream
<<<<<<< Updated upstream
        sandbox_enabled = self.config.get('dynamic_analysis.sandbox_enabled', True) or \
                         self.config.get('dynamic_analysis.sandbox.enabled', True)
        if sandbox_enabled and self.sandbox.is_available():
=======
        if self.config.get('dynamic_analysis.sandbox.enabled', True):
>>>>>>> Stashed changes
=======
        if self.config.get('dynamic_analysis.sandbox.enabled', True):
>>>>>>> Stashed changes
            self.logger.info(f"使用 Docker Sandbox 执行: {executable['cmd']}")
            return self._monitor_with_sandbox(target, executable, files)
        
        # 本地回退 (仅在 Linux 下且 unsafe_mode 开启)
        if self.platform != 'linux':
            self.logger.warning("本地系统调用监控仅支持 Linux (strace)")
            return {'analyzer': 'SyscallMonitor', 'error': 'Not supported on non-Linux platform without Docker'}
            
        if not self.config.get('dynamic_analysis.allow_unsafe_execution', False):
            self.logger.warning("未开启不安全执行模式，且 Docker 不可用，跳过动态分析")
            return {'analyzer': 'SyscallMonitor', 'error': 'Unsafe execution disabled and Docker unavailable'}

        return {'analyzer': 'SyscallMonitor', 'error': 'Local execution not implemented, please use Docker or Sandbox'}

    def _monitor_with_sandbox(self, target: str, executable: Dict, files: List[str]) -> Dict[str, Any]:
        """使用 Sandbox 执行并分析"""
        
<<<<<<< Updated upstream
        # 0. 可选：安装依赖（如果配置启用且项目需要）
        language = executable.get('type', 'python')
        project_path = executable.get('path')
        
        # 确定项目根目录（用于依赖安装）
        if project_path:
            project_root = project_path if os.path.isdir(project_path) else os.path.dirname(project_path)
        else:
            project_root = None
        
        # 检查是否需要安装依赖
        auto_install = self.config.get('dynamic_analysis.auto_install_dependencies', False)
        if auto_install and project_root and language in ['python', 'java', 'go']:
            self.logger.info(f"尝试自动安装 {language} 项目依赖...")
            install_result = self.sandbox.install_dependencies(project_root, language)
            if install_result.get('status') == 'success':
                self.logger.info(f"依赖安装成功 (耗时 {install_result.get('duration', 0):.2f}s)")
            elif install_result.get('status') == 'failed':
                self.logger.warning(f"依赖安装失败，将继续执行: {install_result.get('logs', '')[:200]}")
            # skipped 或 error 时继续执行，不中断
        
        # 1. 在 Sandbox 中运行（带超时）
        timeout = self.config.get('dynamic_analysis.timeout', 10)
        result = self.sandbox.run(executable, files, timeout=timeout)
=======
        # 1. 在 Sandbox 中运行
        # 使用 shared sandbox manager
        result = self.sandbox.run_analysis_command(target, executable)
<<<<<<< Updated upstream
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes
        
        if result.get('error'):
            return {
                'analyzer': 'SyscallMonitor',
                'error': result['error'],
                'findings': [],
                'executed_command': executable.get('cmd')
            }
            
        strace_log = result.get('strace_log', '')
        strace_log_file = result.get('strace_log_file')
        timed_out = result.get('timed_out', False)
        execution_time = result.get('execution_time', 0)
        
        # 检查是否超时
        if timed_out:
            self.logger.warning(f"执行超时（{timeout}秒），已强制终止")
            # 即使超时，也尝试分析已有的 strace 日志
        
        # 检查 strace 日志是否为空
        if not strace_log or not strace_log.strip():
            warning_msg = 'strace log is empty'
            if timed_out:
                warning_msg = 'strace log is empty (execution timed out)'
            self.logger.warning("strace 日志为空，可能是程序执行时间过短或 strace 未正确记录")
            return {
                'analyzer': 'SyscallMonitor',
                'executed_command': executable.get('cmd'),
                'exit_code': result.get('exit_code'),
                'findings': [],
                'log_snippet': [],
                'strace_log_file': strace_log_file,
                'timed_out': timed_out,
                'execution_time': execution_time,
                'warning': warning_msg
            }
        
        # 2. 分析 strace 日志
        findings = self._analyze_strace_log(strace_log)
        
        # 3. 记录日志文件路径
        if strace_log_file:
            self.logger.info(f"strace 日志文件: {strace_log_file}")
        
        return {
            'analyzer': 'SyscallMonitor',
            'executed_command': executable.get('cmd'),
            'exit_code': result.get('exit_code'),
            'findings': findings,
            'log_snippet': strace_log.split('\n')[:20] if strace_log else [],
            'strace_log_file': strace_log_file,
            'timed_out': timed_out,
            'execution_time': round(execution_time, 2)
        }

    def _analyze_strace_log(self, log_content: str) -> List[Dict]:
        """基于规则分析 strace 日志"""
        findings = []
        
        # 按行分析
        for line in log_content.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            for rule in self.rules:
                regex = rule.get('regex_compiled')
                if not regex:
                    continue
                    
                match = regex.search(line)
                if match:
                    # 检查排除项
                    if self._is_excluded(rule, match):
                        continue
                        
                    findings.append({
                        'id': rule['id'],
                        'title': rule['title'],
                        'severity': rule['severity'],
                        'category': rule['category'],
                        'description': rule['description'],
                        'evidence': line,
                        'analyzer': 'FalcoLiteMonitor' # Rename for clarity
                    })
                    # 一行匹配一个规则即可，避免并报
                    break
                    
        return findings

    def _is_excluded(self, rule: Dict, match: re.Match) -> bool:
        """检查是否在排除列表中"""
        groups = match.groupdict()
        
        # IP 排除
        if 'ip' in groups and 'exclude_ips' in rule:
            if groups['ip'] in rule['exclude_ips']:
                return True
                
        # Port 排除
        if 'port' in groups and 'exclude_ports' in rule:
            try:
                port = int(groups['port'])
                if port in rule['exclude_ports']:
                    return True
            except ValueError:
                pass
                
        return False

    def _find_executable(self, target: str, files: List[str], exec_cmd: str = None) -> Optional[Dict]:
        """确定入口点"""
        # 优先使用用户指定的命令
        if exec_cmd:
            self.logger.info(f"使用手动指定的执行命令: {exec_cmd}")
            return {'type': 'custom', 'path': target, 'cmd': exec_cmd}

        target_path = Path(target)
        if target_path.is_file():
            ext = target_path.suffix.lower()
            if ext == '.py':
                return {'type': 'python', 'path': target, 'cmd': f'python {Path(target).name}'}
            elif ext == '.go':
                return {'type': 'go', 'path': target, 'cmd': f'go run {Path(target).name}'}
            elif ext == '.c':
                # 沙箱中的 Wrapper 脚本会处理编译，这里传递原始命令
                return {'type': 'c', 'path': target, 'cmd': f'gcc {Path(target).name} -o app && ./app'}
            elif ext == '.java':
                 # Java 若无明确类名较难处理，此处做简单假设
                 return {'type': 'java', 'path': target, 'cmd': f'javac {Path(target).name} && java {Path(target).stem}'}
        
<<<<<<< Updated upstream
<<<<<<< Updated upstream
        # 目录扫描 - 使用项目根目录（target）作为 path，而不是单个文件
        target_path = Path(target)
        project_root = str(target_path) if target_path.is_dir() else str(target_path.parent)
        
=======
=======
>>>>>>> Stashed changes
        # 1. 优先检测 Spring Boot 多模块项目入口
        spring_boot_entry = self._find_spring_boot_entry(target, files)
        if spring_boot_entry:
            return spring_boot_entry

        # 2. 检测 Python Django 多模块项目入口 (NEW)
        django_entry = self._find_django_entry(target, files)
        if django_entry:
            return django_entry

        # 3. 目录扫描 (现有逻辑)
<<<<<<< Updated upstream
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes
        for f in files:
            p = Path(f)
            if p.name == 'main.py':
                return {'type': 'python', 'path': project_root, 'cmd': 'python main.py'}
            if p.name == 'app.py':
                return {'type': 'python', 'path': project_root, 'cmd': 'python app.py'}
            if p.name == 'go.mod':
                return {'type': 'go', 'path': project_root, 'cmd': 'go run .'}
            if p.name == 'pom.xml':
                self.logger.info("检测到 Maven 项目，推荐使用: mvn spring-boot:run")
<<<<<<< Updated upstream
<<<<<<< Updated upstream
                return {'type': 'java', 'path': project_root, 'cmd': 'mvn spring-boot:run'}
=======
=======
>>>>>>> Stashed changes
                # 如果是单体项目，根目录运行即可；如果是多模块且未找到Spring Boot入口，这也是一种兜底
                return {'type': 'java', 'path': f, 'cmd': 'mvn spring-boot:run'}
>>>>>>> Stashed changes
                
        return None

    def _find_spring_boot_entry(self, target: str, files: List[str]) -> Optional[Dict]:
        """递归查找 @SpringBootApplication 所在的子模块"""
        for f in files:
            if f.endswith('Application.java'):
                try:
                    with open(f, 'r', encoding='utf-8', errors='ignore') as fp:
                        content = fp.read()
                        if '@SpringBootApplication' in content:
                            # 找到启动类，回溯寻找最近的 pom.xml 所在目录（即模块根目录）
                            app_file_path = Path(f)
                            module_root = app_file_path.parent
                            
                            # 向上查找直到 target 根目录
                            target_path = Path(target).resolve()
                            
                            while module_root.resolve() != target_path:
                                if (module_root / 'pom.xml').exists():
                                    break
                                module_root = module_root.parent
                                # 防止死循环或跳出 target
                                if str(target_path) not in str(module_root.resolve()):
                                    break
                            
                            # 计算相对路径，构造 cd 命令
                            try:
                                rel_path = module_root.resolve().relative_to(target_path)
                                # 如果就在根目录
                                if str(rel_path) == '.':
                                     cmd = 'mvn spring-boot:run'
                                else:
                                     # 使用 posix 风格路径 (即使在 Windows 上，因为是在 Linux 容器内执行)
                                     linux_rel_path = str(rel_path).replace('\\', '/')
                                     cmd = f'cd {linux_rel_path} && mvn spring-boot:run'
                                
                                self.logger.info(f"智能探测到 Spring Boot 启动模块: {linux_rel_path} (Entry: {app_file_path.name})")
                                return {'type': 'java', 'path': str(module_root), 'cmd': cmd}
                            except Exception as e:
                                self.logger.warning(f"计算相对路径失败: {e}")
                except Exception as e:
                    pass
        return None
    def _find_django_entry(self, target: str, files: List[str]) -> Optional[Dict]:
        """递归查找 manage.py 所在的 Django 项目入口"""
        for f in files:
            if Path(f).name == 'manage.py':
                try:
                    # 验证是否为 Django 启动脚本
                    with open(f, 'r', encoding='utf-8', errors='ignore') as fp:
                        if 'django' in fp.read().lower():
                             app_file_path = Path(f)
                             module_root = app_file_path.parent
                             target_path = Path(target).resolve()
                             
                             try:
                                rel_path = module_root.resolve().relative_to(target_path)
                                linux_rel_path = str(rel_path).replace('\\', '/')
                                
                                # 构造启动命令
                                base_cmd = f"python {app_file_path.name} runserver 0.0.0.0:8000 --noreload"
                                
                                if str(rel_path) != '.':
                                    cmd = f"cd {linux_rel_path} && {base_cmd}"
                                else:
                                    cmd = base_cmd
                                    
                                self.logger.info(f"智能探测到 Django 启动脚本: {linux_rel_path}/{app_file_path.name}")
                                return {'type': 'python', 'path': str(module_root), 'cmd': cmd}
                             except Exception as e:
                                self.logger.warning(f"Django 路径计算失败: {e}")
                except Exception:
                    pass
        return None
