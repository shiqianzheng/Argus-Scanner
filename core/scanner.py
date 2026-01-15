"""
代码扫描器核心模块
整合静态分析和动态分析功能
"""

import os
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from utils.helpers import get_files_by_language, detect_language, read_file_content
from utils.logger import get_logger
from .config import Config
from .sandbox import SandboxManager


class CodeScanner:
    """代码扫描器主类"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = get_logger()
        self._static_analyzers = {}
        self._dynamic_analyzers = {}
        self.sandbox = SandboxManager(config)
        self._init_analyzers()
    
    def _init_analyzers(self):
        """初始化分析器"""
        # 延迟导入，避免循环依赖
        from analyzers.static import (
            PatternMatcher,
            DataFlowAnalyzer,
            ControlFlowAnalyzer,
            TaintAnalyzer,
            DependencyChecker,
            StaticMemoryAnalyzer
        )
        from analyzers.dynamic import (
            SyscallMonitor,
            NetworkMonitor,
            FileMonitor
        )
        
        # 静态分析器
        if self.config.get('static_analysis.pattern_matching.enabled', True):
            self._static_analyzers['pattern'] = PatternMatcher(self.config)
        
        if self.config.get('static_analysis.dataflow_analysis.enabled', True):
            self._static_analyzers['dataflow'] = DataFlowAnalyzer(self.config)
        
        if self.config.get('static_analysis.controlflow_analysis.enabled', True):
            self._static_analyzers['controlflow'] = ControlFlowAnalyzer(self.config)
        
        if self.config.get('static_analysis.taint_analysis.enabled', True):
            self._static_analyzers['taint'] = TaintAnalyzer(self.config)
        
        if self.config.get('static_analysis.dependency_check.enabled', True):
            self._static_analyzers['dependency'] = DependencyChecker(self.config)

        # 内存安全分析 (New)
        if self.config.get('static_analysis.memory_analysis.enabled', True):
            self._static_analyzers['memory'] = StaticMemoryAnalyzer(self.config)
        
        # 动态分析器
        if self.config.get('dynamic_analysis.syscall_monitor.enabled', True):
            self._dynamic_analyzers['syscall'] = SyscallMonitor(self.config, self.sandbox)
        
        if self.config.get('dynamic_analysis.network_monitor.enabled', True):
            self._dynamic_analyzers['network'] = NetworkMonitor(self.config)
        
        if self.config.get('dynamic_analysis.file_monitor.enabled', True):
            self._dynamic_analyzers['file'] = FileMonitor(self.config)
    
    def scan(self, target: str, static: bool = True, dynamic: bool = True, 
             language: str = 'auto', **kwargs) -> Dict[str, Any]:
        """
        执行代码扫描
        
        Args:
            target: 目标文件或目录路径
            static: 是否进行静态分析
            dynamic: 是否进行动态分析
            language: 指定语言或auto自动检测
        
        Returns:
            扫描结果字典
        """
        start_time = time.time()
        
        results = {
            'target': target,
            'scan_time': 0,
            'scan_date': datetime.now().isoformat(),
            'files_scanned': 0,
            'findings': [],
            'static_analysis': {},
            'dynamic_analysis': {},
            'summary': {}
        }
        
        # 获取要扫描的文件
        files = get_files_by_language(target, language)
        results['files_scanned'] = len(files)
        
        self.logger.info(f"找到 {len(files)} 个源代码文件")
        
        if not files:
            self.logger.warning("未找到任何源代码文件")
            return results
        
        # 静态分析
        if static and self.config.static_analysis_enabled:
            self.logger.info("开始静态分析...")
            static_results = self._run_static_analysis(files)
            results['static_analysis'] = static_results
            results['findings'].extend(static_results.get('findings', []))
        
        # 动态分析
        if dynamic and self.config.dynamic_analysis_enabled:
            # 沙箱环境准备 (New)
            if self.config.get('dynamic_analysis.sandbox.enabled', True) and self.sandbox.is_available():
                
                # 检查是否存在清理请求
                if kwargs.get('cleanup_container'):
                    self.logger.info("执行沙箱清理操作...")
                    self.sandbox.cleanup_sandbox(target)
                    self.logger.info("沙箱清理完成")
                    return results

                self.logger.info("正在初始化 Docker 沙箱环境...")
                
                # 优先使用指定的 Docker 镜像
                sandbox_image = kwargs.get('sandbox_image')
                manual_setup = kwargs.get('manual_setup', False)
                
                # 优化语言探测逻辑：从列表中寻找第一个可识别的编程语言文件
                scan_lang = None
                if language != 'auto':
                    scan_lang = language
                else:
                    for f in files:
                        detected = detect_language(f)
                        if detected:
                            scan_lang = detected
                            break
                
                if not scan_lang and not sandbox_image: # 如果指定了镜像，可以不需要语言
                    self.logger.warning("无法自动识别项目语言，将跳过沙箱依赖安装")
                else:
                    # 尝试拉取镜像
                    if self.sandbox.prepare_image(scan_lang, image_override=sandbox_image):
                         # 安装依赖
                         if manual_setup:
                             self.logger.info("进入手动配置模式...")
                         else:
                             display_name = sandbox_image or scan_lang
                             self.logger.info(f"在沙箱中安装项目依赖 ({display_name})...")
                         
                         install_res = self.sandbox.run_dependency_install(
                             target, 
                             scan_lang, 
                             image_override=sandbox_image, 
                             manual_setup=manual_setup
                         )
                         
                         if install_res['status'] == 'success':
                             self.logger.info("依赖安装环境就绪，准备进行动态分析")
                         elif install_res['status'] == 'manual_setup_waiting':
                             # 手动模式，用户已配置完成
                             self.logger.info("手动配置完成，继续分析")
                         elif install_res['status'] == 'skipped':
                             self.logger.info("跳过依赖安装 (未找到配置文件)")
                         else:
                             self.logger.warning(f"依赖安装失败: {install_res.get('logs')}")
            
            self.logger.info("开始动态分析...")
            exec_cmd = kwargs.get('exec_cmd')
            dynamic_results = self._run_dynamic_analysis(target, files, exec_cmd=exec_cmd)
            results['dynamic_analysis'] = dynamic_results
            results['findings'].extend(dynamic_results.get('findings', []))
        
        # 计算统计信息
        results['scan_time'] = time.time() - start_time
        results['summary'] = self._calculate_summary(results['findings'])
        
        self.logger.info(f"扫描完成，耗时 {results['scan_time']:.2f} 秒")
        
        return results
    
    def _run_static_analysis(self, files: List[str]) -> Dict[str, Any]:
        """执行静态分析"""
        results = {
            'findings': [],
            'analyzers': {}
        }
        
        for name, analyzer in self._static_analyzers.items():
            self.logger.info(f"  运行 {name} 分析器...")
            try:
                analyzer_results = analyzer.analyze(files)
                findings_count = len(analyzer_results.get('findings', []))
                self.logger.info(f"  {name} 分析器完成，发现数量: {findings_count}")
                results['analyzers'][name] = analyzer_results
                results['findings'].extend(analyzer_results.get('findings', []))
            except Exception as e:
                self.logger.error(f"  {name} 分析器出错: {e}")
                results['analyzers'][name] = {'error': str(e)}
        
        return results
    
    def _run_dynamic_analysis(self, target: str, files: List[str], exec_cmd: str = None) -> Dict[str, Any]:
        """执行动态分析"""
        results = {
            'findings': [],
            'monitors': {}
        }
        
        for name, monitor in self._dynamic_analyzers.items():
            self.logger.info(f"  运行 {name} 监控器...")
            try:
                # 适配监控器的接口变化
                if name == 'syscall':
                    monitor_results = monitor.monitor(target, files, exec_cmd=exec_cmd)
                else:
                    monitor_results = monitor.monitor(target, files)
                results['monitors'][name] = monitor_results
                results['findings'].extend(monitor_results.get('findings', []))
            except Exception as e:
                self.logger.error(f"  {name} 监控器出错: {e}")
                results['monitors'][name] = {'error': str(e)}
        
        return results
    
    def _calculate_summary(self, findings: List[Dict]) -> Dict[str, Any]:
        """计算扫描结果摘要"""
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        category_counts = {}
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            category = finding.get('category', 'unknown')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
        
        return {
            'total_findings': len(findings),
            'by_severity': severity_counts,
            'by_category': category_counts
        }
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """扫描单个文件"""
        return self.scan(file_path, static=True, dynamic=False)
    
    def quick_scan(self, target: str) -> Dict[str, Any]:
        """快速扫描（仅模式匹配）"""
        from analyzers.static import PatternMatcher
        
        start_time = time.time()
        files = get_files_by_language(target, 'auto')
        
        pattern_matcher = PatternMatcher(self.config)
        results = pattern_matcher.analyze(files)
        
        return {
            'target': target,
            'scan_time': time.time() - start_time,
            'files_scanned': len(files),
            'findings': results.get('findings', []),
            'summary': self._calculate_summary(results.get('findings', []))
        }
