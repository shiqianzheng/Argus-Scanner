"""
模式匹配分析器 (Smart Pattern Matcher)
基于 AST 和 YAML 规则的智能恶意代码检测
"""

import re
import os
import yaml
from typing import Dict, List, Any, Optional, Set
from pathlib import Path

from utils.helpers import read_file_content, detect_language, get_line_content
from utils.logger import get_logger
from core.ast_engine import ASTEngine

class PatternMatcher:
    """智能模式匹配分析器 - 基于 AST 上下文消除误报"""
    
    def __init__(self, config):
        self.config = config
        self.logger = get_logger()
        self.ast_engine = ASTEngine()
        self.rules = self._load_rules()
        
        # AST 节点类型映射 (Smart Context 核心)
        self.node_types = {
            'python': {
                'string': ['string'],
                'call': ['call']
            },
            'java': {
                'string': ['string_literal'],
                'call': ['method_invocation', 'object_creation_expression']
            },
            'go': {
                'string': ['interpreted_string_literal', 'raw_string_literal'],
                'call': ['call_expression']
            },
            'c': {
                'string': ['string_literal', 'system_lib_string'],
                'call': ['call_expression']
            },
            'cpp': {
                'string': ['string_literal', 'system_lib_string'],
                'call': ['call_expression']
            },
            'javascript': {
                'string': ['string', 'template_string'],
                'call': ['call_expression', 'new_expression']
            }
        }
    
    def _load_rules(self) -> List[Dict]:
        """加载 YAML 规则文件"""
        # 尝试定位 rules 目录
        current_dir = Path(os.path.dirname(__file__))
        # analyzers/static -> Argus-Scanner/rules
        rules_path = current_dir.parent.parent / 'rules' / 'static_rules.yaml'
        
        rules = []
        try:
            if rules_path.exists():
                self.logger.info(f"正在从 {rules_path} 加载规则...")
                with open(rules_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if data and 'rules' in data:
                        rules = data['rules']
                        self.logger.info(f"成功加载 {len(rules)} 条静态分析规则")
            else:
                self.logger.error(f"警告：找不到静态分析规则文件！路径: {rules_path.absolute()}")
                
        except Exception as e:
            self.logger.error(f"加载规则失败: {e}")
            
        # 预编译正则
        for rule in rules:
            if 'patterns' in rule:
                for pat in rule['patterns']:
                    try:
                        pat['regex_compiled'] = re.compile(pat['regex'])
                    except re.error as e:
                        self.logger.error(f"规则 {rule['id']} 正则编译失败: {e}")
                        
        return rules

    def analyze(self, files: List[str]) -> Dict[str, Any]:
        """分析文件列表"""
        findings = []
        files_scanned = 0
        
        for file_path in files:
            try:
                language = detect_language(file_path)
                if not language:
                    continue
                    
                # 尝试 AST 分析 (P0: 降低误报的核心)
                file_findings = self._analyze_file_ast(file_path, language)
                
                if file_findings is not None:
                    findings.extend(file_findings)
                    files_scanned += 1
                else:
                    # 如果 AST 解析失败，是否回退到文本匹配？
                    # 为了低误报，我们暂时只记录错误，不回退。
                    # 或者如果文件很小，可以尝试极简的文本搜索，但要加上注释过滤逻辑(TODO)
                    pass
                    
            except Exception as e:
                self.logger.error(f"分析文件 {file_path} 出错: {e}")

        return {
            'analyzer': 'SmartPatternMatcher',
            'files_analyzed': files_scanned,
            'findings': findings
        }

    def _analyze_file_ast(self, file_path: str, language: str) -> Optional[List[Dict]]:
        """基于 AST 的文件分析"""
        findings = []
        
        # 1. 解析 AST
        tree = self.ast_engine.parse_file(file_path, language)
        if not tree:
            return None # 解析失败
            
        root_node = tree.root_node
        source_code_bytes = None
        
        try:
            with open(file_path, 'rb') as f:
                source_code_bytes = f.read()
        except Exception:
            return None

        # 2. 遍历 AST 节点
        self._traverse_and_check(root_node, source_code_bytes, language, file_path, findings)
            
        return findings

    def _traverse_and_check(self, node, source_bytes, language, file_path, findings):
        """递归遍历并检查节点"""
        
        # 检查当前节点类型
        node_type = node.type
        known_types = self.node_types.get(language, {})
        
        # 1. 检查字符串 (Secrets, IPs)
        if node_type in known_types.get('string', []):
            text = self._get_node_text(node, source_bytes)
            self._check_rules(text, 'string', language, file_path, node.start_point[0] + 1, findings)
            
        # 2. 检查函数调用 (Backdoors, Dangerous APIs)
        elif node_type in known_types.get('call', []):
            text = self._get_node_text(node, source_bytes)
            self._check_rules(text, 'call', language, file_path, node.start_point[0] + 1, findings)
            
        # 递归子节点
        for child in node.children:
            self._traverse_and_check(child, source_bytes, language, file_path, findings)

    def _check_rules(self, text, context_type, language, file_path, line_number, findings):
        """检查文本是否匹配规则"""
        for rule in self.rules:
            # 语言过滤
            if 'languages' in rule and 'all' not in rule['languages']:
                if language not in rule['languages']:
                    continue
            
            # 模式匹配
            for pat in rule.get('patterns', []):
                # 类型必须匹配 (Context Check)
                if pat.get('type') != context_type:
                    continue
                    
                # 正则匹配
                regex = pat.get('regex_compiled')
                if regex:
                    match = regex.search(text)
                    if match:
                        # 发现问题
                        self._add_finding(findings, rule, file_path, line_number, text)
                        return

    def _get_node_text(self, node, source_bytes):
        """获取节点文本"""
        try:
            start = node.start_byte
            end = node.end_byte
            return source_bytes[start:end].decode('utf-8', errors='ignore')
        except Exception:
            return ""

    def _add_finding(self, findings, rule, file_path, line_number, evidence):
        """添加发现"""
        context = get_line_content(file_path, line_number, 3)
        code_snippet = '\n'.join(
            f"{c['line_number']:4d} | {c['content']}"
            for c in context.get('context', [])
        )
        
        findings.append({
            'id': rule['id'],
            'title': rule.get('title_cn', rule['title']),
            'severity': rule['severity'],
            'category': rule['category'],
            'description': rule.get('description_cn', rule['description']),
            'recommendation': rule.get('recommendation_cn', rule.get('recommendation', '请审查该代码段，确认是否为预期行为。建议使用配置文件或环境变量管理敏感信息。')),
            'file': file_path,
            'line': line_number,
            'code_snippet': code_snippet,
            'evidence': evidence, # 具体的匹配内容
            'analyzer': 'SmartPatternMatcher' # 标记为智能分析器
        })
