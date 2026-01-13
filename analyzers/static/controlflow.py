"""
控制流分析器
分析程序的控制流图，寻找异常的流程
"""

import ast
import re
from typing import Dict, List, Any, Set, Tuple, Optional
from dataclasses import dataclass, field

from utils.helpers import read_file_content, detect_language, get_line_content
from utils.logger import get_logger
from core.ast_engine import ASTEngine


@dataclass
class CFGNode:
    """控制流图节点"""
    id: int
    type: str  # 'entry', 'exit', 'block', 'branch', 'loop'
    lineno: int
    code: str
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)


class ControlFlowAnalyzer:
    """控制流分析器 - 检测异常的程序流程"""
    
    def __init__(self, config):
        self.config = config
        self.logger = get_logger()
        self.ast_engine = ASTEngine()
        
        # Tree-sitter 节点类型映射
        self.node_types = {
            'java': {
                'function': ['method_declaration', 'constructor_declaration'],
                'if': 'if_statement',
                'loop': ['while_statement', 'for_statement', 'do_statement', 'enhanced_for_statement'],
                'return': 'return_statement',
                'call': 'method_invocation',
                'try': 'try_statement',
                'catch': 'catch_clause',
                'throw': 'throw_statement'
            },
            'go': {
                'function': ['function_declaration', 'method_declaration', 'func_literal'],
                'if': 'if_statement',
                'loop': ['for_statement'], # Go only has for
                'return': 'return_statement',
                'call': 'call_expression',
                'goto': 'goto_statement'
            },
            'c': {
                'function': 'function_definition',
                'if': 'if_statement',
                'loop': ['while_statement', 'for_statement', 'do_statement'],
                'return': 'return_statement',
                'call': 'call_expression',
                'goto': 'goto_statement'
            },
            'cpp': {
                'function': 'function_definition',
                'if': 'if_statement',
                'loop': ['while_statement', 'for_statement', 'do_statement', 'range_based_for_statement'],
                'return': 'return_statement',
                'call': 'call_expression',
                'goto': 'goto_statement',
                'try': 'try_statement',
                'catch': 'catch_clause'
            }
        }
    
    def analyze(self, files: List[str]) -> Dict[str, Any]:
        """分析文件列表"""
        findings = []
        
        for file_path in files:
            language = detect_language(file_path)
            if language == 'python':
                file_findings = self._analyze_python_file(file_path)
            elif language in ['java', 'go', 'c', 'cpp']:
                file_findings = self._analyze_with_treesitter(file_path, language)
            else:
                file_findings = self._analyze_generic_file(file_path, language)
            findings.extend(file_findings)
        
        return {
            'analyzer': 'ControlFlowAnalyzer',
            'files_analyzed': len(files),
            'findings': findings
        }
    
    def _analyze_python_file(self, file_path: str) -> List[Dict]:
        """分析Python文件的控制流"""
        findings = []
        
        try:
            content = read_file_content(file_path)
            if not content:
                return findings
            
            tree = ast.parse(content)
            analyzer = PythonCFGAnalyzer(file_path)
            analyzer.visit(tree)
            findings.extend(analyzer.findings)
        
        except SyntaxError as e:
            self.logger.debug(f"Python语法错误 {file_path}: {e}")
        except Exception as e:
            self.logger.error(f"分析文件 {file_path} 时出错: {e}")
        
        return findings
    

    def _analyze_with_treesitter(self, file_path: str, language: str) -> List[Dict]:
        """使用 Tree-sitter 分析控制流"""
        findings = []
        
        try:
            tree = self.ast_engine.parse_file(file_path, language)
            if not tree:
                return self._analyze_generic_file(file_path, language)
                
            analyzer = TreeSitterCFGAnalyzer(file_path, language, self.node_types.get(language, {}))
            findings.extend(analyzer.analyze(tree.root_node))
            
        except Exception as e:
            self.logger.error(f"Tree-sitter 分析文件 {file_path} 时出错: {e}")
            # 降级到通用分析
            findings.extend(self._analyze_generic_file(file_path, language))
            
        return findings

    def _analyze_generic_file(self, file_path: str, language: str) -> List[Dict]:
        """通用控制流分析（基于模式匹配）"""
        findings = []
        
        try:
            content = read_file_content(file_path)
            if not content:
                return findings
            
            lines = content.split('\n')
            
            # 检查可疑的控制流模式
            patterns = [
                # 无条件跳转到可疑位置
                {
                    'pattern': r'goto\s+\w+|jmp\s+\w+',
                    'title': '检测到goto/jmp语句',
                    'severity': 'medium',
                    'description': '使用了可能导致控制流混乱的跳转语句'
                },
                # 异常的返回模式
                {
                    'pattern': r'return\s+exec|return\s+eval|return\s+system',
                    'title': '可疑的返回值',
                    'severity': 'high',
                    'description': '函数返回可能执行危险操作的结果'
                },
                # 隐藏的条件分支（优化：排除常见的正常模式）
                {
                    'pattern': r'if\s+.*==\s*["\'][^"\']{40,}["\']|if\s+.*==\s*0x[0-9a-fA-F]{16,}',
                    'title': '可疑的条件判断',
                    'severity': 'medium',
                    'description': '条件判断使用了长字符串常量，可能是后门密钥或触发条件',
                    'exclude_patterns': [
                        r'!=\s*null',  # 排除null检查
                        r'==\s*null',
                        r'\.exists\(\)',  # 排除文件存在性检查
                        r'\.canRead\(\)',
                        r'\.canWrite\(\)',
                        r'\.isEmpty\(\)',
                        r'\.isBlank\(\)'
                    ]
                },
                # 时间条件触发
                {
                    'pattern': r'if.*datetime.*[<>=]|if.*time\(\).*[<>=]|if.*date.*==',
                    'title': '时间条件触发',
                    'severity': 'medium',
                    'description': '代码包含基于时间的条件判断，可能是定时触发的恶意代码'
                },
                # 死代码后的可执行代码
                {
                    'pattern': r'return\s*;?\s*\n\s*[a-zA-Z]',
                    'title': '死代码检测',
                    'severity': 'low',
                    'description': 'return语句后存在代码，可能是隐藏的恶意代码'
                },
                # 异常处理中的可疑代码
                {
                    'pattern': r'except.*:\s*\n\s*(exec|eval|os\.system|subprocess)',
                    'title': '异常处理中的危险操作',
                    'severity': 'high',
                    'description': '异常处理中包含危险操作，可能是利用异常触发的攻击'
                },
            ]
            
            for i, line in enumerate(lines, 1):
                for p in patterns:
                    if re.search(p['pattern'], line, re.IGNORECASE):
                        # 检查排除模式
                        should_exclude = False
                        if 'exclude_patterns' in p:
                            for exclude_pattern in p['exclude_patterns']:
                                if re.search(exclude_pattern, line, re.IGNORECASE):
                                    should_exclude = True
                                    break
                        
                        if should_exclude:
                            continue
                            
                        context = get_line_content(file_path, i, 3)
                        code_snippet = '\n'.join(
                            f"{c['line_number']:4d} | {c['content']}"
                            for c in context.get('context', [])
                        )
                        
                        findings.append({
                            'id': f'CFG-{patterns.index(p)+1:03d}',
                            'title': p['title'],
                            'severity': p['severity'],
                            'category': 'controlflow',
                            'description': p['description'],
                            'recommendation': '审查此代码段的控制流逻辑，确保不存在非预期的逻辑跳转或后门触发条件。',
                            'file': file_path,
                            'line': i,
                            'code_snippet': code_snippet,
                            'analyzer': 'ControlFlowAnalyzer'
                        })
        
        except Exception as e:
            self.logger.error(f"分析文件 {file_path} 时出错: {e}")
        
        return findings


class PythonCFGAnalyzer(ast.NodeVisitor):
    """Python AST控制流分析器"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings = []
        self.current_function = None
        self.loop_depth = 0
        self.try_depth = 0
    
    def visit_FunctionDef(self, node):
        """分析函数定义"""
        old_function = self.current_function
        self.current_function = node.name
        
        # 检查函数复杂度
        complexity = self._calculate_complexity(node)
        if complexity > 20:
            self._add_finding(
                node, 
                'CFG-HIGH-COMPLEXITY',
                '高圈复杂度函数',
                'medium',
                f'函数 "{node.name}" 的圈复杂度为 {complexity}，过高的复杂度可能隐藏恶意逻辑'
            )
        
        # 检查不可达代码
        self._check_unreachable_code(node)
        
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_If(self, node):
        """分析if语句"""
        # 检查可疑的条件判断
        self._check_suspicious_condition(node)
        self.generic_visit(node)
    
    def visit_While(self, node):
        """分析while循环"""
        self.loop_depth += 1
        
        # 检查无限循环
        if isinstance(node.test, ast.Constant) and node.test.value == True:
            # while True 循环
            has_break = any(isinstance(n, ast.Break) for n in ast.walk(node))
            if not has_break:
                self._add_finding(
                    node,
                    'CFG-INFINITE-LOOP',
                    '可能的无限循环',
                    'medium',
                    '检测到while True循环且没有break语句，可能是死循环或后门等待循环'
                )
        
        self.generic_visit(node)
        self.loop_depth -= 1
    
    def visit_Try(self, node):
        """分析try-except语句"""
        self.try_depth += 1
        
        # 检查空的except块
        for handler in node.handlers:
            if len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass):
                self._add_finding(
                    handler,
                    'CFG-EMPTY-EXCEPT',
                    '空的异常处理',
                    'low',
                    '空的except块会静默忽略所有错误，可能隐藏问题'
                )
            
            # 检查except中的危险操作
            for stmt in handler.body:
                if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                    func_name = self._get_call_name(stmt.value)
                    if func_name in ['eval', 'exec', 'os.system', 'subprocess.call']:
                        self._add_finding(
                            handler,
                            'CFG-EXCEPT-DANGER',
                            '异常处理中的危险操作',
                            'high',
                            f'异常处理块中调用了危险函数 "{func_name}"，可能是利用异常触发的攻击'
                        )
        
        self.generic_visit(node)
        self.try_depth -= 1
    
    def visit_Call(self, node):
        """分析函数调用"""
        func_name = self._get_call_name(node)
        
        # 检查动态代码执行
        if func_name in ['eval', 'exec', 'compile']:
            self._add_finding(
                node,
                'CFG-DYNAMIC-EXEC',
                '动态代码执行',
                'high',
                f'使用了动态代码执行函数 "{func_name}"，可能被利用执行恶意代码'
            )
        
        self.generic_visit(node)
    
    def _calculate_complexity(self, node) -> int:
        """计算圈复杂度"""
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        return complexity
    
    def _check_unreachable_code(self, func_node):
        """检查不可达代码"""
        for i, stmt in enumerate(func_node.body):
            if isinstance(stmt, ast.Return) and i < len(func_node.body) - 1:
                # return后还有代码
                next_stmt = func_node.body[i + 1]
                if not isinstance(next_stmt, (ast.FunctionDef, ast.ClassDef)):
                    self._add_finding(
                        next_stmt,
                        'CFG-UNREACHABLE',
                        '不可达代码',
                        'medium',
                        'return语句后存在代码，这些代码永远不会被执行，可能是隐藏的恶意代码'
                    )
    
    def _check_suspicious_condition(self, node):
        """检查可疑的条件判断"""
        test = node.test
        
        # 检查硬编码的长字符串比较
        if isinstance(test, ast.Compare):
            for comparator in test.comparators:
                if isinstance(comparator, ast.Constant):
                    if isinstance(comparator.value, str) and len(comparator.value) > 32:
                        self._add_finding(
                            node,
                            'CFG-SUSPICIOUS-CONDITION',
                            '可疑的条件判断',
                            'medium',
                            '条件判断使用了长字符串常量，可能是后门密钥或触发条件'
                        )
    
    def _get_call_name(self, node) -> str:
        """获取函数调用名称"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            n = node.func
            while isinstance(n, ast.Attribute):
                parts.append(n.attr)
                n = n.value
            if isinstance(n, ast.Name):
                parts.append(n.id)
            return '.'.join(reversed(parts))
        return ''
    
    def _add_finding(self, node, finding_id: str, title: str, severity: str, description: str):
        """添加发现"""
        context = get_line_content(self.file_path, node.lineno, 3)
        code_snippet = '\n'.join(
            f"{c['line_number']:4d} | {c['content']}"
            for c in context.get('context', [])
        )
        
        self.findings.append({
            'id': finding_id,
            'title': title,
            'severity': severity,
            'category': 'controlflow',
            'description': description,
            'recommendation': '仔细审查此代码段的控制流逻辑，排除恶意代码或不安全的逻辑。',
            'file': self.file_path,
            'line': node.lineno,
            'code_snippet': code_snippet,
            'analyzer': 'ControlFlowAnalyzer'
        })


class TreeSitterCFGAnalyzer:
    """Tree-sitter AST控制流分析器 (支持 Java, Go, C, C++)"""
    
    def __init__(self, file_path: str, language: str, node_types: Dict):
        self.file_path = file_path
        self.language = language
        self.node_types = node_types
        self.findings = []
        self.complexity = 0
        
    def analyze(self, root_node) -> List[Dict]:
        self._visit(root_node)
        return self.findings
        
    def _visit(self, node):
        node_type = node.type
        
        # 1. 检查Goto (Go, C, C++)
        if self._match_type(node_type, 'goto'):
            self._add_finding(
                node, 
                'CFG-GOTO',
                '检测到Goto语句',
                'medium',
                '使用了Goto语句，可能导致控制流混乱或难以审计'
            )
            
        # 2. 检查循环
        if self._match_type(node_type, 'loop'):
            self.complexity += 1
            # 简单检查 while(true) 等死循环模式
            # 注意：这里需要根据语言具体节点的子节点来判断，比较复杂，暂时只统计复杂度
            
        # 3. 检查If条件
        if self._match_type(node_type, 'if'):
            self.complexity += 1
            self._check_suspicious_condition(node)
            
        # 4. 检查危险函数调用
        if self._match_type(node_type, 'call'):
            self._check_dangerous_call(node)
            
        # 递归遍历子节点
        for child in node.children:
            self._visit(child)
            
    def _match_type(self, current_type, category):
        """检查节点类型是否匹配类别"""
        target = self.node_types.get(category)
        if not target:
            return False
        if isinstance(target, list):
            return current_type in target
        return current_type == target
        
    def _check_suspicious_condition(self, node):
        """检查可疑的条件判断 (Tree-sitter Generic)"""
        # 获取节点文本
        try:
            text = node.text.decode('utf-8', errors='ignore')
            
            # 排除模式列表
            exclude_patterns = [
                r'!=\s*null', r'==\s*null',  # Null checks (Java/C++)
                r'!=\s*nil', r'==\s*nil',    # Nil checks (Go)
                r'\.exists\(\)', r'\.canRead\(\)', r'\.canWrite\(\)', # File checks
                r'\.length\(\)', r'\.size\(\)', # Length checks
                r'\.equals\(".*?"\)', # Simple string equals
                r'logger\.', r'System\.out\.', # Logging
            ]
            
            # 检查是否有长字符串硬编码 (提高阈值到 40)
            # 并且确保它看起来像是一个比较操作
            if re.search(r'["\'][^"\']{40,}["\']', text):
                # 检查是否命中排除模式
                for pattern in exclude_patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        return

                self._add_finding(
                    node,
                    'CFG-SUSPICIOUS-CONDITION',
                    '可疑的条件判断',
                    'medium',
                    '条件判断使用了长字符串常量(>40字符)，可能是后门密钥或触发条件'
                )
        except:
            pass
            
    def _check_dangerous_call(self, node):
        """检查危险函数调用"""
        try:
            text = node.text.decode('utf-8', errors='ignore')
            # 简单的文本匹配，不够精确但有效
            dangerous = ['system', 'exec', 'popen', 'strcpy', 'sprintf', 'strcat']
            
            # 提取函数名 (这取决于语言，这里简化处理，匹配 text 中的 'func(')
            for d in dangerous:
                if re.search(rf'\b{d}\s*\(', text):
                    self._add_finding(
                        node,
                        'CFG-DANGEROUS-CALL',
                        '危险函数调用',
                        'high',
                        f'使用了不安全的函数 "{d}"，可能导致安全漏洞'
                    )
        except:
            pass

    def _add_finding(self, node, finding_id: str, title: str, severity: str, description: str):
        """添加发现"""
        # 计算行号 (Tree-sitter 是 0-indexed，行号需要 +1)
        line = node.start_point[0] + 1
        
        context = get_line_content(self.file_path, line, 3)
        code_snippet = '\n'.join(
            f"{c['line_number']:4d} | {c['content']}"
            for c in context.get('context', [])
        )
        
        self.findings.append({
            'id': finding_id,
            'title': title,
            'severity': severity,
            'category': 'controlflow',
            'description': description,
            'recommendation': '仔细审查此代码段的控制流逻辑，确保逻辑严密且符合安全标准。',
            'file': self.file_path,
            'line': line,
            'code_snippet': code_snippet,
            'analyzer': 'ControlFlowAnalyzer'
        })
