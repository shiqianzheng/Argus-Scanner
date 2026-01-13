"""
数据流分析器
跟踪数据从输入点到敏感操作的路径
"""

import ast
import re
from typing import Dict, List, Any, Set, Optional
from pathlib import Path

from utils.helpers import read_file_content, detect_language, get_line_content
from utils.logger import get_logger
from core.ast_engine import ASTEngine


class DataFlowAnalyzer:
    """数据流分析器 - 跟踪数据在程序中的传播路径"""
    
    def __init__(self, config):
        self.config = config
        self.logger = get_logger()
        self.max_depth = config.get('static_analysis.dataflow_analysis.max_depth', 10)
        self.ast_engine = ASTEngine()
        
        # 语言特定的节点类型映射
        self.node_mappings = {
            'java': {
                'assignment': ['assignment_expression', 'variable_declarator'],
                'call': ['method_invocation'],
                'identifier': 'identifier', 
                'argument_list': 'argument_list'
            },
            'c': {
                'assignment': ['assignment_expression', 'init_declarator'],
                'call': ['call_expression'],
                'identifier': 'identifier',
                'argument_list': 'argument_list'
            },
            'cpp': {
                'assignment': ['assignment_expression', 'init_declarator'],
                'call': ['call_expression'],
                'identifier': 'identifier',
                'argument_list': 'argument_list'
            },
            'go': {
                'assignment': ['assignment_statement', 'short_var_declaration', 'var_spec'],
                'call': ['call_expression'],
                'identifier': 'identifier',
                'argument_list': 'argument_list'
            }
        }
        
        # 污点源（不可信输入）
        self.taint_sources = {
            'python': [
                'input', 'raw_input', 'request.args', 'request.form', 
                'request.data', 'request.json', 'sys.argv', 'os.environ',
                'request.GET', 'request.POST', 'request.FILES'
            ],
            'java': [
                'getParameter', 'getInputStream', 'getReader', 
                'Scanner', 'BufferedReader', 'args'
            ],
            'go': [
                'r.FormValue', 'r.URL.Query', 'os.Args', 
                'ioutil.ReadAll', 'bufio.NewReader'
            ],
            'c': ['scanf', 'gets', 'fgets', 'read', 'recv', 'argv'],
            'cpp': ['cin', 'scanf', 'gets', 'fgets', 'read', 'recv', 'argv']
        }
        
        # 敏感汇聚点（危险操作）
        self.sensitive_sinks = {
            'python': [
                'eval', 'exec', 'os.system', 'subprocess.call', 
                'subprocess.Popen', 'os.popen', 'execute', 'cursor.execute',
                'open', 'pickle.loads', 'yaml.load'
            ],
            'java': [
                'Runtime.exec', 'ProcessBuilder', 'executeQuery',
                'executeUpdate', 'ObjectInputStream', 'FileWriter'
            ],
            'go': [
                'exec.Command', 'os.Create', 'os.OpenFile',
                'sql.Query', 'sql.Exec', 'template.HTML'
            ],
            'c': ['system', 'popen', 'execve', 'execl', 'strcpy', 'sprintf'],
            'cpp': ['system', 'popen', 'execve', 'execl', 'strcpy', 'sprintf']
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
            'analyzer': 'DataFlowAnalyzer',
            'files_analyzed': len(files),
            'findings': findings
        }
    
    def _analyze_python_file(self, file_path: str) -> List[Dict]:
        """分析Python文件的数据流"""
        findings = []
        
        try:
            content = read_file_content(file_path)
            if not content:
                return findings
            
            tree = ast.parse(content)
            analyzer = PythonDataFlowVisitor(
                file_path, 
                self.taint_sources.get('python', []),
                self.sensitive_sinks.get('python', []),
                self.max_depth
            )
            analyzer.visit(tree)
            findings.extend(analyzer.findings)
        
        except SyntaxError as e:
            self.logger.debug(f"Python语法错误 {file_path}: {e}")
        except Exception as e:
            self.logger.error(f"分析文件 {file_path} 时出错: {e}")
        
        return findings
    


    def _analyze_with_treesitter(self, file_path: str, language: str) -> List[Dict]:
        """使用 Tree-sitter 分析数据流"""
        findings = []
        try:
            tree = self.ast_engine.parse_file(file_path, language)
            if not tree:
                return self._analyze_generic_file(file_path, language)
            
            analyzer = TreeSitterDataFlowAnalyzer(
                file_path, 
                language, 
                self.node_mappings.get(language, {}),
                self.taint_sources.get(language, {}),
                self.sensitive_sinks.get(language, {})
            )
            findings.extend(analyzer.analyze(tree.root_node))
        except Exception as e:
            self.logger.error(f"Tree-sitter (DataFlow) 分析出错 {file_path}: {e}")
            # 降级到通用分析
            findings.extend(self._analyze_generic_file(file_path, language))
        return findings

    def _analyze_generic_file(self, file_path: str, language: str) -> List[Dict]:
        """通用数据流分析（基于正则表达式）"""
        findings = []
        
        try:
            content = read_file_content(file_path)
            if not content:
                return findings
            
            lines = content.split('\n')
            sources = self.taint_sources.get(language, [])
            sinks = self.sensitive_sinks.get(language, [])
            
            # 查找变量赋值和数据流
            tainted_vars = set()
            
            for i, line in enumerate(lines, 1):
                # 检查是否有来自源的输入
                for source in sources:
                    if source in line:
                        # 尝试提取被赋值的变量名
                        var_match = re.match(r'^\s*(\w+)\s*[=:].*' + re.escape(source), line)
                        if var_match:
                            tainted_vars.add(var_match.group(1))
                
                # 检查污点数据是否流向敏感汇聚点
                for sink in sinks:
                    if sink in line:
                        # 检查是否有污点变量作为参数
                        for var in tainted_vars:
                            if var in line:
                                context = get_line_content(file_path, i, 3)
                                code_snippet = '\n'.join(
                                    f"{c['line_number']:4d} | {c['content']}"
                                    for c in context.get('context', [])
                                )
                                
                                findings.append({
                                    'id': 'DATAFLOW-001',
                                    'title': '不安全的数据流',
                                    'severity': 'high',
                                    'category': 'dataflow',
                                    'description': f'变量 "{var}" 来自不可信源，直接流向敏感操作 "{sink}"',
                                    'recommendation': '对输入数据进行验证和过滤，确保在使用前符合预期的安全规范。',
                                    'file': file_path,
                                    'line': i,
                                    'code_snippet': code_snippet,
                                    'tainted_variable': var,
                                    'sink': sink,
                                    'analyzer': 'DataFlowAnalyzer'
                                })
        
        except Exception as e:
            self.logger.error(f"分析文件 {file_path} 时出错: {e}")
        
        return findings


class PythonDataFlowVisitor(ast.NodeVisitor):
    """Python AST数据流分析访问器"""
    
    def __init__(self, file_path: str, sources: List[str], sinks: List[str], max_depth: int):
        self.file_path = file_path
        self.sources = sources
        self.sinks = sinks
        self.max_depth = max_depth
        self.findings = []
        self.tainted_vars: Dict[str, Dict] = {}  # 变量名 -> 污点信息
        self.current_function = None
    
    def visit_FunctionDef(self, node):
        """访问函数定义"""
        old_function = self.current_function
        self.current_function = node.name
        
        # 检查函数参数（可能是污点源）
        for arg in node.args.args:
            arg_name = arg.arg if hasattr(arg, 'arg') else arg
            self.tainted_vars[arg_name] = {
                'source': 'function_parameter',
                'line': node.lineno
            }
        
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_Assign(self, node):
        """访问赋值语句"""
        # 检查赋值源是否是污点
        source_tainted = self._is_tainted_expression(node.value)
        
        if source_tainted:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars[target.id] = {
                        'source': source_tainted,
                        'line': node.lineno
                    }
        
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """访问函数调用"""
        func_name = self._get_call_name(node)
        
        # 检查是否是敏感汇聚点
        if self._is_sink(func_name):
            # 检查参数是否包含污点数据
            for arg in node.args:
                taint_info = self._check_tainted_arg(arg)
                if taint_info:
                    self._add_finding(node, func_name, taint_info)
        
        self.generic_visit(node)
    
    def _is_tainted_expression(self, node) -> Optional[str]:
        """检查表达式是否来自污点源"""
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node)
            for source in self.sources:
                if source in func_name:
                    return source
        elif isinstance(node, ast.Name):
            if node.id in self.tainted_vars:
                return self.tainted_vars[node.id].get('source')
        elif isinstance(node, ast.BinOp):
            # 检查二元操作的两边
            left_taint = self._is_tainted_expression(node.left)
            right_taint = self._is_tainted_expression(node.right)
            return left_taint or right_taint
        elif isinstance(node, ast.Attribute):
            attr_name = self._get_attribute_name(node)
            for source in self.sources:
                if source in attr_name:
                    return source
        
        return None
    
    def _is_sink(self, func_name: str) -> bool:
        """检查是否是敏感汇聚点"""
        for sink in self.sinks:
            if sink in func_name:
                return True
        return False
    
    def _check_tainted_arg(self, arg) -> Optional[Dict]:
        """检查参数是否被污染"""
        if isinstance(arg, ast.Name):
            if arg.id in self.tainted_vars:
                return self.tainted_vars[arg.id]
        elif isinstance(arg, ast.BinOp):
            left_taint = self._check_tainted_arg(arg.left)
            right_taint = self._check_tainted_arg(arg.right)
            return left_taint or right_taint
        elif isinstance(arg, ast.Call):
            for sub_arg in arg.args:
                taint = self._check_tainted_arg(sub_arg)
                if taint:
                    return taint
        
        return None
    
    def _get_call_name(self, node) -> str:
        """获取函数调用名称"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return self._get_attribute_name(node.func)
        return ''
    
    def _get_attribute_name(self, node) -> str:
        """获取属性访问的完整名称"""
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return '.'.join(reversed(parts))
    
    def _add_finding(self, node, sink: str, taint_info: Dict):
        """添加发现"""
        context = get_line_content(self.file_path, node.lineno, 3)
        code_snippet = '\n'.join(
            f"{c['line_number']:4d} | {c['content']}"
            for c in context.get('context', [])
        )
        
        self.findings.append({
            'id': 'DATAFLOW-002',
            'title': '污点数据流向敏感操作',
            'severity': 'high',
            'category': 'dataflow',
            'description': f'来自 "{taint_info.get("source", "unknown")}" 的数据未经验证直接流向敏感操作 "{sink}"。',
            'recommendation': '在使用数据前进行验证、过滤或转义，确保输入符合预期格式。',
            'file': self.file_path,
            'line': node.lineno,
            'code_snippet': code_snippet,
            'source': taint_info.get('source'),
            'sink': sink,
            'analyzer': 'DataFlowAnalyzer'
        })

class TreeSitterDataFlowAnalyzer:
    """基于 Tree-sitter 的通用数据流分析器"""
    
    def __init__(self, file_path: str, language: str, mappings: Dict, sources: List[str], sinks: List[str]):
        self.file_path = file_path
        self.language = language
        self.mappings = mappings
        self.sources = sources
        self.sinks = sinks
        self.findings = []
        self.tainted_vars: Dict[str, Dict] = {}
        self.ast_engine = ASTEngine()
        
    def analyze(self, root_node) -> List[Dict]:
        """执行分析"""
        self._analyze_node(root_node)
        return self.findings
        
    def _analyze_node(self, node):
        """递归分析节点"""
        # 处理赋值 (Source -> Variable)
        if self._is_assignment(node):
            self._handle_assignment(node)
            
        # 处理调用 (Variable -> Sink)
        if self._is_call(node):
            self._check_sink(node)
            
        # 递归子节点
        for child in node.children:
            self._analyze_node(child)
            
    def _is_assignment(self, node) -> bool:
        """检查是否为赋值语句"""
        assign_types = self.mappings.get('assignment', [])
        if isinstance(assign_types, str):
            assign_types = [assign_types]
        return node.type in assign_types
        
    def _is_call(self, node) -> bool:
        """检查是否为函数调用"""
        call_types = self.mappings.get('call', [])
        if isinstance(call_types, str):
            call_types = [call_types]
        return node.type in call_types

    def _handle_assignment(self, node):
        """处理赋值，追踪污点"""
        # 简化实现：如果右值包含已知污点源，则左值被污染
        # 实际实现需要提取左右值的标识符，这里做通用简化处理
        code = self._get_text(node)
        for source in self.sources:
            if source in code:
                # 提取左值变量名 (非常简化的启发式)
                parts = code.split('=')
                if len(parts) > 1:
                    var_name = parts[0].strip().split()[-1] # 取最后一个单词作为变量名
                    self.tainted_vars[var_name] = {
                        'source': source,
                        'line': node.start_point[0] + 1
                    }
                    
    def _check_sink(self, node):
        """检查汇聚点"""
        code = self._get_text(node)
        for sink in self.sinks:
            if sink in code:
                # 检查参数是否包含污点变量
                for var_name, info in self.tainted_vars.items():
                    if var_name in code: # 参数被污染
                        self._add_finding(node, sink, info, var_name)

    def _get_text(self, node) -> str:
        """获取节点文本"""
        # 由于我们没有原始字节，这里只能依靠 AST Engine 的帮助或者重新读取
        # 为了简化，这里假设 AST Engine 提供了工具，或者我们重新读取文件
        # 实际项目中，应该传递源代码内容给 Analyzer
        with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            start_line = node.start_point[0]
            end_line = node.end_point[0]
            if start_line == end_line:
                return lines[start_line][node.start_point[1]:node.end_point[1]]
            else:
                return "".join(lines[start_line:end_line+1])

    def _add_finding(self, node, sink: str, taint_info: Dict, var_name: str):
        """添加发现"""
        context = get_line_content(self.file_path, node.start_point[0] + 1, 3)
        code_snippet = '\n'.join(
            f"{c['line_number']:4d} | {c['content']}"
            for c in context.get('context', [])
        )
        
        self.findings.append({
            'id': 'DATAFLOW-003',
            'title': '跨语言数据流污点',
            'severity': 'high',
            'category': 'dataflow',
            'description': f'变量 "{var_name}" (来自 {taint_info.get("source")}) 流入敏感操作 "{sink}"。',
            'recommendation': '验证所有外部输入，确保其来源及内容的安全性。',
            'file': self.file_path,
            'line': node.start_point[0] + 1,
            'code_snippet': code_snippet,
            'source': taint_info.get('source'),
            'sink': sink,
            'analyzer': 'TreeSitterDataFlowAnalyzer'
        })
