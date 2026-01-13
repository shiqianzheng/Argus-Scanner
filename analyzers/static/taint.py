"""
污点分析器
跟踪外部输入在程序中的传播路径
"""

import ast
import re
from typing import Dict, List, Any, Set, Optional
from dataclasses import dataclass, field
from enum import Enum

from utils.helpers import read_file_content, detect_language, get_line_content
from utils.logger import get_logger
from core.ast_engine import ASTEngine


class TaintState(Enum):
    """污点状态"""
    CLEAN = "clean"
    TAINTED = "tainted"
    SANITIZED = "sanitized"


@dataclass
class TaintedValue:
    """污点值"""
    name: str
    source: str
    source_line: int
    state: TaintState = TaintState.TAINTED
    propagation_path: List[int] = field(default_factory=list)


class TaintAnalyzer:
    """污点分析器 - 跟踪不可信数据的传播"""
    
    def __init__(self, config):
        self.config = config
        self.logger = get_logger()
        self.ast_engine = ASTEngine()
        
        # 语言特定的节点类型映射
        self.node_mappings = {
            'java': {
                'assignment': ['assignment_expression', 'variable_declarator'],
                'call': ['method_invocation', 'object_creation_expression'],
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
        
        # 污点源 - 不可信的数据输入点
        self.taint_sources = {
            'python': {
                'functions': ['input', 'raw_input'],
                'attributes': [
                    'request.args', 'request.form', 'request.data', 'request.json',
                    'request.files', 'request.values', 'request.cookies',
                    'request.headers', 'request.GET', 'request.POST',
                    'sys.argv', 'os.environ'
                ],
                'modules': ['flask.request', 'django.http.request']
            },
            'java': {
                'methods': [
                    'getParameter', 'getInputStream', 'getReader',
                    'getQueryString', 'getHeader', 'getCookies'
                ],
                'classes': ['HttpServletRequest', 'Scanner']
            },
            'go': {
                'functions': ['r.FormValue', 'r.URL.Query', 'r.Header.Get'],
                'packages': ['net/http', 'io/ioutil']
            }
        }
        
        # 污点源 - 不可信的数据输入点
        self.taint_sources = {
            'python': {
                'functions': ['input', 'raw_input'],
                'attributes': [
                    'request.args', 'request.form', 'request.data', 'request.json',
                    'request.files', 'request.values', 'request.cookies',
                    'request.headers', 'request.GET', 'request.POST',
                    'sys.argv', 'os.environ'
                ],
                'modules': ['flask.request', 'django.http.request']
            },
            'java': {
                'methods': [
                    'getParameter', 'getInputStream', 'getReader',
                    'getQueryString', 'getHeader', 'getCookies'
                ],
                'classes': ['HttpServletRequest', 'Scanner']
            },
            'go': {
                'functions': ['r.FormValue', 'r.URL.Query', 'r.Header.Get'],
                'packages': ['net/http', 'io/ioutil']
            }
        }
        
        # 敏感汇聚点 - 危险操作
        self.sensitive_sinks = {
            'python': {
                'code_execution': ['eval', 'exec', 'compile', '__import__', 'code.InteractiveInterpreter'],
                'command_execution': ['os.system', 'os.popen', 'subprocess.call', 
                                     'subprocess.run', 'subprocess.Popen',
                                     'subprocess.check_output', 'subprocess.check_call',
                                     'subprocess.getoutput', 'subprocess.getstatusoutput',
                                     'commands.getoutput', 'popen2.popen4'],
                'file_operations': ['open', 'file', 'codecs.open', 'os.open', 'io.open'],
                'sql_operations': ['execute', 'executemany', 'cursor.execute', 'db.execute'],
                'deserialization': ['pickle.loads', 'yaml.load', 'yaml.unsafe_load', 'json.loads', 'marshal.loads', 'shelve.open'],
                'template': ['render_template_string', 'Markup', 'jinja2.Template', 'mako.template.Template'],
                'network_request': ['requests.get', 'requests.post', 'requests.put', 'requests.delete', 'requests.request',
                                   'urllib.request.urlopen', 'urllib2.urlopen', 'httplib.HTTPConnection',
                                   'socket.socket.connect', 'socket.create_connection'],
                'ldap_injection': ['ldap.search', 'ldap.initialize'],
                'xpath_injection': ['xpath.evaluate', 'lxml.etree.XPath']
            },
            'java': {
                'code_execution': ['Runtime.exec', 'exec', 'ProcessBuilder', 'ProcessBuilder.start', 'Expression.getValue'],
                'sql_operations': ['executeQuery', 'executeUpdate', 'execute', 'Statement.execute'],
                'file_operations': ['FileWriter', 'FileOutputStream', 'File', 'FileReader', 'Files.write', 'Files.readAllBytes'],
                'path_traversal': ['File', 'FileInputStream', 'FileOutputStream', 'FileReader', 'FileWriter', 'Paths.get'],
                'deserialization': ['ObjectInputStream.readObject', 'XMLDecoder.readObject', 'Yaml.load'],
                'network_request': ['URL.openStream', 'HttpURLConnection.connect', 'HttpClient.send', 'RestTemplate.getForObject', 'Jsoup.connect'],
                'ldap_injection': ['InitialDirContext.search', 'DirContext.search'],
                'xpath_injection': ['XPath.evaluate', 'XPathExpression.evaluate']
            },
            'go': {
                'command_execution': ['exec.Command', 'os.StartProcess', 'syscall.Exec'],
                'sql_operations': ['db.Query', 'db.Exec', 'db.QueryRow'],
                'file_operations': ['os.Open', 'os.OpenFile', 'os.Create', 'ioutil.ReadFile', 'ioutil.WriteFile'],
                'network_request': ['http.Get', 'http.Post', 'http.PostForm', 'http.Head', 'net.Dial', 'net.DialTimeout'],
                'path_traversal': ['filepath.Join', 'http.ServeFile']
            }
        }
        
        # 净化函数 - 可以使污点数据变得安全
        self.sanitizers = {
            'python': [
                'escape', 'quote', 'html.escape', 'urllib.parse.quote',
                'bleach.clean', 'sanitize', 'validate', 'int', 'float',
                'str.isdigit', 'str.isalnum', 're.match', 're.fullmatch'
            ],
            'java': [
                'StringEscapeUtils', 'HtmlUtils.htmlEscape', 
                'PreparedStatement', 'Integer.parseInt'
            ],
            'go': [
                'html.EscapeString', 'url.QueryEscape', 'template.HTMLEscapeString'
            ]
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
            'analyzer': 'TaintAnalyzer',
            'files_analyzed': len(files),
            'findings': findings
        }
    
    def _analyze_python_file(self, file_path: str) -> List[Dict]:
        """分析Python文件的污点传播"""
        findings = []
        
        try:
            content = read_file_content(file_path)
            if not content:
                return findings
            
            tree = ast.parse(content)
            analyzer = PythonTaintVisitor(
                file_path,
                self.taint_sources.get('python', {}),
                self.sensitive_sinks.get('python', {}),
                self.sanitizers.get('python', [])
            )
            analyzer.visit(tree)
            findings.extend(analyzer.findings)
        
        except SyntaxError as e:
            self.logger.debug(f"Python语法错误 {file_path}: {e}")
        except Exception as e:
            self.logger.error(f"分析文件 {file_path} 时出错: {e}")
        
        return findings
    
    def _analyze_generic_file(self, file_path: str, language: str) -> List[Dict]:
        """通用污点分析"""
        findings = []
        
        try:
            content = read_file_content(file_path)
            if not content:
                return findings
            
            lines = content.split('\n')
            sources = self.taint_sources.get(language, {})
            sinks = self.sensitive_sinks.get(language, {})
            sanitizers = self.sanitizers.get(language, [])
            
            tainted_vars = {}  # 变量名 -> 污点信息
            
            for i, line in enumerate(lines, 1):
                # 检测污点源
                source_patterns = []
                if 'functions' in sources:
                    source_patterns.extend(sources['functions'])
                if 'attributes' in sources:
                    source_patterns.extend(sources['attributes'])
                if 'methods' in sources:
                    source_patterns.extend(sources['methods'])
                
                for source in source_patterns:
                    if source in line:
                        # 提取赋值的变量
                        var_match = re.match(r'^\s*(\w+)\s*[=:]', line)
                        if var_match:
                            var_name = var_match.group(1)
                            tainted_vars[var_name] = {
                                'source': source,
                                'line': i,
                                'sanitized': False
                            }
                
                # 检测净化
                for sanitizer in sanitizers:
                    if sanitizer in line:
                        for var in list(tainted_vars.keys()):
                            if var in line:
                                tainted_vars[var]['sanitized'] = True
                
                # 检测敏感汇聚点
                all_sinks = []
                for sink_list in sinks.values():
                    all_sinks.extend(sink_list)
                
                for sink in all_sinks:
                    if sink in line:
                        for var_name, var_info in tainted_vars.items():
                            if var_name in line and not var_info['sanitized']:
                                context = get_line_content(file_path, i, 3)
                                code_snippet = '\n'.join(
                                    f"{c['line_number']:4d} | {c['content']}"
                                    for c in context.get('context', [])
                                )
                                
                                findings.append({
                                    'id': 'TAINT-001',
                                    'title': '污点数据流向敏感操作',
                                    'severity': 'high',
                                    'category': 'taint_analysis',
                                    'description': f'来自 "{var_info["source"]}" (行 {var_info["line"]}) 的污点数据 "{var_name}" 未经净化直接流向敏感操作 "{sink}"',
                                    'recommendation': '对输入数据进行验证和净化处理，避免直接在敏感操作中使用未经校验的变量。',
                                    'file': file_path,
                                    'line': i,
                                    'code_snippet': code_snippet,
                                    'tainted_variable': var_name,
                                    'source': var_info['source'],
                                    'sink': sink,
                                    'analyzer': 'TaintAnalyzer'
                                })
        
        except Exception as e:
            self.logger.error(f"分析文件 {file_path} 时出错: {e}")
        
        return findings

    def _analyze_with_treesitter(self, file_path: str, language: str) -> List[Dict]:
        """使用 Tree-sitter 分析污点传播"""
        findings = []
        try:
            tree = self.ast_engine.parse_file(file_path, language)
            if not tree:
                return self._analyze_generic_file(file_path, language)
            
            analyzer = TreeSitterTaintAnalyzer(
                file_path, 
                language, 
                self.node_mappings.get(language, {}),
                self.taint_sources.get(language, {}),
                self.sensitive_sinks.get(language, {}),
                self.sanitizers.get(language, [])
            )
            # DEBUG PRINT
            # print(f"DEBUG: Analyzing {file_path} with sources={list(analyzer.sources.keys())} sinks={list(analyzer.sinks.keys())}")
            findings.extend(analyzer.analyze(tree.root_node))
            # print(f"DEBUG: Findings: {len(findings)} TaintedVars: {analyzer.tainted_vars}")
        except Exception as e:
            self.logger.error(f"Tree-sitter (Taint) 分析出错 {file_path}: {e}")
            findings.extend(self._analyze_generic_file(file_path, language))
        return findings



class PythonTaintVisitor(ast.NodeVisitor):
    """Python AST污点分析访问器"""
    
    def __init__(self, file_path: str, sources: Dict, sinks: Dict, sanitizers: List[str]):
        self.file_path = file_path
        self.sources = sources
        self.sinks = sinks
        self.sanitizers = sanitizers
        self.findings = []
        
        # 污点追踪
        self.tainted_vars: Dict[str, TaintedValue] = {}
        self.current_function = None
    
    def visit_FunctionDef(self, node):
        """访问函数定义"""
        old_function = self.current_function
        self.current_function = node.name
        
        # 函数参数可能是污点源 (启发式)
        suspicious_args = ['input', 'cmd', 'command', 'sql', 'query', 'url', 'path', 'file', 'content', 'data', 'pattern']
        for arg in node.args.args:
            arg_name = arg.arg if hasattr(arg, 'arg') else str(arg)
            # 简单模糊匹配
            is_suspicious = False
            for susp in suspicious_args:
                if susp in arg_name.lower():
                    is_suspicious = True
                    break
            
            if is_suspicious:
                 self.tainted_vars[arg_name] = TaintedValue(
                    name=arg_name,
                    source=f"Function Argument ({arg_name})",
                    source_line=node.lineno,
                    propagation_path=[node.lineno]
                )
        
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_Assign(self, node):
        """访问赋值语句"""
        # 检查右值是否包含污点源
        taint_source = self._check_taint_source(node.value)
        
        if taint_source:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars[target.id] = TaintedValue(
                        name=target.id,
                        source=taint_source,
                        source_line=node.lineno,
                        propagation_path=[node.lineno]
                    )
        else:
            # 检查污点传播
            propagated_taint = self._check_taint_propagation(node.value)
            if propagated_taint:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        new_taint = TaintedValue(
                            name=target.id,
                            source=propagated_taint.source,
                            source_line=propagated_taint.source_line,
                            propagation_path=propagated_taint.propagation_path + [node.lineno]
                        )
                        
                        # 检查是否经过净化
                        if self._is_sanitized(node.value):
                            new_taint.state = TaintState.SANITIZED
                        
                        self.tainted_vars[target.id] = new_taint
        
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """访问函数调用"""
        func_name = self._get_call_name(node)
        
        # 检查是否是敏感汇聚点
        sink_category = self._get_sink_category(func_name)
        if sink_category:
            # 检查参数是否包含未净化的污点数据
            for arg in node.args:
                tainted_value = self._get_tainted_value(arg)
                if tainted_value and tainted_value.state == TaintState.TAINTED:
                    self._add_finding(node, func_name, sink_category, tainted_value)
        
        self.generic_visit(node)
    
    def _check_taint_source(self, node) -> Optional[str]:
        """检查节点是否是污点源"""
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node)
            # 1. 直接匹配函数名
            if func_name in self.sources.get('functions', []):
                return func_name
            
            # 2. 检查方法调用的主体 (e.g. request.args.get)
            if isinstance(node.func, ast.Attribute):
                attr_name = self._get_full_attr_name(node.func.value) # 获取 request.args
                # 检查主体是否在 attribute sources 中
                for attr in self.sources.get('attributes', []):
                    if attr in attr_name:
                         return f"{attr}.{node.func.attr}" # e.g. request.args.get

        elif isinstance(node, ast.Attribute):
            attr_name = self._get_full_attr_name(node)
            for attr in self.sources.get('attributes', []):
                if attr in attr_name:
                    return attr
        
        elif isinstance(node, ast.Subscript):
            # 处理 request.args['key'] 这种形式
            if isinstance(node.value, ast.Attribute):
                attr_name = self._get_full_attr_name(node.value)
                for attr in self.sources.get('attributes', []):
                    if attr in attr_name:
                        return attr
        
        return None
    
    def _check_taint_propagation(self, node) -> Optional[TaintedValue]:
        """检查污点传播"""
        if isinstance(node, ast.Name):
            return self.tainted_vars.get(node.id)
        
        elif isinstance(node, ast.BinOp):
            left_taint = self._check_taint_propagation(node.left)
            right_taint = self._check_taint_propagation(node.right)
            return left_taint or right_taint
        
        elif isinstance(node, ast.Call):
            for arg in node.args:
                taint = self._check_taint_propagation(arg)
                if taint:
                    return taint
        
        elif isinstance(node, ast.JoinedStr):  # f-string
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    taint = self._check_taint_propagation(value.value)
                    if taint:
                        return taint
        
        return None
    
    def _is_sanitized(self, node) -> bool:
        """检查是否经过净化"""
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node)
            for sanitizer in self.sanitizers:
                if sanitizer in func_name:
                    return True
        return False
    
    def _get_tainted_value(self, node) -> Optional[TaintedValue]:
        """获取节点的污点值"""
        if isinstance(node, ast.Name):
            return self.tainted_vars.get(node.id)
        elif isinstance(node, ast.BinOp):
            return self._get_tainted_value(node.left) or self._get_tainted_value(node.right)
        elif isinstance(node, ast.Call):
            for arg in node.args:
                taint = self._get_tainted_value(arg)
                if taint:
                    return taint
        return None
    
    def _get_sink_category(self, func_name: str) -> Optional[str]:
        """获取汇聚点类别"""
        for category, sinks in self.sinks.items():
            for sink in sinks:
                if sink in func_name:
                    return category
        return None
    
    def _get_call_name(self, node) -> str:
        """获取调用名称"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return self._get_full_attr_name(node.func)
        return ''
    
    def _get_full_attr_name(self, node) -> str:
        """获取完整属性名"""
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return '.'.join(reversed(parts))
    
    def _add_finding(self, node, sink: str, category: str, tainted_value: TaintedValue):
        """添加发现"""
        context = get_line_content(self.file_path, node.lineno, 3)
        code_snippet = '\n'.join(
            f"{c['line_number']:4d} | {c['content']}"
            for c in context.get('context', [])
        )
        
        severity_map = {
            'code_execution': 'critical',
            'command_execution': 'critical',
            'sql_operations': 'high',
            'file_operations': 'high',
            'deserialization': 'high',
            'template': 'medium'
        }
        
        category_cn = {
            'code_execution': '代码执行',
            'command_execution': '命令执行',
            'sql_operations': 'SQL 注入',
            'file_operations': '文件操作',
            'deserialization': '不安全的反序列化',
            'template': '模板注入'
        }.get(category, category)

        self.findings.append({
            'id': f'TAINT-{category.upper()}',
            'title': f'污点数据流向{category_cn}操作',
            'severity': severity_map.get(category, 'high'),
            'category': 'taint_analysis',
            'description': f'来自 "{tainted_value.source}" (行 {tainted_value.source_line}) 的污点数据 "{tainted_value.name}" 未经净化直接流向敏感操作 "{sink}"。',
            'recommendation': '对输入数据进行验证和净化处理，使用参数化查询或安全 API，避免直接拼接用户输入。',
            'file': self.file_path,
            'line': node.lineno,
            'code_snippet': code_snippet,
            'tainted_variable': tainted_value.name,
            'source': tainted_value.source,
            'source_line': tainted_value.source_line,
            'sink': sink,
            'sink_category': category,
            'propagation_path': tainted_value.propagation_path,
            'analyzer': 'TaintAnalyzer'
        })

class TreeSitterTaintAnalyzer:
    """Tree-sitter 污点分析器"""
    
    def __init__(self, file_path, language, node_mapping, sources, sinks, sanitizers):
        self.file_path = file_path
        self.language = language
        self.node_mapping = node_mapping
        self.sources = sources
        self.sinks = sinks
        self.sanitizers = sanitizers
        
        self.tainted_vars: Dict[str, Dict] = {} # var_name -> source_info
        self.findings = []
        
    def analyze(self, root_node) -> List[Dict]:
        self._visit(root_node)
        return self.findings
        
    def _visit(self, node):
        node_type = node.type
        
        # 1. 检查赋值 (Taint Propagation)
        if self._match_type(node_type, 'assignment'):
            self._handle_assignment(node)
            
        # 2. 检查调用 (Taint Sink & Source)
        if self._match_type(node_type, 'call'):
            self._handle_call(node)
            
        for child in node.children:
            self._visit(child)
            
    def _handle_assignment(self, node):
        """处理赋值语句"""
        lhs_name = self._extract_identifier(node, position='left')
        rhs_node = self._get_rhs_node(node)
        
        if lhs_name and rhs_node:
            taint_source = self._check_taint(rhs_node)
            # print(f"DEBUG: Assignment {lhs_name} = {rhs_node.text.decode('utf-8')}, TaintSource: {taint_source}")
            if taint_source:
                self.tainted_vars[lhs_name] = {
                    'source': taint_source['source'],
                    'line': node.start_point[0] + 1
                }
            elif lhs_name in self.tainted_vars:
                del self.tainted_vars[lhs_name]
                
    def _handle_call(self, node):
        """处理函数调用"""
        try:
            call_text = node.text.decode('utf-8', errors='ignore')
            
            # 1. 检查是否是 Sink
            sink_category = self._check_sink(call_text)
            if sink_category:
                args = self._extract_arguments(node)
                # print(f"DEBUG: Call {call_text} Sink={sink_category} Args={args}")
                for arg in args:
                    if arg in self.tainted_vars:
                        # Found a path!
                        self._add_finding(node, sink_category, self.tainted_vars[arg])
        except:
             pass
                    
    def _check_taint(self, node) -> Optional[Dict]:
        """检查节点是否被污染"""
        try:
            text = node.text.decode('utf-8', errors='ignore')
            
            # 1. 直接匹配 Source
            for src_cat, src_list in self.sources.items():
                if isinstance(src_list, list):
                    for src in src_list:
                        if src in text:
                            return {'source': src}
                            
            # 2. 检查是否使用已污染变量
            for var, info in self.tainted_vars.items():
                # Fix regex to use simple string boundary if \b is problematic
                if re.search(rf'\b{re.escape(var)}\b', text):
                     return info
                # Also try without boundary for exact match if text IS variable
                if text == var:
                     return info
        except:
            pass
        return None
        
    def _check_sink(self, text) -> Optional[str]:
        """检查是否是汇聚点"""
        for category, sink_list in self.sinks.items():
            for sink in sink_list:
                if sink in text:
                    return category
        return None

    def _extract_identifier(self, node, position='left') -> Optional[str]:
        """从赋值节点提取变量名"""
        try:
            if position == 'left':
                target = node.children[0]
                while target.type != 'identifier' and target.children:
                     target = target.children[0]
                if target.type == 'identifier':
                    return target.text.decode('utf-8', errors='ignore')
        except:
            pass
        return None
        
    def _get_rhs_node(self, node):
        """获取赋值的右值节点"""
        if node.children:
            return node.children[-1]
        return None
        
    def _extract_arguments(self, call_node) -> List[str]:
        """提取函数调用的参数列表中的标识符"""
        args = []
        try:
            # 尝试通过 AST 提取
            arg_list_type = self.node_mapping.get('argument_list')
            arg_list_node = None
            
            # 查找 argument_list 子节点
            for child in call_node.children:
                if child.type == arg_list_type:
                    arg_list_node = child
                    break
            
            if arg_list_node:
                for child in arg_list_node.children:
                    if child.type == self.node_mapping.get('identifier'):
                        args.append(child.text.decode('utf-8', errors='ignore'))
            else:
                # 降级到文本提取 (改进只有最后一个括号的内容)
                text = call_node.text.decode('utf-8', errors='ignore')
                match = re.search(r'\(([^()]*)\)$', text) # 匹配最后一个括号内的内容
                if match:
                    content = match.group(1)
                    parts = content.split(',')
                    for p in parts:
                        p = p.strip()
                        args.append(p)
        except:
            pass
        return args

    def _match_type(self, current_type, category):
        target = self.node_mapping.get(category)
        if not target: return False
        if isinstance(target, list): return current_type in target
        return current_type == target

    def _add_finding(self, node, category, source_info):
        line = node.start_point[0] + 1
        category_cn = {
            'code_execution': '代码执行',
            'command_execution': '命令执行',
            'sql_operations': 'SQL 注入',
            'file_operations': '文件操作',
            'deserialization': '不安全的反序列化',
            'template': '模板注入'
        }.get(category, category)

        self.findings.append({
            'id': f'TAINT-{category.upper()}',
            'title': f'污点数据流向{category_cn}操作',
            'severity': 'high',
            'category': 'taint_analysis',
            'description': f'来自 "{source_info["source"]}" (行 {source_info["line"]}) 的数据流向敏感操作，可能存在注入风险。',
            'recommendation': '在数据源头或使用前进行严格的类型校验和安全过滤。',
            'file': self.file_path,
            'line': line,
            'code_snippet': '',
            'analyzer': 'TaintAnalyzer'
        })
