import os
from typing import Dict, Any, Optional, List, Tuple
try:
    from tree_sitter import Parser, Language, Node, Tree
    import tree_sitter_languages
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

from utils.logger import get_logger

class ASTEngine:
    """
    统一的 AST 解析引擎，基于 Tree-sitter。
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.parsers: Dict[str, Parser] = {}
        self.languages: Dict[str, Language] = {}
        
        if not TREE_SITTER_AVAILABLE:
            self.logger.warning("Tree-sitter not available. AST analysis will be disabled for non-Python languages.")
            
    def get_parser(self, lang_name: str) -> Optional[Parser]:
        """获取指定语言的 Parser"""
        if not TREE_SITTER_AVAILABLE:
            return None
            
        if lang_name in self.parsers:
            return self.parsers[lang_name]
            
        try:
            # 映射语言名称到 tree-sitter 名称
            ts_lang_name = self._map_language_name(lang_name)
            
            # 获取语言定义
            language = tree_sitter_languages.get_language(ts_lang_name)
            self.languages[lang_name] = language
            
            # 创建 Parser (处理版本兼容性问题)
            parser = None
            try:
                # 尝试传统方式: Parser() + set_language()
                parser = Parser()
                parser.set_language(language)
            except Exception:
                try:
                    # 尝试新版本方式: Parser(language)
                    parser = Parser(language)
                except Exception as e2:
                    self.logger.error(f"Failed to initialize parser for {lang_name} after multiple attempts: {e2}")
                    return None
            
            self.parsers[lang_name] = parser
            return parser
        except Exception as e:
            self.logger.error(f"Failed to initialize parser for {lang_name}: {e}")
            return None
            
    def parse_file(self, file_path: str, lang_name: str) -> Optional[Tree]:
        """解析文件内容生成 AST"""
        parser = self.get_parser(lang_name)
        if not parser:
            return None
            
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            return parser.parse(content)
        except Exception as e:
            self.logger.error(f"Failed to parse file {file_path}: {e}")
            return None

    def parse_code(self, code: bytes, lang_name: str) -> Optional[Tree]:
        """解析代码字符串"""
        parser = self.get_parser(lang_name)
        if not parser:
            return None
        return parser.parse(code)
        
    def _map_language_name(self, name: str) -> str:
        """映射通用名称到 tree-sitter 名称"""
        mapping = {
            'c++': 'cpp',
            'c#': 'c_sharp',
            'golang': 'go'
        }
        return mapping.get(name.lower(), name.lower())

    # --- Utility Methods ---
    
    def find_nodes_by_type(self, node: Node, node_type: str) -> List[Node]:
        """在子树中查找指定类型的节点"""
        results = []
        if node.type == node_type:
            results.append(node)
        
        # 递归查找
        # Tree-sitter cursor might be faster, but this is simple
        for child in node.children:
            results.extend(self.find_nodes_by_type(child, node_type))
            
        return results

    def get_node_text(self, node: Node, source_bytes: bytes) -> str:
        """获取节点的源代码文本"""
        return source_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
