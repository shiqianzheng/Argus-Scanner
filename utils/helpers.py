"""
工具函数模块
"""

import os
import hashlib
from pathlib import Path
from typing import List, Dict, Optional

# 支持的文件扩展名映射
LANGUAGE_EXTENSIONS = {
    'python': ['.py', '.pyw'],
    'java': ['.java'],
    'go': ['.go'],
    'javascript': ['.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx'],
    'c': ['.c', '.h'],
    'cpp': ['.cpp', '.cc', '.cxx', '.hpp', '.hh', '.hxx', '.c++', '.h++']
}

# 反向映射：扩展名 -> 语言
EXTENSION_TO_LANGUAGE = {}
for lang, exts in LANGUAGE_EXTENSIONS.items():
    for ext in exts:
        EXTENSION_TO_LANGUAGE[ext] = lang

def detect_language(file_path: str) -> Optional[str]:
    """根据文件扩展名检测编程语言"""
    ext = Path(file_path).suffix.lower()
    return EXTENSION_TO_LANGUAGE.get(ext)

def get_files_by_language(directory: str, language: str = 'auto') -> List[str]:
    """获取指定语言的所有源代码文件和依赖文件"""
    files = []
    directory = Path(directory)
    
    # 定义依赖文件
    dependency_files = {
        'requirements.txt', 'Pipfile', 'pyproject.toml', # Python
        'pom.xml', 'build.gradle',                       # Java
        'go.mod',                                        # Go
        'package.json'                                   # JavaScript/Node
    }
    
    if language == 'auto':
        # 获取所有支持的扩展名
        extensions = set()
        for exts in LANGUAGE_EXTENSIONS.values():
            extensions.update(exts)
    else:
        extensions = set(LANGUAGE_EXTENSIONS.get(language, []))
    
    # 处理单个文件情况
    if directory.is_file():
        # 如果是依赖文件，直接返回
        if directory.name in dependency_files or (directory.name.startswith('requirements') and directory.suffix == '.txt'):
             return [str(directory)]
             
        if directory.suffix.lower() in extensions:
            return [str(directory)]
        return []
    
    for root, dirs, filenames in os.walk(directory):
        # 跳过隐藏目录和常见的非源码目录
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in 
                   ['node_modules', 'venv', 'env', '__pycache__', 'build', 'dist', 'target']]
        
        for filename in filenames:
            # 检查依赖文件
            if filename in dependency_files or (filename.startswith('requirements') and filename.endswith('.txt')):
                files.append(os.path.join(root, filename))
                continue
                
            ext = Path(filename).suffix.lower()
            if ext in extensions:
                files.append(os.path.join(root, filename))
    
    return files

def calculate_file_hash(file_path: str) -> str:
    """计算文件的SHA256哈希值"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def read_file_content(file_path: str, encoding: str = 'utf-8') -> str:
    """读取文件内容"""
    try:
        with open(file_path, 'r', encoding=encoding) as f:
            return f.read()
    except UnicodeDecodeError:
        # 尝试其他编码
        for enc in ['latin-1', 'gbk', 'gb2312']:
            try:
                with open(file_path, 'r', encoding=enc) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
        return ""

def get_line_content(file_path: str, line_number: int, context_lines: int = 3) -> Dict:
    """获取指定行及其上下文"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except:
        return {'line': '', 'context': []}
    
    if line_number < 1 or line_number > len(lines):
        return {'line': '', 'context': []}
    
    start = max(0, line_number - context_lines - 1)
    end = min(len(lines), line_number + context_lines)
    
    context = []
    for i in range(start, end):
        context.append({
            'line_number': i + 1,
            'content': lines[i].rstrip(),
            'is_target': i + 1 == line_number
        })
    
    return {
        'line': lines[line_number - 1].rstrip(),
        'context': context
    }

def normalize_path(path: str) -> str:
    """规范化路径"""
    return str(Path(path).resolve())

def is_binary_file(file_path: str) -> bool:
    """检查是否为二进制文件"""
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(8192)
            if b'\x00' in chunk:
                return True
            # 检查非文本字符的比例
            text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})
            non_text = sum(1 for byte in chunk if byte not in text_chars)
            return non_text / len(chunk) > 0.30 if chunk else False
    except:
        return True
