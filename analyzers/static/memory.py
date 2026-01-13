
import re
from typing import List, Dict, Any, Tuple
from core.config import Config
from utils.logger import get_logger

class StaticMemoryAnalyzer:
    """静态内存分析器，用于检测代码中的可疑内存操作和 Shellcode"""

    def __init__(self, config: Config):
        self.config = config
        self.logger = get_logger()
        
        # 移植自开源社区的高质量规则
        # 可疑的内存操作模式
        self.suspicious_memory_patterns = [
            {
                'pattern': r'ctypes\.create_string_buffer',
                'title': '创建字符串缓冲区',
                'severity': 'medium',
                'description': '检测到使用ctypes创建字符串缓冲区，可能用于内存注入',
                'category': 'memory_static'
            },
            {
                'pattern': r'VirtualAlloc|mmap|allocate.*memory',
                'title': '内存分配操作',
                'severity': 'medium',
                'description': '检测到直接的内存分配 API 调用，尤其是可能用于执行代码的内存',
                'category': 'memory_static'
            },
            {
                'pattern': r'PAGE_EXECUTE|PROT_EXEC|executable.*memory',
                'title': '可执行内存设置',
                'severity': 'high',
                'description': '检测到设置内存为可执行 (PROT_EXEC/PAGE_EXECUTE)，这是代码注入的典型特征',
                'category': 'memory_static'
            },
            {
                'pattern': r'CFUNCTYPE|function.*pointer|ctypes\.cast',
                'title': '函数指针操作',
                'severity': 'medium',
                'description': '检测到函数指针操作，可能用于转换地址并执行注入的代码',
                'category': 'memory_static'
            },
            {
                'pattern': r'RtlMoveMemory|memmove|memcpy|WriteProcessMemory',
                'title': '内存写入操作',
                'severity': 'high',
                'description': '检测到直接的内存写入 API (如 WriteProcessMemory)，通常用于进程注入',
                'category': 'memory_static'
            }
        ]
        
        # 预编译正则
        for p in self.suspicious_memory_patterns:
            p['regex'] = re.compile(p['pattern'], re.IGNORECASE)

        # 检测shellcode特征 (字节码模式)
        # 注意：在文本源码扫描中，我们查找的是 \xHH 形式的转义字符串，或者 bytes([0x...])
        self.shellcode_indicators = [
            r'\\x31\\xc0',  # xor eax,eax string literal
            r'\\x50\\x68',  # push eax; push dword string literal
            r'\\xeb\\x',     # jmp short string literal
            r'\\x90{10,}',  # NOP sled (long sequence of \x90)
            r'0x90,\s*0x90,\s*0x90', # C-style array NOP sled
            r'cd\s*80'      # int 0x80 (in asm string)
        ]
        self.shellcode_regexes = [re.compile(p, re.IGNORECASE) for p in self.shellcode_indicators]

    def analyze(self, files: List[str]) -> Dict[str, Any]:
        """分析文件列表中的内存操作特征"""
        all_findings = []
        for file_path in files:
            try:
                file_findings = self._analyze_file(file_path)
                all_findings.extend(file_findings)
            except Exception as e:
                self.logger.error(f"StaticMemoryAnalyzer 分析文件出错 {file_path}: {e}")
        
        return {'findings': all_findings}

    def _analyze_file(self, file_path: str, content: str = None) -> List[Dict[str, Any]]:
        """分析单个文件中的内存操作特征"""
        findings = []
        if content is None:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except Exception as e:
                self.logger.error(f"StaticMemoryAnalyzer 读取文件失败 {file_path}: {e}")
                return []

        lines = content.split('\n')
        
        # 1. 扫描可疑 API 调用
        for p in self.suspicious_memory_patterns:
            regex = p['regex']
            for i, line in enumerate(lines, 1):
                if len(line) > 1000: continue # 跳过过长的行
                if regex.search(line):
                    findings.append({
                        'id': 'MEM-STATIC-001',
                        'title': p['title'],
                        'severity': p['severity'],
                        'category': p['category'],
                        'description': p['description'],
                        'recommendation': '审查内存操作的必要性，确认是否涉及不安全的代码执行。',
                        'file': file_path,
                        'line': i,
                        'matched_line': line.strip()[:100],
                        'code_snippet': line.strip(),
                        'analyzer': 'StaticMemoryAnalyzer',
                        'type': 'static'
                    })

        # 2. 扫描 Shellcode 特征
        for i, line in enumerate(lines, 1):
            if len(line) > 2000: continue
            for regex in self.shellcode_regexes:
                match = regex.search(line)
                if match:
                    findings.append({
                        'id': 'MEM-SHELLCODE-001',
                        'title': '检测到 Shellcode 特征',
                        'severity': 'critical',
                        'category': 'memory_static',
                        'description': '代码中包含典型的 Shellcode 字节码模式 (如 XOR解码, NOP滑里, 系统中断)，极可能是恶意 Payload。',
                        'recommendation': '立即隔离文件并进行人工逆向分析。',
                        'file': file_path,
                        'line': i,
                        'matched_line': line.strip()[:100],
                        'code_snippet': line.strip(),
                        'analyzer': 'StaticMemoryAnalyzer',
                        'type': 'static'
                    })
                    break # 一行只报一次 Shellcode

        return findings
