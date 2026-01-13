"""
报告生成模块
支持HTML、JSON、TXT格式的报告输出
"""

import os
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
from jinja2 import Template

from .config import Config
from utils.helpers import get_line_content


class ReportGenerator:
    """报告生成器"""
    
    def __init__(self, config: Config):
        self.config = config
    
    def generate(self, results: Dict[str, Any], output_dir: str, 
                 format: str = 'html') -> str:
        """
        生成扫描报告
        
        Args:
            results: 扫描结果
            output_dir: 输出目录
            format: 报告格式 (html/json/txt/all)
        
        Returns:
            报告文件路径
        """
        # 确保输出目录存在
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # 生成报告文件名
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_name = f"report_{timestamp}"
        
        if format == 'all':
            self._generate_html(results, output_dir, base_name)
            self._generate_json(results, output_dir, base_name)
            self._generate_txt(results, output_dir, base_name)
            return os.path.join(output_dir, f"{base_name}.html")
        elif format == 'html':
            return self._generate_html(results, output_dir, base_name)
        elif format == 'json':
            return self._generate_json(results, output_dir, base_name)
        elif format == 'txt':
            return self._generate_txt(results, output_dir, base_name)
        else:
            return self._generate_html(results, output_dir, base_name)
    
    def _generate_html(self, results: Dict, output_dir: str, base_name: str) -> str:
        """生成HTML报告"""
        # 强制重新计算统计数据，确保与发现列表一致
        findings = results.get('findings', [])
        by_severity = {
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0
        }
        
        # 归一化处理
        normalized_findings = []
        category_map = {
            'network': '网络安全',
            'network_monitor': '网络监控',
            'filesystem': '文件系统',
            'file_monitor': '文件监控',
            'process': '进程安全',
            'evasion': '躲避行为',
            'backdoor': '后门木马',
            'vulnerability': '安全漏洞',
            'taint_analysis': '污点分析',
            'controlflow': '控制流分析',
            'dataflow': '数据流分析'
        }
        analyzer_map = {
            'PatternMatcher': '特征匹配分析器',
            'SmartPatternMatcher': '智能模式分析器',
            'NetworkMonitor': '网络分析器',
            'FileMonitor': '文件分析器',
            'SyscallMonitor': '系统调用监控器',
            'FalcoLiteMonitor': '动态行为监控器',
            'TaintAnalyzer': '污点传播分析器',
            'DataFlowAnalyzer': '数据流分析器',
            'ControlFlowAnalyzer': '控制流分析器',
            'DependencyAnalyzer': '依赖分析器'
        }

        static_analyzers = ['PatternMatcher', 'SmartPatternMatcher', 'TaintAnalyzer', 'DataFlowAnalyzer', 'ControlFlowAnalyzer', 'DependencyAnalyzer']
        
        for f in findings:
            # 汉化分类
            cat = f.get('category', 'unknown')
            f['category'] = category_map.get(cat, cat)
            
            # 汉化分析器名称
            original_ana = f.get('analyzer', 'unknown')
            # 统一分析器标识，有些地方可能已经传了中文，我们要识别出来归类
            ana_id = original_ana
            for k, v in analyzer_map.items():
                if original_ana == v:
                    ana_id = k
                    break
            
            f['type'] = 'static' if ana_id in static_analyzers else 'dynamic'
            f['analyzer'] = analyzer_map.get(ana_id, original_ana)

            # 自动补全代码片段 (针对 NetworkMonitor 等混合型分析器)
            if not f.get('code_snippet') and f.get('file') and f.get('line'):
                try:
                    context = get_line_content(f['file'], f['line'], 3)
                    if context and context.get('context'):
                        f['code_snippet'] = '\n'.join(
                            f"{c['line_number']:4d} | {c['content']}"
                            for c in context.get('context', [])
                        )
                except Exception:
                    pass

            # 确保 severity 字段存在且统一
            sev = f.get('severity', 'LOW').lower()
            if sev not in by_severity:
                sev = 'low' # fallback
            by_severity[sev] += 1
            f['severity'] = sev.upper()
            f['severity_label'] = {'critical': '严重', 'high': '高危', 'medium': '中危', 'low': '低危'}.get(sev, sev.upper())
            normalized_findings.append(f)
            
        # 更新 summary
        summary = results.get('summary', {})
        summary['by_severity'] = by_severity
        summary['total_findings'] = len(normalized_findings)
        
        # 更新 results 中的 findings，确保后续渲染使用归一化后的数据
        results['findings'] = normalized_findings
        results['summary'] = summary

        html_template = self._get_html_template()
        
        # 渲染模板 - 启用自动转义以防止HTML注入
        from jinja2 import Environment
        env = Environment(autoescape=True)
        template = env.from_string(html_template)
        
        html_content = template.render(
            title=f"Argus-Scanner 安全扫描报告",
            target=results.get('target', 'Unknown'),
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            scan_time=results.get('scan_time', 0),
            files_scanned=results.get('files_scanned', 0),
            summary=summary,
            findings=normalized_findings
        )
        
        output_path = os.path.join(output_dir, f"{base_name}.html")
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path

    def _get_html_template(self) -> str:
        """获取HTML模板"""
        return '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        /* Modern Reset */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', -apple-system, sans-serif; background-color: #f8fafc; color: #1e293b; line-height: 1.5; }
        .container { max-width: 1100px; margin: 0 auto; padding: 30px 20px; }
        
        /* Header Area */
        .header { background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); color: #f8fafc; padding: 40px; border-radius: 16px; margin-bottom: 24px; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1); }
        .header h1 { font-size: 2.25rem; font-weight: 800; margin-bottom: 12px; display: flex; align-items: center; gap: 12px; }
        .header .meta { display: flex; flex-wrap: wrap; gap: 24px; opacity: 0.9; font-size: 0.875rem; }
        .header code { background: rgba(255,255,255,0.15); padding: 2px 8px; border-radius: 6px; font-family: monospace; }

        /* Banner */
        .alert-banner { background: #fffbeb; border: 1px solid #fef3c7; border-left: 4px solid #f59e0b; padding: 16px 20px; border-radius: 12px; margin-bottom: 24px; display: flex; gap: 16px; align-items: flex-start; }
        .alert-content { font-size: 0.875rem; color: #92400e; }
        .alert-content strong { color: #78350f; display: block; margin-bottom: 4px; }

        /* Dashboard Stats */
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .stat-card { background: white; padding: 20px; border-radius: 12px; text-align: center; border: 1px solid #e2e8f0; transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1); cursor: pointer; }
        .stat-card:hover { transform: translateY(-2px); box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
        .stat-card.active { border: 2px solid #3b82f6; background: #eff6ff; }
        .stat-card .number { font-size: 1.875rem; font-weight: 800; display: block; }
        .stat-card .label { font-size: 0.75rem; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }
        
        .critical .number { color: #ef4444; }
        .high .number { color: #f97316; }
        .medium .number { color: #eab308; }
        .low .number { color: #06b6d4; }

        /* Controls Area */
        .controls-container { background: white; padding: 24px; border-radius: 16px; border: 1px solid #e2e8f0; margin-bottom: 24px; display: flex; flex-direction: column; gap: 20px; }
        .search-box { display: flex; gap: 8px; }
        .search-input { flex: 1; padding: 12px 16px; border: 1px solid #cbd5e1; border-radius: 10px; font-size: 0.95rem; transition: all 0.2s; }
        .search-input:focus { outline: none; border-color: #3b82f6; ring: 2px solid #bfdbfe; }
        .search-button { padding: 12px 24px; background: #3b82f6; color: white; border: none; border-radius: 10px; font-size: 0.95rem; font-weight: 600; cursor: pointer; transition: all 0.2s; }
        .search-button:hover { background: #2563eb; }
        .search-button:active { transform: scale(0.98); }
        
        .filters-row { display: flex; flex-wrap: wrap; gap: 16px; align-items: center; }
        .filter-group { display: flex; align-items: center; gap: 8px; }
        .filter-label { font-size: 0.75rem; font-weight: 700; color: #64748b; text-transform: uppercase; }
        .filter-select { padding: 8px 12px; border: 1px solid #cbd5e1; border-radius: 8px; background: #fff; min-width: 130px; cursor: pointer; font-size: 0.875rem; }

        /* Findings UI */
        .findings { background: white; border-radius: 16px; border: 1px solid #e2e8f0; }
        .findings-header { padding: 20px 24px; background: #f8fafc; border-bottom: 1px solid #e2e8f0; font-weight: 800; font-size: 1.1rem; }
        .finding { padding: 32px 24px; border-bottom: 1px solid #f1f5f9; transition: background 0.2s; }
        .finding:hover { background: #fafafa; }
        
        .finding-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; }
        .finding-title { font-size: 1.25rem; font-weight: 700; color: #0f172a; display: flex; align-items: center; gap: 10px; }
        
        .type-tag { padding: 4px 10px; border-radius: 6px; font-size: 0.7rem; font-weight: 800; }
        .type-static { background: #dbeafe; color: #1e40af; }
        .type-dynamic { background: #fee2e2; color: #991b1b; }
        
        .severity-badge { padding: 4px 12px; border-radius: 20px; font-size: 0.7rem; font-weight: 800; }
        .severity-badge.critical { background: #ef4444; color: white; }
        .severity-badge.high { background: #f97316; color: white; }
        .severity-badge.medium { background: #facc15; color: #854d0e; }
        .severity-badge.low { background: #22d3ee; color: #164e63; }

        .finding-meta { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 16px; font-size: 0.85rem; color: #64748b; }
        .meta-item b { color: #475569; }

        .finding-desc { margin-bottom: 20px; color: #334155; font-size: 0.95rem; }
        
        .finding-code { background: #0f172a; border-radius: 12px; padding: 20px; margin-bottom: 20px; color: #e2e8f0; font-family: 'Fira Code', monospace; font-size: 0.85rem; overflow-x: auto; border: 1px solid #1e293b; }
        .finding-evidence { background: #f1f5f9; padding: 16px; border-radius: 10px; font-size: 0.85rem; border-left: 4px solid #cbd5e1; margin-bottom: 20px; white-space: pre-wrap; font-family: monospace; }
        
        .recommendation { background: #f0fdf4; border: 1px solid #dcfce7; padding: 16px 20px; border-radius: 10px; color: #166534; font-size: 0.9rem; display: flex; gap: 12px; align-items: center; }
        
        /* Helpers */
        .hidden { display: none !important; }
        .fade-in { animation: fadeIn 0.4s ease-out; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        
        .no-findings { padding: 80px 40px; text-align: center; color: #64748b; }
        .no-findings h2 { color: #0f172a; margin-bottom: 8px; }
    </style>
</head>
<body>
    <div class="container fade-in">
        <div class="header">
            <h1>{{ title }}</h1>
            <div class="meta">
                <span>目标: <code>{{ target }}</code></span>
                <span>时间: {{ scan_date }}</span>
                <span>耗时: {{ "%.2f"|format(scan_time) }}s</span>
                <span>文件: {{ files_scanned }}</span>
            </div>
        </div>

        <div class="alert-banner">
            <div style="font-size: 1.5rem;">⚠️</div>
            <div class="alert-content">
                <strong>显示说明：动态执行分析</strong>
                红色“动态”标签代表运行时捕获的行为。由于这些行为是在程序执行期间触发的，可能无法自动关联到具体的源代码行号。建议参考“运行时证据”字段。
            </div>
        </div>

        <div class="stats">
            <div class="stat-card critical" onclick="toggleQuickFilter('CRITICAL')">
                <span class="number">{{ summary.by_severity.critical|default(0) }}</span>
                <span class="label">严重</span>
            </div>
            <div class="stat-card high" onclick="toggleQuickFilter('HIGH')">
                <span class="number">{{ summary.by_severity.high|default(0) }}</span>
                <span class="label">高危</span>
            </div>
            <div class="stat-card medium" onclick="toggleQuickFilter('MEDIUM')">
                <span class="number">{{ summary.by_severity.medium|default(0) }}</span>
                <span class="label">中危</span>
            </div>
            <div class="stat-card low" onclick="toggleQuickFilter('LOW')">
                <span class="number">{{ summary.by_severity.low|default(0) }}</span>
                <span class="label">低危</span>
            </div>
            <div class="stat-card" style="background:#f1f5f9" onclick="toggleQuickFilter('all')">
                <span class="number">{{ summary.total_findings }}</span>
                <span class="label">总计</span>
            </div>
        </div>

        <div class="controls-container">
            <div class="search-box">
                <input type="text" id="searchInput" class="search-input" placeholder="搜索组件、漏洞描述或文件路径..." onkeyup="debouncedFilter()">
                <button class="search-button" onclick="filterFindings()">搜索</button>
            </div>
            
            <div class="filters-row">
                <div class="filter-group">
                    <span class="filter-label">📁 目标文件:</span>
                    <div class="multi-select-container" style="position:relative;">
                        <div class="filter-select" onclick="toggleMultiSelect('fileOptions')" id="fileFilterTitle">所有文件</div>
                        <div id="fileOptions" class="multi-select-options" style="position:absolute; background:white; border:1px solid #ddd; z-index:100; min-width:260px; max-height:300px; overflow-y:auto; padding:10px; border-radius:12px; box-shadow:0 10px 15px -3px rgba(0,0,0,0.1); display:none; top:100%; margin-top:5px;"></div>
                    </div>
                </div>
                
                <div class="filter-group">
                    <span class="filter-label">🔍 扫描类型:</span>
                    <select id="typeFilter" class="filter-select" onchange="filterFindings()">
                        <option value="all">所有类型</option>
                        <option value="static">静态模式</option>
                        <option value="dynamic">动态监控</option>
                    </select>
                </div>

                <div class="filter-group">
                    <span class="filter-label">📊 风险过滤:</span>
                    <select id="severityFilter" class="filter-select" onchange="filterFindings()">
                        <option value="all">全量结果</option>
                        <option value="CRITICAL">严重</option>
                        <option value="HIGH">高危</option>
                        <option value="MEDIUM">中危</option>
                        <option value="LOW">低危</option>
                    </select>
                </div>

                <div style="margin-left:auto; font-size:0.8rem; font-weight:700; color:#3b82f6;">
                    当前展示: <span id="visibleCount">{{ findings|length }}</span>
                </div>
            </div>
        </div>

        <div class="findings" id="findingsWrapper">
            <div class="findings-header">扫描项列表</div>
            <div id="findingsList">
                {% for finding in findings %}
                <div class="finding" 
                     data-severity="{{ finding.severity }}" 
                     data-type="{{ finding.type }}"
                     data-file="{{ finding.file }}"
                     data-content="{{ finding.title }} {{ finding.description }} {{ finding.file }} {{ finding.category }}">
                    
                    <div class="finding-header">
                        <div class="finding-title">
                            <span class="type-tag type-{{ finding.type }}">{{ '静态' if finding.type == 'static' else '动态' }}</span>
                            {{ finding.title }}
                        </div>
                        <span class="severity-badge {{ finding.severity|lower }}">{{ finding.severity_label }}</span>
                    </div>

                    <div class="finding-meta">
                        <span><b>类别:</b> {{ finding.category }}</span>
                        <span><b>引擎:</b> {{ finding.analyzer }}</span>
                        {% if finding.file %}<span><b>文件:</b> {{ finding.file }}</span>{% endif %}
                        {% if finding.line %}<span><b>行号:</b> {{ finding.line }}</span>{% endif %}
                    </div>

                    <div class="finding-desc">{{ finding.description }}</div>

                    {% if finding.type == 'dynamic' and finding.evidence %}
                    <div class="finding-evidence"><b>运行时证据:</b><br>{{ finding.evidence }}</div>
                    {% endif %}

                    {% if finding.code_snippet %}
                    <div class="finding-code"><pre><code>{{ finding.code_snippet }}</code></pre></div>
                    {% endif %}

                    <div class="recommendation">
                        <span><b>修复方案:</b> {{ finding.recommendation }}</span>
                    </div>
                </div>
                {% endfor %}
            </div>

            <div id="noResultsUI" class="no-findings hidden">
                <h2>未发现匹配记录</h2>
                <p>请尝试重置过滤条件或更换关键词。</p>
            </div>
        </div>
    </div>

    <script>
        let selectedFiles = new Set();
        let timeout = null;

        function toggleMultiSelect(id) {
            const dropdown = document.getElementById(id);
            dropdown.style.display = dropdown.style.display === 'none' ? 'block' : 'none';
        }

        window.onclick = function(event) {
            if (!event.target.closest('.multi-select-container')) {
                document.querySelectorAll('.multi-select-options').forEach(o => o.style.display = 'none');
            }
        };

        function debouncedFilter() {
            clearTimeout(timeout);
            timeout = setTimeout(filterFindings, 250);
        }

        function toggleQuickFilter(severity) {
            document.getElementById('severityFilter').value = severity;
            document.querySelectorAll('.stat-card').forEach(c => c.classList.remove('active'));
            if (severity !== 'all') {
                const activeCard = document.querySelector(`.stat-card.${severity.toLowerCase()}`);
                if (activeCard) activeCard.classList.add('active');
            }
            filterFindings();
        }

        function filterFindings() {
            const searchText = document.getElementById('searchInput').value.toLowerCase();
            const selectedSeverity = document.getElementById('severityFilter').value.toUpperCase();
            const selectedType = document.getElementById('typeFilter').value;
            const cards = document.querySelectorAll('.finding');
            let visibleCount = 0;

            cards.forEach(card => {
                const searchContent = card.getAttribute('data-content').toLowerCase();
                const file = card.getAttribute('data-file');
                const severity = (card.getAttribute('data-severity') || '').toUpperCase();
                const type = card.getAttribute('data-type');

                const matchesSearch = !searchText || searchContent.includes(searchText);
                const matchesFile = selectedFiles.size === 0 || selectedFiles.has(file);
                const matchesSeverity = selectedSeverity === 'ALL' || severity === selectedSeverity;
                const matchesType = selectedType === 'all' || type === selectedType;

                if (matchesSearch && matchesFile && matchesSeverity && matchesType) {
                    card.classList.remove('hidden');
                    visibleCount++;
                } else {
                    card.classList.add('hidden');
                }
            });

            document.getElementById('visibleCount').textContent = visibleCount;
            document.getElementById('noResultsUI').classList.toggle('hidden', visibleCount > 0);
            document.getElementById('findingsList').classList.toggle('hidden', visibleCount === 0);
        }

        document.addEventListener('DOMContentLoaded', function() {
            const cards = document.querySelectorAll('.finding');
            const fileSet = new Set();
            cards.forEach(c => {
                const f = c.getAttribute('data-file');
                if (f && f.trim()) fileSet.add(f);
            });

            const sortedFiles = Array.from(fileSet).sort();
            const container = document.getElementById('fileOptions');

            if (sortedFiles.length > 0) {
                const allLabel = document.createElement('label');
                allLabel.style.display = 'flex';
                allLabel.style.alignItems = 'center';
                allLabel.style.gap = '8px';
                allLabel.style.padding = '8px';
                allLabel.style.cursor = 'pointer';
                allLabel.style.borderBottom = '1px solid #f1f5f9';
                allLabel.innerHTML = `<input type="checkbox" id="selectAll"> <b>选择全部文件</b>`;
                container.appendChild(allLabel);

                const list = document.createElement('div');
                list.style.marginTop = '8px';
                sortedFiles.forEach(file => {
                    const item = document.createElement('label');
                    item.style.display = 'flex';
                    item.style.alignItems = 'center';
                    item.style.gap = '8px';
                    item.style.padding = '6px 8px';
                    item.style.cursor = 'pointer';
                    item.style.fontSize = '0.8rem';
                    const fileName = file.split(/[\\\\/]/).pop() || file;
                    item.innerHTML = `<input type="checkbox" class="file-cb" value="${file}"> <span title="${file}">${fileName}</span>`;
                    list.appendChild(item);
                });
                container.appendChild(list);

                document.getElementById('selectAll').onchange = (e) => {
                    const checked = e.target.checked;
                    document.querySelectorAll('.file-cb').forEach(cb => {
                        cb.checked = checked;
                        if (checked) selectedFiles.add(cb.value);
                        else selectedFiles.delete(cb.value);
                    });
                    updateTitle();
                    filterFindings();
                };

                document.querySelectorAll('.file-cb').forEach(cb => {
                    cb.onchange = (e) => {
                        if (e.target.checked) selectedFiles.add(e.target.value);
                        else selectedFiles.delete(e.target.value);
                        updateTitle();
                        filterFindings();
                    };
                });
            } else {
                container.innerHTML = '<div style="padding:20px; text-align:center; color:#94a3b8;">无关联文件</div>';
            }

            function updateTitle() {
                const title = document.getElementById('fileFilterTitle');
                if (selectedFiles.size === 0) title.textContent = "所有文件";
                else title.textContent = `已选 ${selectedFiles.size} 个文件`;
            }
        });
    </script>
</body>
</html>'''

    def _generate_json(self, results: Dict, output_dir: str, base_name: str) -> str:
        """生成JSON报告"""
        output_path = os.path.join(output_dir, f"{base_name}.json")
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        return output_path
    
    def _generate_txt(self, results: Dict, output_dir: str, base_name: str) -> str:
        """生成文本报告"""
        lines = []
        lines.append("=" * 70)
        lines.append("Argus-Scanner 安全扫描报告")
        lines.append("=" * 70)
        lines.append(f"\n扫描目标: {results.get('target', '')}")
        lines.append(f"扫描时间: {results.get('scan_date', '')}")
        lines.append(f"扫描耗时: {results.get('scan_time', 0):.2f} 秒")
        lines.append(f"扫描文件: {results.get('files_scanned', 0)} 个")
        
        summary = results.get('summary', {})
        lines.append(f"\n{'=' * 70}")
        lines.append("扫描结果摘要")
        lines.append("=" * 70)
        lines.append(f"总发现数: {summary.get('total_findings', 0)}")
        
        by_severity = summary.get('by_severity', {})
        lines.append(f"  严重: {by_severity.get('critical', 0)}")
        lines.append(f"  高危: {by_severity.get('high', 0)}")
        lines.append(f"  中危: {by_severity.get('medium', 0)}")
        lines.append(f"  低危: {by_severity.get('low', 0)}")
        
        findings = results.get('findings', [])
        if findings:
            lines.append(f"\n{'=' * 70}")
            lines.append("详细发现")
            lines.append("=" * 70)
            
            for i, finding in enumerate(findings, 1):
                lines.append(f"\n[{i}] {finding.get('title', 'Unknown')}")
                lines.append(f"    严重程度: {finding.get('severity', 'unknown')}")
                lines.append(f"    类别: {finding.get('category', 'unknown')}")
                lines.append(f"    文件: {finding.get('file', '')}")
                lines.append(f"    行号: {finding.get('line', 0)}")
                lines.append(f"    描述: {finding.get('description', '')}")
                if finding.get('recommendation'):
                    lines.append(f"    建议: {finding.get('recommendation')}")
        
        output_path = os.path.join(output_dir, f"{base_name}.txt")
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        
        return output_path

