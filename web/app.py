"""
Argus-Scanner Web应用
Flask Web界面
"""

import os
import sys
import json
import tempfile
import shutil
from pathlib import Path
from datetime import datetime

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, render_template_string, request, jsonify, send_file
from flask_cors import CORS

from core.config import Config
from core.scanner import CodeScanner
from core.report import ReportGenerator


def create_app(config_path: str = None):
    """创建Flask应用"""
    app = Flask(__name__)
    CORS(app)
    
    # 加载配置
    config = Config(config_path)
    scanner = CodeScanner(config)
    report_gen = ReportGenerator(config)
    
    # 存储扫描历史
    scan_history = []
    
    @app.route('/')
    def index():
        """主页"""
        return render_template_string(get_index_html())
    
    @app.route('/api/scan', methods=['POST'])
    def scan():
        """执行扫描"""
        try:
            data = request.get_json()
            
            # 获取目标路径或代码内容
            target_path = data.get('path')
            code_content = data.get('code')
            language = data.get('language', 'auto')
            scan_type = data.get('scan_type', 'all')  # all, static, dynamic
            
            if code_content:
                # 如果提供了代码内容，保存到临时文件
                ext_map = {
                    'python': '.py',
                    'java': '.java',
                    'go': '.go',
                    'c': '.c',
                    'cpp': '.cpp'
                }
                ext = ext_map.get(language, '.txt')
                
                temp_dir = tempfile.mkdtemp()
                temp_file = os.path.join(temp_dir, f'code{ext}')
                with open(temp_file, 'w', encoding='utf-8') as f:
                    f.write(code_content)
                target_path = temp_file
            
            if not target_path or not os.path.exists(target_path):
                return jsonify({
                    'success': False,
                    'error': '目标路径不存在'
                }), 400
            
            # 执行扫描
            scan_options = {
                'static': scan_type in ['all', 'static'],
                'dynamic': scan_type in ['all', 'dynamic'],
                'language': language
            }
            
            results = scanner.scan(target_path, **scan_options)
            
            # 清理临时文件
            if code_content and 'temp_dir' in locals():
                shutil.rmtree(temp_dir, ignore_errors=True)
            
            # 保存到历史记录
            scan_record = {
                'id': len(scan_history) + 1,
                'date': datetime.now().isoformat(),
                'target': target_path if not code_content else 'code_snippet',
                'findings_count': len(results.get('findings', [])),
                'results': results
            }
            scan_history.append(scan_record)
            
            return jsonify({
                'success': True,
                'scan_id': scan_record['id'],
                'results': results
            })
        
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/history')
    def history():
        """获取扫描历史"""
        return jsonify({
            'success': True,
            'history': [
                {
                    'id': h['id'],
                    'date': h['date'],
                    'target': h['target'],
                    'findings_count': h['findings_count']
                }
                for h in scan_history[-20:]  # 最近20条
            ]
        })
    
    @app.route('/api/report/<int:scan_id>')
    def get_report(scan_id):
        """获取扫描报告"""
        for record in scan_history:
            if record['id'] == scan_id:
                return jsonify({
                    'success': True,
                    'results': record['results']
                })
        
        return jsonify({
            'success': False,
            'error': '未找到扫描记录'
        }), 404
    
    @app.route('/api/export/<int:scan_id>')
    def export_report(scan_id):
        """导出报告"""
        format_type = request.args.get('format', 'html')
        
        for record in scan_history:
            if record['id'] == scan_id:
                # 生成报告
                output_dir = tempfile.mkdtemp()
                report_path = report_gen.generate(
                    record['results'], 
                    output_dir, 
                    format_type
                )
                
                return send_file(
                    report_path,
                    as_attachment=True,
                    download_name=f'report_{scan_id}.{format_type}'
                )
        
        return jsonify({
            'success': False,
            'error': '未找到扫描记录'
        }), 404
    
    @app.route('/api/rules')
    def get_rules():
        """获取检测规则"""
        from analyzers.static import PatternMatcher
        pm = PatternMatcher(config)
        rules = pm.get_rules()
        
        return jsonify({
            'success': True,
            'rules': rules
        })
    
    return app


def get_index_html():
    """获取主页HTML"""
    return '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Argus-Scanner - 代码安全检测系统</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #fff;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        
        /* Header */
        .header {
            text-align: center;
            padding: 40px 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            margin-bottom: 30px;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(90deg, #00d4ff, #7c3aed);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .header p { color: #888; font-size: 1.1em; }
        
        /* Main Layout */
        .main-content { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; }
        
        /* Panels */
        .panel {
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 25px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1);
        }
        .panel h2 {
            font-size: 1.3em;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        /* Form Elements */
        .form-group { margin-bottom: 20px; }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #aaa;
            font-size: 0.9em;
        }
        input[type="text"], textarea, select {
            width: 100%;
            padding: 12px 15px;
            background: rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            color: #fff;
            font-size: 1em;
            transition: all 0.3s;
        }
        input[type="text"]:focus, textarea:focus, select:focus {
            outline: none;
            border-color: #00d4ff;
            box-shadow: 0 0 0 3px rgba(0,212,255,0.2);
        }
        textarea {
            font-family: 'Consolas', 'Monaco', monospace;
            min-height: 300px;
            resize: vertical;
        }
        
        /* Buttons */
        .btn {
            padding: 12px 25px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1em;
            font-weight: 600;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        .btn-primary {
            background: linear-gradient(90deg, #00d4ff, #7c3aed);
            color: white;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(0,212,255,0.4);
        }
        .btn-secondary {
            background: rgba(255,255,255,0.1);
            color: white;
        }
        .btn-secondary:hover { background: rgba(255,255,255,0.2); }
        
        /* Tabs */
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab {
            padding: 10px 20px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
        }
        .tab:hover, .tab.active {
            background: rgba(0,212,255,0.2);
            border-color: #00d4ff;
        }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        /* Results */
        .results-panel { grid-column: 1 / -1; }
        .summary-cards { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 25px; }
        .summary-card {
            background: rgba(255,255,255,0.05);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        .summary-card .number { font-size: 2.5em; font-weight: bold; }
        .summary-card .label { color: #888; font-size: 0.9em; }
        .summary-card.critical .number { color: #ef4444; }
        .summary-card.high .number { color: #ec4899; }
        .summary-card.medium .number { color: #f59e0b; }
        .summary-card.low .number { color: #06b6d4; }
        .summary-card:hover { cursor: pointer; transform: translateY(-2px); transition: all 0.3s; }
        .summary-card.active {
            background: rgba(0,212,255,0.2);
            border-color: #00d4ff;
            box-shadow: 0 5px 20px rgba(0,212,255,0.3);
        }
        
        /* Findings List */
        .findings-list { max-height: 500px; overflow-y: auto; }
        .finding {
            background: rgba(0,0,0,0.2);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #888;
        }
        .finding.critical { border-left-color: #ef4444; }
        .finding.high { border-left-color: #ec4899; }
        .finding.medium { border-left-color: #f59e0b; }
        .finding.low { border-left-color: #06b6d4; }
        
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .finding-title { font-weight: 600; font-size: 1.1em; }
        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
        }
        .severity-badge.critical { background: #ef4444; }
        .severity-badge.high { background: #ec4899; }
        .severity-badge.medium { background: #f59e0b; color: #000; }
        .severity-badge.low { background: #06b6d4; }
        
        .finding-meta { color: #888; font-size: 0.9em; margin-bottom: 10px; }
        .finding-description { margin-bottom: 10px; }
        .finding-code {
            background: #0d1117;
            padding: 15px;
            border-radius: 8px;
            font-family: monospace;
            overflow-x: auto;
            font-size: 0.9em;
        }
        .finding-recommendation {
            background: rgba(34,197,94,0.1);
            border-left: 3px solid #22c55e;
            padding: 10px 15px;
            margin-top: 10px;
            border-radius: 0 8px 8px 0;
        }
        
        /* Loading */
        .loading {
            display: none;
            text-align: center;
            padding: 40px;
        }
        .loading.active { display: block; }
        .spinner {
            width: 50px;
            height: 50px;
            border: 3px solid rgba(255,255,255,0.1);
            border-top-color: #00d4ff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        
        /* Options */
        .options { display: flex; gap: 15px; flex-wrap: wrap; margin-bottom: 20px; }
        .option {
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
        }
        .option input[type="checkbox"] {
            width: 18px;
            height: 18px;
            accent-color: #00d4ff;
        }
        
        /* No Results */
        .no-results {
            text-align: center;
            padding: 60px;
            color: #888;
        }
        .no-results svg {
            width: 80px;
            height: 80px;
            margin-bottom: 20px;
            opacity: 0.5;
        }
        
        /* Success Message */
        .success-message {
            background: rgba(34,197,94,0.2);
            border: 1px solid #22c55e;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        .success-message svg {
            width: 60px;
            height: 60px;
            color: #22c55e;
            margin-bottom: 15px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Argus-Scanner</h1>
            <p>开源软件后门木马和安全漏洞检测系统</p>
        </div>
        
        <div class="main-content">
            <div class="panel">
                <h2>📝 代码输入</h2>
                
                <div class="tabs">
                    <div class="tab active" onclick="switchTab('code')">粘贴代码</div>
                    <div class="tab" onclick="switchTab('path')">文件路径</div>
                </div>
                
                <div id="code-tab" class="tab-content active">
                    <div class="form-group">
                        <label>编程语言</label>
                        <select id="language">
                            <option value="auto">自动检测</option>
                            <option value="python">Python</option>
                            <option value="java">Java</option>
                            <option value="go">Go</option>
                            <option value="c">C</option>
                            <option value="cpp">C++</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>粘贴代码</label>
                        <textarea id="code-input" placeholder="在此粘贴要检测的代码..."></textarea>
                    </div>
                </div>
                
                <div id="path-tab" class="tab-content">
                    <div class="form-group">
                        <label>文件或目录路径</label>
                        <input type="text" id="path-input" placeholder="例如: C:\\Projects\\MyApp 或 /home/user/project">
                    </div>
                </div>
                
                <div class="options">
                    <label class="option">
                        <input type="checkbox" id="opt-static" checked>
                        <span>静态分析</span>
                    </label>
                    <label class="option">
                        <input type="checkbox" id="opt-dynamic" checked>
                        <span>动态分析</span>
                    </label>
                </div>
                
                <button class="btn btn-primary" onclick="startScan()">
                    🔍 开始扫描
                </button>
            </div>
            
            <div class="panel">
                <h2>ℹ️ 检测能力</h2>
                <div style="color: #aaa; line-height: 1.8;">
                    <p><strong>静态分析:</strong></p>
                    <ul style="margin-left: 20px; margin-bottom: 15px;">
                        <li>模式匹配 - 检测已知恶意代码模式</li>
                        <li>数据流分析 - 跟踪敏感数据传播</li>
                        <li>控制流分析 - 检测异常程序流程</li>
                        <li>污点分析 - 追踪不可信输入</li>
                        <li>依赖检查 - CVE漏洞数据库比对</li>
                    </ul>
                    <p><strong>动态分析:</strong></p>
                    <ul style="margin-left: 20px; margin-bottom: 15px;">
                        <li>系统调用监控</li>
                        <li>网络活动监控</li>
                        <li>文件操作监控</li>
                    </ul>
                    <p><strong>检测目标:</strong></p>
                    <ul style="margin-left: 20px;">
                        <li>反向Shell/绑定Shell</li>
                        <li>代码混淆/加密</li>
                        <li>SQL/命令注入</li>
                        <li>不安全的反序列化</li>
                        <li>硬编码凭证</li>
                        <li>内存安全分析 (New!)</li>
                        <li>更多...</li>
                    </ul>
                </div>
            </div>
            
            <div class="panel results-panel" id="results-panel" style="display: none;">
                <h2>📊 扫描结果</h2>
                
                <div class="loading" id="loading">
                    <div class="spinner"></div>
                    <p>正在扫描中，请稍候...</p>
                </div>
                
                <div id="results-content"></div>
            </div>
        </div>
    </div>
    
    <script>
        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            
            event.target.classList.add('active');
            document.getElementById(tab + '-tab').classList.add('active');
        }
        
        async function startScan() {
            const resultsPanel = document.getElementById('results-panel');
            const loading = document.getElementById('loading');
            const resultsContent = document.getElementById('results-content');
            
            resultsPanel.style.display = 'block';
            loading.classList.add('active');
            resultsContent.innerHTML = '';
            
            // 获取输入
            const codeTab = document.getElementById('code-tab').classList.contains('active');
            const language = document.getElementById('language').value;
            const staticAnalysis = document.getElementById('opt-static').checked;
            const dynamicAnalysis = document.getElementById('opt-dynamic').checked;
            
            let scanType = 'all';
            if (staticAnalysis && !dynamicAnalysis) scanType = 'static';
            if (!staticAnalysis && dynamicAnalysis) scanType = 'dynamic';
            
            const payload = {
                language: language,
                scan_type: scanType
            };
            
            if (codeTab) {
                payload.code = document.getElementById('code-input').value;
            } else {
                payload.path = document.getElementById('path-input').value;
            }
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                
                const data = await response.json();
                loading.classList.remove('active');
                
                if (data.success) {
                    displayResults(data.results);
                } else {
                    resultsContent.innerHTML = `<div class="finding critical"><div class="finding-title">错误: ${data.error}</div></div>`;
                }
            } catch (error) {
                loading.classList.remove('active');
                resultsContent.innerHTML = `<div class="finding critical"><div class="finding-title">请求失败: ${error.message}</div></div>`;
            }
        }
        
        // 全局变量用于跟踪当前筛选状态
        let currentFilter = 'all';
        let currentResults = null;
        
        function displayResults(results, filter = 'all') {
            const content = document.getElementById('results-content');
            const summary = results.summary || {};
            const allFindings = results.findings || [];
            const bySeverity = summary.by_severity || {};
            
            // 保存当前结果
            currentResults = results;
            currentFilter = filter;
            
            // 根据筛选条件过滤结果
            const findings = filter === 'all' ? allFindings : 
                           filter === 'critical' ? allFindings.filter(f => f.severity === 'critical') :
                           filter === 'high' ? allFindings.filter(f => f.severity === 'high') :
                           filter === 'medium' ? allFindings.filter(f => f.severity === 'medium') :
                           allFindings.filter(f => f.severity === 'low');
            
            let html = `
                <div class="summary-cards">
                    <div class="summary-card critical ${filter === 'critical' ? 'active' : ''}" onclick="filterBySeverity('critical')">
                        <div class="number">${bySeverity.critical || 0}</div>
                        <div class="label">严重</div>
                    </div>
                    <div class="summary-card high ${filter === 'high' ? 'active' : ''}" onclick="filterBySeverity('high')">
                        <div class="number">${bySeverity.high || 0}</div>
                        <div class="label">高危</div>
                    </div>
                    <div class="summary-card medium ${filter === 'medium' ? 'active' : ''}" onclick="filterBySeverity('medium')">
                        <div class="number">${bySeverity.medium || 0}</div>
                        <div class="label">中危</div>
                    </div>
                    <div class="summary-card low ${filter === 'low' ? 'active' : ''}" onclick="filterBySeverity('low')">
                        <div class="number">${bySeverity.low || 0}</div>
                        <div class="label">低危</div>
                    </div>
                    <div class="summary-card ${filter === 'all' ? 'active' : ''}" onclick="filterBySeverity('all')">
                        <div class="number">${summary.total_findings || 0}</div>
                        <div class="label">总计</div>
                    </div>
                </div>
            `;
            
            // 添加筛选提示
            html += `<div style="margin-bottom: 20px; color: #888; font-size: 0.9em;">
                当前显示: ${filter === 'all' ? '全部结果' : 
                           filter === 'critical' ? '严重漏洞' : 
                           filter === 'high' ? '高危漏洞' : 
                           filter === 'medium' ? '中危漏洞' : '低危漏洞'}
                ${filter !== 'all' ? ` (共 ${findings.length} 个)` : ''}
            </div>`;
            
            if (findings.length === 0) {
                html += `
                    <div class="success-message">
                        <svg viewBox="0 0 24 24" fill="currentColor">
                            <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
                        </svg>
                        <h3>未发现安全问题</h3>
                        <p>扫描完成，未检测到任何安全漏洞或可疑代码。</p>
                    </div>
                `;
            } else {
                html += '<div class="findings-list">';
                for (const finding of findings) {
                    html += `
                        <div class="finding ${finding.severity}">
                            <div class="finding-header">
                                <span class="finding-title">${finding.title}</span>
                                <span class="severity-badge ${finding.severity}">${finding.severity}</span>
                            </div>
                            <div class="finding-meta">
                                📁 ${finding.file || 'N/A'} | 📍 行 ${finding.line || 0} | 🏷️ ${finding.category || 'unknown'}
                            </div>
                            <div class="finding-description">${finding.description}</div>
                            ${finding.code_snippet ? `<div class="finding-code"><pre>${escapeHtml(finding.code_snippet)}</pre></div>` : ''}
                            ${finding.recommendation ? `<div class="finding-recommendation">💡 ${finding.recommendation}</div>` : ''}
                        </div>
                    `;
                }
                html += '</div>';
            }
            
            content.innerHTML = html;
        }
        
        function filterBySeverity(severity) {
            if (currentResults) {
                displayResults(currentResults, severity);
            }
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>'''


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)
