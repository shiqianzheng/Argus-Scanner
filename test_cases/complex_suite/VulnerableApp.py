from flask import Flask, request, render_template_string
import requests
import os

app = Flask(__name__)

@app.route('/profile')
def profile():
    # 1. SSTI (Server-Side Template Injection) - True Positive
    # 直接将用户输入渲染到模板中
    username = request.args.get('username', 'Guest')
    template = f"<h1>Hello, {username}!</h1>" # 危险！
    return render_template_string(template)

@app.route('/fetch_url')
def fetch():
    # 2. SSRF (Server-Side Request Forgery) - True Positive
    # 允许用户控制请求的目标 URL
    target_url = request.args.get('url')
    
    # 简单的黑名单 (容易被绕过)
    if "localhost" in target_url or "127.0.0.1" in target_url:
        return "Access denied", 403
        
    try:
        # 直接使用 requests.get 访问用户提供的 URL
        response = requests.get(target_url, timeout=5) 
        return response.content
    except Exception as e:
        return str(e)

@app.route('/safe_ping')
def safe_ping():
    # 3. 安全的命令执行 (列表参数) - True Negative
    ip = request.args.get('ip')
    
    # 简单的验证
    if not ip.replace('.', '').isdigit():
        return "Invalid IP"
        
    # 使用列表而不是字符串，且不使用 shell=True
    # 这在 Python 中通常被认为是安全的 (execvp)
    import subprocess
    subprocess.check_call(['ping', '-c', '1', ip]) 
    return "Pinged"
