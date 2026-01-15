"""
Argus-Scanner - 开源软件后门木马和安全漏洞检测系统
主入口文件
"""

import argparse
import sys
import os
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent))

from core.scanner import CodeScanner
from core.config import Config
from core.report import ReportGenerator
from utils.logger import setup_logger
from utils.banner import get_banner
from colorama import init, Fore, Style

# 初始化colorama
init()

def print_banner():
    """打印程序横幅"""
    print(get_banner())

def main():
    """主函数"""
    # Windows 下保持默认编码 (GBK) 以匹配 cmd/powershell，但忽略不支持的字符 (如 emoji) 以防报错
    # if sys.platform == 'win32':
    #     import io
    #     sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding=sys.stdout.encoding, errors='replace')
    #     sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding=sys.stderr.encoding, errors='replace')

    
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='Argus-Scanner - 开源软件后门木马和安全漏洞检测系统',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        'target',
        nargs='?',
        help='要扫描的目标路径（文件或目录）'
    )
    
    parser.add_argument(
        '-c', '--config',
        default='config.yaml',
        help='配置文件路径（默认: config.yaml）'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='./reports',
        help='报告输出目录（默认: ./reports）'
    )
    
    parser.add_argument(
        '-f', '--format',
        choices=['html', 'json', 'txt', 'all'],
        default='html',
        help='报告格式（默认: html）'
    )
    
    parser.add_argument(
        '--static-only',
        action='store_true',
        help='仅进行静态分析'
    )
    
    parser.add_argument(
        '--dynamic-only',
        action='store_true',
        help='仅进行动态分析'
    )
    
    parser.add_argument(
        '--language',
        choices=['python', 'java', 'go', 'c', 'cpp', 'auto'],
        default='auto',
        help='指定源代码语言（默认: auto自动检测）'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='显示详细输出'
    )
    
    parser.add_argument(
        '--web',
        action='store_true',
        help='启动Web界面'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Web服务端口（默认: 5000）'
    )
    
    parser.add_argument(
        '--exec-cmd',
        help='动态分析时手动指定运行命令（例如: "python main.py" 或 "java -jar target/app.jar"）'
    )
    
    # 沙箱控制参数
    parser.add_argument(
        '--docker-image',
        help='指定用于沙箱分析的Docker镜像（覆盖默认语言镜像）'
    )
    
    parser.add_argument(
        '--manual-setup',
        action='store_true',
        help='沙箱环境手动配置模式（跳过自动依赖安装）'
    )
    
    parser.add_argument(
        '--clean',
        action='store_true',
        help='清理项目的沙箱容器'
    )
    
    args = parser.parse_args()
    
    # 设置日志
    log_level = 'DEBUG' if args.verbose else 'INFO'
    logger = setup_logger(log_level)
    
    # 启动Web界面
    if args.web:
        logger.info("启动Web界面...")
        from web.app import create_app
        app = create_app()
        app.run(host='127.0.0.1', port=args.port, debug=args.verbose)
        return
    
    # 检查目标参数
    if not args.target:
        parser.print_help()
        print(f"\n{Fore.RED}错误: 请指定要扫描的目标路径{Style.RESET_ALL}")
        sys.exit(1)
    
    # 检查目标是否存在
    target_path = Path(args.target)
    if not target_path.exists():
        print(f"{Fore.RED}错误: 目标路径不存在: {args.target}{Style.RESET_ALL}")
        sys.exit(1)
    
    # 加载配置
    config = Config(args.config)
    
    # 创建扫描器
    scanner = CodeScanner(config)
    
    # 执行扫描
    print(f"\n{Fore.CYAN}[*] 开始扫描: {args.target}{Style.RESET_ALL}")
    
    scan_options = {
        'static': not args.dynamic_only,
        'dynamic': not args.static_only,
        'language': args.language,
        'exec_cmd': args.exec_cmd,
        'sandbox_image': args.docker_image,
        'manual_setup': args.manual_setup,
        'cleanup_container': args.clean
    }
    
    results = scanner.scan(str(target_path), **scan_options)
    
    # 生成报告
    print(f"\n{Fore.CYAN}[*] 生成报告...{Style.RESET_ALL}")
    
    report_gen = ReportGenerator(config)
    report_path = report_gen.generate(results, args.output, args.format)
    
    # 打印摘要
    print_summary(results)
    
    print(f"\n{Fore.GREEN}[+] 报告已保存到: {report_path}{Style.RESET_ALL}")

def print_summary(results):
    """打印扫描结果摘要"""
    print(f"\n{Fore.WHITE}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}扫描结果摘要{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{'='*60}{Style.RESET_ALL}")
    
    # 统计各类问题
    critical = sum(1 for r in results.get('findings', []) if r.get('severity', '').lower() == 'critical')
    high = sum(1 for r in results.get('findings', []) if r.get('severity', '').lower() == 'high')
    medium = sum(1 for r in results.get('findings', []) if r.get('severity', '').lower() == 'medium')
    low = sum(1 for r in results.get('findings', []) if r.get('severity', '').lower() == 'low')
    
    print(f"  扫描文件数: {results.get('files_scanned', 0)}")
    print(f"  扫描时间: {results.get('scan_time', 0):.2f}秒")
    print(f"\n  {Fore.RED}严重 (Critical): {critical}{Style.RESET_ALL}")
    print(f"  {Fore.MAGENTA}高危 (High): {high}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}中危 (Medium): {medium}{Style.RESET_ALL}")
    print(f"  {Fore.BLUE}低危 (Low): {low}{Style.RESET_ALL}")
    
    total = critical + high + medium + low
    if total > 0:
        print(f"\n  {Fore.RED}[!] 共发现 {total} 个安全问题{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.GREEN}[OK] 未发现安全问题{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
