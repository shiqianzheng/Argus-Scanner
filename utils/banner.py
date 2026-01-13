"""
程序横幅模块
"""

from colorama import Fore, Style

def get_banner():
    """获取程序横幅"""
    # 使用 r 前缀处理 ASCII 艺术中的反斜杠
    content = rf"""
{Fore.CYAN}
    _                              ____                                  
   / \   _ __ __ _ _   _ ___      / ___|  ___ __ _ _ __  _ __   ___ _ __ 
  / _ \ | '__/ _` | | | / __|_____\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 / ___ \| | | (_| | |_| \__ \_____|___) | (_| (_| | | | | | | |  __/ |   
/_/   \_\_|  \__, |\__,_|___/     |____/ \___\__,_|_| |_|_| |_|\___|_|   
             |___/                                                       
{Style.RESET_ALL}
{Fore.YELLOW}  Argus-Scanner 开源软件后门木马和安全漏洞检测系统{Style.RESET_ALL}
{Fore.GREEN}  支持语言: Python, Java, Go, C/C++{Style.RESET_ALL}
{Fore.WHITE}  ============================================{Style.RESET_ALL}
"""
    return content