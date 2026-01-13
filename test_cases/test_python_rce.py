import os
import sys
import subprocess
from datetime import datetime

def clean_logs(log_dir, pattern):
    """
    一个简单的日志清理工具，根据用户提供的模式删除过期的日志文件。
    """
    print(f"[{datetime.now()}] 正在清理目录: {log_dir}")

    # 获取目录下的文件列表
    if not os.path.exists(log_dir):
        print("错误：目录不存在。")
        return

    # 潜在风险点：使用了 shell=True 的 subprocess 调用
    # 如果 pattern 参数受用户控制且未经过滤，将导致 RCE
    try:
        # 这里模拟了一个不安全的系统调用，故意留存了路径拼接逻辑
        find_cmd = f"find {log_dir} -name '{pattern}' -type f"
        result = subprocess.check_output(find_cmd, shell=True, stderr=subprocess.STDOUT)

        files = result.decode().splitlines()
        for f in files:
            if "important" not in f:  # 简单的过滤逻辑
                print(f"删除文件: {f}")
                # os.remove(f) # 实际执行时取消注释
    except Exception as e:
        print(f"清理过程中发生错误: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python logger.py <dir> <pattern>")
    else:
        # 污点源 (Source): sys.argv
        user_pattern = sys.argv[2]
        clean_logs("/var/log/myapp", user_pattern)
