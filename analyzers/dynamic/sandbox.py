
import docker
import os
import tarfile
import io
import time
from typing import Dict, List, Any
from utils.logger import get_logger

class Sandbox:
    """Docker Sandbox for securely executing code."""

    def __init__(self, config=None):
        self.logger = get_logger()
        # Initialize Docker client
        try:
            self.client = docker.from_env()
            self.client.ping()
        except Exception as e:
            self.logger.warning(f"Failed to connect to Docker daemon: {e}")
            self.client = None

        self.image = "python:3.9-slim" # Base image
        # Install necessary tools in the base image dynamically if needed
        # Or preferably assume a pre-built image. For this course project, 
        # we might assume the image has `strace` or we install it.
        # But installing apt-get update in every run is slow.
        # Let's try to use a standard image and maybe accept limited monitoring or install on fly.
        
    def is_available(self):
        return self.client is not None

    def run(self, executable: Dict, files: List[str]) -> Dict[str, Any]:
        """执行可执行文件及其相关文件。"""
        if not self.client:
            return {'error': 'Docker daemon not available'}
            
        language = executable.get('type', 'python')
        cmd = executable.get('cmd')
        target_path = executable.get('path')
        
        # 确定挂载目录
        if os.path.isdir(target_path):
            mount_dir = os.path.abspath(target_path)
        else:
            mount_dir = os.path.abspath(os.path.dirname(target_path))
            
        image_map = {
            'python': 'python:3.9',
            'c': 'gcc:latest',
            'cpp': 'gcc:latest',
            'go': 'golang:latest',
            'java': 'openjdk:11',
            'custom': 'ubuntu:20.04'
        }
        
        target_image = image_map.get(language, 'python:3.9-slim')
        
        # Ensure image exists
        try:
             self.client.images.get(target_image)
        except docker.errors.ImageNotFound:
             self.logger.info(f"Pulling image {target_image}...")
             self.client.images.pull(target_image)

        container = None
        try:
            # Create container
            # We configure 'cap_add=["SYS_PTRACE"]' to allow strace work inside container
            container = self.client.containers.run(
                target_image,
                command="/bin/sleep 3600", # Start and keep alive
                detach=True,
                volumes={mount_dir: {'bind': '/app', 'mode': 'rw'}},
                working_dir='/app',
                cap_add=['SYS_PTRACE'],
                security_opt=['seccomp:unconfined'] # Often needed for strace
            )

            # Install strace and basic tools if needed
            exit_code, _ = container.exec_run("which strace")
            if exit_code != 0:
                self.logger.info("沙箱环境缺少监控工具 strace，准备进行自动安装...")
                self.logger.info("提示：首次安装可能需要 1-3 分钟，取决于您的网络环境 (Debian/Ubuntu 官方源速度)。")
                
                if 'alpine' in target_image:
                     self.logger.info("正在通过 apk 安装 strace (Alpine)...")
                     container.exec_run("apk add --no-cache strace")
                else:
                     self.logger.info("正在同步软件包列表 (apt-get update)...")
                     container.exec_run("apt-get update")
                     self.logger.info("正在下载并安装 strace (apt-get install)...")
                     container.exec_run("apt-get install -y strace")
                
                self.logger.info("strace 安装完成，开始执行分析任务。")

            # Run with strace
            final_cmd = f"strace -f -o /tmp/strace.log {cmd}"
            self.logger.info(f"Executing in container: {final_cmd}")
            
            # Exec run
            exec_res = container.exec_run(
                ["/bin/sh", "-c", final_cmd],
                workdir='/app'
            )
            
            # Read strace log
            strace_out = ""
            try:
                bits, stat = container.get_archive("/tmp/strace.log")
                bio = io.BytesIO()
                for chunk in bits:
                    bio.write(chunk)
                bio.seek(0)
                with tarfile.open(fileobj=bio) as tar:
                    f = tar.extractfile("strace.log")
                    if f:
                        strace_out = f.read().decode('utf-8', errors='ignore')
            except Exception as e:
                self.logger.warning(f"Could not retrieve strace log: {e}")

            return {
                'exit_code': exec_res.exit_code,
                'stdout': exec_res.output.decode('utf-8', errors='ignore'),
                'strace_log': strace_out
            }

        except Exception as e:
            self.logger.error(f"Sandbox Error: {e}")
            return {'error': str(e)}
        finally:
            if container:
                try:
                    container.kill()
                    container.remove()
                except:
                    pass

    def run_with_strace(self, file_path, language, timeout=30):
        """
        Run a file in a docker container with strace monitoring.
        Returns: (exit_code, stdout, stderr, strace_output)
        """
        # Prepare mount or file copy
        abs_path = os.path.abspath(file_path)
        file_name = os.path.basename(abs_path)

        # Determine execution command
        run_cmd_str = ""
        if language == 'python':
            run_cmd_str = f"python {file_name}"
        elif language == 'c':
            run_cmd_str = f"gcc {file_name} -o app && ./app"
        elif language == 'cpp':
            run_cmd_str = f"g++ {file_name} -o app && ./app"
        elif language == 'go':
            run_cmd_str = f"go run {file_name}"
        elif language == 'java':
            # Assuming filename matches class name for simplicity
            class_name = os.path.splitext(file_name)[0]
            run_cmd_str = f"javac {file_name} && java {class_name}"
        else:
            run_cmd_str = file_name # Default to just running the file

        executable = {
            'type': language,
            'path': file_path,
            'cmd': run_cmd_str
        }
        res = self.run(executable, [])
        
        # Map the new run method's dictionary output to the old tuple format
        exit_code = res.get('exit_code', -1)
        stdout = res.get('stdout', '')
        stderr = res.get('error', '') # Map 'error' from new method to stderr
        strace_output = res.get('strace_log', '')

        return exit_code, stdout, stderr, strace_output
