
import docker
import os
import tarfile
import io
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from utils.logger import get_logger

class Sandbox:
    """Docker Sandbox for securely executing code and managing dependencies."""

    def __init__(self, config=None):
        self.logger = get_logger()
        self.config = config
        self.container_name = "argus"
        self.image_tag = "argus-sandbox:latest"
        self.dockerfile_path = os.path.join(os.path.dirname(__file__), "Dockerfile")
        # Initialize Docker client
        try:
            # 设置超时时间，避免在 Docker 未响应时无限等待
            self.client = docker.from_env(timeout=5)
            self.client.ping()
        except Exception as e:
            self.logger.warning(f"Failed to connect to Docker daemon: {e}")
            self.client = None

        self.image = self.image_tag # Base image

    def is_available(self):
        return self.client is not None

    def _ensure_image_built(self, target_image: str):
        """确保沙箱镜像存在，不存在则基于 dynamic/Dockerfile 构建。"""
        try:
            self.client.images.get(target_image)
            return
        except docker.errors.ImageNotFound:
            self.logger.info(f"未找到镜像 {target_image}，开始构建...")
        except Exception as e:
            self.logger.warning(f"检查镜像时出错，尝试重新构建: {e}")

        build_context = os.path.dirname(self.dockerfile_path)
        try:
            self.client.images.build(path=build_context, tag=target_image, rm=True, forcerm=True)
            self.logger.info(f"镜像 {target_image} 构建完成。")
        except Exception as e:
            self.logger.error(f"构建沙箱镜像失败: {e}")
            raise

    def _get_or_create_container(self, mount_dir: str, target_image: str):
        """
        获取或创建命名容器以复用沙箱。
        如果已存在但挂载目录不符，则删除并重新创建。
        """
        expected_bind = f"{mount_dir}:/app:rw"
        container = None

        try:
            container = self.client.containers.get(self.container_name)
            container.reload()
            binds = container.attrs.get("HostConfig", {}).get("Binds", [])
            if expected_bind not in binds:
                self.logger.info("已有沙箱容器挂载目录不匹配，重新创建以更新挂载。")
                container.remove(force=True)
                container = None
            elif container.status != "running":
                container.start()
        except docker.errors.NotFound:
            container = None
        except Exception as e:
            self.logger.warning(f"获取已有沙箱容器失败，将尝试重新创建: {e}")
            container = None

        if container is None:
            # 自动探测并挂载本地 Maven 仓库以加速并解决多模块依赖
            volumes = {mount_dir: {'bind': '/app', 'mode': 'rw'}}
            m2_path = os.path.expanduser("~/.m2/repository")
            if os.path.exists(m2_path):
                volumes[m2_path] = {'bind': '/root/.m2/repository', 'mode': 'rw'}
                self.logger.info(f"检测到本地 Maven 仓库，已同步挂载: {m2_path}")

            container = self.client.containers.run(
                target_image,
                command=["tail", "-f", "/dev/null"],
                name=self.container_name,
                detach=True,
                volumes=volumes,
                working_dir='/app',
                cap_add=['SYS_PTRACE'],
                security_opt=['seccomp:unconfined']
            )
            self.logger.info(f"已创建沙箱容器 {self.container_name} 并挂载 {mount_dir} -> /app")

        return container

    def run(self, executable: Dict, files: List[str], timeout: int = 10) -> Dict[str, Any]:
        """
        执行可执行文件及其相关文件。
        
        Args:
            executable: 可执行文件信息字典
            files: 文件列表
            timeout: 执行超时时间（秒），默认10秒
        """
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
            
        target_image = self.image_tag

        # Ensure image exists (build if missing)
        try:
            self._ensure_image_built(target_image)
        except Exception as e:
            return {'error': f'Failed to build sandbox image: {e}'}

        container = None
        timed_out = False
        execution_time = 0
        try:
            # Get or create reusable container
            container = self._get_or_create_container(mount_dir, target_image)

            # Run with strace and timeout
            # 使用 timeout 命令包装，超时后发送 SIGTERM，再等待1秒后发送 SIGKILL
            final_cmd = f"timeout -s TERM -k 1 {timeout} strace -f -o /tmp/strace.log {cmd}"
            self.logger.info(f"Executing in container (timeout={timeout}s): {final_cmd}")
            
            # Exec run with timeout
            start_time = time.time()
            exec_res = container.exec_run(
                ["/bin/sh", "-c", final_cmd],
                workdir='/app'
            )
            execution_time = time.time() - start_time
            
            # 检查是否超时（exit_code 124 表示 timeout 命令超时）
            timed_out = exec_res.exit_code == 124
            if timed_out:
                self.logger.warning(f"执行超时（{timeout}秒），已强制终止")
            
            # Read strace log
            strace_out = ""
            strace_file_path = None
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
                        
                        # 保存 strace 日志到文件
                        strace_file_path = self._save_strace_log(strace_out, target_path, language)
            except Exception as e:
                self.logger.warning(f"Could not retrieve strace log: {e}")

            return {
                'exit_code': exec_res.exit_code,
                'stdout': exec_res.output.decode('utf-8', errors='ignore'),
                'strace_log': strace_out,
                'strace_log_file': strace_file_path,
                'timed_out': timed_out,
                'execution_time': execution_time
            }

        except Exception as e:
            self.logger.error(f"Sandbox Error: {e}")
            return {'error': str(e)}
        finally:
            # 为复用容器，不做删除；只记录存在即可
            if container:
                try:
                    container.reload()
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
        res = self.run(executable, [], timeout=timeout)
        
        # Map the new run method's dictionary output to the old tuple format
        exit_code = res.get('exit_code', -1)
        stdout = res.get('stdout', '')
        stderr = res.get('error', '') # Map 'error' from new method to stderr
        strace_output = res.get('strace_log', '')

        return exit_code, stdout, stderr, strace_output

    def install_dependencies(self, project_path: str, language: str) -> Dict[str, Any]:
        """
        在沙箱中安装项目依赖（使用复用容器）。
        返回: {'status': 'success/failed/skipped/error', 'logs': '...', 'duration': float}
        """
        if not self.client:
            return {'status': 'error', 'logs': 'Docker daemon not available'}
        
        abs_path = os.path.abspath(project_path)
        if not os.path.exists(abs_path):
            return {'status': 'error', 'logs': f'路径不存在: {abs_path}'}
        
        # 确定挂载目录
        if os.path.isdir(abs_path):
            mount_dir = abs_path
        else:
            mount_dir = os.path.dirname(abs_path)
        
        # 准备安装命令
        install_cmd = self._get_install_command(language)
        if not install_cmd:
            return {'status': 'skipped', 'logs': '未检测到标准依赖文件，跳过安装'}
        
        container = None
        try:
            # 确保镜像存在
            try:
                self._ensure_image_built(self.image_tag)
            except Exception as e:
                return {'status': 'error', 'logs': f'镜像构建失败: {e}'}
            
            # 获取或创建复用容器
            container = self._get_or_create_container(mount_dir, self.image_tag)
            
            # 执行依赖安装
            self.logger.info(f"执行依赖安装命令: {install_cmd}")
            start_time = time.time()
            
            exec_res = container.exec_run(
                ["/bin/sh", "-c", install_cmd],
                workdir='/app'
            )
            
            duration = time.time() - start_time
            logs = exec_res.output.decode('utf-8', errors='replace')
            
            status = 'success' if exec_res.exit_code == 0 else 'failed'
            self.logger.info(f"依赖安装完成 (耗时 {duration:.2f}s), 状态: {status}")
            
            return {
                'status': status,
                'logs': logs,
                'duration': duration,
                'exit_code': exec_res.exit_code
            }
            
        except Exception as e:
            self.logger.error(f"依赖安装异常: {e}")
            return {'status': 'error', 'logs': str(e)}
        finally:
            # 容器复用，不删除
            if container:
                try:
                    container.reload()
                except:
                    pass

    def _get_install_command(self, language: str) -> Optional[str]:
        """
        根据语言生成自动安装命令。
        注意: 命令将被包裹在 sh -c 'CMD' 中运行，因此 CMD 内部不能包含未转义的单引号。
        """
        if language == 'python':
            # 优先检查 requirements.txt
            cmd = []
            cmd.append("if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; ")
            cmd.append("elif [ -f Pipfile ]; then pip install pipenv && pipenv install --system; ")
            cmd.append("elif [ -f pyproject.toml ]; then pip install .; ")
            cmd.append("else echo \"No python dependencies found\"; exit 0; fi")
            return "".join(cmd)
            
        elif language == 'java':
            # Maven / Gradle
            cmd = []
            cmd.append("if [ -f pom.xml ]; then mvn dependency:resolve -B -DskipTests; ") 
            cmd.append("elif [ -f build.gradle ]; then gradle dependencies; ")
            cmd.append("else echo \"No java dependencies found\"; exit 0; fi")
            return "".join(cmd)
            
        elif language == 'go':
            # go mod
            return "if [ -f go.mod ]; then go mod download; else echo \"No go dependencies found\"; exit 0; fi"
        
        elif language in ['c', 'cpp']:
            # C/C++ 项目通常不需要依赖安装，但可以检查 Makefile 或 CMakeLists.txt
            # 这里返回 None，表示跳过
            return None
        
        return None

    def _save_strace_log(self, strace_content: str, target_path: str, language: str) -> Optional[str]:
        """
        保存 strace 日志到文件
        
        Args:
            strace_content: strace 日志内容
            target_path: 目标文件或目录路径
            language: 编程语言
            
        Returns:
            保存的文件路径，失败返回 None
        """
        if not strace_content or not strace_content.strip():
            return None
        
        try:
            # 确定保存目录
            output_dir = self.config.get('system.output_dir', './reports') if self.config else './reports'
            temp_dir = self.config.get('system.temp_dir', './temp') if self.config else './temp'
            
            # 创建 strace_logs 子目录
            strace_logs_dir = os.path.join(temp_dir, 'strace_logs')
            os.makedirs(strace_logs_dir, exist_ok=True)
            
            # 生成文件名：strace_<target_name>_<timestamp>_<language>.log
            target_name = os.path.basename(target_path.rstrip('/'))
            if not target_name:
                target_name = 'unknown'
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"strace_{target_name}_{timestamp}_{language}.log"
            
            # 确保文件名安全（移除特殊字符）
            filename = "".join(c for c in filename if c.isalnum() or c in ('_', '-', '.'))
            
            file_path = os.path.join(strace_logs_dir, filename)
            
            # 写入文件
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(strace_content)
            
            self.logger.info(f"strace 日志已保存到: {file_path}")
            return file_path
            
        except Exception as e:
            self.logger.error(f"保存 strace 日志失败: {e}")
            return None
