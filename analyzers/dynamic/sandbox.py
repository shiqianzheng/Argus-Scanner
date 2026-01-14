
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
        self.container_name = "argus"
        self.image_tag = "argus-sandbox:latest"
        self.dockerfile_path = os.path.join(os.path.dirname(__file__), "Dockerfile")
        # Initialize Docker client
        try:
            self.client = docker.from_env()
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
            container = self.client.containers.run(
                target_image,
                command=["tail", "-f", "/dev/null"],
                name=self.container_name,
                detach=True,
                volumes={mount_dir: {'bind': '/app', 'mode': 'rw'}},
                working_dir='/app',
                cap_add=['SYS_PTRACE'],
                security_opt=['seccomp:unconfined']
            )
            self.logger.info(f"已创建沙箱容器 {self.container_name} 并挂载 {mount_dir} -> /app")

        return container

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
            
        target_image = self.image_tag

        # Ensure image exists (build if missing)
        try:
            self._ensure_image_built(target_image)
        except Exception as e:
            return {'error': f'Failed to build sandbox image: {e}'}

        container = None
        try:
            # Get or create reusable container
            container = self._get_or_create_container(mount_dir, target_image)

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
        res = self.run(executable, [])
        
        # Map the new run method's dictionary output to the old tuple format
        exit_code = res.get('exit_code', -1)
        stdout = res.get('stdout', '')
        stderr = res.get('error', '') # Map 'error' from new method to stderr
        strace_output = res.get('strace_log', '')

        return exit_code, stdout, stderr, strace_output
