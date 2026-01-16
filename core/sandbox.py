"""
Docker 沙箱环境管理器
负责容器生命周期管理、文件挂载和隔离执行
"""

import os
import shutil
import tarfile
import tempfile
import time
import io
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any
from utils.logger import get_logger

try:
    import docker
    from docker.errors import APIError, ImageNotFound
    from docker.models.containers import Container
    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False

class SandboxManager:
    """沙箱管理器 - 管理 Docker 容器的安全执行环境"""
    
    def __init__(self, config):
        self.config = config
        self.logger = get_logger()
        self.client = None
        
        if not HAS_DOCKER:
            self.logger.warning("未检测到 docker 模块，沙箱功能将不可用。请运行 pip install docker")
            return
            
        try:
            self.client = docker.from_env()
            self.client.ping() # 测试连接
        except Exception as e:
            self.logger.error(f"无法连接到 Docker 服务: {e}。请确保 Docker Desktop 已运行。")
            self.client = None
            
        # 基础镜像配置
        self.images = {
            'python': 'python:3.11-slim',
            'java': 'maven:3.8-openjdk-11-slim', # 包含 Maven 和 JDK
            'go': 'golang:1.20-alpine',
            'javascript': 'node:18-alpine'
        }
        
    def is_available(self) -> bool:
        """检查沙箱是否可用"""
        return self.client is not None

    def _get_container_name(self, project_path: str) -> str:
        """根据项目路径生成确定的容器名称"""
        import hashlib
        # Windows 路径不区分大小写，统一转为小写以确保跨平台一致性
        abs_path = os.path.abspath(project_path).lower()
        hash_digest = hashlib.md5(abs_path.encode()).hexdigest()[:12]
        return f"argus_sandbox_{hash_digest}"

    def prepare_image(self, language: Optional[str] = None, image_override: Optional[str] = None) -> bool:
        """准备指定语言的基础镜像"""
        if not self.is_available():
            return False
            
        image_name = image_override
        if not image_name:
            if language:
                image_name = self.images.get(language, self.images['python'])
            else:
                self.logger.error("未指定语言或镜像")
                return False
        
        # 1. 检查本地是否存在
        local_exists = False
        try:
            self.client.images.get(image_name)
            local_exists = True
        except ImageNotFound:
            pass

        try:
            if not local_exists:
                self.logger.info(f"正在拉取镜像: {image_name}...")
                self.client.images.pull(image_name)
                self.logger.info(f"镜像 {image_name} 准备就绪")
            else:
                 self.logger.debug(f"镜像 {image_name} 已存在")
            return True
        except Exception as e:
            if local_exists:
                self.logger.warning(f"镜像拉取失败 ({e})，但检测到本地已存在，将使用本地镜像。")
                return True
            else:
                self.logger.error(f"拉取镜像 {image_name} 失败: {e}")
                return False

    def cleanup_sandbox(self, project_path: str):
        """清理指定项目的沙箱容器"""
        if not self.is_available():
            return

        container_name = self._get_container_name(project_path)
        try:
            container = self.client.containers.get(container_name)
            self.logger.info(f"停止并清理容器: {container_name}...")
            container.stop()
            container.remove()
        except docker.errors.NotFound:
            self.logger.info(f"容器 {container_name} 不存在，无需清理")
        except Exception as e:
            self.logger.error(f"清理容器失败: {e}")

    def run_dependency_install(self, project_path: str, language: Optional[str] = None, 
                             image_override: Optional[str] = None, manual_setup: bool = False) -> Dict[str, str]:
        """
        在沙箱中运行依赖安装
        支持持久化容器和手动配置
        """
        if not self.is_available():
            return {'status': 'error', 'logs': 'Docker 服务不可用'}

        abs_path = os.path.abspath(project_path)
        if not os.path.exists(abs_path):
             return {'status': 'error', 'logs': f'路径不存在: {abs_path}'}
             
        # 确定镜像
        image = image_override
        if not image and language:
            image = self.images.get(language)
        if not image:
             return {'status': 'error', 'logs': f'无法确定镜像 (语言: {language})'}

        container_name = self._get_container_name(project_path)
        container = None
        
        try:
            # 1. 获取或创建容器
            try:
                container = self.client.containers.get(container_name)
                if container.status != 'running':
                    self.logger.info(f"启动已存在的沙箱容器: {container_name}")
                    container.start()
                else:
                    self.logger.info(f"复用已运行的沙箱容器: {container_name}")
            except docker.errors.NotFound:
                self.logger.info(f"创建新的沙箱容器: {container_name} ({image})...")
                container = self.client.containers.run(
                    image,
                    name=container_name,
                    command="tail -f /dev/null", # 保持容器运行
                    detach=True,
                    working_dir="/app",
                    volumes={
                        abs_path: {'bind': '/input', 'mode': 'ro'}
                    },
                    # 限制资源
                    mem_limit="2g", # 稍微增加内存以防编译失败
                    cpu_quota=50000, 
                    network_disabled=False
                )
                
            # 2. 同步代码 (每次运行都需要同步，确保代码通过持久化容器更新)
            self.logger.info("同步代码到沙箱工作区...")
            # 确保 /app 目录存在 (如果是复用的容器，可能已经存在，但为了安全起见)
            container.exec_run("mkdir -p /app")
            # 使用 cp -rf 强制覆盖
            copy_cmd = "cp -rf /input/. /app/" 
            exit_code, output = container.exec_run(f"sh -c '{copy_cmd}'")
            if exit_code != 0:
                 return {'status': 'error', 'logs': f"工作区代码同步失败: {output.decode()}"}

            # 3. 如果是手动模式，直接暂停
            if manual_setup:
                print(f"\n{'-'*60}")
                print(f"[*] 手动配置模式已激活")
                print(f"[*] 容器名称: {container_name}")
                print(f"[*] 请在新的终端运行以下命令进入容器配置环境:")
                print(f"    docker exec -it {container_name} /bin/bash (或 /bin/sh)")
                print(f"{'-'*60}")
                input(">>> 配置完成后，请按回车键继续测试...")
                return {'status': 'manual_setup_waiting', 'logs': 'Manual setup completed'}

            # 3. 自动安装依赖
            install_cmd = self._get_install_command(language, "/app")
            # 如果没有自动安装命令，且没有手动配置，可能需要提示
            if not install_cmd:
                return {'status': 'skipped', 'logs': '未检测到标准依赖文件，跳过自动安装'}

            self.logger.info(f"执行依赖安装命令: {install_cmd}")
            start_time = time.time()
            
            # 使用 sh -c 执行
            exit_code, output = container.exec_run(f"sh -c '{install_cmd}'", stream=False)
            
            duration = time.time() - start_time
            logs = output.decode('utf-8', errors='replace')
            
            if exit_code == 0:
                self.logger.info(f"安装完成 (耗时 {duration:.2f}s), 状态: success")
                return {'status': 'success', 'logs': logs, 'duration': duration}
            else:
                # 4. 自动安装失败，转为手动引导
                self.logger.warning(f"依赖安装失败 (耗时 {duration:.2f}s)。")
                print(f"\n{'-'*60}")
                print(f"[!] 自动依赖安装失败。")
                print(f"[*] 容器已保留，名称: {container_name}")
                print(f"[*] 错误日志摘要: {logs[-500:]}")
                print(f"[*] 您可以手动进入容器修复环境:")
                print(f"    docker exec -it {container_name} /bin/bash (或 /bin/sh)")
                print(f"{'-'*60}")
                
                choice = input(">>> 按回车键重试/继续，或输入 'q' 放弃退出: ")
                if choice.lower() == 'q':
                    return {'status': 'failed', 'logs': logs}
                else:
                    return {'status': 'manual_setup_waiting', 'logs': 'User chose to continue after failure'}

        except Exception as e:
            self.logger.error(f"沙箱执行异常: {e}")
            return {'status': 'error', 'logs': str(e)}
            
        # 移除 finally 块以保持容器持久化运行，供后续分析复用

    def _get_install_command(self, language: str, work_dir: str) -> Optional[str]:
        """根据语言生成自动安装命令"""
        # 注意: 命令将被包裹在 sh -c 'CMD' 中运行，因此 CMD 内部不能包含未转义的单引号
        
        if language == 'python':
            # 优先安装系统依赖 (针对 mysqlclient, python-ldap 等需要编译的库)
            # 添加 strace 以支持动态分析
            pre_install = "apt-get update && apt-get install -y strace pkg-config build-essential default-libmysqlclient-dev libldap2-dev libsasl2-dev && "
            
            # 优先检查 requirements.txt
            cmd = []
            cmd.append(pre_install)
            cmd.append("if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; ")
            cmd.append("elif [ -f requirements/requirements.txt ]; then pip install --no-cache-dir -r requirements/requirements.txt; ")
            cmd.append("elif [ -f uv.lock ]; then pip install uv && uv pip install --system -r pyproject.toml; ")
            cmd.append("elif [ -f Pipfile ]; then pip install pipenv && pipenv install --system; ")
            cmd.append("elif [ -f pyproject.toml ]; then pip install .; ")
            cmd.append("else echo \"No python dependencies found\"; exit 0; fi")
            return "".join(cmd)
            
        elif language == 'java':
            # Maven / Gradle
            # 添加 strace 安装 (Debian based)
            pre_install = "apt-get update && apt-get install -y strace && "
            cmd = []
            cmd.append(pre_install)
            cmd.append("if [ -f pom.xml ]; then mvn dependency:resolve -B -DskipTests; ") 
            cmd.append("elif [ -f build.gradle ]; then gradle dependencies; ")
            cmd.append("else echo \"No java dependencies found\"; exit 0; fi")
            return "".join(cmd)
            
        elif language == 'javascript':
            # npm (Alpine based)
            # 添加 strace
            pre_install = "apk add --no-cache strace && "
            cmd = []
            cmd.append(pre_install)
            cmd.append("if [ -f package.json ]; then npm install; ")
            cmd.append("else echo \"No javascript dependencies found\"; exit 0; fi")
            return "".join(cmd)
            
        elif language == 'go':
             # go mod (Alpine based)
             return "apk add --no-cache strace && if [ -f go.mod ]; then go mod download; else echo \"No go dependencies found\"; exit 0; fi"
             
        return None

    def run_analysis_command(self, project_path: str, executable: Dict) -> Dict[str, Any]:
        """
        在持久化沙箱中运行分析命令 (例如 strace)
        """
        if not self.is_available():
            return {'error': 'Docker daemon not available'}
            
        container_name = self._get_container_name(project_path)
        container = None
        try:
            container = self.client.containers.get(container_name)
            if container.status != 'running':
                container.start()
        except docker.errors.NotFound:
            # 如果没找到特定的持久化容器，可能是用户跳过了依赖安装
            # 或者是在跑一些不需要安装依赖的快速扫描
            # 这种情况下，我们可以尝试 fallback 到临时的 argus 容器，或者报错
            # 为了统一，建议报错提示用户先进行依赖安装，或者自动创建一个临时容器
            # 这里简单起见，返回错误
            return {'error': f'Sandbox container not found: {container_name}. Please run dependency install first.'}
        except Exception as e:
            return {'error': f'Error getting container: {e}'}

        cmd = executable.get('cmd')
        
        try:
            # 构造 strace 命令
            # 注意: 需要确保容器内有 strace。基础镜像 (slim) 可能没有。
            # 如果由于基础镜像缺失 strace 导致失败，需要提示用户 or 在 prepare_image 时安装
            # 暂且假设用户或基础镜像已处理，或者 accept failure
            final_cmd = f"strace -f -o /tmp/strace.log {cmd}"
            self.logger.info(f"Executing in container ({container_name}): {final_cmd}")
            
            # 使用 exec_run 执行
            exec_res = container.exec_run(
                ["/bin/sh", "-c", final_cmd],
                workdir='/app'
            )
            
            # 读取 strace 日志
            strace_out = ""
            try:
                # get_archive 返回的是 tar 流
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
            self.logger.error(f"Analysis Error: {e}")
            return {'error': str(e)}


