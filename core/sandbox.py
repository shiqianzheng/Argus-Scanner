"""
Docker 沙箱环境管理器
负责容器生命周期管理、文件挂载和隔离执行
"""

import os
import shutil
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Optional, Dict, List, Tuple
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
            'python': 'python:3.9-slim',
            'java': 'maven:3.8-openjdk-11-slim', # 包含 Maven 和 JDK
            'go': 'golang:1.20-alpine',
            'javascript': 'node:18-alpine'
        }
        
    def is_available(self) -> bool:
        """检查沙箱是否可用"""
        return self.client is not None

    def prepare_image(self, language: str) -> bool:
        """准备指定语言的基础镜像"""
        if not self.is_available():
            return False
            
        image_name = self.images.get(language, self.images['python'])
        try:
            self.logger.info(f"正在检查/拉取镜像: {image_name}...")
            self.client.images.pull(image_name)
            self.logger.info(f"镜像 {image_name} 准备就绪")
            return True
        except Exception as e:
            self.logger.error(f"拉取镜像 {image_name} 失败: {e}")
            return False

    def run_dependency_install(self, project_path: str, language: str) -> Dict[str, str]:
        """
        在沙箱中运行依赖安装
        返回: {'status': 'success/failed', 'logs': '...'}
        """
        if not self.is_available():
            return {'status': 'error', 'logs': 'Docker 服务不可用'}

        abs_path = os.path.abspath(project_path)
        if not os.path.exists(abs_path):
             return {'status': 'error', 'logs': f'路径不存在: {abs_path}'}
             
        # 确定容器配置
        image = self.images.get(language)
        if not image:
             return {'status': 'error', 'logs': f'不支持的语言: {language}'}

        # 准备构建命令
        install_cmd = self._get_install_command(language, "/app")
        if not install_cmd:
            return {'status': 'skipped', 'logs': '未检测到标准依赖文件，跳过安装'}

        container = None
        try:
            # 1. 启动容器 (保持运行状态)
            # 使用 sleep infinity 让容器保持运行，以便我们通过 exec 执行命令
            # 挂载策略: 
            # - 项目目录挂载为只读 (/app_src)
            # - 工作目录 (/app) 为可写，我们将代码复制过去或使用 OverlayFS (这里简化为复制)
            # 简化方案: 直接挂载 source 到 /app (Read-Write) 可能会修改宿主机文件，不安全。
            # 安全方案: 挂载 source 到 /input (Read-Only)，容器启动后 cp -r /input/* /app/，然后在 /app 构建
            
            self.logger.info(f"启动沙箱容器 ({image})...")
            
            # 使用临时卷作为工作区，隔离修改
            # 注意：对于大型项目，cp 操作可能耗时。
            
            container = self.client.containers.run(
                image,
                command="tail -f /dev/null", # 保持容器运行
                detach=True,
                working_dir="/app",
                volumes={
                    abs_path: {'bind': '/input', 'mode': 'ro'}
                },
                # 限制资源
                mem_limit="1g",
                cpu_quota=50000, # 50% CPU
                network_disabled=False # 允许下载依赖，但理想情况下应通过代理或配置只允许特定 Registry
            )
            
            # 2. 初始化工作区
            self.logger.info("初始化沙箱工作区...")
            # 复制文件 (由于 /input 是只读挂载且属于 root 或其他用户，cp 需要权限)
            # 简单起见，我们在容器内执行 cp
            copy_cmd = "cp -r /input/. /app/"
            exit_code, output = container.exec_run(f"sh -c '{copy_cmd}'")
            if exit_code != 0:
                 return {'status': 'error', 'logs': f"工作区初始化失败: {output.decode()}"}

            # 3. 执行安装
            self.logger.info(f"执行依赖安装命令: {install_cmd}")
            start_time = time.time()
            
            # 使用 sh -c 执行组合命令
            exit_code, output = container.exec_run(f"sh -c '{install_cmd}'", stream=False)
            
            duration = time.time() - start_time
            logs = output.decode('utf-8', errors='replace')
            
            status = 'success' if exit_code == 0 else 'failed'
            self.logger.info(f"安装完成 (耗时 {duration:.2f}s), 状态: {status}")
            
            return {
                'status': status,
                'logs': logs,
                'duration': duration
            }

        except Exception as e:
            self.logger.error(f"沙箱执行异常: {e}")
            return {'status': 'error', 'logs': str(e)}
            
        finally:
            # 4. 清理
            if container:
                try:
                    self.logger.info("清理沙箱容器...")
                    container.kill()
                    container.remove()
                except Exception as e:
                    self.logger.error(f"清理容器失败: {e}")

    def _get_install_command(self, language: str, work_dir: str) -> Optional[str]:
        """根据语言生成自动安装命令"""
        # 注意: 命令将被包裹在 sh -c 'CMD' 中运行，因此 CMD 内部不能包含未转义的单引号
        
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
            
        elif language == 'javascript':
            # npm
            cmd = []
            cmd.append("if [ -f package.json ]; then npm install; ")
            cmd.append("else echo \"No javascript dependencies found\"; exit 0; fi")
            return "".join(cmd)
            
        elif language == 'go':
             # go mod
             return "if [ -f go.mod ]; then go mod download; else echo \"No go dependencies found\"; exit 0; fi"
             
        return None
