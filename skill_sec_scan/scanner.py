"""
扫描引擎模块

负责协调检测器执行扫描任务
"""
from pathlib import Path
from typing import List, Optional
import time
import yaml

from .config import Config
from .models import SkillScanResult, Finding
from .detectors import (
    CodeExecutionDetector,
    DataExfiltrationDetector,
    SystemOperationDetector,
)


class Scanner:
    """
    技能扫描器
    
    负责加载技能、运行检测器、聚合结果
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        初始化扫描器
        
        Args:
            config: 配置实例，如果为 None 则使用默认配置
        """
        self.config = config or Config()
        self.detectors = []
        self._load_detectors()
    
    def _load_detectors(self) -> None:
        """加载所有检测器"""
        # 加载三个检测引擎
        self.detectors = [
            CodeExecutionDetector(),
            DataExfiltrationDetector(),
            SystemOperationDetector(),
        ]
    
    def scan(self, skill_path: Path) -> SkillScanResult:
        """
        扫描指定技能目录
        
        Args:
            skill_path: 技能目录路径
            
        Returns:
            扫描结果
        """
        start_time = time.time()
        
        # 1. 加载技能元数据
        skill_metadata = self._load_skill_metadata(skill_path)
        skill_name = skill_metadata.get('name', skill_path.name)
        
        # 2. 检查白名单
        if self.config.is_skill_whitelisted(skill_name):
            return SkillScanResult(
                skill_name=skill_name,
                skill_path=skill_path,
                skill_metadata=skill_metadata,
                findings=[],
                scanned_files=[],
                scan_duration=time.time() - start_time,
            )
        
        # 3. 收集待扫描的 Python 文件
        python_files = self._collect_python_files(skill_path)
        
        # 4. 运行所有检测器
        findings: List[Finding] = []
        
        for detector in self.detectors:
            # 检查检测器是否启用
            detector_name = detector.__class__.__name__.replace('Detector', '').lower()
            if not self.config.is_detector_enabled(detector_name):
                continue
            
            # 对每个 Python 文件运行检测
            for py_file in python_files:
                try:
                    file_findings = detector.detect_file(py_file)
                    findings.extend(file_findings)
                except Exception as e:
                    # 记录错误但继续扫描
                    print(f"Warning: Error scanning {py_file}: {e}")
        
        # 5. 根据最低严重性过滤
        findings = self._filter_by_severity(findings)
        
        scan_duration = time.time() - start_time
        
        return SkillScanResult(
            skill_name=skill_name,
            skill_path=skill_path,
            skill_metadata=skill_metadata,
            findings=findings,
            scanned_files=python_files,
            scan_duration=scan_duration,
        )
    
    def _load_skill_metadata(self, skill_path: Path) -> dict:
        """
        从 SKILL.md 加载技能元数据
        
        Args:
            skill_path: 技能目录路径
            
        Returns:
            元数据字典
        """
        skill_md = skill_path / "SKILL.md"
        if not skill_md.exists():
            return {}
        
        try:
            with open(skill_md, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 解析 YAML frontmatter
            if content.startswith('---'):
                parts = content.split('---', 2)
                if len(parts) >= 3:
                    yaml_content = parts[1].strip()
                    return yaml.safe_load(yaml_content) or {}
        except Exception:
            pass
        
        return {}
    
    def _collect_python_files(self, skill_path: Path) -> List[Path]:
        """
        收集技能目录中的所有 Python 文件
        
        Args:
            skill_path: 技能目录路径
            
        Returns:
            Python 文件列表
        """
        python_files = []
        
        # 收集 scripts/ 目录下的 .py 文件
        scripts_dir = skill_path / "scripts"
        if scripts_dir.exists():
            python_files.extend(scripts_dir.rglob("*.py"))
        
        # 收集根目录下的 .py 文件（如果有）
        for py_file in skill_path.glob("*.py"):
            python_files.append(py_file)
        
        return sorted(python_files)
    
    def _filter_by_severity(self, findings: List[Finding]) -> List[Finding]:
        """根据最低严重性过滤发现"""
        severity_order = ['low', 'medium', 'high', 'critical']
        min_severity = self.config.min_severity.lower()
        
        if min_severity not in severity_order:
            return findings
        
        min_index = severity_order.index(min_severity)
        
        return [
            f for f in findings
            if severity_order.index(f.risk_level.value) >= min_index
        ]
