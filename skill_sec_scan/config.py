"""
配置管理模块

负责加载和管理扫描配置
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional, Any
import yaml


@dataclass
class DetectorConfig:
    """检测器配置"""
    enabled: bool = True
    severity_overrides: Dict[str, str] = field(default_factory=dict)


@dataclass
class WhitelistConfig:
    """白名单配置"""
    skills: List[str] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)
    allowed_calls: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class OutputConfig:
    """输出配置"""
    format: str = "text"
    show_code_snippet: bool = True
    max_snippet_lines: int = 5
    verbosity: str = "normal"  # quiet, normal, verbose


@dataclass
class Config:
    """主配置类"""
    version: str = "1.0"
    detectors: Dict[str, DetectorConfig] = field(default_factory=dict)
    whitelist: WhitelistConfig = field(default_factory=WhitelistConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    
    # 命令行参数覆盖
    skill_path: Optional[Path] = None
    output_file: Optional[Path] = None
    output_format: Optional[str] = None
    verbose: bool = False
    quiet: bool = False
    min_severity: str = "low"

    @classmethod
    def from_file(cls, config_path: Path) -> 'Config':
        """
        从 YAML 文件加载配置
        
        Args:
            config_path: 配置文件路径
            
        Returns:
            Config 实例
        """
        if not config_path.exists():
            return cls()
        
        with open(config_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}
        
        config = cls()
        config.version = data.get('version', '1.0')
        
        # 解析检测器配置
        if 'detectors' in data:
            for name, det_cfg in data['detectors'].items():
                config.detectors[name] = DetectorConfig(
                    enabled=det_cfg.get('enabled', True),
                    severity_overrides=det_cfg.get('severity_overrides', {}),
                )
        
        # 解析白名单配置
        if 'whitelist' in data:
            wl = data['whitelist']
            config.whitelist = WhitelistConfig(
                skills=wl.get('skills', []),
                patterns=wl.get('patterns', []),
                allowed_calls=wl.get('allowed_calls', []),
            )
        
        # 解析输出配置
        if 'output' in data:
            out = data['output']
            config.output = OutputConfig(
                format=out.get('format', 'text'),
                show_code_snippet=out.get('show_code_snippet', True),
                max_snippet_lines=out.get('max_snippet_lines', 5),
                verbosity=out.get('verbosity', 'normal'),
            )
        
        return config
    
    def apply_cli_overrides(
        self,
        skill_path: Optional[str] = None,
        output_file: Optional[str] = None,
        output_format: Optional[str] = None,
        verbose: bool = False,
        quiet: bool = False,
        min_severity: str = "low",
    ) -> None:
        """
        应用命令行参数覆盖配置文件设置
        
        Args:
            skill_path: Skills 目录路径
            output_file: 输出文件路径
            output_format: 输出格式
            verbose: 详细输出模式
            quiet: 静默模式
            min_severity: 最低显示风险等级
        """
        if skill_path:
            self.skill_path = Path(skill_path)
        
        if output_file:
            self.output_file = Path(output_file)
        
        if output_format:
            self.output_format = output_format
            self.output.format = output_format
        
        self.verbose = verbose
        self.quiet = quiet
        self.min_severity = min_severity
        
        # 根据 verbose/quiet 调整 verbosity
        if quiet:
            self.output.verbosity = "quiet"
        elif verbose:
            self.output.verbosity = "verbose"
    
    def is_detector_enabled(self, detector_name: str) -> bool:
        """
        检查检测器是否启用
        
        Args:
            detector_name: 检测器名称
            
        Returns:
            是否启用
        """
        if detector_name in self.detectors:
            return self.detectors[detector_name].enabled
        return True  # 默认启用
    
    def get_severity_override(self, detector_name: str, rule_id: str) -> Optional[str]:
        """
        获取规则的严重性覆盖
        
        Args:
            detector_name: 检测器名称
            rule_id: 规则 ID
            
        Returns:
            覆盖的严重性等级，如果没有则返回 None
        """
        if detector_name in self.detectors:
            return self.detectors[detector_name].severity_overrides.get(rule_id)
        return None
    
    def is_skill_whitelisted(self, skill_name: str) -> bool:
        """
        检查技能是否在白名单中
        
        Args:
            skill_name: 技能名称
            
        Returns:
            是否在白名单中
        """
        return skill_name in self.whitelist.skills
    
    def to_dict(self) -> dict:
        """转换为字典格式"""
        return {
            "version": self.version,
            "detectors": {
                name: {
                    "enabled": cfg.enabled,
                    "severity_overrides": cfg.severity_overrides,
                }
                for name, cfg in self.detectors.items()
            },
            "whitelist": {
                "skills": self.whitelist.skills,
                "patterns": self.whitelist.patterns,
                "allowed_calls": self.whitelist.allowed_calls,
            },
            "output": {
                "format": self.output.format,
                "show_code_snippet": self.output.show_code_snippet,
                "max_snippet_lines": self.output.max_snippet_lines,
                "verbosity": self.output.verbosity,
            },
            "cli_overrides": {
                "skill_path": str(self.skill_path) if self.skill_path else None,
                "output_file": str(self.output_file) if self.output_file else None,
                "output_format": self.output_format,
                "verbose": self.verbose,
                "quiet": self.quiet,
                "min_severity": self.min_severity,
            },
        }


def create_default_config() -> Config:
    """
    创建默认配置
    
    Returns:
        默认配置实例
    """
    config = Config()
    
    # 默认启用所有检测器
    config.detectors = {
        "code_exec": DetectorConfig(enabled=True),
        "data_exfil": DetectorConfig(enabled=True),
        "sensitive_access": DetectorConfig(enabled=True),
        "system_op": DetectorConfig(enabled=True),
        "crypto_mining": DetectorConfig(enabled=True),
    }
    
    return config
