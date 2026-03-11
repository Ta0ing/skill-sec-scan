"""
skill-sec-scan

CoPaw Worker Skills 安全扫描工具

这是一个用于扫描 CoPaw Worker Skills 目录安全风险的工具。
支持检测恶意代码执行、数据泄露、危险系统操作等多种风险类型。
"""
from .config import Config, create_default_config
from .scanner import Scanner
from .models import RiskLevel, RiskCategory, Finding, SkillScanResult, Location

__version__ = '1.0.0'
__author__ = 'CoPaw Worker Team'

__all__ = [
    # 配置
    'Config',
    'create_default_config',
    
    # 扫描器
    'Scanner',
    
    # 数据模型
    'RiskLevel',
    'RiskCategory',
    'Finding',
    'SkillScanResult',
    'Location',
]
