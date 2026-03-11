"""
数据模型定义

包含风险等级、风险类别、检测结果等核心数据结构
"""
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Dict, Optional
from collections import Counter


class RiskLevel(Enum):
    """风险等级"""
    LOW = "low"           # 绿色，信息性
    MEDIUM = "medium"     # 黄色，需关注
    HIGH = "high"         # 红色，需处理
    CRITICAL = "critical" # 深红，禁止安装

    def __str__(self) -> str:
        return self.value


class RiskCategory(Enum):
    """风险类别"""
    CODE_EXECUTION = "code_execution"         # 代码执行
    DATA_EXFILTRATION = "data_exfiltration"   # 数据外传
    SENSITIVE_ACCESS = "sensitive_access"     # 敏感信息访问
    SYSTEM_OPERATION = "system_operation"     # 危险系统操作
    CRYPTO_MINING = "crypto_mining"           # 加密货币挖矿
    SUSPICIOUS = "suspicious"                 # 可疑行为

    def __str__(self) -> str:
        return self.value
    
    @property
    def display_name(self) -> str:
        """获取显示名称"""
        names = {
            RiskCategory.CODE_EXECUTION: "恶意代码执行",
            RiskCategory.DATA_EXFILTRATION: "数据泄露风险",
            RiskCategory.SENSITIVE_ACCESS: "敏感信息访问",
            RiskCategory.SYSTEM_OPERATION: "危险系统操作",
            RiskCategory.CRYPTO_MINING: "加密货币挖矿",
            RiskCategory.SUSPICIOUS: "可疑行为",
        }
        return names.get(self, self.value)


@dataclass
class Location:
    """代码位置"""
    file: Path
    line: int
    column: int = 0
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    
    def __str__(self) -> str:
        return f"{self.file}:{self.line}:{self.column}"


@dataclass
class Finding:
    """检测结果"""
    category: RiskCategory
    risk_level: RiskLevel
    message: str
    location: Location
    code_snippet: str              # 问题代码片段
    suggestion: str                # 修复建议
    confidence: float = 1.0        # 检测置信度 0.0-1.0
    references: List[str] = field(default_factory=list)  # 参考链接
    rule_id: str = ""              # 规则 ID（如 CE001）

    def to_dict(self) -> dict:
        """转换为字典格式"""
        return {
            "category": self.category.value,
            "risk_level": self.risk_level.value,
            "message": self.message,
            "location": str(self.location),
            "code_snippet": self.code_snippet,
            "suggestion": self.suggestion,
            "confidence": self.confidence,
            "references": self.references,
            "rule_id": self.rule_id,
        }


@dataclass
class SkillScanResult:
    """技能扫描结果"""
    skill_name: str
    skill_path: Path
    skill_metadata: Dict           # SKILL.md 的 YAML frontmatter
    findings: List[Finding]
    scanned_files: List[Path]
    scan_duration: float           # 扫描耗时（秒）
    
    @property
    def risk_summary(self) -> Dict[RiskLevel, int]:
        """各风险等级的统计"""
        summary = {level: 0 for level in RiskLevel}
        for finding in self.findings:
            summary[finding.risk_level] += 1
        return summary
    
    @property
    def category_summary(self) -> Dict[RiskCategory, int]:
        """各风险类别的统计"""
        counter = Counter(f.category for f in self.findings)
        return {cat: counter.get(cat, 0) for cat in RiskCategory}
    
    @property
    def overall_risk(self) -> RiskLevel:
        """整体风险等级（取最高）"""
        if not self.findings:
            return RiskLevel.LOW
        
        # 规则1: 存在 CRITICAL 级别发现
        if any(f.risk_level == RiskLevel.CRITICAL for f in self.findings):
            return RiskLevel.CRITICAL
        
        # 规则2: 高风险发现 >= 3 个
        high_count = sum(1 for f in self.findings if f.risk_level == RiskLevel.HIGH)
        if high_count >= 3:
            return RiskLevel.CRITICAL
        
        # 规则3: 存在 HIGH 级别发现
        if high_count > 0:
            return RiskLevel.HIGH
        
        # 规则4: 中风险发现 >= 5 个
        medium_count = sum(1 for f in self.findings if f.risk_level == RiskLevel.MEDIUM)
        if medium_count >= 5:
            return RiskLevel.HIGH
        
        # 规则5: 存在 MEDIUM 级别发现
        if medium_count > 0:
            return RiskLevel.MEDIUM
        
        return RiskLevel.LOW
    
    @property
    def overall_suggestion(self) -> str:
        """整体处理建议"""
        overall = self.overall_risk
        
        if overall == RiskLevel.CRITICAL:
            return "⚠️  严重安全风险！强烈建议不要安装此技能，或立即移除。"
        elif overall == RiskLevel.HIGH:
            return "⚠️  发现高危风险！建议在充分审查代码后谨慎使用，或联系开发者修复。"
        elif overall == RiskLevel.MEDIUM:
            return "ℹ️  存在中等风险。建议审查相关代码，确保符合安全要求后再使用。"
        else:
            return "✅ 未发现明显安全风险，可以正常使用。"

    def to_dict(self) -> dict:
        """转换为字典格式"""
        return {
            "skill_name": self.skill_name,
            "skill_path": str(self.skill_path),
            "skill_metadata": self.skill_metadata,
            "findings": [f.to_dict() for f in self.findings],
            "scanned_files": [str(f) for f in self.scanned_files],
            "scan_duration": self.scan_duration,
            "risk_summary": {k.value: v for k, v in self.risk_summary.items()},
            "category_summary": {k.value: v for k, v in self.category_summary.items()},
            "overall_risk": self.overall_risk.value,
            "overall_suggestion": self.overall_suggestion,
            "total_findings": len(self.findings),
        }
