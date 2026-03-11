"""
报告生成器

生成多种格式的扫描报告：终端彩色输出、JSON、Markdown
"""
from pathlib import Path
from typing import Optional, Dict
import json

from .base import BaseReporter
from ..models import SkillScanResult, Finding, RiskLevel, RiskCategory


class TextReporter(BaseReporter):
    """
    文本报告器
    
    生成彩色文本格式的扫描报告，适合终端输出
    """
    
    def __init__(self, show_snippet: bool = True, max_snippet_lines: int = 5):
        """
        初始化文本报告器
        
        Args:
            show_snippet: 是否显示代码片段
            max_snippet_lines: 最大代码片段行数
        """
        self.show_snippet = show_snippet
        self.max_snippet_lines = max_snippet_lines
    
    def generate(self, result: SkillScanResult) -> str:
        """生成文本报告"""
        lines = []
        
        # 标题
        lines.append(self._section_header("skill-sec-scan 安全扫描报告"))
        
        # 基本信息区
        lines.append("")
        lines.append(self._sub_header("基本信息"))
        lines.append(f"  技能名称: {result.skill_name}")
        lines.append(f"  技能路径: {result.skill_path}")
        lines.append(f"  扫描文件: {len(result.scanned_files)} 个")
        lines.append(f"  扫描耗时: {result.scan_duration:.2f} 秒")
        
        # 风险概览区
        lines.append("")
        lines.append(self._sub_header("风险概览"))
        lines.append(f"  整体风险等级: {self._format_risk_level(result.overall_risk)}")
        lines.append(f"  发现问题总数: {len(result.findings)} 个")
        lines.append("")
        
        # 风险等级统计
        lines.append("  风险等级分布:")
        risk_summary = result.risk_summary
        lines.append(f"    🔴 严重 (Critical): {risk_summary[RiskLevel.CRITICAL]}")
        lines.append(f"    🔴 高危 (High):     {risk_summary[RiskLevel.HIGH]}")
        lines.append(f"    🟡 中危 (Medium):   {risk_summary[RiskLevel.MEDIUM]}")
        lines.append(f"    🟢 低危 (Low):      {risk_summary[RiskLevel.LOW]}")
        
        # 风险类别统计
        lines.append("")
        lines.append("  风险类别分布:")
        category_summary = result.category_summary
        for cat in RiskCategory:
            count = category_summary[cat]
            if count > 0:
                lines.append(f"    • {cat.display_name}: {count} 个")
        
        # 处理建议
        lines.append("")
        lines.append(self._sub_header("处理建议"))
        lines.append(f"  {result.overall_suggestion}")
        
        # 详细发现
        if result.findings:
            lines.append("")
            lines.append(self._sub_header("详细发现"))
            
            # 按风险等级分组显示
            findings_by_level = self._group_by_risk_level(result.findings)
            
            for level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
                if findings_by_level[level]:
                    lines.append("")
                    lines.append(f"  【{self._format_risk_level(level)}】")
                    for i, finding in enumerate(findings_by_level[level], 1):
                        lines.append(self._format_finding(i, finding, level))
        else:
            lines.append("")
            lines.append(self._sub_header("扫描结果"))
            lines.append("  ✅ 未发现安全风险")
        
        # 页脚
        lines.append("")
        lines.append(self._section_footer())
        
        return "\n".join(lines)
    
    def _section_header(self, title: str) -> str:
        """生成章节标题"""
        return f"\n{'=' * 70}\n  {title}\n{'=' * 70}"
    
    def _section_footer(self) -> str:
        """生成页脚"""
        return f"{'=' * 70}\n  报告生成时间: skill-sec-scan v1.0.0\n{'=' * 70}"
    
    def _sub_header(self, title: str) -> str:
        """生成子标题"""
        return f"\n  {'─' * 60}\n  {title}\n  {'─' * 60}"
    
    def _format_risk_level(self, level: RiskLevel) -> str:
        """格式化风险等级"""
        level_map = {
            RiskLevel.LOW: "🟢 低风险 (LOW)",
            RiskLevel.MEDIUM: "🟡 中风险 (MEDIUM)",
            RiskLevel.HIGH: "🔴 高风险 (HIGH)",
            RiskLevel.CRITICAL: "🔴 严重风险 (CRITICAL)",
        }
        return level_map.get(level, str(level))
    
    def _group_by_risk_level(self, findings: list) -> Dict[RiskLevel, list]:
        """按风险等级分组"""
        grouped = {level: [] for level in RiskLevel}
        for finding in findings:
            grouped[finding.risk_level].append(finding)
        return grouped
    
    def _format_finding(self, index: int, finding: Finding, level: RiskLevel) -> str:
        """格式化单个发现"""
        lines = []
        
        # 编号和消息
        rule_info = f"[{finding.rule_id}] " if finding.rule_id else ""
        lines.append(f"    [{index}] {rule_info}{finding.message}")
        
        # 详细信息
        lines.append(f"        类别: {finding.category.display_name}")
        lines.append(f"        位置: {finding.location}")
        
        # 代码片段
        if self.show_snippet and finding.code_snippet:
            snippet_lines = finding.code_snippet.split('\n')[:self.max_snippet_lines]
            lines.append(f"        代码:")
            for line in snippet_lines:
                lines.append(f"          {line}")
        
        # 建议
        if finding.suggestion:
            lines.append(f"        建议: {finding.suggestion}")
        
        # 置信度
        if finding.confidence < 1.0:
            lines.append(f"        置信度: {finding.confidence * 100:.0f}%")
        
        lines.append("")
        return "\n".join(lines)


class JSONReporter(BaseReporter):
    """
    JSON 报告器
    
    生成结构化的 JSON 格式报告，适合程序处理和 CI/CD 集成
    """
    
    def generate(self, result: SkillScanResult) -> str:
        """生成 JSON 报告"""
        report_data = {
            "report_type": "skill-sec-scan",
            "version": "1.0.0",
            "scan_result": result.to_dict(),
        }
        return json.dumps(report_data, indent=2, ensure_ascii=False)


class MarkdownReporter(BaseReporter):
    """
    Markdown 报告器
    
    生成 Markdown 格式报告，适合文档生成和 GitHub 展示
    """
    
    def generate(self, result: SkillScanResult) -> str:
        """生成 Markdown 报告"""
        lines = []
        
        # 标题
        lines.append("# 🔍 skill-sec-scan 安全扫描报告")
        lines.append("")
        
        # 基本信息
        lines.append("## 📋 基本信息")
        lines.append("")
        lines.append(f"| 项目 | 值 |")
        lines.append(f"|------|-----|")
        lines.append(f"| 技能名称 | {result.skill_name} |")
        lines.append(f"| 技能路径 | `{result.skill_path}` |")
        lines.append(f"| 扫描文件 | {len(result.scanned_files)} 个 |")
        lines.append(f"| 扫描耗时 | {result.scan_duration:.2f} 秒 |")
        lines.append("")
        
        # 风险概览
        lines.append("## 📊 风险概览")
        lines.append("")
        
        # 整体风险等级（使用徽章样式）
        risk_badge = self._get_risk_badge(result.overall_risk)
        lines.append(f"**整体风险等级**: {risk_badge}")
        lines.append("")
        
        # 风险等级统计表
        lines.append("### 风险等级分布")
        lines.append("")
        lines.append("| 风险等级 | 数量 | 状态 |")
        lines.append("|---------|------|------|")
        
        risk_summary = result.risk_summary
        lines.append(f"| 🔴 严重 (Critical) | {risk_summary[RiskLevel.CRITICAL]} | {'⚠️ 需立即处理' if risk_summary[RiskLevel.CRITICAL] > 0 else '✅'} |")
        lines.append(f"| 🔴 高危 (High) | {risk_summary[RiskLevel.HIGH]} | {'⚠️ 需处理' if risk_summary[RiskLevel.HIGH] > 0 else '✅'} |")
        lines.append(f"| 🟡 中危 (Medium) | {risk_summary[RiskLevel.MEDIUM]} | {'ℹ️ 建议审查' if risk_summary[RiskLevel.MEDIUM] > 0 else '✅'} |")
        lines.append(f"| 🟢 低危 (Low) | {risk_summary[RiskLevel.LOW]} | {'✅ 可忽略' if risk_summary[RiskLevel.LOW] > 0 else '✅'} |")
        lines.append("")
        
        # 风险类别统计
        lines.append("### 风险类别分布")
        lines.append("")
        category_summary = result.category_summary
        has_categories = any(count > 0 for count in category_summary.values())
        
        if has_categories:
            lines.append("| 风险类别 | 数量 |")
            lines.append("|---------|------|")
            for cat in RiskCategory:
                count = category_summary[cat]
                if count > 0:
                    lines.append(f"| {cat.display_name} | {count} |")
            lines.append("")
        
        # 处理建议
        lines.append("## 💡 处理建议")
        lines.append("")
        lines.append(f"> {result.overall_suggestion}")
        lines.append("")
        
        # 详细发现
        if result.findings:
            lines.append("## 🔎 详细发现")
            lines.append("")
            
            # 按风险等级分组
            findings_by_level = self._group_by_risk_level(result.findings)
            
            for level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
                if findings_by_level[level]:
                    level_header = self._get_risk_level_header(level)
                    lines.append(f"### {level_header}")
                    lines.append("")
                    
                    for i, finding in enumerate(findings_by_level[level], 1):
                        lines.extend(self._format_finding_md(i, finding))
                        lines.append("---")
                        lines.append("")
        else:
            lines.append("## ✅ 扫描结果")
            lines.append("")
            lines.append("**未发现安全风险**")
            lines.append("")
        
        # 页脚
        lines.append("---")
        lines.append("")
        lines.append("*报告由 skill-sec-scan v1.0.0 生成*")
        
        return "\n".join(lines)
    
    def _get_risk_badge(self, level: RiskLevel) -> str:
        """获取风险等级徽章"""
        badges = {
            RiskLevel.LOW: "![低风险](https://img.shields.io/badge/风险-低-green)",
            RiskLevel.MEDIUM: "![中风险](https://img.shields.io/badge/风险-中-yellow)",
            RiskLevel.HIGH: "![高风险](https://img.shields.io/badge/风险-高-red)",
            RiskLevel.CRITICAL: "![严重](https://img.shields.io/badge/风险-严重-critical)",
        }
        # 简化版本，不使用外部图片
        simple_badges = {
            RiskLevel.LOW: "🟢 **低风险**",
            RiskLevel.MEDIUM: "🟡 **中风险**",
            RiskLevel.HIGH: "🔴 **高风险**",
            RiskLevel.CRITICAL: "🔴 **严重风险**",
        }
        return simple_badges.get(level, str(level))
    
    def _get_risk_level_header(self, level: RiskLevel) -> str:
        """获取风险等级标题"""
        headers = {
            RiskLevel.LOW: "🟢 低风险问题",
            RiskLevel.MEDIUM: "🟡 中风险问题",
            RiskLevel.HIGH: "🔴 高风险问题",
            RiskLevel.CRITICAL: "🔴 严重风险问题",
        }
        return headers.get(level, str(level))
    
    def _group_by_risk_level(self, findings: list) -> Dict[RiskLevel, list]:
        """按风险等级分组"""
        grouped = {level: [] for level in RiskLevel}
        for finding in findings:
            grouped[finding.risk_level].append(finding)
        return grouped
    
    def _format_finding_md(self, index: int, finding: Finding) -> list:
        """格式化单个发现（Markdown 格式）"""
        lines = []
        
        # 标题
        rule_info = f"[{finding.rule_id}] " if finding.rule_id else ""
        lines.append(f"#### {index}. {rule_info}{finding.message}")
        lines.append("")
        
        # 信息表格
        lines.append("| 属性 | 值 |")
        lines.append("|------|-----|")
        lines.append(f"| 风险类别 | {finding.category.display_name} |")
        lines.append(f"| 位置 | `{finding.location}` |")
        if finding.confidence < 1.0:
            lines.append(f"| 置信度 | {finding.confidence * 100:.0f}% |")
        lines.append("")
        
        # 代码片段
        if finding.code_snippet:
            lines.append("**代码片段**:")
            lines.append("")
            lines.append("```python")
            lines.append(finding.code_snippet)
            lines.append("```")
            lines.append("")
        
        # 建议
        if finding.suggestion:
            lines.append(f"**💡 建议**: {finding.suggestion}")
            lines.append("")
        
        return lines
