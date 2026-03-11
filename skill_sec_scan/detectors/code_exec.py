"""
恶意代码检测引擎

检测动态代码执行、系统调用等危险行为
"""
import ast
import re
from pathlib import Path
from typing import List, Set

from .base import BaseDetector
from ..models import Finding, RiskCategory, RiskLevel, Location


class CodeExecutionDetector(BaseDetector):
    """恶意代码执行检测器"""
    
    # 危险函数映射
    DANGEROUS_FUNCTIONS = {
        # 动态代码执行
        'eval': RiskLevel.HIGH,
        'exec': RiskLevel.HIGH,
        'compile': RiskLevel.MEDIUM,
        'execfile': RiskLevel.HIGH,
        
        # 系统调用
        'os.system': RiskLevel.HIGH,
        'os.popen': RiskLevel.HIGH,
        'os.spawn': RiskLevel.HIGH,
        'os.spawnl': RiskLevel.HIGH,
        'os.spawnle': RiskLevel.HIGH,
        'os.spawnlp': RiskLevel.HIGH,
        'os.spawnlpe': RiskLevel.HIGH,
        'os.spawnv': RiskLevel.HIGH,
        'os.spawnve': RiskLevel.HIGH,
        'os.spawnvp': RiskLevel.HIGH,
        'os.spawnvpe': RiskLevel.HIGH,
        
        # 子进程
        'subprocess.call': RiskLevel.MEDIUM,
        'subprocess.run': RiskLevel.MEDIUM,
        'subprocess.Popen': RiskLevel.MEDIUM,
        'subprocess.check_output': RiskLevel.MEDIUM,
        'subprocess.check_call': RiskLevel.MEDIUM,
        
        # 动态导入
        '__import__': RiskLevel.MEDIUM,
    }
    
    # 可疑模式
    SUSPICIOUS_PATTERNS = [
        (r'base64\.b64decode\s*\(', 'Base64 解码（可能隐藏恶意代码）', RiskLevel.MEDIUM),
        (r'__import__\s*\(\s*["\']os["\']', '动态导入 os 模块', RiskLevel.MEDIUM),
        (r'__import__\s*\(\s*["\']subprocess["\']', '动态导入 subprocess 模块', RiskLevel.MEDIUM),
    ]
    
    @property
    def category(self) -> RiskCategory:
        return RiskCategory.CODE_EXECUTION
    
    @property
    def description(self) -> str:
        return "检测恶意代码执行风险（eval, exec, 系统调用等）"
    
    def detect(self, tree: ast.AST, file_path: Path) -> List[Finding]:
        """检测 AST 中的恶意代码执行风险"""
        findings = []
        
        # 读取源代码用于正则匹配和代码片段提取
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()
        except Exception:
            source = ""
        
        # 1. AST 检测危险函数调用
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node.func)
                if func_name in self.DANGEROUS_FUNCTIONS:
                    risk_level = self.DANGEROUS_FUNCTIONS[func_name]
                    
                    # 检查是否可能是安全的
                    if self._is_likely_safe(node, func_name, file_path):
                        risk_level = RiskLevel.LOW
                    
                    code_snippet = ast.get_source_segment(source, node) or ""
                    
                    findings.append(Finding(
                        category=self.category,
                        risk_level=risk_level,
                        message=f"检测到危险函数调用: {func_name}()",
                        location=Location(file_path, node.lineno, node.col_offset),
                        code_snippet=code_snippet,
                        suggestion=self._get_suggestion(func_name),
                        confidence=self._calculate_confidence(node, file_path),
                        rule_id=f"CE{list(self.DANGEROUS_FUNCTIONS.keys()).index(func_name) + 1:03d}",
                    ))
        
        # 2. 正则模式检测
        for pattern, message, risk_level in self.SUSPICIOUS_PATTERNS:
            for match in re.finditer(pattern, source):
                # 计算行号
                line_no = source[:match.start()].count('\n') + 1
                
                findings.append(Finding(
                    category=self.category,
                    risk_level=risk_level,
                    message=f"检测到可疑模式: {message}",
                    location=Location(file_path, line_no, 0),
                    code_snippet=match.group(0),
                    suggestion="检查此代码的用途，确保不是恶意行为",
                    confidence=0.7,
                    rule_id="CE999",
                ))
        
        return findings
    
    def _get_func_name(self, node) -> str:
        """获取函数调用名称"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value_name = self._get_func_name(node.value)
            return f"{value_name}.{node.attr}"
        return ""
    
    def _is_likely_safe(self, node: ast.Call, func_name: str, file_path: Path) -> bool:
        """判断调用是否可能是安全的"""
        # 测试文件中的调用
        if 'test' in str(file_path).lower():
            return True
        
        # 字面量参数的 eval/exec
        if func_name in ('eval', 'exec'):
            if len(node.args) == 1:
                arg = node.args[0]
                if isinstance(arg, ast.Constant):
                    return True
        
        return False
    
    def _calculate_confidence(self, node: ast.Call, file_path: Path) -> float:
        """计算检测置信度"""
        confidence = 1.0
        
        # 测试文件降低置信度
        if 'test' in str(file_path).lower():
            confidence *= 0.3
        
        return max(0.1, confidence)
    
    def _get_suggestion(self, func_name: str) -> str:
        """获取修复建议"""
        suggestions = {
            'eval': '避免使用 eval()，使用 ast.literal_eval() 或 json.loads() 替代',
            'exec': '避免使用 exec()，重构代码避免动态执行',
            'compile': '检查 compile() 的用途，确保不执行不受信任的代码',
            'execfile': '避免使用 execfile()，这是不安全的做法',
            'os.system': '使用 subprocess 模块替代 os.system()',
            'os.popen': '使用 subprocess.Popen 替代 os.popen()',
            '__import__': '使用 import 语句替代 __import__()',
        }
        
        # 匹配前缀
        for key in suggestions:
            if func_name.startswith(key):
                return suggestions[key]
        
        return "审查此函数调用，确保不会执行恶意代码"
