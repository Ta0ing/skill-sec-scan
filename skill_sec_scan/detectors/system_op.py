"""
危险操作检测引擎

检测文件系统操作、进程操作等危险行为
"""
import ast
import re
from pathlib import Path
from typing import List

from .base import BaseDetector
from ..models import Finding, RiskCategory, RiskLevel, Location


class SystemOperationDetector(BaseDetector):
    """危险系统操作检测器"""
    
    # 文件系统操作
    FILE_OPS = {
        'os.remove': RiskLevel.HIGH,
        'os.unlink': RiskLevel.HIGH,
        'os.rmdir': RiskLevel.MEDIUM,
        'os.mkdir': RiskLevel.LOW,
        'os.makedirs': RiskLevel.LOW,
        'shutil.rmtree': RiskLevel.CRITICAL,
        'shutil.copy': RiskLevel.LOW,
        'shutil.move': RiskLevel.MEDIUM,
        'os.chmod': RiskLevel.MEDIUM,
        'os.chown': RiskLevel.HIGH,
        'os.rename': RiskLevel.MEDIUM,
    }
    
    # 进程操作
    PROCESS_OPS = {
        'os.kill': RiskLevel.HIGH,
        'os.killpg': RiskLevel.HIGH,
        'os.fork': RiskLevel.MEDIUM,
        'os.spawn': RiskLevel.MEDIUM,
        'os.exec': RiskLevel.HIGH,
        'os.execl': RiskLevel.HIGH,
        'os.execle': RiskLevel.HIGH,
        'os.execlp': RiskLevel.HIGH,
        'os.execlpe': RiskLevel.HIGH,
        'os.execv': RiskLevel.HIGH,
        'os.execve': RiskLevel.HIGH,
        'os.execvp': RiskLevel.HIGH,
        'os.execvpe': RiskLevel.HIGH,
    }
    
    # 危险命令模式
    DANGEROUS_COMMANDS = [
        (r'rm\s+-rf', '危险删除命令 rm -rf', RiskLevel.CRITICAL),
        (r'shutdown', '系统关机命令', RiskLevel.CRITICAL),
        (r'reboot', '系统重启命令', RiskLevel.CRITICAL),
        (r'halt', '系统停止命令', RiskLevel.CRITICAL),
        (r'poweroff', '系统关机命令', RiskLevel.CRITICAL),
        (r'init\s+[06]', '系统关机/重启', RiskLevel.CRITICAL),
        (r'kill\s+-9', '强制终止进程', RiskLevel.HIGH),
        (r'killall', '终止所有进程', RiskLevel.HIGH),
        (r'\bdd\b', '磁盘操作命令', RiskLevel.HIGH),
        (r'mkfs', '格式化文件系统', RiskLevel.HIGH),
        (r'fdisk', '磁盘分区工具', RiskLevel.HIGH),
        (r'parted', '磁盘分区工具', RiskLevel.HIGH),
        (r'iptables', '防火墙规则', RiskLevel.HIGH),
        (r'chmod\s+777', '设置危险权限', RiskLevel.MEDIUM),
        (r'chown\s+.*:', '修改文件所有者', RiskLevel.MEDIUM),
    ]
    
    @property
    def category(self) -> RiskCategory:
        return RiskCategory.SYSTEM_OPERATION
    
    @property
    def description(self) -> str:
        return "检测危险系统操作（文件删除、进程终止等）"
    
    def detect(self, tree: ast.AST, file_path: Path) -> List[Finding]:
        """检测 AST 中的危险系统操作"""
        findings = []
        
        # 读取源代码
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()
        except Exception:
            source = ""
        
        # 合并所有危险操作
        all_dangerous_ops = {**self.FILE_OPS, **self.PROCESS_OPS}
        
        # 1. AST 检测危险函数调用
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node.func)
                
                if func_name in all_dangerous_ops:
                    risk_level = all_dangerous_ops[func_name]
                    code_snippet = ast.get_source_segment(source, node) or ""
                    
                    # 检查是否在字符串参数中包含危险命令
                    cmd_risk = self._check_command_in_args(node, source)
                    if cmd_risk:
                        risk_level = max(risk_level, cmd_risk, key=lambda x: x.value)
                    
                    findings.append(Finding(
                        category=self.category,
                        risk_level=risk_level,
                        message=f"检测到危险操作: {func_name}()",
                        location=Location(file_path, node.lineno, node.col_offset),
                        code_snippet=code_snippet,
                        suggestion=self._get_suggestion(func_name),
                        confidence=0.9,
                        rule_id=f"SO{list(all_dangerous_ops.keys()).index(func_name) + 1:03d}",
                    ))
        
        # 2. 正则检测危险命令
        for pattern, message, risk_level in self.DANGEROUS_COMMANDS:
            for match in re.finditer(pattern, source, re.IGNORECASE):
                line_no = source[:match.start()].count('\n') + 1
                
                # 获取上下文
                lines = source.split('\n')
                context = lines[line_no - 1] if line_no <= len(lines) else match.group(0)
                
                findings.append(Finding(
                    category=self.category,
                    risk_level=risk_level,
                    message=f"检测到危险命令: {message}",
                    location=Location(file_path, line_no, 0),
                    code_snippet=context.strip(),
                    suggestion="避免执行危险的系统命令",
                    confidence=0.95,
                    rule_id="SO050",
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
    
    def _check_command_in_args(self, node: ast.Call, source: str) -> RiskLevel:
        """检查参数中是否包含危险命令"""
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                cmd = arg.value
                for pattern, _, risk_level in self.DANGEROUS_COMMANDS:
                    if re.search(pattern, cmd, re.IGNORECASE):
                        return risk_level
        return None
    
    def _get_suggestion(self, func_name: str) -> str:
        """获取修复建议"""
        if 'rmtree' in func_name:
            return "避免使用 shutil.rmtree()，这是极度危险的操作"
        elif 'remove' in func_name or 'unlink' in func_name:
            return "仔细审查文件删除操作，确保不会删除重要文件"
        elif 'kill' in func_name:
            return "避免终止其他进程，除非必要"
        elif 'chmod' in func_name:
            return "审查权限修改，避免设置过于宽松的权限"
        elif 'chown' in func_name:
            return "审查所有者修改，这可能导致权限问题"
        elif 'exec' in func_name:
            return "避免使用 exec 系列函数，这会替换当前进程"
        else:
            return "审查此系统操作，确保不会造成安全问题"
