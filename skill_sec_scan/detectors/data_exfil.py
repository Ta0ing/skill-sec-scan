"""
数据泄露检测引擎

检测网络请求、敏感数据访问等可能导致数据泄露的行为
"""
import ast
import re
from pathlib import Path
from typing import List, Set

from .base import BaseDetector
from ..models import Finding, RiskCategory, RiskLevel, Location


class DataExfiltrationDetector(BaseDetector):
    """数据泄露检测器"""
    
    # 网络请求模块
    NETWORK_MODULES = {
        'requests', 'urllib', 'httpx', 'http', 'httplib', 
        'websocket', 'socket', 'aiohttp'
    }
    
    # 网络请求函数
    NETWORK_FUNCTIONS = {
        'requests.get': RiskLevel.MEDIUM,
        'requests.post': RiskLevel.HIGH,
        'requests.put': RiskLevel.HIGH,
        'requests.patch': RiskLevel.MEDIUM,
        'requests.delete': RiskLevel.MEDIUM,
        'urllib.request.urlopen': RiskLevel.MEDIUM,
        'urllib.request.Request': RiskLevel.MEDIUM,
        'http.client.HTTPConnection': RiskLevel.MEDIUM,
        'httpx.get': RiskLevel.MEDIUM,
        'httpx.post': RiskLevel.HIGH,
        'socket.socket': RiskLevel.HIGH,
        'websocket.create_connection': RiskLevel.HIGH,
    }
    
    # 敏感信息访问
    SENSITIVE_FUNCTIONS = {
        'os.environ': RiskLevel.MEDIUM,
        'os.getenv': RiskLevel.MEDIUM,
        'keyring.get_password': RiskLevel.HIGH,
        'keyring.set_password': RiskLevel.HIGH,
    }
    
    # 敏感路径模式
    SENSITIVE_PATH_PATTERNS = [
        (r'[\'"]~/\.ssh/[\'"]', 'SSH 密钥目录', RiskLevel.HIGH),
        (r'[\'"]~/\.aws/[\'"]', 'AWS 凭证目录', RiskLevel.HIGH),
        (r'[\'"]~/\.gnupg/[\'"]', 'GPG 密钥目录', RiskLevel.HIGH),
        (r'[\'"]\.env[\'"]', '环境变量文件', RiskLevel.MEDIUM),
        (r'[\'"].*\.pem[\'"]', 'PEM 证书文件', RiskLevel.HIGH),
        (r'[\'"].*\.key[\'"]', '密钥文件', RiskLevel.HIGH),
        (r'[\'"].*_rsa[\'"]', 'RSA 密钥文件', RiskLevel.HIGH),
    ]
    
    @property
    def category(self) -> RiskCategory:
        return RiskCategory.DATA_EXFILTRATION
    
    @property
    def description(self) -> str:
        return "检测数据泄露风险（网络请求、敏感信息访问等）"
    
    def detect(self, tree: ast.AST, file_path: Path) -> List[Finding]:
        """检测 AST 中的数据泄露风险"""
        findings = []
        
        # 读取源代码
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()
        except Exception:
            source = ""
        
        # 获取导入的模块
        imports = self.get_imports(tree)
        
        # 1. 检测网络请求
        if imports & self.NETWORK_MODULES:
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = self._get_func_name(node.func)
                    if func_name in self.NETWORK_FUNCTIONS:
                        risk_level = self.NETWORK_FUNCTIONS[func_name]
                        
                        # 检查是否有数据上传
                        if self._has_data_upload(node):
                            risk_level = RiskLevel.HIGH
                        
                        code_snippet = ast.get_source_segment(source, node) or ""
                        
                        findings.append(Finding(
                            category=self.category,
                            risk_level=risk_level,
                            message=f"检测到网络请求: {func_name}()",
                            location=Location(file_path, node.lineno, node.col_offset),
                            code_snippet=code_snippet,
                            suggestion="检查网络请求目标，确保不泄露敏感数据",
                            confidence=0.85,
                            rule_id=f"DE{list(self.NETWORK_FUNCTIONS.keys()).index(func_name) + 1:03d}",
                        ))
        
        # 2. 检测敏感信息访问
        for node in ast.walk(tree):
            # 环境变量访问
            if isinstance(node, ast.Attribute):
                if node.attr == 'environ':
                    code_snippet = ast.get_source_segment(source, node) or ""
                    findings.append(Finding(
                        category=self.category,
                        risk_level=RiskLevel.MEDIUM,
                        message="检测到访问环境变量 (os.environ)",
                        location=Location(file_path, node.lineno, node.col_offset),
                        code_snippet=code_snippet,
                        suggestion="审查环境变量读取，确保不访问敏感凭证",
                        confidence=0.6,
                        rule_id="DE010",
                    ))
            
            # keyring 调用
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node.func)
                if 'keyring' in func_name:
                    code_snippet = ast.get_source_segment(source, node) or ""
                    findings.append(Finding(
                        category=self.category,
                        risk_level=RiskLevel.HIGH,
                        message=f"检测到密钥库访问: {func_name}()",
                        location=Location(file_path, node.lineno, node.col_offset),
                        code_snippet=code_snippet,
                        suggestion="不应访问系统密钥库，这是严重的隐私和安全问题",
                        confidence=1.0,
                        rule_id="DE011",
                    ))
        
        # 3. 正则检测敏感路径
        for pattern, message, risk_level in self.SENSITIVE_PATH_PATTERNS:
            for match in re.finditer(pattern, source):
                line_no = source[:match.start()].count('\n') + 1
                
                findings.append(Finding(
                    category=self.category,
                    risk_level=risk_level,
                    message=f"检测到访问敏感路径: {message}",
                    location=Location(file_path, line_no, 0),
                    code_snippet=match.group(0),
                    suggestion="不应访问敏感凭证文件",
                    confidence=1.0,
                    rule_id="DE020",
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
    
    def _has_data_upload(self, node: ast.Call) -> bool:
        """检查是否有数据上传"""
        # 检查关键字参数
        for kw in node.keywords:
            if kw.arg in ('data', 'json', 'files', 'params'):
                return True
        
        # POST/PUT 请求
        func_name = self._get_func_name(node.func)
        if 'post' in func_name or 'put' in func_name:
            return True
        
        return False
