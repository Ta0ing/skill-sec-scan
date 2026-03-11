"""
检测器基类

所有检测器的抽象基类
"""
from abc import ABC, abstractmethod
from typing import List, Set
import ast
from pathlib import Path

from ..models import Finding, RiskCategory


class BaseDetector(ABC):
    """检测器基类"""
    
    @property
    @abstractmethod
    def category(self) -> RiskCategory:
        """检测器所属风险类别"""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """检测器描述"""
        pass
    
    @abstractmethod
    def detect(self, tree: ast.AST, file_path: Path) -> List[Finding]:
        """
        检测 AST 中的风险点
        
        Args:
            tree: Python 文件的 AST
            file_path: 文件路径
            
        Returns:
            发现的风险列表
        """
        pass
    
    def detect_file(self, file_path: Path) -> List[Finding]:
        """
        检测单个文件
        
        Args:
            file_path: 文件路径
            
        Returns:
            发现的风险列表
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()
            
            tree = ast.parse(source, filename=str(file_path))
            return self.detect(tree, file_path)
        except SyntaxError:
            # 语法错误，跳过该文件
            return []
        except Exception as e:
            # 其他错误，记录但不中断
            return []
    
    def get_imports(self, tree: ast.AST) -> Set[str]:
        """
        提取文件中导入的所有模块
        
        Args:
            tree: AST 树
            
        Returns:
            导入的模块名称集合
        """
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split('.')[0])
        return imports
    
    def get_source_segment(self, source: str, node: ast.AST) -> str:
        """
        获取节点的源代码片段
        
        Args:
            source: 源代码
            node: AST 节点
            
        Returns:
            源代码片段
        """
        try:
            # Python 3.8+ 支持 ast.get_source_segment
            import sys
            if sys.version_info >= (3, 8):
                segment = ast.get_source_segment(source, node)
                if segment:
                    return segment.strip()
        except Exception:
            pass
        
        # 降级处理：返回空字符串
        return ""
