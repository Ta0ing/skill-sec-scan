"""
报告器基类

所有报告器的抽象基类
"""
from abc import ABC, abstractmethod
from pathlib import Path

from ..models import SkillScanResult


class BaseReporter(ABC):
    """报告器基类"""
    
    @abstractmethod
    def generate(self, result: SkillScanResult) -> str:
        """
        生成报告内容
        
        Args:
            result: 扫描结果
            
        Returns:
            报告内容（字符串）
        """
        pass
    
    def export(self, result: SkillScanResult, output_path: Path) -> None:
        """
        导出报告到文件
        
        Args:
            result: 扫描结果
            output_path: 输出文件路径
        """
        content = self.generate(result)
        
        # 确保输出目录存在
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
