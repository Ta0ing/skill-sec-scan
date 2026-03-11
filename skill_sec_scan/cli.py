"""
skill-sec-scan CLI 入口

命令行界面，提供参数解析、进度显示、结果输出等功能
"""
import sys
import click
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

from .config import Config, create_default_config
from .scanner import Scanner
from .models import RiskLevel, RiskCategory
from .reporters import TextReporter, JSONReporter, MarkdownReporter


# 初始化 Rich Console
console = Console()


def get_reporter(format_type: str, config: Config):
    """
    根据格式类型获取报告器
    
    Args:
        format_type: 输出格式 (text/json/markdown)
        config: 配置实例
        
    Returns:
        报告器实例
    """
    reporters = {
        'text': TextReporter(
            show_snippet=config.output.show_code_snippet,
            max_snippet_lines=config.output.max_snippet_lines,
        ),
        'json': JSONReporter(),
        'markdown': MarkdownReporter(),
    }
    return reporters.get(format_type, reporters['text'])


def print_banner():
    """打印工具横幅"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║              🔍 skill-sec-scan v1.0.0                        ║
    ║         Skills 安全扫描工具 - Security Scanner               ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold blue")


def print_summary(result):
    """打印扫描结果摘要"""
    # 风险等级颜色映射
    risk_colors = {
        RiskLevel.LOW: "green",
        RiskLevel.MEDIUM: "yellow",
        RiskLevel.HIGH: "red",
        RiskLevel.CRITICAL: "red bold",
    }
    
    # 整体风险
    overall_color = risk_colors.get(result.overall_risk, "white")
    console.print()
    console.print(Panel(
        f"[bold]技能:[/] {result.skill_name}\n"
        f"[bold]路径:[/] {result.skill_path}\n"
        f"[bold]扫描文件:[/] {len(result.scanned_files)} 个\n"
        f"[bold]扫描耗时:[/] {result.scan_duration:.2f} 秒",
        title="📋 扫描信息",
        border_style="blue",
    ))
    
    # 风险统计表格
    table = Table(title="📊 风险统计", show_header=True, header_style="bold magenta")
    table.add_column("风险等级", style="cyan", width=20)
    table.add_column("数量", justify="right", width=10)
    
    risk_summary = result.risk_summary
    risk_labels = [
        ("🔴 严重 (Critical)", RiskLevel.CRITICAL, risk_summary[RiskLevel.CRITICAL]),
        ("🔴 高危 (High)", RiskLevel.HIGH, risk_summary[RiskLevel.HIGH]),
        ("🟡 中危 (Medium)", RiskLevel.MEDIUM, risk_summary[RiskLevel.MEDIUM]),
        ("🟢 低危 (Low)", RiskLevel.LOW, risk_summary[RiskLevel.LOW]),
    ]
    
    for label, level, count in risk_labels:
        color = risk_colors.get(level, "white")
        table.add_row(f"[{color}]{label}[/]", str(count))
    
    console.print()
    console.print(table)
    
    # 整体风险等级
    console.print()
    console.print(Panel(
        f"[bold {overall_color}]{result.overall_risk.value.upper()}[/]",
        title="⚠️  整体风险等级",
        border_style=overall_color,
    ))


def print_findings(result, verbose: bool = False):
    """打印详细发现"""
    if not result.findings:
        console.print()
        console.print(Panel(
            "[bold green]✅ 未发现安全风险[/]",
            border_style="green",
        ))
        return
    
    console.print()
    console.print(Panel(
        f"[bold red]发现 {len(result.findings)} 个安全风险[/]",
        title="⚠️  安全风险",
        border_style="red",
    ))
    
    for i, finding in enumerate(result.findings, 1):
        # 风险等级颜色
        risk_colors = {
            RiskLevel.LOW: "green",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.HIGH: "red",
            RiskLevel.CRITICAL: "red bold",
        }
        color = risk_colors.get(finding.risk_level, "white")
        
        # 构建发现信息
        console.print()
        console.print(f"[bold cyan][{i}][/][bold {color}] {finding.message}[/]")
        console.print(f"  [dim]风险等级:[/] [{color}]{finding.risk_level.value}[{color}]")
        console.print(f"  [dim]风险类别:[/] {finding.category.value}")
        console.print(f"  [dim]位置:[/] {finding.location}")
        
        if verbose and finding.code_snippet:
            console.print(f"  [dim]代码片段:[/]")
            console.print(f"  [dim]  {finding.code_snippet}[/]")
        
        if finding.suggestion:
            console.print(f"  [dim]建议:[/] [italic]{finding.suggestion}[/]")


@click.group()
@click.version_option('1.0.0', prog_name='skill-sec-scan')
def cli():
    """
    skill-sec-scan - Skills 安全扫描工具
    
    扫描 CoPaw Worker Skills 目录，检测潜在安全风险
    """
    pass


@cli.command()
@click.argument('skill_path', type=click.Path(exists=True))
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['text', 'json', 'markdown']),
              default='text',
              help='输出格式 (text/json/markdown)')
@click.option('--output', '-o', 'output_file',
              type=click.Path(),
              default=None,
              help='输出文件路径（默认输出到终端）')
@click.option('--severity', '-s', 'min_severity',
              type=click.Choice(['low', 'medium', 'high', 'critical']),
              default='low',
              help='最低显示风险等级')
@click.option('--config', '-c', 'config_path',
              type=click.Path(exists=True),
              default=None,
              help='配置文件路径')
@click.option('--verbose', '-v',
              is_flag=True,
              help='详细输出模式')
@click.option('--quiet', '-q',
              is_flag=True,
              help='静默模式（仅输出结果）')
def scan(skill_path: str, output_format: str, output_file: Optional[str],
         min_severity: str, config_path: Optional[str], verbose: bool, quiet: bool):
    """
    扫描指定 Skills 目录的安全风险
    
    SKILL_PATH: Skills 目录路径
    """
    # 加载配置
    config = create_default_config()
    if config_path:
        config = Config.from_file(Path(config_path))
    
    # 应用命令行参数覆盖
    config.apply_cli_overrides(
        skill_path=skill_path,
        output_file=output_file,
        output_format=output_format,
        verbose=verbose,
        quiet=quiet,
        min_severity=min_severity,
    )
    
    # 显示横幅（非静默模式）
    if not quiet:
        print_banner()
    
    # 创建扫描器
    scanner = Scanner(config)
    
    # 执行扫描（带进度显示）
    if not quiet:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]正在扫描...", total=None)
            result = scanner.scan(Path(skill_path))
            progress.update(task, completed=100)
    else:
        result = scanner.scan(Path(skill_path))
    
    # 生成报告
    reporter = get_reporter(output_format, config)
    
    if output_file:
        # 输出到文件
        reporter.export(result, Path(output_file))
        if not quiet:
            console.print()
            console.print(f"[bold green]✅ 报告已保存到: {output_file}[/]")
    else:
        # 输出到终端
        if output_format == 'text':
            if not quiet:
                print_summary(result)
                print_findings(result, verbose=verbose)
            else:
                # 静默模式仅输出摘要
                console.print(f"整体风险: {result.overall_risk.value}")
                console.print(f"发现问题: {len(result.findings)} 个")
        else:
            # JSON/Markdown 格式直接输出
            console.print(reporter.generate(result))
    
    # 设置退出码
    if result.overall_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
        sys.exit(1)
    else:
        sys.exit(0)


@cli.command()
@click.argument('skill_path', type=click.Path(exists=True))
@click.option('--check-only', is_flag=True, help='仅返回退出码，不输出报告')
def quick(skill_path: str, check_only: bool):
    """
    快速扫描，仅显示高风险项
    
    SKILL_PATH: Skills 目录路径
    """
    config = create_default_config()
    config.output.verbosity = "quiet"
    
    scanner = Scanner(config)
    result = scanner.scan(Path(skill_path))
    
    if not check_only:
        # 仅显示高风险和严重风险
        high_risk_findings = [
            f for f in result.findings
            if f.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        ]
        
        if high_risk_findings:
            console.print(f"[bold red]发现 {len(high_risk_findings)} 个高风险问题:[/]")
            for i, finding in enumerate(high_risk_findings, 1):
                console.print(f"  [{i}] {finding.message} ({finding.location})")
        else:
            console.print("[bold green]✅ 未发现高风险问题[/]")
    
    # 退出码
    if result.overall_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
        sys.exit(1)
    else:
        sys.exit(0)


@cli.command()
def rules():
    """列出所有可用的检测规则"""
    console.print()
    console.print(Panel(
        "[bold]内置检测规则[/]",
        border_style="blue",
    ))
    
    # 代码执行检测
    table = Table(title="🔍 代码执行检测 (Code Execution)", show_header=True)
    table.add_column("规则 ID", style="cyan", width=10)
    table.add_column("检测目标", width=30)
    table.add_column("风险等级", width=15)
    table.add_column("描述", width=40)
    
    code_exec_rules = [
        ("CE001", "eval()", "HIGH", "执行字符串表达式"),
        ("CE002", "exec()", "HIGH", "执行字符串代码"),
        ("CE003", "compile()", "MEDIUM", "编译代码对象"),
        ("CE004", "os.system()", "HIGH", "执行 shell 命令"),
        ("CE005", "subprocess.*", "MEDIUM", "启动子进程"),
    ]
    
    for rule in code_exec_rules:
        table.add_row(*rule)
    
    console.print(table)
    
    # 数据外传检测
    table2 = Table(title="📤 数据外传检测 (Data Exfiltration)", show_header=True)
    table2.add_column("规则 ID", style="cyan", width=10)
    table2.add_column("检测目标", width=30)
    table2.add_column("风险等级", width=15)
    table2.add_column("描述", width=40)
    
    data_exfil_rules = [
        ("DE001", "requests.post()", "HIGH", "POST 请求（可能上传数据）"),
        ("DE002", "socket.socket()", "HIGH", "原始 socket 通信"),
        ("DE003", "smtplib.SMTP()", "HIGH", "邮件发送"),
        ("DE004", "ftplib.FTP()", "HIGH", "FTP 上传"),
    ]
    
    for rule in data_exfil_rules:
        table2.add_row(*rule)
    
    console.print()
    console.print(table2)
    
    # 敏感信息访问检测
    table3 = Table(title="🔐 敏感信息访问检测 (Sensitive Access)", show_header=True)
    table3.add_column("规则 ID", style="cyan", width=10)
    table3.add_column("检测目标", width=30)
    table3.add_column("风险等级", width=15)
    table3.add_column("描述", width=40)
    
    sensitive_rules = [
        ("SA001", "os.environ", "MEDIUM", "读取环境变量"),
        ("SA002", "~/.ssh/", "HIGH", "访问 SSH 密钥"),
        ("SA003", "~/.aws/", "HIGH", "访问 AWS 凭证"),
        ("SA004", "keyring.*", "HIGH", "读取系统密钥库"),
    ]
    
    for rule in sensitive_rules:
        table3.add_row(*rule)
    
    console.print()
    console.print(table3)
    
    # 系统操作检测
    table4 = Table(title="⚠️  危险系统操作检测 (System Operation)", show_header=True)
    table4.add_column("规则 ID", style="cyan", width=10)
    table4.add_column("检测目标", width=30)
    table4.add_column("风险等级", width=15)
    table4.add_column("描述", width=40)
    
    system_rules = [
        ("SO001", "os.remove()", "HIGH", "删除文件"),
        ("SO002", "shutil.rmtree()", "CRITICAL", "删除目录树"),
        ("SO003", "os.chmod()", "MEDIUM", "修改文件权限"),
        ("SO004", "os.kill()", "HIGH", "终止进程"),
    ]
    
    for rule in system_rules:
        table4.add_row(*rule)
    
    console.print()
    console.print(table4)
    console.print()


@cli.command()
def version():
    """显示版本信息"""
    console.print("[bold blue]skill-sec-scan[/] version [bold]1.0.0[/]")
    console.print("Skills 安全扫描工具")


def main():
    """主入口"""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]扫描已取消[/]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[bold red]错误: {e}[/]")
        sys.exit(1)


if __name__ == '__main__':
    main()
