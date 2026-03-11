# 🔍 skill-sec-scan

**CoPaw Worker Skills 安全扫描工具**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

一个用于扫描 CoPaw Worker Skills 目录安全风险的命令行工具，支持检测恶意代码执行、数据泄露、危险系统操作等多种风险类型。

---

## ✨ 功能特性

### 🔐 多维度安全检测

| 检测类别 | 检测内容 | 风险等级 |
|---------|---------|---------|
| **恶意代码执行** | eval(), exec(), os.system(), subprocess.* 等 | 🔴 HIGH/CRITICAL |
| **数据泄露风险** | 网络请求、敏感文件访问、密钥读取等 | 🟡 MEDIUM/HIGH |
| **危险系统操作** | 文件删除、进程终止、系统命令等 | 🔴 HIGH/CRITICAL |

### 📊 风险等级评估

- **🔴 CRITICAL** - 严重风险，禁止安装
- **🔴 HIGH** - 高风险，强烈建议修复
- **🟡 MEDIUM** - 中等风险，建议审查
- **🟢 LOW** - 低风险，可忽略

### 📄 多格式报告输出

- **文本格式** - 终端彩色输出，清晰易读
- **JSON 格式** - 结构化数据，适合程序处理
- **Markdown 格式** - 文档友好，适合 GitHub 展示

---

## 🚀 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/copaw/skill-sec-scan.git
cd skill-sec-scan

# 安装（开发模式）
pip install -e .
```

### 基本使用

```bash
# 扫描技能目录
skill-sec-scan scan /path/to/skill

# 详细输出
skill-sec-scan scan /path/to/skill -v

# JSON 格式输出
skill-sec-scan scan /path/to/skill --format json

# 导出到文件
skill-sec-scan scan /path/to/skill -o report.txt
```

---

## 📖 使用指南

### 命令说明

#### `scan` - 完整扫描

扫描指定 Skills 目录，输出详细的安全报告。

```bash
skill-sec-scan scan <skill_path> [OPTIONS]
```

**参数**：

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `skill_path` | - | Skills 目录路径（必需） | - |
| `--format` | `-f` | 输出格式 (text/json/markdown) | text |
| `--output` | `-o` | 输出文件路径 | 终端输出 |
| `--severity` | `-s` | 最低显示风险等级 | low |
| `--config` | `-c` | 配置文件路径 | - |
| `--verbose` | `-v` | 详细输出模式 | - |
| `--quiet` | `-q` | 静默模式 | - |

**示例**：

```bash
# 基本扫描
skill-sec-scan scan ./my-skill

# 详细输出
skill-sec-scan scan ./my-skill -v

# JSON 格式输出到文件
skill-sec-scan scan ./my-skill --format json -o report.json

# 使用配置文件
skill-sec-scan scan ./my-skill --config scan-config.yaml

# 仅显示高风险问题
skill-sec-scan scan ./my-skill --severity high
```

#### `quick` - 快速扫描

快速扫描，仅显示高风险项，适合 CI/CD 集成。

```bash
skill-sec-scan quick <skill_path> [OPTIONS]
```

**参数**：

| 参数 | 说明 |
|------|------|
| `skill_path` | Skills 目录路径（必需） |
| `--check-only` | 仅返回退出码，不输出报告 |

**示例**：

```bash
# 快速扫描
skill-sec-scan quick ./my-skill

# CI/CD 模式（仅返回退出码）
skill-sec-scan quick ./my-skill --check-only
```

#### `rules` - 查看规则

列出所有可用的检测规则。

```bash
skill-sec-scan rules
```

### 退出码

| 退出码 | 说明 |
|--------|------|
| `0` | 扫描成功，未发现高风险问题 |
| `1` | 发现高风险或严重风险问题 |
| `130` | 用户取消扫描 |
| 其他 | 扫描出错 |

---

## ⚙️ 配置文件

配置文件使用 YAML 格式，支持以下配置项：

```yaml
# sec-scan-config.yaml
version: "1.0"

# 检测器配置
detectors:
  code_exec:
    enabled: true
    severity_overrides:
      eval: critical
  
  data_exfil:
    enabled: true
    allowed_domains:
      - "api.github.com"
  
  system_op:
    enabled: true

# 白名单配置
whitelist:
  skills:
    - file-sync
    - pdf
  patterns:
    - "scripts/helpers/.*\\.py"

# 输出配置
output:
  format: text
  show_code_snippet: true
  max_snippet_lines: 5
  verbosity: normal
```

---

## 📝 示例输出

### 文本格式

```
======================================================================
  skill-sec-scan 安全扫描报告
======================================================================

  ────────────────────────────────────────────────────────────
  基本信息
  ────────────────────────────────────────────────────────────
  技能名称: example-skill
  技能路径: /skills/example-skill
  扫描文件: 5 个
  扫描耗时: 0.15 秒

  ────────────────────────────────────────────────────────────
  风险概览
  ────────────────────────────────────────────────────────────
  整体风险等级: 🔴 高风险 (HIGH)
  发现问题总数: 3 个

  风险等级分布:
    🔴 严重 (Critical): 0
    🔴 高危 (High):     2
    🟡 中危 (Medium):   1
    🟢 低危 (Low):      0

  【🔴 高风险 (HIGH)】
    [1] [CE001] 检测到 eval() 动态代码执行
        类别: 恶意代码执行
        位置: /skills/example/scripts/main.py:15:8
        代码:
          result = eval(user_input)
        建议: 避免使用 eval()，使用 ast.literal_eval() 或 json.loads() 替代
```

### JSON 格式

```json
{
  "report_type": "skill-sec-scan",
  "version": "1.0.0",
  "scan_result": {
    "skill_name": "example-skill",
    "overall_risk": "high",
    "total_findings": 3,
    "risk_summary": {
      "critical": 0,
      "high": 2,
      "medium": 1,
      "low": 0
    }
  }
}
```

### Markdown 格式

```markdown
# 🔍 skill-sec-scan 安全扫描报告

## 📊 风险概览

**整体风险等级**: 🔴 **高风险**

### 风险等级分布

| 风险等级 | 数量 | 状态 |
|---------|------|------|
| 🔴 严重 (Critical) | 0 | ✅ |
| 🔴 高危 (High) | 2 | ⚠️ 需处理 |
| 🟡 中危 (Medium) | 1 | ℹ️ 建议审查 |
```

---

## 🔧 高级用法

### Python API

```python
from skill_sec_scan import Scanner, Config
from skill_sec_scan.reporters import TextReporter, JSONReporter

# 创建配置
config = Config.from_file("sec-scan-config.yaml")

# 创建扫描器
scanner = Scanner(config)

# 执行扫描
result = scanner.scan("/path/to/skill")

# 获取结果
print(f"整体风险: {result.overall_risk.value}")
print(f"发现问题: {len(result.findings)} 个")

# 生成报告
reporter = TextReporter()
report = reporter.generate(result)

# 导出到文件
reporter.export(result, "report.txt")
```

### CI/CD 集成

```yaml
# GitHub Actions 示例
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install skill-sec-scan
        run: pip install -e .
      
      - name: Run security scan
        run: skill-sec-scan quick ./skills --check-only
```

---

## 📂 项目结构

```
skill_sec_scan/
├── __init__.py           # 包初始化
├── cli.py                # CLI 入口
├── config.py             # 配置管理
├── models.py             # 数据模型
├── scanner.py            # 扫描引擎
├── detectors/            # 检测器模块
│   ├── __init__.py
│   ├── base.py           # 检测器基类
│   ├── code_exec.py      # 恶意代码检测
│   ├── data_exfil.py     # 数据泄露检测
│   └── system_op.py      # 危险操作检测
├── reporters/            # 报告生成模块
│   ├── __init__.py
│   ├── base.py           # 报告器基类
│   └── text.py           # 文本/JSON/Markdown 报告器
└── utils/                # 工具函数
```

---

## 🛡️ 检测规则

### 代码执行检测 (CE)

| 规则 ID | 检测目标 | 风险等级 |
|---------|---------|---------|
| CE001 | eval() | HIGH |
| CE002 | exec() | HIGH |
| CE003 | compile() | MEDIUM |
| CE004 | os.system() | HIGH |
| CE005 | os.popen() | HIGH |
| CE006 | subprocess.call() | MEDIUM |
| CE007 | subprocess.run() | MEDIUM |
| CE008 | subprocess.Popen() | MEDIUM |

### 数据泄露检测 (DE)

| 规则 ID | 检测目标 | 风险等级 |
|---------|---------|---------|
| DE001 | requests.post() | HIGH |
| DE002 | socket.socket() | HIGH |
| DE003 | os.environ | MEDIUM |
| DE004 | keyring.* | HIGH |
| DE005 | ~/.ssh/ | HIGH |
| DE006 | ~/.aws/ | HIGH |

### 系统操作检测 (SO)

| 规则 ID | 检测目标 | 风险等级 |
|---------|---------|---------|
| SO001 | os.remove() | HIGH |
| SO002 | shutil.rmtree() | CRITICAL |
| SO003 | os.chmod() | MEDIUM |
| SO004 | os.kill() | HIGH |
| SO005 | rm -rf | CRITICAL |
| SO006 | shutdown/reboot | CRITICAL |

---

## 🤝 贡献指南

欢迎贡献代码、报告问题或提出建议！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

---

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

---

