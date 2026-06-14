#!/usr/bin/env python3
"""
Security Scanner Module - AI Agent Skill Security Scanner
安全扫描模块 - AI Agent Skill安全扫描器

新增scan子命令，用于扫描AI Agent技能文件中的安全漏洞
"""

import re
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any


class SecurityRule:
    """安全规则基类"""
    def __init__(self, rule_id: str, name: str, description: str, severity: str,
                 category: str, patterns: List[str], recommendation: str):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW
        self.category = category
        self.patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
        self.recommendation = recommendation

    def check(self, content: str, filename: str) -> List[Dict[str, Any]]:
        """检查内容是否匹配规则"""
        findings = []
        for pattern in self.patterns:
            for match in pattern.finditer(content):
                findings.append({
                    "rule_id": self.rule_id,
                    "rule_name": self.name,
                    "severity": self.severity,
                    "category": self.category,
                    "description": self.description,
                    "recommendation": self.recommendation,
                    "line_number": content[:match.start()].count('\n') + 1,
                    "column": match.start() - content.rfind('\n', 0, match.start()),
                    "matched_text": match.group()[:100],
                    "filename": filename
                })
        return findings


# 预定义安全规则库
SECURITY_RULES = [
    # === 提示注入攻击 (Prompt Injection) ===
    SecurityRule(
        "AGENT-001", "系统提示词泄露",
        "检测到可能的系统提示词或system prompt硬编码，可能导致提示词注入攻击",
        "HIGH", "Prompt Injection",
        [r"system[_\s]?prompt\s*[=:]\s*[\"'][^\"']{50,}",
         r"you are a helpful assistant[^\"']{0,500}",
         r"system[_\s]?instruction\s*[=:]\s*[\"'][^\"']{50,}"],
        "避免在代码中硬编码系统提示词，使用外部配置文件或环境变量"
    ),
    SecurityRule(
        "AGENT-002", "动态代码执行风险",
        "检测到使用eval/exec等动态代码执行函数，可能导致代码注入",
        "CRITICAL", "Prompt Injection",
        [r"\beval\s*\(", r"\bexec\s*\(", r"\b__import__\s*\("],
        "避免使用eval/exec，使用ast.literal_eval或json.loads替代"
    ),
    SecurityRule(
        "AGENT-003", "提示词拼接漏洞",
        "检测到用户输入直接与提示词拼接，存在提示注入风险",
        "HIGH", "Prompt Injection",
        [r"prompt\s*\+?\s*=\s*f?[\"'].*\{.*\}.*[\"']",
         r"\.format\s*\([^)]*user",
         r"f[\"'][^\"']*\{[^}]*input[^}]*\}"],
        "使用参数化提示词模板，对用户输入进行严格校验和过滤"
    ),

    # === 数据外泄 (Data Exfiltration) ===
    SecurityRule(
        "AGENT-004", "敏感信息硬编码",
        "检测到API密钥、密码等敏感信息硬编码",
        "CRITICAL", "Data Exfiltration",
        [r"api[_\s]?key\s*[=:]\s*[\"'][^\"']{20,}[\"']",
         r"password\s*[=:]\s*[\"'][^\"']{8,}[\"']",
         r"secret\s*[=:]\s*[\"'][^\"']{16,}[\"']",
         r"token\s*[=:]\s*[\"'][^\"']{20,}[\"']"],
        "使用环境变量或密钥管理服务存储敏感信息"
    ),
    SecurityRule(
        "AGENT-005", "外部网络请求",
        "检测到向外部地址发送数据，可能存在数据外泄风险",
        "MEDIUM", "Data Exfiltration",
        [r"requests\.(post|put|patch)\s*\(\s*[\"']https?://[^\"']+",
         r"urllib\.request\.urlopen\s*\(\s*[\"']https?://",
         r"http\.Client\(\)\.Post\s*\("],
        "审查所有外部网络请求，确保数据传输符合隐私政策"
    ),
    SecurityRule(
        "AGENT-006", "文件读取操作",
        "检测到读取敏感文件的操作，可能存在信息泄露",
        "MEDIUM", "Data Exfiltration",
        [r"open\s*\(\s*[\"']/(etc|proc|sys|var)[^\"']*[\"']",
         r"open\s*\(\s*[\"'].*\.(env|key|pem|p12)[\"']"],
        "限制文件访问范围，实施最小权限原则"
    ),

    # === 权限提升 (Privilege Escalation) ===
    SecurityRule(
        "AGENT-007", "系统命令执行",
        "检测到执行系统命令的代码，存在权限提升和命令注入风险",
        "CRITICAL", "Privilege Escalation",
        [r"os\.system\s*\(", r"subprocess\.(run|call|Popen)\s*\(",
         r"os\.popen\s*\(", r"commands\.(getoutput|getstatusoutput)"],
        "避免直接执行系统命令，使用安全的API替代"
    ),
    SecurityRule(
        "AGENT-008", "文件权限修改",
        "检测到修改文件权限的操作，可能导致权限提升",
        "HIGH", "Privilege Escalation",
        [r"os\.chmod\s*\(", r"Path\.chmod\s*\(", r"os\.chown\s*\("],
        "审慎修改文件权限，避免赋予不必要的执行权限"
    ),
    SecurityRule(
        "AGENT-009", "Sudo/Root操作",
        "检测到需要提升权限的操作",
        "HIGH", "Privilege Escalation",
        [r"\bsudo\b", r"\broot\b", r"setuid", r"setgid"],
        "避免在Agent Skill中执行需要特权权限的操作"
    ),

    # === 供应链攻击 (Supply Chain) ===
    SecurityRule(
        "AGENT-010", "依赖安装风险",
        "检测到自动安装依赖的代码，存在供应链投毒风险",
        "MEDIUM", "Supply Chain",
        [r"pip\s+install", r"npm\s+install", r"cargo\s+install",
         r"apt\s+install", r"brew\s+install"],
        "固定依赖版本，使用私有镜像源，审查依赖包"
    ),
    SecurityRule(
        "AGENT-011", "远程脚本执行",
        "检测到下载并执行远程脚本的操作",
        "CRITICAL", "Supply Chain",
        [r"curl\s+.*\|\s*(bash|sh|python)",
         r"wget\s+.*\|\s*(bash|sh|python)",
         r"Invoke-Expression\s*\("],
        "禁止下载并直接执行远程脚本，使用本地验证后的脚本"
    ),
    SecurityRule(
        "AGENT-012", "不安全的反序列化",
        "检测到不安全的反序列化操作，可能导致远程代码执行",
        "CRITICAL", "Supply Chain",
        [r"pickle\.loads?\s*\(", r"yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.Loader",
         r"marshal\.loads?\s*\("],
        "使用安全的序列化方式，如json、yaml.safe_load"
    ),

    # === 其他安全风险 ===
    SecurityRule(
        "AGENT-013", "调试模式开启",
        "检测到调试模式或详细错误信息输出，可能泄露敏感信息",
        "LOW", "Information Disclosure",
        [r"debug\s*[=:]\s*True", r"DEBUG\s*[=:]\s*True",
         r"app\.run\s*\(.*debug\s*=\s*True"],
        "生产环境关闭调试模式"
    ),
    SecurityRule(
        "AGENT-014", "不安全的临时文件",
        "检测到不安全的临时文件创建方式",
        "MEDIUM", "Insecure Configuration",
        [r"mktemp\s*\(", r"tempfile\.mkstemp", r"/tmp/[^\"']+"],
        "使用安全的临时文件API，设置适当的文件权限"
    ),
    SecurityRule(
        "AGENT-015", "日志敏感信息",
        "检测到日志中可能记录敏感信息",
        "MEDIUM", "Information Disclosure",
        [r"log(ger)?\.(debug|info|warning|error)\s*\([^)]*(password|token|secret|key)",
         r"print\s*\([^)]*(password|token|secret|key)"],
        "避免在日志中记录敏感信息，使用脱敏处理"
    ),
]


class Scanner:
    """安全扫描引擎"""

    SUPPORTED_EXTENSIONS = {'.py', '.js', '.ts', '.json', '.yaml', '.yml',
                           '.md', '.txt', '.sh', '.bash', '.zsh'}

    def __init__(self, rules: Optional[List[SecurityRule]] = None):
        self.rules = rules or SECURITY_RULES
        self.findings: List[Dict[str, Any]] = []
        self.stats = {
            "files_scanned": 0,
            "files_with_issues": 0,
            "total_findings": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        }

    def scan_file(self, filepath: Path) -> List[Dict[str, Any]]:
        """扫描单个文件"""
        findings = []
        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
            for rule in self.rules:
                rule_findings = rule.check(content, str(filepath))
                findings.extend(rule_findings)
        except Exception as e:
            print(f"Warning: Could not scan {filepath}: {e}")

        self.stats["files_scanned"] += 1
        if findings:
            self.stats["files_with_issues"] += 1
            self.stats["total_findings"] += len(findings)
            for f in findings:
                self.stats["severity_counts"][f["severity"]] += 1

        return findings

    def scan_directory(self, directory: Path, recursive: bool = True) -> List[Dict[str, Any]]:
        """扫描目录"""
        all_findings = []

        if recursive:
            files = [f for f in directory.rglob('*') if f.is_file()]
        else:
            files = [f for f in directory.iterdir() if f.is_file()]

        # 过滤支持的文件类型
        files = [f for f in files if f.suffix in self.SUPPORTED_EXTENSIONS]

        # 排除常见非代码目录
        exclude_dirs = {'.git', '.github', 'node_modules', '__pycache__', '.venv',
                       'venv', 'dist', 'build', '.pytest_cache', '.mypy_cache'}
        files = [f for f in files if not any(ex in f.parts for ex in exclude_dirs)]

        for filepath in files:
            findings = self.scan_file(filepath)
            all_findings.extend(findings)

        return all_findings

    def scan_path(self, path: Path, recursive: bool = True) -> List[Dict[str, Any]]:
        """扫描路径（文件或目录）"""
        if path.is_file():
            return self.scan_file(path)
        elif path.is_dir():
            return self.scan_directory(path, recursive)
        else:
            print(f"Error: {path} is not a valid file or directory")
            return []


class TerminalFormatter:
    """终端表格格式化输出"""

    COLORS = {
        "CRITICAL": "\033[91m",  # 红色
        "HIGH": "\033[93m",      # 黄色
        "MEDIUM": "\033[94m",    # 蓝色
        "LOW": "\033[92m",       # 绿色
        "RESET": "\033[0m",
        "BOLD": "\033[1m"
    }

    def format(self, findings: List[Dict[str, Any]], stats: Dict[str, Any]) -> str:
        lines = []
        lines.append("=" * 80)
        lines.append(f"{self.COLORS['BOLD']}AgentShield-CLI 安全扫描报告{self.COLORS['RESET']}")
        lines.append(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"扫描文件: {stats['files_scanned']} | 问题文件: {stats['files_with_issues']} | 发现问题: {stats['total_findings']}")
        lines.append("-" * 80)

        if not findings:
            lines.append(f"{self.COLORS['LOW']}✓ 未检测到安全问题{self.COLORS['RESET']}")
            lines.append("=" * 80)
            return "\n".join(lines)

        # 按严重程度和文件分组
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        sorted_findings = sorted(findings, key=lambda x: severity_order.index(x["severity"]))

        current_file = None
        for finding in sorted_findings:
            if finding["filename"] != current_file:
                current_file = finding["filename"]
                lines.append(f"\n{self.COLORS['BOLD']}📁 {current_file}{self.COLORS['RESET']}")

            color = self.COLORS.get(finding["severity"], self.COLORS["RESET"])
            severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(finding["severity"], "⚪")

            lines.append(f"  {severity_icon} {color}[{finding['severity']}]{self.COLORS['RESET']} {finding['rule_id']}: {finding['rule_name']}")
            lines.append(f"     位置: 第{finding['line_number']}行, 第{finding['column']}列")
            lines.append(f"     描述: {finding['description']}")
            lines.append(f"     匹配: {finding['matched_text'][:60]}...")
            lines.append(f"     建议: {finding['recommendation']}")
            lines.append("")

        # 统计摘要
        lines.append("-" * 80)
        lines.append(f"{self.COLORS['BOLD']}风险统计:{self.COLORS['RESET']}")
        for sev in severity_order:
            count = stats["severity_counts"][sev]
            color = self.COLORS.get(sev, self.COLORS["RESET"])
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
            lines.append(f"  {icon} {color}{sev}{self.COLORS['RESET']}: {count}")

        lines.append("=" * 80)
        return "\n".join(lines)


class JSONFormatter:
    """JSON格式化输出"""
    def format(self, findings: List[Dict[str, Any]], stats: Dict[str, Any]) -> str:
        report = {
            "tool": "AgentShield-CLI",
            "version": "1.0.0",
            "scan_time": datetime.now().isoformat(),
            "summary": stats,
            "findings": findings
        }
        return json.dumps(report, ensure_ascii=False, indent=2)


class MarkdownFormatter:
    """Markdown格式化输出"""
    def format(self, findings: List[Dict[str, Any]], stats: Dict[str, Any]) -> str:
        lines = []
        lines.append("# AgentShield-CLI 安全扫描报告\n")
        lines.append(f"**扫描时间:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        lines.append(f"**扫描文件:** {stats['files_scanned']} | **问题文件:** {stats['files_with_issues']} | **发现问题:** {stats['total_findings']}\n")

        if not findings:
            lines.append("✅ **未检测到安全问题**\n")
            return "\n".join(lines)

        lines.append("## 风险统计\n")
        lines.append("| 严重程度 | 数量 |")
        lines.append("|---------|------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = stats["severity_counts"][sev]
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
            lines.append(f"| {icon} {sev} | {count} |")

        lines.append("\n## 详细发现\n")

        # 按文件分组
        by_file: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            by_file.setdefault(f["filename"], []).append(f)

        for filename, file_findings in by_file.items():
            lines.append(f"### 📁 {filename}\n")
            for finding in file_findings:
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(finding["severity"], "⚪")
                lines.append(f"#### {icon} [{finding['severity']}] {finding['rule_id']}: {finding['rule_name']}\n")
                lines.append(f"- **位置:** 第{finding['line_number']}行, 第{finding['column']}列")
                lines.append(f"- **描述:** {finding['description']}")
                lines.append(f"- **匹配内容:** `{finding['matched_text'][:80]}`")
                lines.append(f"- **修复建议:** {finding['recommendation']}")
                lines.append("")

        return "\n".join(lines)


class SARIFFormatter:
    """SARIF格式化输出（用于GitHub Security Tab集成）"""
    def format(self, findings: List[Dict[str, Any]], stats: Dict[str, Any]) -> str:
        rules_dict: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            if f["rule_id"] not in rules_dict:
                rules_dict[f["rule_id"]] = {
                    "id": f["rule_id"],
                    "name": f["rule_name"],
                    "shortDescription": {"text": f["description"]},
                    "fullDescription": {"text": f["description"]},
                    "defaultConfiguration": {"level": self._severity_to_level(f["severity"])},
                    "help": {"text": f["recommendation"]},
                    "properties": {"category": f["category"]}
                }

        results = []
        for f in findings:
            results.append({
                "ruleId": f["rule_id"],
                "level": self._severity_to_level(f["severity"]),
                "message": {"text": f"{f['description']} - {f['recommendation']}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["filename"]},
                        "region": {
                            "startLine": f["line_number"],
                            "startColumn": f["column"],
                            "snippet": {"text": f["matched_text"]}
                        }
                    }
                }]
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "AgentShield-CLI",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/gitstq/AgentShield-CLI",
                        "rules": list(rules_dict.values())
                    }
                },
                "results": results
            }]
        }

        return json.dumps(sarif, ensure_ascii=False, indent=2)

    def _severity_to_level(self, severity: str) -> str:
        mapping = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
        return mapping.get(severity, "warning")


def run_scan(args) -> int:
    """运行扫描命令"""
    target_path = Path(args.path)
    if not target_path.exists():
        print(f"Error: 路径不存在: {target_path}")
        return 1

    print(f"🛡️ AgentShield-CLI v1.0.0 - 开始扫描...")
    print(f"📁 目标: {target_path.absolute()}")
    print("-" * 60)

    scanner = Scanner()
    findings = scanner.scan_path(target_path, recursive=not args.no_recursive)

    # 按严重程度过滤
    if args.severity:
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        min_level = severity_order.index(args.severity)
        findings = [f for f in findings if severity_order.index(f["severity"]) <= min_level]

    # 格式化输出
    formatters = {
        "terminal": TerminalFormatter(),
        "json": JSONFormatter(),
        "markdown": MarkdownFormatter(),
        "sarif": SARIFFormatter()
    }

    formatter = formatters[args.format]
    output = formatter.format(findings, scanner.stats)

    if args.output:
        Path(args.output).write_text(output, encoding='utf-8')
        print(f"\n✅ 报告已保存至: {args.output}")
    else:
        print(output)

    # 返回码
    critical_high = scanner.stats["severity_counts"]["CRITICAL"] + scanner.stats["severity_counts"]["HIGH"]
    if critical_high > 0:
        return 2  # 发现高危问题
    elif scanner.stats["total_findings"] > 0:
        return 1  # 发现中低危问题
    else:
        return 0  # 无问题
