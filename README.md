<p align="center">
  <img src="https://img.shields.io/badge/version-v1.0.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/python-3.8+-blue?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/dependencies-zero-orange?style=flat-square" alt="Zero Dependencies">
  <img src="https://img.shields.io/badge/platform-cross--platform-informational?style=flat-square" alt="Cross-Platform">
</p>

<h1 align="center">🛡️ AgentShield-CLI</h1>

<p align="center">
  <strong>Lightweight Terminal AI Agent Execution Security Sandbox Engine</strong><br>
  轻量级终端AI Agent执行安全沙箱引擎
</p>

---

**[简体中文](#简体中文) | [繁體中文](#繁體中文) | [English](#english)**

---

<a id="简体中文"></a>

## 🇨🇳 简体中文

### 🎉 项目介绍

**AgentShield-CLI** 是一款专为AI Agent代码执行场景设计的轻量级终端安全沙箱引擎。在AI Agent（如Claude Code、Copilot、Cursor等）日益普及的今天，Agent自动生成的代码可能包含潜在的安全风险——未经授权的文件访问、网络请求、资源滥用等。AgentShield-CLI 为个人开发者提供了一个**零依赖、开箱即用**的安全执行环境，让每一次Agent代码执行都在可控、可审计的沙箱中完成。

**💡 灵感来源**：受NVIDIA OpenShell等AI Agent安全运行时项目的启发，我们设计了这款面向个人开发者的轻量级替代方案，专注于本地单机场景的安全隔离与行为审计。

**✨ 自研差异化亮点**：
- 🚫 **零核心依赖** — 纯Python标准库实现，无需安装任何第三方包
- 📊 **智能风险评分** — 自动评估每次执行的安全风险等级（0-100分）
- 📜 **声明式策略引擎** — YAML/JSON策略配置，支持3套内置模板
- 📁 **文件变更追踪** — 自动检测并记录所有文件创建/修改/删除操作
- 🖥️ **TUI实时仪表盘** — 终端内实时监控执行状态
- 📋 **多格式审计报告** — 支持JSON/HTML/Markdown格式导出

### ✨ 核心特性

| 特性 | 描述 |
|------|------|
| 🔒 **沙箱执行引擎** | 隔离执行Agent生成的命令，自动追踪所有行为 |
| 📜 **策略引擎** | 3套内置策略模板（default/strict/permissive），支持自定义YAML策略 |
| 📁 **文件系统监控** | 自动检测文件创建、修改、删除操作 |
| 🧠 **智能风险评分** | 基于网络活动、文件操作、策略违规等多维度自动评估风险 |
| ⏱️ **资源管控** | 内存限制、CPU限制、执行超时控制 |
| 📋 **审计日志** | 完整记录每次执行的行为，支持多格式导出 |
| 🖥️ **TUI仪表盘** | 终端实时监控面板，自动刷新 |
| 📊 **执行历史** | 持久化存储执行记录，支持查询和分析 |
| 🚀 **零依赖** | 核心引擎纯Python标准库实现 |
| 💻 **跨平台** | 支持Linux、macOS、Windows |

### 🚀 快速开始

**环境要求**：
- Python 3.8+
- 无需任何第三方依赖

**安装**：

```bash
# 克隆仓库
git clone https://github.com/gitstq/AgentShield-CLI.git
cd AgentShield-CLI

# 直接运行（无需安装）
python agentshield.py --version
```

**基本使用**：

```bash
# 在沙箱中执行命令
python agentshield.py run "python script.py"

# 使用严格策略执行
python agentshield.py run --policy strict "npm install"

# 设置超时和内存限制
python agentshield.py run --timeout 30 --memory-limit 256 "node app.js"

# 查看详细输出
python agentshield.py run --verbose "echo hello"

# 预演模式（不实际执行）
python agentshield.py run --dry-run "rm -rf /tmp/test"
```

**审计与监控**：

```bash
# 查看审计日志
python agentshield.py audit

# 导出HTML报告
python agentshield.py audit --export report.html

# 查看执行历史
python agentshield.py history

# 查看系统状态
python agentshield.py status

# 启动TUI仪表盘
python agentshield.py tui
```

**策略管理**：

```bash
# 查看可用策略模板
python agentshield.py policy list

# 查看默认策略详情
python agentshield.py policy show

# 从模板创建自定义策略
python agentshield.py policy init --template strict --output my-policy.json

# 验证策略文件
python agentshield.py policy validate my-policy.json
```

### 📖 详细使用指南

#### 策略模板说明

| 模板 | 网络模式 | 内存限制 | 超时 | 适用场景 |
|------|---------|---------|------|---------|
| `default` | restricted | 512MB | 60s | 日常开发任务 |
| `strict` | deny | 128MB | 30s | 不受信任的代码 |
| `permissive` | allow | 2048MB | 300s | 可信代码（仅监控） |

#### 执行报告示例

```
============================================================
🛡️  AgentShield Execution Report
============================================================
  Session ID    : e1a8f85c
  Duration      : 0.005s
  Exit Code     : 0
  Risk Score    : 🟢 0/100 (low)

  📁 File Activity (3 operations):
     ✅ Created  : 2
     ✏️  Modified : 1

  📤 stdout:
     Hello from AgentShield!

============================================================
```

#### 风险评分机制

风险评分基于以下维度自动计算（满分100）：
- **网络活动**（0-30分）：检测到的网络连接数量
- **文件操作**（0-25分）：文件创建/修改/删除数量
- **策略违规**（0-30分）：违反安全策略的次数
- **资源使用**（0-15分）：内存占用和执行时长

| 风险等级 | 分数范围 | 图标 |
|---------|---------|------|
| 低风险 | 0-39 | 🟢 |
| 中风险 | 40-69 | 🟡 |
| 高风险 | 70-100 | 🔴 |

### 💡 设计思路与迭代规划

**设计理念**：
- **安全优先**：默认使用restricted策略，在安全与可用性之间取得平衡
- **零依赖原则**：核心引擎仅使用Python标准库，确保在任何环境下都能运行
- **声明式配置**：通过YAML/JSON策略文件定义安全规则，可版本化管理
- **全链路审计**：从执行前策略检查到执行后行为分析，完整记录每个环节

**技术选型原因**：
- Python标准库：最大化兼容性，零安装成本
- subprocess模块：成熟的进程隔离方案
- JSON策略格式：无需额外解析依赖，与工具链无缝集成

**后续迭代计划**：
- 🔮 集成更多AI Agent后端（Claude Code、Codex等）的专用策略模板
- 🔮 支持eBPF/BPF级别的系统调用监控（Linux）
- 🔮 添加Web仪表盘界面
- 🔮 支持团队共享策略配置
- 🔮 集成CI/CD管道的安全检查

### 📦 打包与部署

本项目为纯Python工具库/CLI项目，无需打包为可执行文件。

**直接使用**：
```bash
git clone https://github.com/gitstq/AgentShield-CLI.git
cd AgentShield-CLI
python agentshield.py run "your-command"
```

**作为模块引入**：
```python
from src.core.runner import SandboxExecutor, SandboxConfig

# 创建沙箱配置
config = SandboxConfig(args)
executor = SandboxExecutor(config)
result = executor.execute()

print(f"Exit code: {result.exit_code}")
print(f"Risk score: {result.risk_score}")
```

**兼容环境**：Python 3.8+ / Linux / macOS / Windows

### 🤝 贡献指南

欢迎贡献代码！请查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解详情。

**提交规范**：
- `feat: 新增功能`
- `fix: 修复问题`
- `docs: 文档更新`
- `refactor: 代码重构`
- `test: 测试相关`

### 📄 开源协议

本项目基于 [MIT License](LICENSE) 开源。

---

<a id="繁體中文"></a>

## 🇹🇼 繁體中文

### 🎉 專案介紹

**AgentShield-CLI** 是一款專為AI Agent程式碼執行場景設計的輕量級終端安全沙箱引擎。在AI Agent（如Claude Code、Copilot、Cursor等）日益普及的今天，Agent自動生成的程式碼可能包含潛在的安全風險——未經授權的檔案存取、網路請求、資源濫用等。AgentShield-CLI 為個人開發者提供了一個**零依賴、開箱即用**的安全執行環境，讓每一次Agent程式碼執行都在可控、可審計的沙箱中完成。

**💡 靈感來源**：受NVIDIA OpenShell等AI Agent安全執行時專案的啟發，我們設計了這款面向個人開發者的輕量級替代方案，專注於本地單機場景的安全隔離與行為審計。

**✨ 自研差異化亮點**：
- 🚫 **零核心依賴** — 純Python標準庫實現，無需安裝任何第三方套件
- 📊 **智慧風險評分** — 自動評估每次執行的安全風險等級（0-100分）
- 📜 **宣告式策略引擎** — YAML/JSON策略配置，支援3套內建模板
- 📁 **檔案變更追蹤** — 自動偵測並記錄所有檔案建立/修改/刪除操作
- 🖥️ **TUI即時儀表板** — 終端內即時監控執行狀態
- 📋 **多格式審計報告** — 支援JSON/HTML/Markdown格式匯出

### ✨ 核心特性

| 特性 | 描述 |
|------|------|
| 🔒 **沙箱執行引擎** | 隔離執行Agent生成的命令，自動追蹤所有行為 |
| 📜 **策略引擎** | 3套內建策略模板（default/strict/permissive），支援自訂YAML策略 |
| 📁 **檔案系統監控** | 自動偵測檔案建立、修改、刪除操作 |
| 🧠 **智慧風險評分** | 基於網路活動、檔案操作、策略違規等多維度自動評估風險 |
| ⏱️ **資源管控** | 記憶體限制、CPU限制、執行逾時控制 |
| 📋 **審計日誌** | 完整記錄每次執行的行為，支援多格式匯出 |
| 🖥️ **TUI儀表板** | 終端即時監控面板，自動刷新 |
| 📊 **執行歷史** | 持久化儲存執行記錄，支援查詢和分析 |
| 🚀 **零依賴** | 核心引擎純Python標準庫實現 |
| 💻 **跨平台** | 支援Linux、macOS、Windows |

### 🚀 快速開始

**環境要求**：
- Python 3.8+
- 無需任何第三方依賴

**安裝**：

```bash
# 克隆倉庫
git clone https://github.com/gitstq/AgentShield-CLI.git
cd AgentShield-CLI

# 直接執行（無需安裝）
python agentshield.py --version
```

**基本使用**：

```bash
# 在沙箱中執行命令
python agentshield.py run "python script.py"

# 使用嚴格策略執行
python agentshield.py run --policy strict "npm install"

# 設定逾時和記憶體限制
python agentshield.py run --timeout 30 --memory-limit 256 "node app.js"

# 查看詳細輸出
python agentshield.py run --verbose "echo hello"

# 預演模式（不實際執行）
python agentshield.py run --dry-run "rm -rf /tmp/test"
```

**審計與監控**：

```bash
# 查看審計日誌
python agentshield.py audit

# 匯出HTML報告
python agentshield.py audit --export report.html

# 查看執行歷史
python agentshield.py history

# 查看系統狀態
python agentshield.py status

# 啟動TUI儀表板
python agentshield.py tui
```

**策略管理**：

```bash
# 查看可用策略模板
python agentshield.py policy list

# 查看預設策略詳情
python agentshield.py policy show

# 從模板建立自訂策略
python agentshield.py policy init --template strict --output my-policy.json

# 驗證策略檔案
python agentshield.py policy validate my-policy.json
```

### 📖 詳細使用指南

#### 策略模板說明

| 模板 | 網路模式 | 記憶體限制 | 逾時 | 適用場景 |
|------|---------|---------|------|---------|
| `default` | restricted | 512MB | 60s | 日常開發任務 |
| `strict` | deny | 128MB | 30s | 不受信任的程式碼 |
| `permissive` | allow | 2048MB | 300s | 可信程式碼（僅監控） |

#### 風險評分機制

風險評分基於以下維度自動計算（滿分100）：
- **網路活動**（0-30分）：偵測到的網路連線數量
- **檔案操作**（0-25分）：檔案建立/修改/刪除數量
- **策略違規**（0-30分）：違反安全策略的次數
- **資源使用**（0-15分）：記憶體佔用和執行時長

| 風險等級 | 分數範圍 | 圖示 |
|---------|---------|------|
| 低風險 | 0-39 | 🟢 |
| 中風險 | 40-69 | 🟡 |
| 高風險 | 70-100 | 🔴 |

### 💡 設計思路與迭代規劃

**設計理念**：
- **安全優先**：預設使用restricted策略，在安全與可用性之間取得平衡
- **零依賴原則**：核心引擎僅使用Python標準庫，確保在任何環境下都能執行
- **宣告式配置**：透過YAML/JSON策略檔案定義安全規則，可版本化管理
- **全鏈路審計**：從執行前策略檢查到執行後行為分析，完整記錄每個環節

**後續迭代計劃**：
- 🔮 整合更多AI Agent後端的專用策略模板
- 🔮 支援eBPF/BPF級別的系統呼叫監控（Linux）
- 🔮 新增Web儀表板介面
- 🔮 支援團隊共享策略配置
- 🔮 整合CI/CD管道的安全檢查

### 📦 打包與部署

本專案為純Python工具庫/CLI專案，無需打包為可執行檔案。

**相容環境**：Python 3.8+ / Linux / macOS / Windows

### 🤝 貢獻指南

歡迎貢獻程式碼！請查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解詳情。

### 📄 開源協議

本專案基於 [MIT License](LICENSE) 開源。

---

<a id="english"></a>

## 🇺🇸 English

### 🎉 Introduction

**AgentShield-CLI** is a lightweight terminal security sandbox engine designed specifically for AI Agent code execution scenarios. As AI Agents (like Claude Code, Copilot, Cursor, etc.) become increasingly popular, auto-generated code may carry potential security risks — unauthorized file access, network requests, resource abuse, and more. AgentShield-CLI provides individual developers with a **zero-dependency, ready-to-use** secure execution environment, ensuring every Agent code execution runs within a controlled, auditable sandbox.

**💡 Inspiration**: Inspired by NVIDIA OpenShell and similar AI Agent security runtime projects, we designed this lightweight alternative focused on local single-machine security isolation and behavior auditing for individual developers.

**✨ Differentiation Highlights**:
- 🚫 **Zero Core Dependencies** — Pure Python standard library, no third-party packages needed
- 📊 **Intelligent Risk Scoring** — Automatically assesses security risk level (0-100) for each execution
- 📜 **Declarative Policy Engine** — YAML/JSON policy configuration with 3 built-in templates
- 📁 **File Change Tracking** — Automatically detects and records all file creation/modification/deletion
- 🖥️ **TUI Real-time Dashboard** — In-terminal real-time execution monitoring
- 📋 **Multi-format Audit Reports** — Export to JSON/HTML/Markdown formats

### ✨ Core Features

| Feature | Description |
|---------|-------------|
| 🔒 **Sandbox Execution Engine** | Isolated execution of Agent-generated commands with full behavior tracking |
| 📜 **Policy Engine** | 3 built-in policy templates (default/strict/permissive) + custom YAML support |
| 📁 **File System Monitoring** | Automatic detection of file creation, modification, and deletion |
| 🧠 **Intelligent Risk Scoring** | Multi-dimensional risk assessment based on network, file ops, and policy violations |
| ⏱️ **Resource Management** | Memory limits, CPU limits, execution timeout control |
| 📋 **Audit Logging** | Complete behavior recording for each execution with multi-format export |
| 🖥️ **TUI Dashboard** | Real-time terminal monitoring panel with auto-refresh |
| 📊 **Execution History** | Persistent execution records with query and analysis support |
| 🚀 **Zero Dependencies** | Core engine built entirely on Python standard library |
| 💻 **Cross-Platform** | Supports Linux, macOS, and Windows |

### 🚀 Quick Start

**Requirements**:
- Python 3.8+
- No third-party dependencies required

**Installation**:

```bash
# Clone the repository
git clone https://github.com/gitstq/AgentShield-CLI.git
cd AgentShield-CLI

# Run directly (no installation needed)
python agentshield.py --version
```

**Basic Usage**:

```bash
# Execute a command in the sandbox
python agentshield.py run "python script.py"

# Execute with strict policy
python agentshield.py run --policy strict "npm install"

# Set timeout and memory limits
python agentshield.py run --timeout 30 --memory-limit 256 "node app.js"

# Verbose output
python agentshield.py run --verbose "echo hello"

# Dry run (simulate without executing)
python agentshield.py run --dry-run "rm -rf /tmp/test"
```

**Audit & Monitoring**:

```bash
# View audit logs
python agentshield.py audit

# Export HTML report
python agentshield.py audit --export report.html

# View execution history
python agentshield.py history

# Show system status
python agentshield.py status

# Launch TUI dashboard
python agentshield.py tui
```

**Policy Management**:

```bash
# List available policy templates
python agentshield.py policy list

# Show default policy details
python agentshield.py policy show

# Create custom policy from template
python agentshield.py policy init --template strict --output my-policy.json

# Validate policy file
python agentshield.py policy validate my-policy.json
```

### 📖 Detailed Usage Guide

#### Policy Templates

| Template | Network Mode | Memory Limit | Timeout | Use Case |
|----------|-------------|-------------|---------|----------|
| `default` | restricted | 512MB | 60s | General development tasks |
| `strict` | deny | 128MB | 30s | Untrusted code execution |
| `permissive` | allow | 2048MB | 300s | Trusted code (monitoring only) |

#### Risk Scoring System

Risk scores are automatically calculated based on the following dimensions (max 100):
- **Network Activity** (0-30): Number of detected network connections
- **File Operations** (0-25): Number of file creations/modifications/deletions
- **Policy Violations** (0-30): Number of security policy violations
- **Resource Usage** (0-15): Memory consumption and execution duration

| Risk Level | Score Range | Icon |
|-----------|-------------|------|
| Low | 0-39 | 🟢 |
| Medium | 40-69 | 🟡 |
| High | 70-100 | 🔴 |

#### Execution Report Example

```
============================================================
🛡️  AgentShield Execution Report
============================================================
  Session ID    : e1a8f85c
  Duration      : 0.005s
  Exit Code     : 0
  Risk Score    : 🟢 0/100 (low)

  📁 File Activity (3 operations):
     ✅ Created  : 2
     ✏️  Modified : 1

  📤 stdout:
     Hello from AgentShield!

============================================================
```

### 💡 Design Philosophy & Roadmap

**Design Principles**:
- **Security First**: Default `restricted` policy balances security with usability
- **Zero Dependencies**: Core engine uses only Python standard library for maximum compatibility
- **Declarative Configuration**: YAML/JSON policy files for version-controllable security rules
- **Full-chain Auditing**: Complete recording from pre-execution policy checks to post-execution behavior analysis

**Technology Choices**:
- Python Standard Library: Maximum compatibility, zero installation cost
- `subprocess` module: Mature process isolation solution
- JSON policy format: No extra parsing dependencies, seamless toolchain integration

**Roadmap**:
- 🔮 Dedicated policy templates for more AI Agent backends (Claude Code, Codex, etc.)
- 🔮 eBPF/BPF-level system call monitoring (Linux)
- 🔮 Web dashboard interface
- 🔮 Team-shared policy configurations
- 🔮 CI/CD pipeline security checks integration

### 📦 Packaging & Deployment

This is a pure Python tool/library/CLI project — no executable packaging required.

**Direct Usage**:
```bash
git clone https://github.com/gitstq/AgentShield-CLI.git
cd AgentShield-CLI
python agentshield.py run "your-command"
```

**As a Module**:
```python
from src.core.runner import SandboxExecutor, SandboxConfig

config = SandboxConfig(args)
executor = SandboxExecutor(config)
result = executor.execute()

print(f"Exit code: {result.exit_code}")
print(f"Risk score: {result.risk_score}")
```

**Compatible Environments**: Python 3.8+ / Linux / macOS / Windows

### 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

**Commit Convention**:
- `feat: new feature`
- `fix: bug fix`
- `docs: documentation update`
- `refactor: code refactoring`
- `test: test related`

### 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">
  Built with ❤️ by AgentShield Team | Inspired by NVIDIA OpenShell
</p>
