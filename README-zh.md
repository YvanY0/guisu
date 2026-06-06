# Guisu（归宿）

> **Guisu（归宿）** — Dotfiles 的港湾。"归宿"在中文中意为"家"、"归属之地"，正如这个词所蕴含的意义，Guisu为配置文件提供了一个安全的家园，让你能够在所有机器上轻松管理它们。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org)
[![Status](https://img.shields.io/badge/status-early%20development-yellow.svg)](#project-status)

**[English Documentation](README.md)**

**早期开发阶段提示**：Guisu 目前处于早期开发阶段（1.0 版本之前）。API 和功能可能会发生变化，暂不建议在日常环境中使用。

## 什么是 Guisu？

Guisu 是一个基于 **Rust** 的 dotfile 管理工具，灵感来源于 [chezmoi](https://www.chezmoi.io/)，旨在帮助你在多台机器上管理配置文件（dotfiles），具有以下特性：

- **极速性能**：Rust 原生二进制文件，支持并行处理
- **默认安全**：内置 age 加密，无需外部依赖
- **基于模板**：通过 minijinja 提供强大的 Jinja2 风格模板
- **类型安全**：利用 Rust 的类型系统防止运行时错误
- **智能状态跟踪**：使用 redb 进行持久化状态管理
- **交互式冲突解决**：精美的 TUI 界面处理冲突
- **跨平台**：支持 macOS、Linux 和 Windows

## 为什么选择 Guisu？

| 特性 | Guisu | Chezmoi | 优势 |
|------|-------|---------|------|
| **性能** | 原生 Rust | Go（含 cgo） | 快 2-5 倍 |
| **二进制大小** | ~3-5 MB | ~20 MB | 小 4 倍 |
| **加密** | 内置 age | 外部 age 二进制 | 无依赖 |
| **数据库** | redb（纯 Rust） | BoltDB（cgo） | 构建更简单 |
| **类型安全** | 编译时路径类型 | 运行时检查 | 更少 bug |
| **模板** | minijinja（Jinja2） | Go text/template | 更熟悉 |

## 快速开始

### 安装

**从源码安装**（需要 Rust 工具链）：

```bash
git clone https://github.com/YvanY0/guisu.git
cd guisu
cargo install --path crates/cli
```

**二进制发布版本**：即将推出

### 从 GitHub 初始化

```bash
# 克隆你的 dotfiles 仓库
guisu init username

# 或使用完整 URL
guisu init https://github.com/username/dotfiles.git
```

### 本地初始化

```bash
# 创建新的 dotfiles 仓库
guisu init
```

## 基础用法

### 添加文件到管理

```bash
# 添加单个文件
guisu add ~/.bashrc

# 添加加密文件
guisu add --encrypt ~/.ssh/id_rsa

# 添加整个目录
guisu add ~/.config/nvim
```

### 应用变更

```bash
# 应用所有变更
guisu apply

# 交互模式（手动解决冲突）
guisu apply --interactive

# 空运行（预览变更）
guisu apply --dry-run
```

### 查看状态

```bash
# 显示被管理文件的状态
guisu status

# 显示差异
guisu diff

# 预览渲染后的内容
guisu cat ~/.bashrc
```

### 编辑文件

```bash
# 编辑源文件（自动处理加密）
guisu edit ~/.bashrc

# 在配置的编辑器中打开
```

### 从仓库更新

```bash
# 拉取最新变更并应用
guisu update

# 只拉取不应用
guisu update --no-apply
```

### 查看系统信息

```bash
# 显示基本状态并验证配置
guisu info

# 显示详细信息（构建信息、版本、公钥、配置等）
guisu info --all

# 以 JSON 格式输出
guisu info --json
guisu info --all --json
```

### 查看模板变量

```bash
# 显示所有变量（系统、guisu 和用户定义的）
guisu variables

# 仅显示内置变量（系统 + guisu）
guisu variables --builtin

# 仅显示用户定义的变量
guisu variables --user

# 以 JSON 格式输出
guisu variables --json
```

## 核心概念

### 三态模型

Guisu 通过三个不同的状态管理文件：

```
源状态              目标状态              目的状态
（仓库）            （处理后）            （实际文件）
   ↓                    ↓                     ↓
.bashrc.j2    →    .bashrc（已渲染）  →   ~/.bashrc
key.txt.age   →    key.txt（已解密）  →   ~/key.txt
```

**持久化状态**（redb 数据库）跟踪上次应用的内容，以检测外部变更。

### 文件属性

Guisu 使用文件扩展名来编码文件属性。源文件和目标文件名相同，除了特殊扩展名：

```bash
# 模板文件（使用 Jinja2 渲染）
.bashrc.j2                       → ~/.bashrc（已渲染）

# 加密文件（age 加密）
private_key.age                  → private_key（已解密）

# 组合：模板 + 加密
.bashrc.j2.age                   → ~/.bashrc（先解密，后渲染）

# 普通文件（无转换）
.bashrc                          → ~/.bashrc
.ssh/config                      → ~/.ssh/config
scripts/deploy.sh                → scripts/deploy.sh
```

### 模板

Guisu 使用 **minijinja**（兼容 Jinja2）作为模板引擎：

```jinja2
# ~/.local/share/guisu/.bashrc.j2

# 平台特定配置
{% if os == "darwin" %}
export HOMEBREW_PREFIX="/opt/homebrew"
alias ls="gls --color=auto"
{% elif os == "linux" %}
alias ls="ls --color=auto"
{% endif %}

# 用户变量
export EDITOR="{{ editor }}"
export EMAIL="{{ email }}"

# 来自 Bitwarden 的密钥
export GITHUB_TOKEN="{{ bitwarden("GitHub").login.password }}"
# 或使用 bitwardenFields 获取自定义字段
export API_KEY="{{ bitwardenFields("GitHub", "APIKey") }}"
```

### 配置

在你的 dotfiles 仓库中创建 `.guisu.toml`：

```toml
[general]
color = true
progress = true
editor = "nvim"

[age]
identity = "~/.config/guisu/key.txt"
derive = true  # 从身份密钥派生公钥用于加密

[bitwarden]
provider = "rbw"  # 或 "bw"

[variables]
email = "user@example.com"
editor = "nvim"

[ignore]
# 从 guisu 管理中排除的文件/目录（不是 .gitignore 的替代品）
global = [".git", ".DS_Store"]
darwin = ["Thumbs.db"]
linux = ["*~"]
```

## 高级特性

### 加密

```bash
# 生成 age 身份密钥
guisu age generate -o ~/.config/guisu/key.txt

# 添加加密文件
guisu add --encrypt ~/.ssh/id_rsa

# 编辑加密文件（自动解密）
guisu edit ~/.ssh/id_rsa
```

### 平台特定变量

在 `.guisu/variables/` 目录中组织变量：

```
.guisu/variables/
├── user.toml               # 全局用户变量
├── visual.toml             # UI/外观设置
├── darwin/
│   ├── git.toml           # macOS 特定 git 配置
│   └── terminal.toml      # macOS 特定终端配置
└── linux/
    ├── git.toml           # Linux 特定 git 配置
    └── terminal.toml      # Linux 特定终端配置
```

### 交互式冲突解决

当本地文件与 dotfiles 不同时：

```bash
guisu apply --interactive
```

精美的 TUI 界面显示：
- 并排差异对比
- 三方比较（源、目标、目的地、数据库）
- 选项：覆盖、跳过、查看差异、预览

## 项目状态

### 已实现功能

- 文件管理（文件、目录、符号链接）
- 模板处理（minijinja，约 30 个函数）
- Age 加密（文件 + 内联）
- Git 集成（克隆、拉取、推送）
- 交互式冲突解决（TUI）
- 持久化状态跟踪（redb）
- 并行处理（rayon）
- 平台特定配置
- Bitwarden 集成（bw、rbw、bws）

### 相比 Chezmoi 缺失的功能

**关键功能**：
- 脚本执行系统（`run_before_*`、`run_after_*`、`run_once_*`、`run_onchange_*`）
- 外部资源（`.chezmoiexternal` 等效功能）
- 修改文件类型（`modify_*` 前缀）
- 仅创建文件（`create_*` 前缀）

**高优先级**：
- 密码管理器支持有限（仅 Bitwarden；缺少 1Password、LastPass、Pass、Vault 等）
- 模板函数有限（约 30 个 vs chezmoi 的 200+ 个）

**中等优先级**：
- 缺失命令：`doctor`、`unmanaged`、`re-add`、`archive`、`verify`、`merge`

详见 [ROADMAP.md](docs/development/ROADMAP.md) 了解详细开发计划。

## 文档

- [架构概览](docs/architecture/README.md) - 系统架构和设计
- [容器架构](docs/architecture/containers.md) - Crate 结构
- [组件设计](docs/architecture/components.md) - 内部组件
- [数据流](docs/architecture/data-flow.md) - 处理管道
- [贡献指南](docs/development/CONTRIBUTING.md) - 如何贡献
- [路线图](docs/development/ROADMAP.md) - 功能路线图

## 贡献

Guisu 处于早期开发阶段，欢迎贡献！请查看 [CONTRIBUTING.md](docs/development/CONTRIBUTING.md) 了解：

- 开发环境设置
- 代码结构
- 测试指南
- Pull Request 流程

## 灵感来源

Guisu 深受 [chezmoi](https://www.chezmoi.io/) 启发，目标是在 Rust 原生包中提供类似功能。

## 许可证

MIT 许可证 - 详见 [LICENSE](LICENSE)。
