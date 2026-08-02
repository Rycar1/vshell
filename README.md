# VShell

> **An incomplete reverse-engineered re-implementation of the in-the-wild exploited C2 framework "VShell"**
> **对在野利用的 C2 框架 "VShell" 的不完整逆向工程复刻**

[![Go Version](https://img.shields.io/badge/Go-1.25-blue)](https://go.dev/dl/)
[![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red)](license.txt)

> **⚠️ 声明 / Disclaimer**
>
> 本仓库是对在野利用的 C2 框架 **VShell**（v3.0）的 **不完整 / incomplete** 逆向工程产物，仅用于安全研究与学习交流。
> This repository is an **incomplete** reverse-engineering / re-implementation of the in-the-wild exploited C2 framework **VShell** (v3.0), for security research and learning purposes only.
>
> - **仅供授权测试使用** / For authorized testing only. 禁止用于任何非法用途。
> - 与原版无关，原作者保留所有权利；本仓库不附带原版许可。Unofficial, unaffiliated with the original author; all rights of the original software remain with its author.
> - 功能与原版存在差异，部分模块缺失或行为不一致。Functionality differs from the original; some modules are missing or behave differently.

---

## 简介 / Introduction

**English**: VShell is an open-source, **incomplete** re-implementation of the VShell C2 (Command & Control) management framework. It provides a web management panel, a multi-protocol C2 engine (HTTP/HTTPS, DNS, KCP, WebSocket/CDN), and an agent with remote terminal, screen streaming and plugin execution. The project was produced by decompiling and reimplementing the original Windows binary (`v_windows_amd64.exe`); many internal details were recovered through static analysis and may be incomplete or inaccurate.

**中文**: VShell 是对原版 VShell C2（命令与控制）管理框架的不完整开源复刻。包含 Web 管理面板、多协议 C2 引擎（HTTP/HTTPS、DNS、KCP、WebSocket/CDN）以及具备远程终端、屏幕直播、插件执行能力的 Agent。项目通过对原版 Windows 二进制（`v_windows_amd64.exe`）进行逆向分析并重新实现，内部细节大量依赖静态分析推断，可能存在缺失或不准确之处。

---

## 功能特性 / Features

| 模块 Module | 功能 Description |
|---|---|
| **Web 管理面板 Web panel** | 登录认证、Basic Auth、JWT、仪表盘、客户端/监听器/任务管理、文件上传下载、屏幕查看 / Login auth, Basic Auth, JWT, dashboard, client/listener/task management, file upload/download, screen viewer |
| **C2 引擎 C2 engine** | HTTP/HTTPS、DNS、KCP、CDN WebSocket 多协议监听；在线监控、健康检查、维护任务 / Multi-protocol listeners; online monitoring, health checks, maintenance tasks |
| **Agent** | 远程终端、屏幕流、插件执行、任务下发/结果回传；VerifyKey + 加密盐握手 / Remote terminal, screen streaming, plugin execution; VerifyKey + salt handshake |
| **通知 Notifications** | 钉钉 / 企业微信机器人告警（可选）/ DingTalk / WeChat Work bot alerts (optional) |
| **持久化 Persistence** | SQLite（web）+ JSON（engine）双存储 / SQLite (web) + JSON (engine) dual storage |

---

## 目录结构 / Layout

```
vshell/
├── main.go            # 入口：加载配置、初始化引擎/数据库/路由 / Entry: config, engine, db, router
├── conf/              # 配置文件（gitignore 排除，含密钥）/ Config files (gitignored; contains keys)
├── c2engine/          # C2 引擎：监听器、协议、KCP/DNS、存储（SQL 层）/ Engine: listeners, protocol, KCP/DNS, storage (SQL)
├── agent/             # Agent：终端/屏幕/插件；ldflags 注入配置 / Agent: terminal/screen/plugins; ldflags injection
├── controllers/       # Web API 控制器 / Web API controllers
├── router/            # HTTP 路由与中间件 / HTTP routing & middleware
├── utils/             # 配置解析、认证、许可证、通知 / Config, auth, license, notifications
└── static/            # 前端 SPA（从原版二进制提取）/ Frontend SPA (extracted from the original binary)
```

---

## 快速开始 / Quick Start

### 1. 构建 / Build

```bash
# 服务端 (Web + C2 Engine) / Server (Web + C2 Engine)
go build -o vshell-server .

# Agent（独立 module）/ Agent (standalone module)
cd agent && go build -o agent.exe .
```

### 2. 配置 / Configure

创建 `conf/setting.conf`（模板见 `utils/config.go` 的 `generateConfigContent`）：
Create `conf/setting.conf` (see `generateConfigContent` in `utils/config.go` for the template):

```ini
master_type=web              # web / gui / all
web_port=8082
web_ip=0.0.0.0
web_basic_auth=true          # 防止被资产测绘收录 / blocks mass-asset discovery scanners
web_username=admin
web_password=<你的强密码>      # 留空则启动时自动生成随机密码并打印 / empty → random password generated at startup
web_jwt_secret=              # 留空则每次启动随机生成 / empty → random secret per process
```

> **安全提醒 / Security note**: 若 `setting.conf` 不存在，服务启动时自动生成随机管理密码并打印在日志中，代码内**不包含任何硬编码凭据**。请务必在部署后修改默认配置。If `setting.conf` is absent, a random admin password is generated at startup and printed to the log. **No hardcoded credentials exist in the codebase.** Always change the default configuration after deployment.

### 3. 运行 / Run

```bash
./vshell-server
# 浏览器访问 / Open in browser: http://<ip>:8082/login
```

### 4. 构建 Agent（注入配置）/ Build the Agent with injected config

Agent 连接配置在编译时通过 `ldflags` 注入（对应 `agent/main.go` 中的 `ServerAddr`、`VerifyKey`、`EncryptSalt`）：
Agent connection settings are injected at compile time via `ldflags` (matching `ServerAddr`, `VerifyKey`, `EncryptSalt` in `agent/main.go`):

```bash
cd agent
go build -ldflags "\
  -X main.ServerAddr=REPLACE_SERVER_ADDR___XXXXXXXXXXXXXXXXXXXXXXXX \
  -X main.VerifyKey=REPLACE_VERIFY_KEY___XXXXXXXXXXXXXXXXXXXXXXXX \
  -X main.EncryptSalt=REPLACE_ENCRYPT_SALT_XXXXXXXXXXXXXXXXXXXXXXXX" \
  -o agent.exe .
```

### 5. 创建监听器 / Create a listener

通过 Web 面板 API 动态创建监听器（`c2engine.NewListener(listenAddr, connectAddr, mode, verifyKey, encryptSalt, remark)`），支持模式：`http` / `https` / `dns` / `kcp` / `websocket`（CDN）。
Listeners are created dynamically through the web panel API. Supported modes: `http` / `https` / `dns` / `kcp` / `websocket` (CDN).

---

## 逆向工程进度 / Reverse-Engineering Status

> 本项目对原版 Windows 二进制（`v_windows_amd64.exe`，garble 混淆 Go 1.21+）进行**自顶向下**逆向：每个模块与 Ghidra 反编译结果 1:1 对齐，禁止自行臆造实现。以下为当前状态。
> This project reverse-engineers the original Windows binary (`v_windows_amd64.exe`, garble-obfuscated Go 1.21+) **top-down**: every module is aligned 1:1 with its Ghidra decompilation, no invented implementations. Current status:

### 已实现（1:1 对齐 + 测试验证）/ Implemented (1:1 aligned & test-verified)

| 模块 / Module | 对齐内容 / Aligned content | 验证 / Verification |
|---|---|---|
| `c2engine/storage.go` | SQL 层（clients/listeners/hosts/tasks 全表）与反编译 SQL 逐字段一致 | 运行时 DB schema 动态比对 ✓ |
| `c2engine/wire.go` | 24B 类型化字段帧（kind 字节 + flags + 3 dword） | 单测 ✓ |
| `c2engine/channel_frame.go` | 频道/隧道帧协议（FUN_011b4040/011b5600/011b5b40 等 6 函数） | 6 测试 ✓ |
| `c2engine/dns.go` | DNS 信道 = Go 标准 base32（无填充）；查询 = `[8B agent ID][消息].domain` | 测试 ✓ |
| `c2engine/kcp.go / protocol.go / engine.go` | KCP/协议/监听器调度 | 测试 ✓ |
| `controllers/*`（16 文件） | 全部控制器对齐反编译 API（登录/客户端/监听器/文件/下载/屏幕/隧道/插件） | 测试 ✓ |
| `router/` + `utils/` | 路由、中间件、配置、认证、许可证、通知 | 测试 ✓ |

**破解成果 / Cracked artifacts**：
- 登录：password = `web_password` 原文 → JWT（admin/qwe123qwe）
- 线格式：`<u32 LE 长度><加密载荷>`（strace 实锤）
- AES 密钥：`22f97f672c3c5113d31fcaaad26fce42`（密钥调度逆推，rk1 验证）
- Agent 二进制提取：5+ 变体（linux_amd64/386/arm、darwin、tcp/dns/ws），动态注册 clientId 2-14
- Agent 配置 JSON：`{server,type,vkey,proxy,salt,l,e,d,h}` 全捕获
- **消息帧结构**：`[16B IV][21B ct]` = 37B；PT = JSON 直接（`{"VerifyKey":"0l...`）
- **counter 结构**：`[rbx 运行时常量][len 0x0015×4 广播]`；state = counter XOR key
- 服务器 AES-128（FUN_0053a1e0）实现验证 roundtrip；T 表 = 标准 Td0 字节交换变体
- Channel/隧道对象（会话 230-237）、Client 结构体（22 字段 @ 0x1bb9580）、Checkin 链全部解码

### 未实现 / Not yet implemented

| 项 / Item | 状态 / Status | 难度 / Difficulty |
|---|---|---|
| **0x458f00 精确轮结构重建** | 3×aesenc 自密钥链输出 vs 密钥流不匹配；缺输入窗口/掩码语义。帧结构已确认，差最后一环 | 高（运行时轮序） |
| **Agent 999 函数全量映射** | ~60+ 函数已映射（架构框架 + 加密链）；剩余 ~930 逐函数对齐反编译 | 多周规模 |
| **Agent 源码对齐** | `agent/main.go`（1607 行）为早期未对齐版本；实际加密 = 自定义链（非标准 AES-GCM） | 高 |
| **serT 状态机字符串** | FUN_017019c0 深加密，已放弃静态解 | 极高 |
| **226B 解密 stub** | FUN_011a02e0/01564720 静态求解受阻 | 高 |
| **DNS 注册完整闭环** | 需消息帧解密完成后验证 | 中 |

---

## 已知限制 / Known Limitations

> 由于是**不完整**逆向工程，以下方面可能与原版不一致 / Because this is an **incomplete** reverse-engineering effort, the following may differ from the original:

- **License 校验 License validation**：原版 RSA 私钥**未包含**在仓库中（`conf/license.pem` 需自行配置）；未配置时运行在"观察模式"，许可证值来自观测推断（`LicenseName=public, LimitClient=99, VIP=true`）。The original RSA private key is **not** included; without it the server runs in "observation mode" with inferred license values.
- **前端资产 Frontend assets**：`static/` 中的 SPA 提取自原版二进制，部分表单默认值可能与新版不同。The SPA was extracted from the original binary; some form defaults may differ.
- **Agent 行为 Agent behavior**：平台特化代码（进程隐藏、持久化等）为最小实现。Platform-specific code (process hiding, persistence, etc.) is a minimal implementation.
- **协议兼容性 Protocol compatibility**：与官方服务端/客户端的互通性**未经保证**，仅供独立研究。Interop with the official server/client is **not guaranteed**; intended for independent research only.

---

## 技术栈 / Tech Stack

Go 1.25 · gorilla/websocket · kcp-go/v5 · modernc.org/sqlite · gorilla/sessions

---

## 许可 / License

本仓库不含原版许可；所有权利归原版作者所有。**仅供研究使用，禁止商用或非法用途。**
This repository does not include the original license; all rights of the original software belong to its author. **Research only — no commercial or unlawful use.**
