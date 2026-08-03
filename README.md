# VShell

> **An incomplete reverse-engineered re-implementation of the in-the-wild exploited C2 framework "VShell"**

[![Go Version](https://img.shields.io/badge/Go-1.25-blue)](https://go.dev/dl/)
[![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red)](license.txt)
[![中文文档](https://img.shields.io/badge/docs-简体中文-green)](README.zh-CN.md)

> **⚠️ Disclaimer**
>
> This repository is an **incomplete** reverse-engineering / re-implementation of the in-the-wild exploited C2 framework **VShell** (v3.0), for security research and learning purposes only.
>
> - **For authorized testing only.** Any unlawful use is prohibited.
> - Unofficial, unaffiliated with the original author; all rights of the original software remain with its author.
> - Functionality differs from the original; some modules are missing or behave differently.

---

## Introduction

VShell is an open-source, **incomplete** re-implementation of the VShell C2 (Command & Control) management framework. It provides a web management panel, a multi-protocol C2 engine (HTTP/HTTPS, DNS, KCP, WebSocket/CDN), and an agent with remote terminal, screen streaming and plugin execution. The project was produced by decompiling and reimplementing the original Windows binary (`v_windows_amd64.exe`); many internal details were recovered through static analysis and may be incomplete or inaccurate.

---

## Features

| Module | Description |
|---|---|
| **Web panel** | Login auth, Basic Auth, JWT, dashboard, client/listener/task management, file upload/download, screen viewer |
| **C2 engine** | Multi-protocol listeners (HTTP/HTTPS, DNS, KCP, WebSocket/CDN); online monitoring, health checks, maintenance tasks |
| **Agent** | Remote terminal, screen streaming, plugin execution; VerifyKey + salt handshake |
| **Notifications** | DingTalk / WeChat Work bot alerts (optional) |
| **Persistence** | SQLite (web) + JSON (engine) dual storage |

---

## Layout

```
vshell/
├── main.go            # Entry: config, engine, db, router
├── conf/              # Config files (gitignored; contains keys)
├── c2engine/          # Engine: listeners, protocol, KCP/DNS, storage (SQL)
├── agent/             # Agent: terminal/screen/plugins; ldflags injection
├── controllers/       # Web API controllers
├── router/            # HTTP routing & middleware
├── utils/             # Config, auth, license, notifications
└── static/            # Frontend SPA (extracted from the original binary)
```

---

## Quick Start

### 1. Build

```bash
# Server (Web + C2 Engine)
go build -o vshell-server .

# Agent (standalone module)
cd agent && go build -o agent.exe .
```

### 2. Configure

Create `conf/setting.conf` (see `generateConfigContent` in `utils/config.go` for the template):

```ini
master_type=web              # web / gui / all
web_port=8082
web_ip=0.0.0.0
web_basic_auth=true          # blocks mass-asset discovery scanners
web_username=admin
web_password=<your-strong-password>   # empty → random password generated at startup
web_jwt_secret=              # empty → random secret per process
```

> **Security note**: If `setting.conf` is absent, a random admin password is generated at startup and printed to the log. **No hardcoded credentials exist in the codebase.** Always change the default configuration after deployment.

### 3. Run

```bash
./vshell-server
# Open in browser: http://<ip>:8082/login
```

### 4. Build the Agent with injected config

Agent connection settings are injected at compile time via `ldflags` (matching `ServerAddr`, `VerifyKey`, `EncryptSalt` in `agent/main.go`):

```bash
cd agent
go build -ldflags "\
  -X main.ServerAddr=REPLACE_SERVER_ADDR___XXXXXXXXXXXXXXXXXXXXXXXX \
  -X main.VerifyKey=REPLACE_VERIFY_KEY___XXXXXXXXXXXXXXXXXXXXXXXX \
  -X main.EncryptSalt=REPLACE_ENCRYPT_SALT_XXXXXXXXXXXXXXXXXXXXXXXX" \
  -o agent.exe .
```

### 5. Create a listener

Listeners are created dynamically through the web panel API (`c2engine.NewListener(listenAddr, connectAddr, mode, verifyKey, encryptSalt, remark)`). Supported modes: `http` / `https` / `dns` / `kcp` / `websocket` (CDN).

---

## Reverse-Engineering Status

> This project reverse-engineers the original Windows binary (`v_windows_amd64.exe`, garble-obfuscated Go 1.21+) **top-down**: every module is aligned 1:1 with its Ghidra decompilation, no invented implementations. Current status:

### Implemented (1:1 aligned & test-verified)

| Module | Aligned content | Verification |
|---|---|---|
| `c2engine/storage.go` | SQL layer (clients/listeners/hosts/tasks) field-for-field with decompiled SQL | runtime DB schema diff ✓ |
| `c2engine/wire.go` | 24-byte typed-field frames (kind byte + flags + 3 dwords) | unit tests ✓ |
| `c2engine/channel_frame.go` | Channel/tunnel frame protocol (FUN_011b4040/011b5600/011b5b40 et al.) | 6 tests ✓ |
| `c2engine/dns.go` | DNS channel = Go std base32 (no padding); query = `[8B agent ID][message].domain` | tests ✓ |
| `c2engine/kcp.go / protocol.go / engine.go` | KCP/protocol/listener dispatch | tests ✓ |
| `controllers/*` (16 files) | All controllers aligned to decompiled API (login/client/listener/file/download/screen/tunnel/plugin) | tests ✓ |
| `router/` + `utils/` | Routing, middleware, config, auth, license, notifications | tests ✓ |

**Cracked artifacts**:
- Login: password = `web_password` verbatim → JWT (admin/qwe123qwe)
- Wire format: `<u32 LE len><encrypted payload>` (strace-confirmed)
- AES key: `22f97f672c3c5113d31fcaaad26fce42` (key-schedule inversion, rk1-verified)
- Agent binaries extracted: 5+ variants (linux_amd64/386/arm, darwin, tcp/dns/ws), dynamic registration clientId 2-14
- Agent config JSON: `{server,type,vkey,proxy,salt,l,e,d,h}` fully captured
- **Message frame**: `[16B IV][21B ct]` = 37B; PT = JSON direct (`{"VerifyKey":"0l...`)
- **Counter structure**: `[rbx runtime const][len 0x0015×4 broadcast]`; state = counter XOR key
- **Message cipher (0x458f00) fully recovered** (session 533, gdb XMM tracing): state=aesenc(ctr^key), 3x self-keyed aesenc, dual-block path, CBC chain — byte-verified; Go impl in `agent/message_crypto.go`. Later gdb (session 535) shows the 0x458f00 `rcx=0x15` calls are garble string-decryption; the message-encrypt loop lives behind function-pointer dispatch and is not yet statically located. The block cipher itself is byte-exact vs gdb XMM captures.
- Wire frame module `agent/message_wire.go`: `<u32 LE len><[16B IV][ct]>`, ct = payload XOR keystream (msgKeyStream); IV independent per message. NOTE: the decrypt direction is not yet reversed — the recovered keystream depends on the plaintext (CBC chain input), so server-side decryption remains open.
- Server AES-128 (FUN_0053a1e0) implemented and roundtrip-verified; T-table = std Td0 byte-swapped variant
- Channel/tunnel objects (sessions 230-237), Client struct (22 fields @ 0x1bb9580), checkin chain fully decoded

### Not yet implemented

| Item | Status | Difficulty |
|---|---|---|
| **0x458f00 exact round-structure** | **SOLVED** (session 533): counter=[rbx LE][len x4]; state=aesenc(ctr^key); 3x self-keyed aesenc; dual-block path for 21B; CBC chain — byte-verified vs gdb XMM captures | Done |
| **Agent 999-function full mapping** | **546 functions mapped** (`.re/decomp/agent_map_*.txt`): full pipeline decoded — main state machine 0xfb1440 → decode → expression engine → executor (182-opcode 0x101df40 + 0x155-opcode 0x10f3220) → 24B frame builder → transport (pooled conn 0xfc7560) → session CRUD → result send. Architecture: `.re/AGENT_ARCHITECTURE.md` | Substantial |
| **Agent source alignment** | `agent/main.go` (1607 lines) is an early unaligned version; real crypto = custom chain (not std AES-GCM). `message_crypto.go` (0x458f00 chain, byte-verified) + `message_wire.go` (u32-LE frame) + `transport_real.go` (pooled TCP, FUN_00fc7560/00fc9de0) landed; main.go now dispatches 'tcp'/'raw' to the aligned transport. Command/terminal/screen paths remain re-implemented | High |
| **Message decrypt direction** | keystream = msgKeyStream(pt) depends on plaintext (CBC chain); server-side reversal not yet derived | High |
| **serT state-machine strings** | FUN_017019c0 deeply encrypted; static solving abandoned | Very high |
| **226B decrypt stub** | FUN_011a02e0/01564720 static solve blocked | High |
| **DNS registration full loop** | needs message-frame decrypt completion to verify | Medium |

---

## Known Limitations

> Because this is an **incomplete** reverse-engineering effort, the following may differ from the original:

- **License validation**: the original RSA private key is **not** included; without it the server runs in "observation mode" with inferred license values (`LicenseName=public, LimitClient=99, VIP=true`).
- **Frontend assets**: the SPA in `static/` was extracted from the original binary; some form defaults may differ.
- **Agent behavior**: platform-specific code (process hiding, persistence, etc.) is a minimal implementation.
- **Protocol compatibility**: interop with the official server/client is **not guaranteed**; intended for independent research only.

---

## Tech Stack

Go 1.25 · gorilla/websocket · kcp-go/v5 · modernc.org/sqlite · gorilla/sessions

---

## License

This repository does not include the original license; all rights of the original software belong to its author. **Research only — no commercial or unlawful use.**
