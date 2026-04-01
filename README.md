# Firewall_V1

A simple packet-filtering firewall written in C++ for Windows, using WinDivert to intercept and control network traffic.

---

## What it does

- Intercepts all incoming and outgoing network packets
- Reads the IP, TCP, and UDP headers of each packet
- Checks each packet against a list of rules
- Allows or blocks packets based on those rules
- Logs every packet to the console, showing source IP, destination IP, and port

---

## Requirements

- Windows 10 or 11 (64-bit)
- Visual Studio 2019 or 2022 with the **Desktop development with C++** workload
- [WinDivert 2.x](https://github.com/basil00/WinDivert/releases)
- Administrator rights

---

## Setup

### 1. Download WinDivert

Go to https://github.com/basil00/WinDivert/releases and download the latest ZIP.
Extract it somewhere easy to find, for example: `C:\WinDivert\`

### 2. Configure Visual Studio

In your project Properties:

| Setting | Where to find it | Value |
|---|---|---|
| Include directory | C/C++ → General → Additional Include Directories | `C:\WinDivert\include` |
| Library directory | Linker → General → Additional Library Directories | `C:\WinDivert\x64` |
| Library file | Linker → Input → Additional Dependencies | `WinDivert.lib` |
| Platform | Top toolbar | `x64` |

### 3. Copy runtime files

Copy these two files from `C:\WinDivert\x64\` into your build output folder (e.g. `x64\Debug\`):

- `WinDivert.dll`
- `WinDivert64.sys`

### 4. Build the project

Press `Ctrl+Shift+B` in Visual Studio.

---

## Running

> **You must run as Administrator or the firewall will fail to open.**

**Option A** — Right-click Visual Studio → Run as administrator, then press F5.

**Option B** — Build the project, then right-click `Firewall_V1.exe` in `x64\Debug\` and choose Run as administrator.


## How rules work

Rules are defined in `Rules` vector inside the source file. Each rule has four fields:

```cpp
{ DstPort, Protocol, Action, Description }
```

Rules are checked **top to bottom**. The first matching rule wins.

### Example rules

```cpp
vector<FirewallRules> Rules = {
    { 23,  6,  Action::BLOCK, "Block Telnet"  },  // block port 23 TCP
    { 80,  6,  Action::BLOCK, "Block HTTP"    },  // block port 80 TCP
    { 443, 6,  Action::PASS,  "Allow HTTPS"   },  // allow port 443 TCP
    { 53,  17, Action::PASS,  "Allow DNS"     },  // allow port 53 UDP
    { 0,   0,  Action::PASS,  "Allow all"     },  // default: allow everything else
};
```




## Project structure

```
Firewall_V1/
├── Firewall_V1.cpp     # Main source file — all firewall logic
├── README.md           # This file
└── x64/
    └── Debug/
        ├── Firewall_V1.exe
        ├── WinDivert.dll       # Must be copied here manually
        └── WinDivert64.sys     # Must be copied here manually
```
