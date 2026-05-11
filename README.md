
# Firewall V1 - Packet Filtering in C++

A stateless packet-filtering firewall built in C++ using Windivert, capable of intercepting, inspecting, and enforcing pass/block rules on live network traffic.

---
## Overview
Built to learn the basics of C++ and how firewalls operate on a packet level. Implements core concepts such as rule based filtering, protocol inspection, and real-time logging in.

---


## How it works
```
   Incoming Packet
        ↓
   WinDivert Hook (kernel-level intercept)
        ↓
   Parse IP / TCP / UDP headers
        ↓
   Match against Rules vector (top-to-bottom, first match wins)
        ↓
   BLOCK → packet dropped    |    PASS → packet forwarded
        ↓
   Log to console (src IP, dst IP, port, protocol, action)
```
---

## Features
- Intercepts all inbound packets via WinDivert
- Parses IP, TCP, and UDP headers
- Configurable rule engine
- Real time logging via CLI
- Default-allow or default-deny configurable via catch-all rule

---

## Security concepts demonstrated
- **Stateless packet filtering** — rules evaluated per-packet with no session tracking
- **Port-based access control** — analogous to ACLs on enterprise routers/firewalls
- **Protocol discrimination** — separate handling of TCP (6) vs UDP (17) traffic
- **Default deny principle** — Denies all network traffic as a test to see if the firewall is actually blocking inbound packets

## Rule configuration
 
Rules are defined in the `Rules` vector in `Firewall_V1.cpp`. Each rule specifies a destination port, protocol, and action.

``` cpp
vector<FirewallRules> Rules = {
	{80, 6, Action::BLOCK, "HTTP traffic"},
	{443, 6, Action::BLOCK, "HTTPS traffic"},
	{53, 17, Action::BLOCK, "DNS traffic"},
	{0, 17, Action::BLOCK, "DNS" },
	{0, 53, Action:: BLOCK, "TCP"}, 
	{0, 0, Action::BLOCK, "BLOCKS EVERYTHING"}
};
```
--- 

## Requirements
 
- Windows 10 / 11 (64-bit)
- Visual Studio 2019 or 2022 with Desktop development with C++ workload
- [WinDivert 2.x](https://github.com/basil00/WinDivert/releases)
- Administrator privileges

---

## Setup & build
 
- Download WinDivert and extract to e.g. `C:\WinDivert\`
- In Visual Studio project properties, set:
   - Include directory → `C:\WinDivert\include`
   - Library directory → `C:\WinDivert\x64`
   - Additional dependencies → `WinDivert.lib`
   - Platform → `x64`
- Copy `WinDivert.dll` and `WinDivert64.sys` into your build output folder. Build with `Ctrl+Shift+B`
- Run the executable as Administrator

---

## Limitations (V1)
  
- Stateless — does not track TCP sessions or connection state
- Rules are hardcoded at compile time (no config file)
- No rate limiting or connection throttling
- Windows-only (WinDivert dependency)
- Code is currently uncommented
- This was an early implementation built to understand packet filtering fundamentals.

---

## What changed in V2

V1 was a stateless packet filter — every packet was evaluated independently 
against a flat list of port/protocol rules. V2 is a significant architectural 
upgrade built on top of that foundation.

### New features in V2

- **Zone-based filtering** — IPs are classified into zones (LOCAL, LOOPBACK, PUBLIC, BLOCKED).
  Rules are applied based on traffic direction between zones (e.g. block PUBLIC → LOCAL on port 22)
  rather than blindly blocking ports globally.

- **Stateful connection tracking** — allowed connections are stored in a hash map.
  Reply packets from established connections are passed automatically without 
  re-evaluating rules, mimicking how real firewalls handle sessions.

- **IP blacklisting** — supports blocking individual IPs and entire subnets 
  using configurable blacklist vectors and subnet masks.

- **CSV logging** — every packet decision (PASS / BLOCK / ESTABLISHED) is written 
  to a timestamped `.csv` file on the desktop with full metadata: timestamp, protocol, 
  src/dst IP, zones, ports, rule matched, and packet size.

- **TCP FIN/RST handling** — detects connection teardown and removes closed 
  sessions from the connection table.

- **Connection timeout cleanup** — idle connections are evicted from the table 
  after 60 seconds, preventing unbounded memory growth

See [Firewall_V2](https://github.com/Lazymelly-z/Firewall_V2) for the full implementation.


---

## Project structure

```
Firewall_V1/
├── Firewall_V1.cpp     # Core firewall logic
├── README.md
└── x64/
    └── Debug/
        ├── Firewall_V1.exe
        ├── WinDivert.dll        ← copy from WinDivert release
        └── WinDivert64.sys      ← copy from WinDivert release
```

---

## Built with 
- C++ (C++17)
- Windivert (Windows Packet Interception Libary)

---

## Author 
**Matthew Belvian** · [GitHub](https://github.com/Lazymelly-z)

**Matt Belvian** · [LinkedIn](https://www.linkedin.com/in/matt-belvian-18b27b354/)


