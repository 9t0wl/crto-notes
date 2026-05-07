# CRTO — Lateral Movement Lab

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** Lateral Movement
**Objective:** Impersonate a user and move laterally using SCShell

---

## The Full Chain

```
BloodHound (AdminTo edge: Workstation Admins → lon-ws-1)
    ↓
steal_token 844  (rsteel's cmd.exe)
    ↓
ak-settings spawnto_x64 svchost.exe
    ↓
jump scshell64 lon-ws-1 smb
    ↓
SYSTEM Beacon on lon-ws-1
```

---

## Step 1 — User Impersonation: Token Theft

**What you did:**
Opened the Process Browser (`ps`), identified `cmd.exe` (PID 844) running as `CONTOSO\rsteel`, and stole his token:

```
steal_token 844
```

**Result:**
```
[LON-WKSTN-1] - x64 | SYSTEM * [CONTOSO\rsteel] | 15312 - x64
```

> The `*` in the beacon prompt indicates impersonation is active.
> Local actions run as SYSTEM, network-authenticated actions use rsteel's token.

**TTP:**
- **MITRE:** T1134.001 — Access Token Manipulation: Token Impersonation/Theft
- **Requires:** High integrity / SYSTEM Beacon to steal tokens from other users' processes
- **Cleanup:** `rev2self` to drop impersonation when done

### Token Impersonation Method Comparison

| Method | When to Use |
|---|---|
| `steal_token` | Target user has active processes on the box |
| `make_token` | You have plaintext credentials |
| `pth` | You have NTLM hash only |
| PTT (Rubeus) | You have a TGT/kirbi only |

---

## Step 2 — Pre-Flight: Set spawnto

**What you did:**
```
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
```

**TTP:**
- **MITRE:** T1055 — Process Injection (spawn context)
- SCShell uses the **service binary payload** which spawns a new process — `spawnto` controls what that process looks like
- Without setting this, CS defaults to a suspicious process. `svchost.exe` blends into normal Windows traffic
- Set this **before any lateral movement** as standard practice, not just for SCShell

---

## Step 3 — Lateral Movement: SCShell via SMB

**What you did:**
```
# Load aggressor script
Cobalt Strike > Script Manager > C:\Tools\SCShell\CS-BOF\scshell.cna

# Execute
jump scshell64 lon-ws-1 smb
```

**TTP:**
- **MITRE:** T1543.003 — Create or Modify System Process: Windows Service
- **MITRE:** T1021.002 — Remote Services: SMB/Windows Admin Shares

### How SCShell Works
Abuses `ChangeServiceConfigA` to modify an **existing** service's binary path to your payload → starts it → restores the original config. No new service is created, making it harder to detect than `psexec`.

### Why SMB Listener
Beacon callbacks over named pipe — no new outbound network connection from the target. Traffic rides existing SMB.

### Requirements
- Local admin on target (rsteel had this via **Workstation Admins GPO** → BloodHound `AdminTo` edge on lon-ws-1)

### Common Error
```
Advapi32$StartServiceA failed to start the service. 1056
```
**Cause:** Service is already running. SCShell assumes it's stopped.
**Fix:** Wait a few minutes and try again.

---

## Key Takeaways

- The full chain (BloodHound → creds/token → spawnto → jump) is the **core exam loop** — every flag is some variation of this
- Always set `spawnto` before lateral movement
- `rev2self` after impersonation to drop back to SYSTEM cleanly
- SCShell is stealthier than psexec — no new service created, uses existing service config modification
- SMB listener keeps lateral movement traffic off the wire as new outbound connections
