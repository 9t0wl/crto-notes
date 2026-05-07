# CRTO — Constrained Delegation Lab

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** Constrained Delegation
**Objective:** Abuse constrained delegation with protocol transition (S4U2Self + S4U2Proxy) to impersonate any user to a delegated back-end service

---

## The Full Chain

```
ldapsearch → find computers with msDS-AllowedToDelegateTo set
    ↓
Identify lon-ws-1$ → permitted to delegate to cifs/lon-fs-1
    ↓
Verify TRUSTED_TO_AUTH_FOR_DELEGATION UAC flag (protocol transition enabled)
    ↓
Lateral move to lon-ws-1 (SYSTEM Beacon)
    ↓
krb_dump /luid:3e7 → extract lon-ws-1's machine account TGT (LSASS SYSTEM session)
    ↓
krb_s4u → S4U2Self (get TGS for Administrator → lon-ws-1) +
          S4U2Proxy (get TGS for cifs/lon-fs-1 as Administrator)
    ↓
Inject TGS → ls \\lon-fs-1\c$ succeeds as Administrator
```

---

## How Constrained Delegation Works

Constrained delegation restricts which services a machine/account can delegate to (unlike unconstrained which allows any). With **protocol transition** (`TRUSTED_TO_AUTH_FOR_DELEGATION`), the delegating machine can obtain a TGS for any user to the allowed service — without needing that user's TGT.

```
S4U2Self:  lon-ws-1 requests a TGS for Administrator → lon-ws-1 (impersonation ticket)
               ↓
S4U2Proxy: lon-ws-1 uses that TGS to request a TGS for Administrator → cifs/lon-fs-1
               ↓
Result:    Forwardable TGS for Administrator to access cifs/lon-fs-1
```

> **Key difference from unconstrained delegation:** No TGT from the target user is needed — the machine account's own TGT is sufficient. The attack works entirely from the compromised machine's credentials.

---

## Step 1 — Enumerate Constrained Delegation

```bash
ldapsearch (&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*)) --attributes samAccountName,msDS-AllowedToDelegateTo,userAccountControl
```

### Filter Breakdown

| Component | Meaning |
|---|---|
| `samAccountType=805306369` | Computer accounts only |
| `msDS-AllowedToDelegateTo=*` | Must have at least one entry in the allowed delegation list |

**Attributes requested:**

| Attribute | Purpose |
|---|---|
| `samAccountName` | Account name (e.g. `lon-ws-1$`) |
| `msDS-AllowedToDelegateTo` | List of SPNs this account can delegate to (e.g. `cifs/lon-fs-1`) |
| `userAccountControl` | Needed to verify protocol transition flag |

**Expected result:**
```
samAccountName: lon-ws-1$
msDS-AllowedToDelegateTo: cifs/lon-fs-1
userAccountControl: 16781312
```

---

## Step 2 — Verify Protocol Transition Flag

```powershell
[Convert]::ToBoolean(16781312 -band 16777216)
# Returns: True
```

**What this checks:**

| UAC Value | Flag | Meaning |
|---|---|---|
| `16781312` | Combined UAC value on lon-ws-1$ | Includes `WORKSTATION_TRUST_ACCOUNT` + `TRUSTED_TO_AUTH_FOR_DELEGATION` |
| `16777216` | `0x1000000` | `TRUSTED_TO_AUTH_FOR_DELEGATION` — protocol transition enabled |

**Bitwise AND (`-band`):** Returns non-zero (True) if `TRUSTED_TO_AUTH_FOR_DELEGATION` bit is set in the UAC value.

**Why protocol transition matters:**

| Delegation Type | Protocol Transition | Can Impersonate Arbitrary Users? |
|---|---|---|
| Constrained without protocol transition | No | Only users who authenticate to the machine first |
| Constrained **with** protocol transition | Yes | **Any user** — S4U2Self generates the initial ticket |

> Without `TRUSTED_TO_AUTH_FOR_DELEGATION`, S4U2Self only works if the target user has already authenticated. With it, the machine can self-issue an impersonation ticket for anyone — making it a much more powerful attack primitive.

---

## Step 3 — Lateral Move to lon-ws-1

```bash
# Impersonate rsteel (AdminTo on lon-ws-1 via Workstation Admins GPO)
steal_token [rsteel_pid]    # or make_token CONTOSO\rsteel Passw0rd!
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
jump scshell64 lon-ws-1 smb
```

---

## Step 4 — Dump the Machine Account TGT

From the SYSTEM Beacon on lon-ws-1:

```bash
krb_dump /luid:3e7 /service:krbtgt
```

**Why `/luid:3e7` instead of `/user:`:**

| Flag | What it targets |
|---|---|
| `/user:lon-ws-1$` | Searches by account name — may not find the SYSTEM session ticket |
| `/luid:3e7` | Targets the **SYSTEM logon session** directly by LUID |

> `0x3e7` is the hardcoded LUID for the SYSTEM logon session on every Windows machine. The machine account's TGT always lives here — it's how the computer authenticates to the domain. SYSTEM access is required to read it.

**What you get:** The TGT for `lon-ws-1$` (the machine account) — not a user TGT. This is the credential used to perform S4U2Self/S4U2Proxy.

---

## Step 5 — S4U Abuse (krb_s4u)

```bash
krb_s4u /ticket:[LON-WS-1$ TGT base64] /service:cifs/lon-fs-1 /impersonateuser:Administrator
```

**Flag breakdown:**

| Flag | Value | Purpose |
|---|---|---|
| `/ticket` | Base64 machine TGT | lon-ws-1$'s TGT — used to authenticate the S4U requests to the KDC |
| `/service` | `cifs/lon-fs-1` | The delegated service to obtain a TGS for — must be in `msDS-AllowedToDelegateTo` |
| `/impersonateuser` | `Administrator` | The user to impersonate — any domain user is valid due to protocol transition |

**What `krb_s4u` does internally:**

```
1. S4U2Self Request:
   lon-ws-1$ → KDC: "Give me a TGS for Administrator authenticating to me (lon-ws-1)"
   KDC → lon-ws-1$: TGS for Administrator → lon-ws-1$ (forwardable)

2. S4U2Proxy Request:
   lon-ws-1$ → KDC: "Use this Administrator TGS to get me a TGS for cifs/lon-fs-1"
   KDC validates: cifs/lon-fs-1 is in lon-ws-1$'s msDS-AllowedToDelegateTo → approved
   KDC → lon-ws-1$: TGS for Administrator → cifs/lon-fs-1
```

> The resulting ticket is a fully valid TGS for `Administrator` to access the CIFS service on `lon-fs-1` — the KDC issued it, so it passes all validation. No forgery involved.

---

## Step 6 — Access the Target Service

```bash
# Inject the returned TGS
make_token CONTOSO\Administrator FakePass
kerberos_ticket_use [path to Administrator cifs ticket]

# Verify
run klist

# Access target
ls \\lon-fs-1\c$
```

> Access to `lon-fs-1\c$` as Administrator confirms successful constrained delegation abuse. The scope is limited to `cifs/lon-fs-1` — this ticket cannot be used to access other services or machines unless they're also in `msDS-AllowedToDelegateTo`.

---

## Constrained Delegation: With vs Without Protocol Transition

| Scenario | S4U2Self Works For | Attack Requirement |
|---|---|---|
| **With protocol transition** (`TRUSTED_TO_AUTH_FOR_DELEGATION`) | Any user — machine self-issues impersonation ticket | Only need machine TGT |
| **Without protocol transition** | Only users who already authenticated to the machine | Need target user's TGT or prior authentication |

---

## Constrained vs Unconstrained — Attack Comparison

| Property | Unconstrained | Constrained (w/ Protocol Transition) |
|---|---|---|
| TGT needed | Target user's TGT (stolen from cache) | Machine account's own TGT |
| Scope | Any service in the domain | Only services in `msDS-AllowedToDelegateTo` |
| Requires waiting | Yes — wait for privileged user to authenticate | No — impersonate any user immediately |
| Coercion needed | Often (PrinterBug etc.) | Never |
| Detectability | TGT theft from LSASS | S4U requests to KDC (Kerberos event 4769) |

---

## MITRE ATT&CK Mapping

| TTP | Technique | Detail |
|---|---|---|
| T1558.001 | Steal or Forge Kerberos Tickets | Machine TGT extraction via `/luid:3e7` |
| T1550.003 | Pass the Ticket | Inject S4U2Proxy TGS into sacrificial session |
| T1134.001 | Access Token Manipulation | Impersonate Administrator via forged service ticket |
| T1018 | Remote System Discovery | LDAP enum of constrained delegation computers |

---

## Key Takeaways

- `msDS-AllowedToDelegateTo=*` is the LDAP filter for constrained delegation — always pull `userAccountControl` alongside it to check for protocol transition
- **Protocol transition (`TRUSTED_TO_AUTH_FOR_DELEGATION`) is required** to impersonate arbitrary users — without it you can only delegate for users who have already authenticated to the machine
- `/luid:3e7` is the SYSTEM session LUID — always valid on any Windows machine, always contains the machine account TGT
- The machine account TGT (`lon-ws-1$`) is the credential — you don't need any user's TGT for constrained delegation abuse
- The scope of access is **strictly limited** to services listed in `msDS-AllowedToDelegateTo` — the KDC enforces this
- Constrained delegation abuse is **faster and more reliable** than unconstrained — no waiting for a privileged user to authenticate, no coercion needed
- `krb_s4u` handles both S4U2Self and S4U2Proxy in a single command — the two-step protocol is abstracted away
