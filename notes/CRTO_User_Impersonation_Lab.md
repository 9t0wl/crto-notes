# CRTO — User Impersonation Lab

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** User Impersonation
**Objective:** Dump a user's TGT from their active logon session, inject it into a sacrificial logon session, and impersonate them to access a remote resource

---

## The Full Chain

```
SYSTEM Beacon on LON-WKSTN-1
    ↓
krb_triage → identify rsteel's TGT in memory (krbtgt/CONTOSO.COM)
    ↓
krb_dump /user:rsteel /service:krbtgt → extract TGT as base64
    ↓
WriteAllBytes → save rsteel.kirbi to attacker desktop
    ↓
make_token CONTOSO\rsteel FakePass → create sacrificial logon session
    ↓
kerberos_ticket_use → inject rsteel.kirbi into sacrificial session
    ↓
klist → verify ticket present in session
    ↓
ls \\lon-ws-1\c$ → access succeeds as rsteel
    ↓
rev2self → drop impersonation
```

---

## Step 1 — Verify Access is Denied

```bash
ls \\lon-ws-1\c$
```

> Expected: `ACCESS_DENIED` — confirms current context (SYSTEM on LON-WKSTN-1) has no access to lon-ws-1's C$ share. This establishes the baseline before impersonation.

---

## Step 2 — Triage Kerberos Tickets in Memory

```bash
krb_triage
```

**What this does:** Lists all Kerberos tickets across all logon sessions on the current machine. You're looking for:

```
rsteel @ CONTOSO.COM | krbtgt/CONTOSO.COM
```

| Field | Meaning |
|---|---|
| `rsteel @ CONTOSO.COM` | The ticket owner — rsteel's logon session |
| `krbtgt/CONTOSO.COM` | Service the ticket is for — this is a **TGT** (Ticket Granting Ticket) |

> A ticket for `krbtgt/CONTOSO.COM` is the TGT itself — the master credential used to request service tickets (TGS) for any resource. Stealing this is more powerful than stealing individual service tickets because it can be used to access any service rsteel is authorised to use.

**TTP:** T1558.001 — Steal or Forge Kerberos Tickets: Golden Ticket (adjacent — this is TGT theft, not forging)
**TTP:** T1003 — OS Credential Dumping (ticket extraction from LSASS memory)

---

## Step 3 — Dump the TGT

```bash
krb_dump /user:rsteel /service:krbtgt
```

**Flags:**

| Flag | Purpose |
|---|---|
| `/user:rsteel` | Target rsteel's logon session specifically |
| `/service:krbtgt` | Only dump the TGT — not service tickets |

**Output:** Base64-encoded `.kirbi` blob representing rsteel's TGT.

### Save to Disk

```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String("[B64 TICKET]"))
```

> **Why `.kirbi`:** The Kerberos ticket binary format used by Windows (and Mimikatz/Rubeus). It contains the encrypted TGT and session key. Rubeus and CS both read this format natively.

---

## Step 4 — Pass the Ticket (PTT)

**TTP:** T1550.003 — Use Alternate Authentication Material: Pass the Ticket

### Why a Sacrificial Logon Session

You cannot inject a ticket into your current SYSTEM session — SYSTEM doesn't have a Kerberos identity. PTT requires a user-context logon session to attach the ticket to.

`make_token` creates a new logon session with arbitrary credentials — the password doesn't matter because Kerberos authentication uses the injected ticket, not the password:

```bash
# Create sacrificial logon session (password is intentionally fake)
make_token CONTOSO\rsteel FakePass
```

> The fake password is never validated against the DC — `make_token` creates a local logon session (`LOGON32_LOGON_NEW_CREDENTIALS`) which only authenticates when network resources are accessed. By injecting a valid TGT before that happens, Kerberos takes over and the fake password is never used.

### Inject the Ticket

```bash
kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel.kirbi
```

Injects rsteel's TGT into the sacrificial logon session. Beacon will now use this ticket for all Kerberos-based network authentication.

### Verify

```bash
run klist
```

Expected output shows rsteel's TGT present in the current session with a valid expiry. If the ticket isn't listed, the injection failed — retry `kerberos_ticket_use`.

---

## Step 5 — Access the Remote Resource

```bash
ls \\lon-ws-1\c$
```

> Expected: Directory listing succeeds — Beacon is now authenticating as rsteel using his TGT to obtain a TGS for the CIFS service on lon-ws-1.

---

## Step 6 — Cleanup

```bash
rev2self
```

Drops the impersonation token and returns Beacon to its original context (SYSTEM). The sacrificial logon session is discarded.

---

## make_token vs steal_token vs PTT — When to Use Each

| Method | Requires | Network Auth | Use When |
|---|---|---|---|
| `steal_token <pid>` | Target user has active process on box | Uses stolen token | User is logged in, processes visible |
| `make_token user pass` | Plaintext credentials | NTLM or Kerberos | You have the password |
| `pth user hash` | NTLM hash | NTLM only | You have the hash, no ticket |
| PTT (`make_token` + `kerberos_ticket_use`) | Valid TGT (.kirbi) | Kerberos only | You have the TGT, no password/hash — or in Kerberos-only environments |

> **PTT is the only method that works in Kerberos-only environments** (NTLM disabled) — like the HTB PingPong lab. If NTLM is disabled, `pth` and `make_token` with a real password fall back to NTLM and fail. PTT bypasses this entirely.

---

## How PTT Works at the Protocol Level

```
1. make_token creates logon session with fake creds (LOGON_NEW_CREDENTIALS)
       ↓
2. kerberos_ticket_use injects rsteel's TGT into that session's ticket cache
       ↓
3. ls \\lon-ws-1\c$ triggers Kerberos auth:
   Beacon sends TGS-REQ to KDC using the injected TGT
       ↓
4. KDC returns TGS for CIFS/lon-ws-1 (encrypted with computer account key)
       ↓
5. Beacon presents TGS to lon-ws-1's SMB service
       ↓
6. lon-ws-1 decrypts TGS, sees rsteel's identity, grants access
```

No password ever transmitted. No NTLM hash ever used. Purely Kerberos.

---

## MITRE ATT&CK Mapping

| TTP | Technique | Detail |
|---|---|---|
| T1558.001 | Steal or Forge Kerberos Tickets | TGT extraction from logon session memory |
| T1550.003 | Pass the Ticket | Inject stolen TGT into sacrificial session |
| T1134.001 | Token Impersonation | make_token creates sacrificial logon session |
| T1021.002 | Remote Services: SMB | Access C$ share using impersonated identity |

---

## Key Takeaways

- `krb_triage` first — identify what tickets are available before dumping blindly
- The ticket for `krbtgt/CONTOSO.COM` is the TGT — stealing it gives access to any resource rsteel can reach, not just one service
- `make_token` with a fake password is intentional — the password is never validated, the TGT does all the authentication work
- `klist` after injection is a mandatory sanity check — don't attempt access without confirming the ticket is in session
- PTT is the correct technique for **Kerberos-only environments** — remember this for PingPong and any engagement where NTLM is disabled
- `rev2self` after every impersonation — never leave a token or ticket active in a Beacon you're not actively using
- TGTs have a default lifetime of **10 hours** — plan your lateral movement window accordingly
