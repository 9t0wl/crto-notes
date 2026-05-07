# CRTO — Discovery Lab

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** Discovery
**Objective:** Carry out OPSEC-safe domain discovery using LDAP BOFs, parse results with BOFHound, ingest into BloodHound CE, and manually add missing attack path edges from GPO/SysVol analysis

---

## The Full Chain

```
ldapsearch BOFs → enumerate domain objects + ACLs in-process (no SharpHound)
    ↓
SCP Beacon logs from team server to attacker desktop
    ↓
bofhound -i logs → parse raw ldapsearch output → BloodHound-compatible JSON
    ↓
Ingest JSON into BloodHound CE
    ↓
Cypher query → find Workstation Admins GPO → note gpcpath + affected computers
    ↓
Download GptTmpl.inf from SysVol via Beacon → read Restricted Groups config
    ↓
Manually add AdminTo edges in BloodHound via Cypher → attack path complete
```

---

## Step 1 — LDAP Enumeration via BOF (BOFHound Collection)

```bash
# Enumerate domain root, OUs, and GPOs + their ACLs
ldapsearch (|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)) --attributes *,ntsecuritydescriptor

# Enumerate users, computers, and security groups + their ACLs
ldapsearch (|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)) --attributes *,ntsecuritydescriptor
```

### Why BOFHound Over SharpHound

| Method | Execution | Detection Risk | Notes |
|---|---|---|---|
| SharpHound | Drops EXE/DLL to disk, spawns new process | High — heavily signatured by AV/EDR | Makes bulk LDAP queries in short bursts |
| BOFHound | Runs ldapsearch BOF in-process inside Beacon | Low — looks like normal LDAP traffic | No new process, no disk artefact |

> The `ldapsearch` BOF runs inside Beacon's process — output goes directly to Cobalt Strike's beacon log files on the team server. BOFHound parses those logs offline.

### LDAP Query Breakdown

**Query 1 — Structure and GPOs:**

| Filter | Objects Returned |
|---|---|
| `objectClass=domain` | Domain root object |
| `objectClass=organizationalUnit` | All OUs |
| `objectClass=groupPolicyContainer` | All GPOs (includes `gPCFileSysPath` → SysVol path) |

**Query 2 — Principals:**

| samAccountType | Objects Returned |
|---|---|
| `805306368` | User accounts |
| `805306369` | Computer accounts |
| `268435456` | Security groups |

**Why `ntsecuritydescriptor` on both queries:**
- `ntsecuritydescriptor` is an **operational attribute** — not returned by `*` alone, must be explicitly requested
- Contains the raw DACL for every object — this is what gives BloodHound its ACL-based attack path edges (`GenericAll`, `WriteDacl`, `WriteProperty`, `AdminTo`, etc.)
- Without it, BOFHound produces object data but no ACL-based edges

---

## Step 2 — Copy Beacon Logs to Attacker Desktop

```bash
# From Ubuntu WSL tab in Windows Terminal
cd /mnt/c/Users/Attacker/Desktop
scp -r attacker@10.0.0.5:/opt/cobaltstrike/logs .
# Password: Passw0rd!
```

> Logs are stored on the team server at `/opt/cobaltstrike/logs` — each Beacon session has its own subdirectory containing timestamped output files. BOFHound reads all of them.

---

## Step 3 — Parse with BOFHound

```bash
bofhound -i logs
```

**What BOFHound does:**
- Reads raw ldapsearch output from CS log files
- Parses LDAP attributes and `ntsecuritydescriptor` ACL data
- Outputs BloodHound-compatible JSON files to the current directory

**Output files:** JSON files in `C:\Users\Attacker\Desktop\` — ready to ingest into BloodHound CE.

---

## Step 4 — BloodHound CE Setup and Ingest

```
Start Menu → Docker Desktop → Containers → Play (start all containers)
Edge → http://localhost:8080/ui/login
Credentials: admin : eA%N4frBrnn2
```

**Ingest BOFHound data:**
```
First login → 'Start by uploading your data'
Upload File(s) → select JSON files from C:\Users\Attacker\Desktop\
Wait for status: Complete
```

---

## Step 5 — Find GPOs and Identify Attack Surface

From the Explore view, use the Cypher query box:

```cypher
MATCH (n:GPO) RETURN n
```

**Select the Workstation Admins GPO and note:**
- **Gpcpath** — the SysVol UNC path to the GPO's files (e.g. `\\contoso.com\SysVol\contoso.com\Policies\{2583E34A-...}`)
- **Affected Objects → Computers** — which machines this GPO applies to
- **Object IDs** of each affected computer — needed for the Cypher edge injection

---

## Step 6 — Download GptTmpl.inf from SysVol

**Why this step is necessary:**
BloodHound (via BOFHound) has no way to know that Workstation Admins has local admin rights on the workstations — that relationship is defined in the GPO's **security template** stored in SysVol, not in LDAP. It must be read manually.

```bash
# List the SecEdit directory of the GPO
ls \\contoso.com\SysVol\contoso.com\Policies\{2583E34A-BBCE-4061-9972-E2ADAB399BB4}\Machine\Microsoft\Windows NT\SecEdit\

# Download GptTmpl.inf
download \\contoso.com\SysVol\contoso.com\Policies\{2583E34A-BBCE-4061-9972-E2ADAB399BB4}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
```

**Sync from CS:**
```
Cobalt Strike → View → Downloads → Sync Files
```

### What to Look For in GptTmpl.inf

The `[Group Membership]` section defines Restricted Groups — which domain groups are pushed into local groups on target machines:

```ini
[Group Membership]
*S-1-5-21-3926355307-1661546229-813047887-1106__Memberof = *S-1-5-32-544
```

| SID | Meaning |
|---|---|
| `...-1106` | Workstation Admins group (domain group) |
| `S-1-5-32-544` | Built-in Administrators (local group on target machines) |

This confirms Workstation Admins is pushed into the local Administrators group on all machines the GPO applies to → `AdminTo` relationship.

---

## Step 7 — Add Custom AdminTo Edges in BloodHound

BloodHound has the group and computers as objects but no edge between them — add it manually via Cypher:

```cypher
# WKSTN-1
MATCH (x:Computer{objectid:'S-1-5-21-3926355307-1661546229-813047887-2101'})
MATCH (y:Group{objectid:'S-1-5-21-3926355307-1661546229-813047887-1106'})
MERGE (y)-[:AdminTo]->(x)

# WKSTN-2
MATCH (x:Computer{objectid:'S-1-5-21-3926355307-1661546229-813047887-2102'})
MATCH (y:Group{objectid:'S-1-5-21-3926355307-1661546229-813047887-1106'})
MERGE (y)-[:AdminTo]->(x)
```

**After adding edges:** BloodHound now shows rsteel → Workstation Admins → AdminTo → WKSTN-1/2 — the full lateral movement path is visible and queryable.

### Cypher Template for Real Engagements

```cypher
# Generic template — swap SIDs for environment
MATCH (x:Computer{objectid:'<COMPUTER_SID>'})
MATCH (y:Group{objectid:'<GROUP_SID>'})
MERGE (y)-[:AdminTo]->(x)
```

---

## MITRE ATT&CK Mapping

| TTP | Technique | Detail |
|---|---|---|
| T1018 | Remote System Discovery | ldapsearch enumerates computers |
| T1069.002 | Domain Groups Discovery | ldapsearch enumerates groups and memberships |
| T1087.002 | Domain Account Discovery | ldapsearch enumerates user accounts |
| T1482 | Domain Trust Discovery | Domain object enumeration |
| T1615 | Group Policy Discovery | GPO enumeration via ldapsearch + GptTmpl.inf read |

---

## Key Takeaways

- **Never use SharpHound on a live engagement** if you can avoid it — BOFHound via ldapsearch BOF is the OPSEC-safe alternative
- `ntsecuritydescriptor` must be explicitly requested — it's the attribute that makes BloodHound's ACL edges possible
- **GPO-based local admin relationships are invisible to LDAP** — they live in SysVol `GptTmpl.inf` and must be manually read and added as Cypher edges
- The `[Group Membership]` section in `GptTmpl.inf` + `__Memberof = *S-1-5-32-544` is the pattern to look for — that SID is always the built-in Administrators group
- Object IDs from BloodHound are required for the Cypher edge injection — note them before leaving the GPO view
- On real engagements, check every GPO's `gpcpath` and walk its SysVol directory — Restricted Groups and other security settings are commonly misconfigured
- BloodHound is only as good as the data fed into it — manual edge injection for GPO-based relationships is a necessary part of thorough enumeration
