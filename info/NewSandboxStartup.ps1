param(
    # Include -launchingSandbox when started from the .wsb so first-run items can be gated
    [switch]$launchingSandbox
)

$ErrorActionPreference = 'Stop'

# ------------------------------- Paths & helpers -------------------------------
$psExe = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$cmdExe = "C:\Windows\System32\cmd.exe"
$base   = 'C:\Users\WDAGUtilityAccount\Desktop\HostShared'

function Start-PS {
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [string[]]$Args = @()
    )
    if (-not (Test-Path $ScriptPath)) { return }
    $argList = @('-ExecutionPolicy','Bypass','-NoExit','-File', $ScriptPath) + $Args
    Start-Process -FilePath 'powershell.exe' -ArgumentList $argList
}

# ------------------------------- Explorer / UI prefs ---------------------------
# Old right-click menu
reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve

# Show file extensions
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f

# Show hidden files
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f

# ------------------------------- MSI perf fix ---------------------------------
# https://github.com/microsoft/Windows-Sandbox/issues/68#issuecomment-2754867968
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d 0 /f
try {
    $ci = Get-Command "CiTool.exe" -ErrorAction SilentlyContinue
    if ($ci) { & $ci.Source --refresh --json | Out-Null }
} catch { }

# ------------------------------- PowerShell policy -----------------------------
try { Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -ErrorAction Stop | Out-Null } catch {}

# ---------------------- Context menu: Open PS/CMD here -------------------------
Write-Host "`nAdding 'Open PowerShell/CMD Here' context menu options"
reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\MyPowerShell" /ve /d "Open PowerShell Here" /f
reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\MyPowerShell" /v "Icon" /t REG_SZ /d "$psExe,0" /f
reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\MyPowerShell\command" /ve /d "powershell.exe -noexit -command Set-Location -literalPath '%V'" /f

reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\Mycmd" /ve /d "Open CMD Here" /f
reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\Mycmd" /v "Icon" /t REG_SZ /d "$cmdExe,0" /f
reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\Mycmd\command" /ve /d "cmd.exe /s /k cd /d `"\`"%V`"\`"" /f

# ---------------------- New menu: .txt and .ps1 templates ----------------------
Write-Host "`nAdding New menu entries (txt, ps1)"
# .txt
reg add "HKEY_CLASSES_ROOT\txtfile" /ve /d "Text Document" /f
reg add "HKEY_CLASSES_ROOT\.txt\ShellNew" /f
reg --% add "HKEY_CLASSES_ROOT\.txt\ShellNew" /v "NullFile" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\.txt\ShellNew" /v "ItemName" /t REG_SZ /d "New Text Document" /f

# .ps1 (also associates ps1file so scripts are clickable)
reg add "HKEY_CLASSES_ROOT\.ps1" /ve /d "ps1file" /f
reg add "HKEY_CLASSES_ROOT\ps1file" /ve /d "PowerShell Script" /f
reg add "HKEY_CLASSES_ROOT\ps1file\DefaultIcon" /ve /d "%SystemRoot%\System32\imageres.dll,-5372" /f
reg add "HKEY_CLASSES_ROOT\.ps1\ShellNew" /ve /d "ps1file" /f
reg add "HKEY_CLASSES_ROOT\.ps1\ShellNew" /f
reg --% add "HKEY_CLASSES_ROOT\.ps1\ShellNew" /v "NullFile" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\.ps1\ShellNew" /v "ItemName" /t REG_SZ /d "script" /f

# ---------------------- Optional editors: Notepad / Notepad++ ------------------
# Tip for Notepad.exe portability (copy exe + en-US\notepad.exe.mui into same folder tree)
$notepadPath         = Join-Path $base 'notepad.exe'
$notepadPlusPlusPath = Join-Path $base 'Notepad++\Notepad++.exe'

If (!(Test-Path $notepadPath))         { $notepadPath = $null;         Write-Host "Notepad not found, context menus will not be added." }
If (!(Test-Path $notepadPlusPlusPath)) { $notepadPlusPlusPath = $null; Write-Host "Notepad++ not found, context menus will not be added." }

# 'Edit with Notepad' / 'Open Notepad'
If ($null -ne $notepadPath) {
    Write-Host "`nAdding Notepad context menu"
    reg add "HKEY_CLASSES_ROOT\*\shell\Edit with Notepad" /f
    reg add "HKEY_CLASSES_ROOT\*\shell\Edit with Notepad" /v "Icon" /t REG_SZ /d "$notepadPath,0" /f
    reg add "HKEY_CLASSES_ROOT\*\shell\Edit with Notepad\command" /ve /d "`"$notepadPath`" `"%1`"" /f
    reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\Notepad" /ve /d "Open Notepad" /f
    reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\Notepad" /v "Icon" /t REG_SZ /d "$notepadPath,0" /f
    reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\Notepad\command" /ve /d "`"$notepadPath`"" /f
}

# 'Edit/Open with Notepad++'
If ($null -ne $notepadPlusPlusPath) {
    Write-Host "`nAdding Notepad++ context menu"
    reg add "HKEY_CLASSES_ROOT\*\shell\Edit with Notepad++" /f
    reg add "HKEY_CLASSES_ROOT\*\shell\Edit with Notepad++" /v "Icon" /t REG_SZ /d "$notepadPlusPlusPath,0" /f
    reg add "HKEY_CLASSES_ROOT\*\shell\Edit with Notepad++\command" /ve /t REG_EXPAND_SZ /d "`"$notepadPlusPlusPath`" -settingsDir=`"%appdata%`" `"`"%1`"`"" /f
    reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\Notepad++" /ve /d "Open Notepad++" /f
    reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\Notepad++" /v "Icon" /t REG_SZ /d "$notepadPlusPlusPath,0" /f
    reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\Notepad++\command" /ve /t REG_EXPAND_SZ /d "`"$notepadPlusPlusPath`" -settingsDir=`"%appdata%`"" /f
}

# Set .txt default editor (prefer Notepad++, else Notepad if available)
cmd /c assoc .txt=txtfile | Out-Null
If (($null -ne $notepadPath) -or ($null -ne $notepadPlusPlusPath)) {
    if (!(Test-Path 'HKLM:\SOFTWARE\Classes\txtfile\shell\open\command')) {
        New-Item -Path 'HKLM:\SOFTWARE\Classes\txtfile\shell\open\command' -Force | Out-Null
    }
    if ($null -ne $notepadPlusPlusPath) {
        # FIX: use actual Notepad++ path (the original used an undefined $editorPath)
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\txtfile\shell\open\command' -Name '(Default)' `
            -Value ("`"{0}`" -settingsDir=%appdata% `"%1`"" -f $notepadPlusPlusPath) -Type ExpandString -Force
    }
    elseif ($null -ne $notepadPath) {
        cmd /c ftype txtfile="`"$notepadPath`"" "%1" | Out-Null
    }
}

# ------------------------------- Apply UI changes ------------------------------
# Restart Explorer so UI/registry changes take effect
try { Stop-Process -Name explorer -Force } catch { }
Start-Process explorer.exe | Out-Null

# ------------------------------- First-launch tasks ----------------------------
# Gate heavier installs to the initial boot only (remove the if-block if you want them every run)
if ($launchingSandbox) {
    # Optional helpers you mentioned — they’ll each open in their own visible PowerShell window
    Start-PS -ScriptPath (Join-Path $base 'SetThemeDark.ps1')           -Args '-launchingSandbox'
    Start-PS -ScriptPath (Join-Path $base 'Install-VC-Redist.ps1')      -Args '-launchingSandbox'
    Start-PS -ScriptPath (Join-Path $base 'Install-Microsoft-Store.ps1')-Args '-launchingSandbox'
    Start-PS -ScriptPath (Join-Path $base 'Install-Winget.ps1')         -Args '-launchingSandbox'

    #---------------------- New: Install Google Chrome via winget ----------------------
    Write-Host "Starting silent installation of Google Chrome via winget..."

    # Ensure winget is available and install Google Chrome
    # Note: This command will wait for completion before moving to the next line.
    try {
        & winget install --id Google.Chrome --silent --accept-source-agreements --exact -e -Scope machine
        Write-Host "Google Chrome installation command initiated successfully."
    } catch {
        Write-Warning "Failed to run winget install for Google Chrome. Ensure Install-Winget.ps1 completed successfully."
    }

    # Open the shared folder so you can see everything right away
    Start-Process explorer.exe $base

}

Write-Host "`nSandboxStartup.ps1 complete. You can close this window once any child installer windows finish."
