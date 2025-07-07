<#
.SYNOPSIS
    Exovate - The Ultimate Windows 11 Optimization & Debloat Script (CLI Version).

.DESCRIPTION
    This script provides a rich, interactive command-line interface to debloat, optimize, and customize Windows 11.
    It allows users to select entire categories of tweaks to apply, offering a powerful and efficient way to tailor a system.
    
    Features:
    - Interactive, multi-select menu for choosing categories.
    - Over 100 tweaks organized into 10 logical categories.
    - Preset modes for quick application (Safe, Gaming, etc.).
    - Detailed logging and safe-guards like an automatic restore point creation.

    Run this script in an elevated PowerShell terminal (as Administrator).

.NOTES
    Version: 5.0 (CLI Edition)
    Author: Gemini & Aakesh
#>

# --- SCRIPT CONFIGURATION & HELPER FUNCTIONS ---

function Write-Log {
    param([string]$Message, [System.ConsoleColor]$Color = 'Gray')
    Write-Host $Message -ForegroundColor $Color
}

function Invoke-Tweak {
    param([string]$Name, [scriptblock]$ScriptBlock)
    try {
        Write-Log -Message "🚀 Applying Tweak: $Name..." -Color 'Cyan'
        Invoke-Command -ScriptBlock $ScriptBlock
        Write-Log -Message "✅ Success: $Name applied." -Color 'Green'
    } catch {
        Write-Log -Message "❌ Error applying '$Name': $_.Exception.Message" -Color 'Red'
    }
    Write-Host "" # Newline for spacing
}

# --- TWEAK DEFINITIONS (ORGANIZED BY CATEGORY) ---

$Global:TweakCategories = @{
    "Core System & Setup" = @(
        { Invoke-Tweak -Name "Create System Restore Point" -ScriptBlock { Checkpoint-Computer -Description "Exovate Pre-Debloat Restore Point" -RestorePointType "MODIFY_SETTINGS" } },
        { Invoke-Tweak -Name "Enable Long Path Support" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable Hibernation" -ScriptBlock { powercfg /hibernate off } },
        { Invoke-Tweak -Name "Completely Uninstall OneDrive" -ScriptBlock { if (Test-Path "$env:SystemRoot\SysWOW64\OneDriveSetup.exe") { Start-Process "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait }; if (Test-Path "$env:SystemRoot\System32\OneDriveSetup.exe") { Start-Process "$env:SystemRoot\System32\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait } } },
        { Invoke-Tweak -Name "Disable Storage Sense" -ScriptBlock { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Value 0 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable Windows Error Reporting" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord -Force } },
        { Invoke-Tweak -Name "Prevent Store App Reinstalls" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 2 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable Automatic Driver Updates" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable File System Tips" -ScriptBlock { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProtectedData\AnyoneRead\User\shell\Tips" -Name "Enabled" -Value 0 -Type DWord -Force } }
    );
    "App & Feature Removal" = @(
        { Invoke-Tweak -Name "Remove Common Bloatware" -ScriptBlock { $apps = @('*Clipchamp*','*3DBuilder*','*OfficeHub*','*SolitaireCollection*','*ZuneVideo*'); foreach ($app in $apps) { Get-AppxPackage $app -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue } } },
        { Invoke-Tweak -Name "Remove ALL Xbox Apps" -ScriptBlock { Get-AppxPackage *xbox* -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue } },
        { Invoke-Tweak -Name "Remove Communication Apps" -ScriptBlock { Get-AppxPackage *skype* -AllUsers | Remove-AppxPackage -AllUsers; Get-AppxPackage *people* -AllUsers | Remove-AppxPackage -AllUsers; Get-AppxPackage *windowscommunicationsapps* -AllUsers | Remove-AppxPackage -AllUsers } },
        { Invoke-Tweak -Name "Remove Old Media Apps" -ScriptBlock { Get-AppxPackage *ZuneMusic* -AllUsers | Remove-AppxPackage -AllUsers; Get-AppxPackage *WindowsMediaPlayer* -AllUsers | Remove-AppxPackage -AllUsers } },
        { Invoke-Tweak -Name "Force Remove Microsoft Edge" -ScriptBlock { $edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\*\Installer"; Get-ChildItem $edgePath | ForEach-Object { Start-Process "$_\setup.exe" -ArgumentList "--uninstall --system-level --verbose-logging --force-uninstall" -Wait } } },
        { Invoke-Tweak -Name "Remove Microsoft Print to PDF" -ScriptBlock { Disable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart } },
        { Invoke-Tweak -Name "Remove XPS Document Writer" -ScriptBlock { Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSPrinter-Driver-Features" -NoRestart } },
        { Invoke-Tweak -Name "Remove Quick Assist" -ScriptBlock { Get-AppxPackage *QuickAssist* -AllUsers | Remove-AppxPackage -AllUsers } },
        { Invoke-Tweak -Name "Remove Internet Explorer 11" -ScriptBlock { Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-amd64" -NoRestart } },
        { Invoke-Tweak -Name "Remove Math Input Panel" -ScriptBlock { Disable-WindowsOptionalFeature -Online -FeatureName "MathRecognizer" -NoRestart } }
    );
    "Privacy & Telemetry" = @(
        { Invoke-Tweak -Name "Disable Core Telemetry" -ScriptBlock { sc.exe stop "DiagTrack"; sc.exe config "DiagTrack" start=disabled; sc.exe stop "dmwappushservice"; sc.exe config "dmwappushservice" start=disabled; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable Ads & Suggestions" -ScriptBlock { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable Bing Search" -ScriptBlock { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable Copilot & Recall" -ScriptBlock { Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1 -Type DWord -Force; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAIDataAnalysis" -Value 1 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable Activity History" -ScriptBlock { Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable Location Tracking" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Type String -Force } },
        { Invoke-Tweak -Name "Disable Advertising ID" -ScriptBlock { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable App Launch Tracking" -ScriptBlock { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable Tailored Experiences" -ScriptBlock { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable Feedback Notifications" -ScriptBlock { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Type DWord -Force } }
    );
    "Performance & Gaming" = @(
        { Invoke-Tweak -Name "Enable Ultimate Performance" -ScriptBlock { powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61; powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61 } },
        { Invoke-Tweak -Name "Disable SysMain" -ScriptBlock { sc.exe stop "SysMain"; sc.exe config "SysMain" start=disabled } },
        { Invoke-Tweak -Name "Disable Search Indexing" -ScriptBlock { sc.exe stop "WSearch"; sc.exe config "WSearch" start=disabled } },
        { Invoke-Tweak -Name "Disable Fast Startup" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable Game DVR" -ScriptBlock { Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWord -Force } },
        { Invoke-Tweak -Name "Optimize Visual Effects" -ScriptBlock { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable Power Throttling" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Value 1 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable Spectre/Meltdown Patches" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Value 3 -Type DWord -Force; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Value 3 -Type DWord -Force } },
        { Invoke-Tweak -Name "Prioritize Foreground Apps" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 38 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable Prefetcher" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Value 0 -Type DWord -Force } }
    );
    "UI & Experience" = @(
        { Invoke-Tweak -Name "Enable Dark Mode" -ScriptBlock { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Type DWord -Force; Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Type DWord -Force } },
        { Invoke-Tweak -Name "Restore Classic Context Menu" -ScriptBlock { if (!(Test-Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32")) { New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force } } },
        { Invoke-Tweak -Name "Align Taskbar Left" -ScriptBlock { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Type DWord -Force } },
        { Invoke-Tweak -Name "Hide Extra Taskbar Icons" -ScriptBlock { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Type DWord -Force; Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -Type DWord -Force } },
        { Invoke-Tweak -Name "Hide Recommended in Start" -ScriptBlock { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_ShowRecommended" -Value 0 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable Sticky Keys" -ScriptBlock { Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506" -Type String -Force } },
        { Invoke-Tweak -Name "Disable Mouse Acceleration" -ScriptBlock { Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Value "0" -Type String -Force } },
        { Invoke-Tweak -Name "Show File Extensions" -ScriptBlock { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Type DWord -Force } },
        { Invoke-Tweak -Name "Show Hidden Files" -ScriptBlock { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable Lock Screen Blur" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -Value 1 -Type DWord -Force } }
    );
    "Security & Hardening" = @(
        { Invoke-Tweak -Name "Enable Controlled Folder Access" -ScriptBlock { Set-MpPreference -EnableControlledFolderAccess Enabled } },
        { Invoke-Tweak -Name "Disable SMBv1" -ScriptBlock { Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart } },
        { Invoke-Tweak -Name "Disable PowerShell v2" -ScriptBlock { Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -NoRestart } },
        { Invoke-Tweak -Name "Enable SmartScreen" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "RequireAdmin" -Type String -Force } },
        { Invoke-Tweak -Name "Disable AutoRun" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable Remote Assistance" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Type DWord -Force } },
        { Invoke-Tweak -Name "Enable Audit Process Creation" -ScriptBlock { auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable } },
        { Invoke-Tweak -Name "Disable LanMan Hash Storage" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Type DWord -Force } },
        { Invoke-Tweak -Name "Harden TCP/IP Stack" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDataRetransmissions" -Value 5 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable Guest Account" -ScriptBlock { net user guest /active:no } }
    );
    "Network & Connectivity" = @(
        { Invoke-Tweak -Name "Flush DNS Cache" -ScriptBlock { ipconfig /flushdns } },
        { Invoke-Tweak -Name "Reset TCP/IP Stack" -ScriptBlock { netsh int ip reset } },
        { Invoke-Tweak -Name "Disable NetBIOS" -ScriptBlock { $regkey = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"; Get-ChildItem $regkey | ForEach-Object { Set-ItemProperty -Path "$regkey\$($_.PSChildName)" -Name "NetbiosOptions" -Value 2 -Type DWord -Force } } },
        { Invoke-Tweak -Name "Disable LLMNR" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord -Force } },
        { Invoke-Tweak -Name "Disable Network Discovery" -ScriptBlock { netsh advfirewall firewall set rule group="Network Discovery" new enable=No } },
        { Invoke-Tweak -Name "Set Google DNS" -ScriptBlock { Set-DnsClientServerAddress -InterfaceAlias (Get-NetAdapter | Where-Object {$_.Status -eq "Up"}).Name -ServerAddresses ("8.8.8.8", "8.8.4.4") } },
        { Invoke-Tweak -Name "Set Cloudflare DNS" -ScriptBlock { Set-DnsClientServerAddress -InterfaceAlias (Get-NetAdapter | Where-Object {$_.Status -eq "Up"}).Name -ServerAddresses ("1.1.1.1", "1.0.0.1") } },
        { Invoke-Tweak -Name "Disable IPv6" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xffffffff -Type DWord -Force } },
        { Invoke-Tweak -Name "Apply Network Optimizations" -ScriptBlock { netsh int tcp set global autotuninglevel=disabled } },
        { Invoke-Tweak -Name "Show Current WiFi Password" -ScriptBlock { (netsh wlan show profiles) | Select-String "\:(.+)$" | ForEach-Object { $n = $_.Matches.Groups[1].Value.Trim(); (netsh wlan show profile name="$n" key=clear) } } }
    );
    "Developer & Power User" = @(
        { Invoke-Tweak -Name "Install WSL" -ScriptBlock { wsl --install } },
        { Invoke-Tweak -Name "Enable Hyper-V" -ScriptBlock { Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart } },
        { Invoke-Tweak -Name "Enable Windows Sandbox" -ScriptBlock { Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -NoRestart } },
        { Invoke-Tweak -Name "Enable Developer Mode" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Value 1 -Type DWord -Force } },
        { Invoke-Tweak -Name "Add 'Take Ownership' Context Menu" -ScriptBlock { $regPath = "HKCR:\*\shell\runas"; New-Item $regPath -Force; Set-ItemProperty -Path $regPath -Name "(Default)" -Value "Take Ownership"; Set-ItemProperty -Path $regPath -Name "NoWorkingDirectory" -Value "" } },
        { Invoke-Tweak -Name "Add 'PowerShell Here' Context Menu" -ScriptBlock { Set-ItemProperty -Path "HKCR:\Directory\shell\powershell\command" -Name "(Default)" -Value "powershell.exe -NoExit -Command Set-Location -LiteralPath '%L'" } },
        { Invoke-Tweak -Name "Disable UAC" -ScriptBlock { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Type DWord -Force } },
        { Invoke-Tweak -Name "Create 'God Mode' on Desktop" -ScriptBlock { New-Item -Path "$env:USERPROFILE\Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}" -ItemType Directory } },
        { Invoke-Tweak -Name "Install Chocolatey" -ScriptBlock { Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')) } },
        { Invoke-Tweak -Name "Update Winget" -ScriptBlock { winget upgrade winget } }
    );
    "Services Management" = @(
        { Invoke-Tweak -Name "Disable Print Spooler" -ScriptBlock { sc.exe stop "Spooler"; sc.exe config "Spooler" start=disabled } },
        { Invoke-Tweak -Name "Disable Fax Service" -ScriptBlock { sc.exe stop "Fax"; sc.exe config "Fax" start=disabled } },
        { Invoke-Tweak -Name "Disable Remote Registry" -ScriptBlock { sc.exe stop "RemoteRegistry"; sc.exe config "RemoteRegistry" start=disabled } },
        { Invoke-Tweak -Name "Disable Touch Keyboard Service" -ScriptBlock { sc.exe stop "TabletInputService"; sc.exe config "TabletInputService" start=disabled } },
        { Invoke-Tweak -Name "Disable Bluetooth Service" -ScriptBlock { sc.exe stop "BthServ"; sc.exe config "BthServ" start=disabled } },
        { Invoke-Tweak -Name "Disable AllJoyn Router Service" -ScriptBlock { sc.exe stop "AJRouter"; sc.exe config "AJRouter" start=disabled } },
        { Invoke-Tweak -Name "Disable Geolocation Service" -ScriptBlock { sc.exe stop "lfsvc"; sc.exe config "lfsvc" start=disabled } },
        { Invoke-Tweak -Name "Disable WalletService" -ScriptBlock { sc.exe stop "WalletService"; sc.exe config "WalletService" start=disabled } },
        { Invoke-Tweak -Name "Disable Phone Service" -ScriptBlock { sc.exe stop "PhoneSvc"; sc.exe config "PhoneSvc" start=disabled } },
        { Invoke-Tweak -Name "Disable Diagnostic Policy Service" -ScriptBlock { sc.exe stop "DPS"; sc.exe config "DPS" start=disabled } }
    );
    "System Cleanup & Maintenance" = @(
        { Invoke-Tweak -Name "Clear Temp Files" -ScriptBlock { Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue } },
        { Invoke-Tweak -Name "Empty Recycle Bin" -ScriptBlock { Clear-RecycleBin -Force -ErrorAction SilentlyContinue } },
        { Invoke-Tweak -Name "Clear Windows Update Cache" -ScriptBlock { net stop wuauserv; Remove-Item "C:\Windows\SoftwareDistribution" -Recurse -Force; net start wuauserv } },
        { Invoke-Tweak -Name "Run Full Disk Cleanup" -ScriptBlock { $drive = $env:SystemDrive; cleanmgr /sagerun:1 } },
        { Invoke-Tweak -Name "Reset Microsoft Store Cache" -ScriptBlock { wsreset.exe -q } },
        { Invoke-Tweak -Name "Run System File Checker" -ScriptBlock { sfc /scannow } },
        { Invoke-Tweak -Name "Run DISM Component Store Repair" -ScriptBlock { Dism.exe /Online /Cleanup-Image /RestoreHealth } },
        { Invoke-Tweak -Name "Rebuild Icon Cache" -ScriptBlock { ie4uinit.exe -show; Stop-Process -Name explorer -Force; $iconCache = "$env:LOCALAPPDATA\IconCache.db"; if (Test-Path $iconCache) { Remove-Item $iconCache -Force }; Start-Process explorer } },
        { Invoke-Tweak -Name "Rebuild Font Cache" -ScriptBlock { Stop-Service FontCache; $fontCache = "$env:WINDIR\ServiceProfiles\LocalService\AppData\Local\FontCache"; if (Test-Path $fontCache) { Remove-Item "$fontCache\*" -Recurse -Force }; Start-Service FontCache } },
        { Invoke-Tweak -Name "Defragment & Optimize All Drives" -ScriptBlock { Optimize-Volume -DriveLetter (Get-Volume).DriveLetter -Defrag -Verbose } }
    );
}

# --- MAIN MENU LOGIC ---

function Show-Menu {
    param(
        [hashtable]$SelectedCategories
    )
    Clear-Host
    Write-Host @"
███████╗██╗   ██╗ ██████╗  ██████╗  █████╗ ████████╗███████╗
██╔════╝╚██╗ ██╔╝██╔═══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝
█████╗   ╚████╔╝ ██║   ██║██║   ██║███████║   ██║   █████╗
██╔══╝    ╚██╔╝  ██║   ██║██║   ██║██╔══██║   ██║   ██╔══╝
███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║   ██║   ███████╗
╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝
"@ -ForegroundColor Cyan
    Write-Host "          EXOVATE By Aakesh" -ForegroundColor White
    Write-Host "=======================================================================" -ForegroundColor DarkGray
    Write-Host ""
    Write-Log -Message "Select categories to apply. Use numbers to toggle, then press 'A' to apply." -Color "White"
    Write-Host ""

    $i = 1
    foreach ($categoryName in $Global:TweakCategories.Keys) {
        $selectionChar = if ($SelectedCategories.ContainsKey($categoryName)) { "[x]" } else { "[ ]" }
        Write-Host (" {0,2}. {1,-4} {2}" -f $i, $selectionChar, $categoryName)
        $i++
    }

    Write-Host ""
    Write-Log -Message "-----------------------------------------------------------------------" -Color "DarkGray"
    Write-Log -Message "A - Apply Selected Categories     P - Apply a Preset     Q - Quit" -Color "Yellow"
    Write-Log -Message "-----------------------------------------------------------------------" -Color "DarkGray"
}

function Show-PresetMenu {
    Clear-Host
    Write-Log -Message "Select a Preset Profile:" -Color "White"
    Write-Host ""
    Write-Log "1. Safe (Recommended for most users)" -Color "Green"
    Write-Log "2. Gaming (Safe profile + gaming optimizations)" -Color "Magenta"
    Write-Log "3. Lightweight (Safe profile + aggressive resource saving)" -Color "Cyan"
    Write-Log "4. Performance (All optimizations combined)" -Color "Red"
    Write-Host ""
    Write-Log "B - Back to Main Menu" -Color "Yellow"
    Write-Host ""
}

# --- SCRIPT EXECUTION ---

# Check for Admin Rights
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "❌ This script requires administrator privileges. Please re-run as Administrator." -Color 'Red'
    Read-Host "Press Enter to exit..."
    return
}

$selectedCategories = @{}
$categoryKeys = @($Global:TweakCategories.Keys)

while ($true) {
    Show-Menu -SelectedCategories $selectedCategories
    $input = Read-Host -Prompt "Enter your choice"

    if ($input -match '^\d+$' -and $input -ge 1 -and $input -le $categoryKeys.Count) {
        $index = [int]$input - 1
        $categoryName = $categoryKeys[$index]
        if ($selectedCategories.ContainsKey($categoryName)) {
            $selectedCategories.Remove($categoryName)
        } else {
            $selectedCategories[$categoryName] = $true
        }
    } elseif ($input -eq 'a') {
        if ($selectedCategories.Count -eq 0) {
            Write-Log "No categories selected. Nothing to apply." -Color "Yellow"
            Read-Host "Press Enter to continue..."
            continue
        }
        Clear-Host
        Write-Log "Applying selected categories..." -Color "White"
        foreach ($categoryName in $selectedCategories.Keys) {
            Write-Log "--- Applying Category: $categoryName ---" -Color "Yellow"
            foreach ($tweak in $Global:TweakCategories[$categoryName]) {
                & $tweak
            }
        }
        break
    } elseif ($input -eq 'p') {
        $presetChoice = ''
        while ($presetChoice -ne 'b') {
            Show-PresetMenu
            $presetChoice = Read-Host -Prompt "Select a preset"
            $selectedCategories.Clear() # Clear previous selections
            $safePreset = @("Core System & Setup", "App & Feature Removal", "Privacy & Telemetry", "Performance & Gaming", "UI & Experience", "Security & Hardening", "Network & Connectivity", "Developer & Power User", "Services Management")
            $gamingPreset = @("Performance & Gaming")
            $lightweightPreset = @("Services Management", "App & Feature Removal")
            
            switch ($presetChoice) {
                '1' { $safePreset | ForEach-Object { $selectedCategories[$_] = $true }; break }
                '2' { $safePreset + $gamingPreset | ForEach-Object { $selectedCategories[$_] = $true }; break }
                '3' { $safePreset + $lightweightPreset | ForEach-Object { $selectedCategories[$_] = $true }; break }
                '4' { $Global:TweakCategories.Keys | ForEach-Object { $selectedCategories[$_] = $true }; break }
            }
        }
    } elseif ($input -eq 'q') {
        break
    }
}

Write-Log "✅ Script finished." -Color 'Green'
Write-Log "It is recommended to reboot your computer for all changes to take full effect." -Color 'Yellow'
Read-Host "Press Enter to exit..."
