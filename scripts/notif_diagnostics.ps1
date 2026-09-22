# MailBuddy notification diagnostics (read-only)
$ErrorActionPreference = 'SilentlyContinue'

Write-Host '=== 1. Start Menu shortcuts named MailBuddy ==='
$dirs = @(
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
)
foreach ($dir in $dirs) {
  if (Test-Path $dir) {
    $links = Get-ChildItem -Path $dir -Filter '*.lnk' -Recurse | Where-Object { $_.BaseName -like '*MailBuddy*' }
    foreach ($lnk in $links) {
      Write-Host "found: $($lnk.FullName)"
      $shell = New-Object -ComObject WScript.Shell
      $ws = $shell.CreateShortcut($lnk.FullName)
      Write-Host "  target: $($ws.TargetPath)"
      # Read the System.AppUserModel.ID property via Shell property store
      $shellApp = New-Object -ComObject Shell.Application
      $folder = $shellApp.Namespace($lnk.DirectoryName)
      $item = $folder.ParseName($lnk.Name)
      # property index 26 is often AppUserModelId in some views; enumerate properties instead
      $found = $false
      for ($i = 0; $i -lt 400; $i++) {
        $name = $folder.GetDetailsOf($null, $i)
        if ($name -match 'AppUserModel') {
          $val = $folder.GetDetailsOf($item, $i)
          Write-Host "  [$i] $name = $val"
          $found = $true
        }
      }
      if (-not $found) { Write-Host '  (no AppUserModel property exposed by GetDetailsOf enumeration)' }
    }
  }
}

Write-Host ''
Write-Host '=== 2. HKCU AppUserModelId registrations ==='
Get-ChildItem 'HKCU:\Software\Classes\AppUserModelId' | ForEach-Object {
  $disp = (Get-ItemProperty $_.PSPath).'DisplayName'
  Write-Host "  $($_.PSChildName)  DisplayName=$disp"
}

Write-Host ''
Write-Host '=== 3. Global toast / Focus assist settings ==='
$push = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications'
Write-Host "  ToastEnabled (PushNotifications): $($push.ToastEnabled)"
$noc = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings'
Write-Host "  NOC_GLOBAL_SETTING_TOASTS_ENABLED: $($noc.NOC_GLOBAL_SETTING_TOASTS_ENABLED)"
$quiet = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\QuietHours'
Write-Host "  QuietHours (focus assist) keys: $($quiet | Out-String)"

Write-Host ''
Write-Host '=== 4. Per-app notification settings for MailBuddy/PhishGuard ==='
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings' | ForEach-Object {
  if ($_.PSChildName -match 'phishguard|mailbuddy') {
    Write-Host "  $($_.PSChildName):"
    Get-ItemProperty $_.PSPath | Format-List | Out-String | Write-Host
  }
}

Write-Host '=== 5. Is the AUMID registered with a ToastActivatorCLSID (electron-builder)? ==='
$clsidPath = 'HKCU:\Software\Classes\AppUserModelId\com.phishguard.desktop'
if (Test-Path $clsidPath) {
  Get-ItemProperty $clsidPath | Format-List | Out-String | Write-Host
} else {
  Write-Host "  MISSING: $clsidPath"
}
