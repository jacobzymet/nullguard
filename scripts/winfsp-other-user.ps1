# Checks that another local user can't open anything on a mounted vault
# drive, and can't tell which names exist in it. Run as an administrator
# (it creates and deletes a temporary local user), while a vault holding
# \a\greeting.txt is mounted on -Drive.
# Usage: powershell -File scripts/winfsp-other-user.ps1 -Drive N:
param([Parameter(Mandatory = $true)][string]$Drive)
$ErrorActionPreference = 'Stop'

# The drive letter only exists for the user who mounted it, but the device
# behind it can be opened by path from any account.
Add-Type -Namespace NgProbe -Name Dos -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint QueryDosDevice(string name, System.Text.StringBuilder target, uint max);
'@
$target = New-Object System.Text.StringBuilder 1024
if ([NgProbe.Dos]::QueryDosDevice($Drive, $target, 1024) -eq 0) { throw "no device behind $Drive" }
$device = $target.ToString()
Write-Host "device: $device"

$work = Join-Path $env:PUBLIC ("ngprobe-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $work | Out-Null
$user = 'ngprobe'
$password = 'Ng-' + [guid]::NewGuid().ToString('N').Substring(0, 16) + '!aA1'
# (Not `net user /add`: it stops to ask about passwords over 14 characters.)
$secure = ConvertTo-SecureString $password -AsPlainText -Force
New-LocalUser -Name $user -Password $secure -AccountNeverExpires -PasswordNeverExpires | Out-Null
try {
    icacls $work /grant "${user}:(OI)(CI)M" | Out-Null
    # Runs as the other user: try to open an existing file, a missing file,
    # a path under a missing folder and an existing folder, each once with
    # no access rights (WinFsp skips its own permission check for those)
    # and once for reading. Prints "<path> <access> <Win32 error>".
    @'
param([string]$Device)
Add-Type -Namespace NgProbe -Name Open -MemberDefinition @"
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
[DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
"@
foreach ($p in '\a\greeting.txt', '\nope.txt', '\nodir\nope.txt', '\a') {
    foreach ($access in [uint32]0, [uint32]2147483648) {
        $h = [NgProbe.Open]::CreateFileW("\\?\GLOBALROOT$Device$p", $access, 7, [IntPtr]::Zero, 3, 0x02000000, [IntPtr]::Zero)
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($h -ne [IntPtr]-1) { [NgProbe.Open]::CloseHandle($h) | Out-Null; $err = 0 }
        "$p $access $err"
    }
}
'@ | Set-Content -Encoding UTF8 (Join-Path $work 'probe.ps1')

    $cred = New-Object System.Management.Automation.PSCredential($user, $secure)
    $out = Join-Path $work 'out.txt'
    $p = Start-Process powershell -Credential $cred -WorkingDirectory $work -Wait -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $out -RedirectStandardError (Join-Path $work 'err.txt') `
        -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $work 'probe.ps1'), '-Device', $device
    $lines = @(Get-Content $out)
    $lines | ForEach-Object { Write-Host "  $_" }
    if ($lines.Count -ne 8) {
        Get-Content (Join-Path $work 'err.txt') | Write-Host
        throw "the probe ran incompletely (exit $($p.ExitCode))"
    }
    # 5 = ERROR_ACCESS_DENIED: the same answer for every path, existing or not.
    $leaks = @($lines | Where-Object { -not $_.EndsWith(' 5') })
    if ($leaks.Count -ne 0) { throw "another user got a different answer: $($leaks -join '; ')" }
    Write-Host "another user is refused everything, the same way for every name"
}
finally {
    Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
