<#
.SYNOPSIS
    Report whether H.264/AVC 444 is enabled on an RDP host. Read-only.

.DESCRIPTION
    Answers "is my fleet actually using H.264 today?" - which decides whether IronRDP's
    lack of H.264 costs anything in practice.

    Checks the machine you point it at, not your client. Remote checks need
    PS remoting and admin on the target.

.EXAMPLE
    ./check-h264.ps1
    ./check-h264.ps1 -ComputerName srv-db01,srv-app02,srv-rds01
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName = @($env:COMPUTERNAME)
)

$ErrorActionPreference = 'Stop'

$probe = {
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $get = {
        param($name)
        try { (Get-ItemProperty -Path $key -Name $name -ErrorAction Stop).$name }
        catch { $null }
    }

    $avc444 = & $get 'AVC444ModePreferred'
    $avchw  = & $get 'AVCHardwareEncodePreferred'

    # An H.264 encoder exposed to Media Foundation is what hardware encoding needs.
    $gpu = try {
        (Get-CimInstance Win32_VideoController -ErrorAction Stop |
            Select-Object -ExpandProperty Name) -join '; '
    } catch { 'unknown' }

    [pscustomobject]@{
        Computer     = $env:COMPUTERNAME
        OS           = (Get-CimInstance Win32_OperatingSystem).Caption
        Build        = [Environment]::OSVersion.Version.ToString()
        AVC444       = if ($null -eq $avc444) { 'not set (default: off)' } else { $avc444 }
        HardwareEnc  = if ($null -eq $avchw)  { 'not set (default: off)' } else { $avchw }
        GPU          = $gpu
    }
}

$results = foreach ($c in $ComputerName) {
    if ($c -eq $env:COMPUTERNAME -or $c -eq 'localhost' -or $c -eq '.') {
        & $probe
    } else {
        try { Invoke-Command -ComputerName $c -ScriptBlock $probe -ErrorAction Stop }
        catch {
            [pscustomobject]@{
                Computer = $c; OS = "UNREACHABLE: $($_.Exception.Message)"
                Build = ''; AVC444 = ''; HardwareEnc = ''; GPU = ''
            }
        }
    }
}

$results | Format-List

Write-Host @'
How to read this
----------------
  AVC444 = 1                 H.264/AVC 444 is prioritised. Your current mstsc
                             sessions to this host likely use it, so an
                             IronRDP-vs-mstsc comparison here is NOT like for
                             like - mstsc gets H.264, IronRDP gets RemoteFX.

  AVC444 = 0 / not set       Host falls back to RemoteFX Adaptive Graphics,
                             which is what IronRDP negotiates. Nothing is lost
                             by switching. This is the Windows default.

  HardwareEnc = 1 but no     Hardware encode will not engage; the host software-
  capable GPU                encodes instead and burns CPU per session.

Supported on Windows 10 / Server 2016 and later. Server 2012 R2 and Windows 8.1
support only AVC 4:2:0, never 444.
'@ -ForegroundColor Cyan
