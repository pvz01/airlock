<#
.SYNOPSIS
    Scans Windows Program Files directories for files containing Microsoft
    Managed Installer or Airlock Digital Trusted Installer Extended Attributes
    (EAs).

.DESCRIPTION
    This script recursively scans the following directories by default:

        C:\Program Files
        C:\Program Files (x86)

    It inspects files matching the configured extension list using the built-in
    Windows fsutil.exe utility and checks for the following Extended Attributes:

        $KERNEL.SMARTLOCKER.ORIGINCLAIM
            Microsoft Managed Installer

        $KERNEL.AIRLOCK.TRUSTEDINSTALLER
            Airlock Digital Trusted Installer

        $KERNEL.PURGE.AIRLOCK.TRUSTEDINSTALLER.VALID
            Airlock Digital Trusted Installer validation EA

    Files containing one or more of these EAs are written to a CSV file in
    the directory from which the script is run.

    The output filename includes the computer hostname and UTC execution
    timestamp:

        TrustedInstaller-EAs_<hostname>_<yyyy-MM-dd_HH-mm>_UTC.csv

    The script displays progress every 500 files and reports the total number
    of files scanned, matches found, and inaccessible paths skipped when
    complete.

    Directory traversal is performed one directory at a time rather than with
    Get-ChildItem -Recurse. This allows access-denied directories to be caught
    and skipped cleanly without displaying PowerShell error blocks.

.AUTHOR
    Patrick Van Zandt

.DATE
    2026-10-07

.CONFIGURATION
    The default scan paths are configured in the $Paths array:

        $Paths = @(
            "C:\Program Files"
            "C:\Program Files (x86)"
        )

    The file types to scan are configured in the $Extensions array:

        $Extensions = @(
            ".exe"
            ".dll"
        )

    Additional paths or file extensions can be added as needed. For example,
    to scan the entire C:\ drive, replace the $Paths array with:

        $Paths = @(
            "C:\"
        )

    To include additional file types, add them to $Extensions:

        $Extensions = @(
            ".exe"
            ".dll"
            ".sys"
            ".msi"
        )

.USAGE
    Run the script from an elevated PowerShell session for the best filesystem
    access:

        .\Find-TrustedInstallerEAs.ps1

    If PowerShell script execution is disabled, the script can be run without
    permanently changing the system execution policy:

        powershell.exe -ExecutionPolicy Bypass -File .\Find-TrustedInstallerEAs.ps1

    Alternatively, allow script execution only for the current PowerShell
    process:

        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

        .\Find-TrustedInstallerEAs.ps1

.OUTPUT
    CSV columns:

        File
            Full path to the file containing a matching EA.

        Microsoft Managed Installer
            True if $KERNEL.SMARTLOCKER.ORIGINCLAIM is present.

        Airlock Trusted Installer
            True if $KERNEL.AIRLOCK.TRUSTEDINSTALLER is present.

        Airlock Valid
            True if $KERNEL.PURGE.AIRLOCK.TRUSTEDINSTALLER.VALID is present.

.NOTES
    - The script is read-only and does not modify Extended Attributes.
    - Running as Administrator is recommended to maximize filesystem access.
    - Inaccessible paths are skipped and counted rather than printed as errors.
    - fsutil.exe is executed once for each candidate file, so broader scans
      and larger extension lists may take additional time.
#>

$Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd_HH-mm")
$Hostname = $env:COMPUTERNAME
$OutputFile = ".\TrustedInstaller-EAs_${Hostname}_${Timestamp}_UTC.csv"

$Paths = @(
    "C:\Program Files"
    "C:\Program Files (x86)"
)

$Extensions = @(
    ".exe"
    ".dll"
)

# Normalize configured extensions so matching is case-insensitive and consistent.
$Extensions = $Extensions | ForEach-Object { $_.ToLowerInvariant() }

$Count = 0
$Matches = 0
$InaccessiblePaths = 0
$Results = @()

# Explicit directory traversal avoids noisy errors from Get-ChildItem -Recurse.
$Directories = New-Object System.Collections.Generic.Stack[string]

foreach ($Path in $Paths) {
    if (Test-Path -LiteralPath $Path -PathType Container) {
        $Directories.Push($Path)
    }
}

while ($Directories.Count -gt 0) {
    $CurrentDirectory = $Directories.Pop()

    # Get child directories. Access failures are caught and counted.
    try {
        $ChildDirectories = Get-ChildItem -LiteralPath $CurrentDirectory -Directory -Force -ErrorAction Stop
    }
    catch {
        $InaccessiblePaths++
        continue
    }

    foreach ($Directory in $ChildDirectories) {
        # Skip reparse points/junctions to avoid loops and protected compatibility links.
        if (($Directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
            $Directories.Push($Directory.FullName)
        }
    }

    # Get files from this directory. Access failures are caught and counted.
    try {
        $Files = Get-ChildItem -LiteralPath $CurrentDirectory -File -Force -ErrorAction Stop |
            Where-Object {
                $Extensions -contains $_.Extension.ToLowerInvariant()
            }
    }
    catch {
        $InaccessiblePaths++
        continue
    }

    foreach ($Item in $Files) {
        $Count++

        if (($Count % 500) -eq 0) {
            Write-Host "Scanned $Count files... Matches found: $Matches"
        }

        $File = $Item.FullName
        $Output = & fsutil.exe file queryEA $File 2>$null

        if ($LASTEXITCODE -eq 0) {
            $Microsoft = [bool]($Output -match '\$KERNEL\.SMARTLOCKER\.ORIGINCLAIM')
            $Airlock = [bool]($Output -match '\$KERNEL\.AIRLOCK\.TRUSTEDINSTALLER')
            $AirlockValid = [bool]($Output -match '\$KERNEL\.PURGE\.AIRLOCK\.TRUSTEDINSTALLER\.VALID')

            if ($Microsoft -or $Airlock -or $AirlockValid) {
                $Matches++

                $Results += [PSCustomObject]@{
                    File                          = $File
                    "Microsoft Managed Installer" = $Microsoft
                    "Airlock Trusted Installer"   = $Airlock
                    "Airlock Valid"               = $AirlockValid
                }
            }
        }
    }
}

$Results | Export-Csv $OutputFile -NoTypeInformation

Write-Host ""
Write-Host "Scan complete."
Write-Host "Files scanned: $Count"
Write-Host "Matches found: $Matches"
Write-Host "Inaccessible paths skipped: $InaccessiblePaths"
Write-Host "Output: $OutputFile"
